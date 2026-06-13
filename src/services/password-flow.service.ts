import { AUTH_MAIL_SUBJECTS } from "../common/access-control";
import type { AppContext } from "../types";
import { AppException } from "../lib/errors";
import { sendEmail } from "../lib/email";
import { getHeaderValue, getRequestIp } from "../lib/request-policy";
import { hashPassword, verifyPassword } from "../lib/password";
import type { FlowSupportService } from "./flow-support.service";

export class PasswordFlowService {
	constructor(private readonly support: FlowSupportService) {}

	async forgotPassword(c: AppContext, dto: { email: string }) {
		const normalizedEmail = this.support.normalizeEmail(dto.email);
		if (await this.support.rateLimit.isForgotPasswordLimited(getRequestIp(c), normalizedEmail)) {
			return { success: true };
		}

		await this.support.rateLimit.recordForgotPasswordAttempt(getRequestIp(c), normalizedEmail);
		const user = await this.support.users.findByNormalizedEmail(normalizedEmail);
		if (!user) return { success: true };

		const { rawToken, token, expiresAt } = await this.support.createPasswordActionToken({
			userId: user.id,
			purpose: "PASSWORD_RESET",
		});

		await this.support.audit.log({
			eventType: "PASSWORD_RESET_REQUESTED",
			userId: user.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		if (this.support.config.passwordResetDelivery.enabled) {
			const url = new URL(
				this.support.config.passwordResetDelivery.resetUrlPath,
				this.support.config.passwordResetDelivery.resetUrlOrigin,
			);
			url.searchParams.set(this.support.config.passwordResetDelivery.tokenQueryParam, rawToken);

			try {
				await sendEmail({
					config: this.support.config,
					to: user.email,
					subject: AUTH_MAIL_SUBJECTS.passwordReset,
					text: `Reset your password: ${url.toString()}`,
				});
			} catch {
				if (token) {
					await this.support.passwordReset.markRevoked(token.id, new Date().toISOString());
				}
				throw new AppException({
					code: "EMAIL_DELIVERY_FAILED",
					message: "Failed to send password reset email.",
					status: 503,
				});
			}
		}

		return { success: true };
	}

	async resetPassword(c: AppContext, dto: { token: string; newPassword: string }) {
		const tokenHash = await this.support.sessions.hashOpaqueToken(dto.token);
		await this.support.rateLimit.assertResetPasswordAllowed(getRequestIp(c), undefined, tokenHash);

		const resetToken = await this.support.passwordReset.findByTokenHash(tokenHash);
		if (!resetToken || resetToken.used_at || resetToken.revoked_at) {
			await this.support.rateLimit.recordResetPasswordAttempt(getRequestIp(c), undefined, tokenHash);
			throw new AppException({
				code: "AUTH_PASSWORD_RESET_INVALID",
				message: "Password reset token is invalid.",
				status: 401,
			});
		}

		if (resetToken.purpose !== "PASSWORD_RESET") {
			throw new AppException({
				code: "AUTH_PASSWORD_RESET_INVALID",
				message: "Password reset token is invalid.",
				status: 401,
			});
		}

		if (new Date(resetToken.expires_at as string) <= new Date()) {
			throw new AppException({
				code: "AUTH_PASSWORD_RESET_EXPIRED",
				message: "Password reset token has expired.",
				status: 401,
			});
		}

		const user = await this.support.users.findById(resetToken.user_id as string);
		if (!user) {
			throw new AppException({ code: "NOT_FOUND", message: "User not found.", status: 404 });
		}

		await this.support.assertValidNewPassword(user, dto.newPassword);
		const passwordHash = await hashPassword(dto.newPassword, this.support.config.auth);
		const now = new Date().toISOString();

		await this.support.users.updateUser(user.id, {
			passwordHash,
			passwordChangedAt: now,
			mustSetPassword: false,
		});
		await this.support.passwordReset.markUsed(resetToken.id as string, now);
		await this.support.sessions.revokeAllActiveSessionsForUser(user.id);

		await this.support.audit.log({
			eventType: "PASSWORD_RESET_COMPLETED",
			userId: user.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		return { success: true };
	}

	async setupAccount(c: AppContext, dto: { token: string; newPassword: string }) {
		const tokenHash = await this.support.sessions.hashOpaqueToken(dto.token);
		const resetToken = await this.support.passwordReset.findByTokenHash(tokenHash);

		if (!resetToken || resetToken.used_at || resetToken.revoked_at) {
			throw new AppException({
				code: "AUTH_ACCOUNT_SETUP_INVALID",
				message: "Account setup token is invalid.",
				status: 401,
			});
		}

		if (resetToken.purpose !== "ACCOUNT_SETUP") {
			throw new AppException({
				code: "AUTH_ACCOUNT_SETUP_INVALID",
				message: "Account setup token is invalid.",
				status: 401,
			});
		}

		const user = await this.support.users.findById(resetToken.user_id as string);
		if (!user) {
			throw new AppException({ code: "NOT_FOUND", message: "User not found.", status: 404 });
		}

		await this.support.assertValidNewPassword(user, dto.newPassword);
		const passwordHash = await hashPassword(dto.newPassword, this.support.config.auth);
		const now = new Date().toISOString();

		await this.support.users.updateUser(user.id, {
			passwordHash,
			passwordChangedAt: now,
			mustSetPassword: false,
			emailVerifiedAt: user.email_verified_at ?? now,
		});
		await this.support.passwordReset.markUsed(resetToken.id as string, now);

		return { success: true };
	}

	async changePassword(
		c: AppContext,
		dto: { currentPassword: string; newPassword: string },
	) {
		const authContext = await this.support.getAuthenticatedContext(c);
		const user = await this.support.users.findById(authContext.userId);
		if (!user) {
			throw new AppException({ code: "AUTH_TOKEN_EXPIRED", message: "User not found", status: 401 });
		}

		if (!(await verifyPassword(dto.currentPassword, user.password_hash))) {
			throw new AppException({
				code: "AUTH_INVALID_CREDENTIALS",
				message: "Current password is invalid.",
				status: 401,
			});
		}

		await this.support.assertValidNewPassword(user, dto.newPassword);
		const passwordHash = await hashPassword(dto.newPassword, this.support.config.auth);
		const now = new Date().toISOString();

		await this.support.users.updateUser(user.id, {
			passwordHash,
			passwordChangedAt: now,
		});
		await this.support.sessions.revokeAllOtherSessions(user.id, authContext.sessionId);

		await this.support.audit.log({
			eventType: "PASSWORD_CHANGED",
			userId: user.id,
			sessionId: authContext.sessionId,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		return { success: true };
	}
}
