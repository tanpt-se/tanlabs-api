import { DEFAULT_CLIENT_ROLE } from "../common/access-control";
import type { AppContext } from "../types";
import { AppException } from "../lib/errors";
import { getHeaderValue, getRequestIp } from "../lib/request-policy";
import { hashPassword } from "../lib/password";
import type { FlowSupportService } from "./flow-support.service";

export class RegistrationFlowService {
	constructor(private readonly support: FlowSupportService) {}

	async register(
		c: AppContext,
		dto: { email: string; displayName: string; password: string; captchaToken: string },
	) {
		const normalizedEmail = this.support.normalizeEmail(dto.email);
		await this.support.rateLimit.assertSignupAllowed(getRequestIp(c), normalizedEmail);
		await this.assertTurnstile(dto.captchaToken, getRequestIp(c));

		const existingUser = await this.support.users.findByNormalizedEmail(normalizedEmail);
		if (existingUser) {
			await this.support.rateLimit.recordSignupAttempt(getRequestIp(c), normalizedEmail);
			throw new AppException({ code: "CONFLICT", message: "Email already exists.", status: 409 });
		}

		const defaultRole = await this.support.users.findRoleByName(DEFAULT_CLIENT_ROLE);
		if (!defaultRole) {
			throw new AppException({ code: "NOT_FOUND", message: "Default role not found.", status: 500 });
		}

		const passwordHash = await hashPassword(dto.password, this.support.config.auth);
		const draftUser = {
			email: dto.email,
			emailNormalized: normalizedEmail,
			displayName: dto.displayName.trim(),
			passwordHash,
			roleId: defaultRole.id,
		};

		await this.support.assertValidNewPassword(
			{
				id: "signup-draft",
				email: dto.email,
				email_normalized: normalizedEmail,
				display_name: dto.displayName,
				password_hash: passwordHash,
				password_changed_at: null,
				email_verified_at: null,
				must_set_password: 0,
				two_factor_enabled: 0,
				status: "ACTIVE",
				role_id: defaultRole.id,
				created_at: new Date().toISOString(),
				updated_at: new Date().toISOString(),
				role: defaultRole,
			},
			dto.password,
		);

		const user = await this.support.users.createUser({
			email: draftUser.email,
			emailNormalized: draftUser.emailNormalized,
			displayName: draftUser.displayName,
			passwordHash: draftUser.passwordHash,
			roleId: draftUser.roleId,
		});

		await this.support.rateLimit.clearSignupAttempts(getRequestIp(c), normalizedEmail);
		await this.support.audit.log({
			eventType: "SIGNUP_REGISTERED",
			userId: user.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		const challenge = await this.support.issueEmailVerificationChallenge(user, "signup_email_verification");
		return { success: true, email: user.email, ...challenge };
	}

	async verifyEmailVerification(
		dto: { challengeId: string; verificationContextToken: string; code: string },
	) {
		let verificationContext;
		try {
			verificationContext = await this.support.verifyVerificationContextToken(
				dto.verificationContextToken,
				"signup_email_verification",
			);
		} catch (error) {
			try {
				verificationContext = await this.support.verifyVerificationContextToken(
					dto.verificationContextToken,
					"account_email_verification",
				);
			} catch {
				throw error;
			}
		}

		const user = await this.support.users.findById(verificationContext.user_id);
		if (!user) {
			throw new AppException({ code: "NOT_FOUND", message: "User not found.", status: 404 });
		}

		const purpose =
			verificationContext.purpose === "signup_email_verification"
				? "SIGNUP_EMAIL_VERIFICATION"
				: "ACCOUNT_EMAIL_VERIFICATION";

		await this.support.challenges.verifyEmailOtpChallenge({
			challengeId: dto.challengeId,
			userId: user.id,
			purpose,
			contextKey: `${verificationContext.purpose}:${user.id}`,
			code: dto.code,
		});

		await this.support.users.updateUser(user.id, {
			emailVerifiedAt: new Date().toISOString(),
		});

		await this.support.audit.log({
			eventType: "EMAIL_VERIFIED",
			userId: user.id,
		});

		return { success: true };
	}

	async resendEmailVerification(dto: { verificationContextToken: string }) {
		const verificationContext = await this.support.verifyVerificationContextToken(
			dto.verificationContextToken,
			"signup_email_verification",
		).catch(async () =>
			this.support.verifyVerificationContextToken(
				dto.verificationContextToken,
				"account_email_verification",
			),
		);

		const user = await this.support.users.findById(verificationContext.user_id);
		if (!user) {
			throw new AppException({ code: "NOT_FOUND", message: "User not found.", status: 404 });
		}

		const challenge = await this.support.issueEmailVerificationChallenge(
			user,
			verificationContext.purpose,
		);
		return { success: true, ...challenge };
	}

	private async assertTurnstile(token: string, ip: string | null): Promise<void> {
		const secret = this.support.config.auth.turnstileSecretKey;
		if (!secret) return;

		const body = new URLSearchParams({ secret, response: token });
		if (ip) body.set("remoteip", ip);

		const response = await fetch(this.support.config.auth.turnstileVerifyUrl, {
			method: "POST",
			body,
		});
		const result = (await response.json()) as { success?: boolean };
		if (!result.success) {
			throw new AppException({
				code: "AUTH_CAPTCHA_INVALID",
				message: "Captcha verification failed.",
				status: 400,
			});
		}
	}
}
