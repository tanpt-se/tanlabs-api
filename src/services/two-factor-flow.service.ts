import type { AppContext } from "../types";
import { decryptTwoFactorSecret, encryptTwoFactorSecret } from "../lib/crypto";
import { AppException } from "../lib/errors";
import { getHeaderValue, getRequestIp } from "../lib/request-policy";
import { verifyPassword } from "../lib/password";
import { generateTotpSecret, verifyTotpCode } from "../lib/totp";
import type { FlowSupportService } from "./flow-support.service";

export class TwoFactorFlowService {
	constructor(private readonly support: FlowSupportService) {}

	private encryptionKey(): string {
		return this.support.env.TWO_FACTOR_SECRET_ENCRYPTION_KEY ?? "dev-two-factor-secret-key";
	}

	async getTwoFactorStatus(c: AppContext) {
		const userId = await this.support.getAuthenticatedUserId(c);
		const user = await this.support.users.findById(userId);
		if (!user) {
			throw new AppException({ code: "AUTH_TOKEN_EXPIRED", message: "User not found", status: 401 });
		}
		this.support.assertUserCanLogin(user);
		const secret = await this.support.twoFactor.findByUserId(userId);

		return {
			twoFactor: {
				enabled: user.two_factor_enabled === 1,
				verified: secret?.is_verified === 1,
				method: user.two_factor_enabled === 1 ? "totp" : null,
			},
		};
	}

	async setupTwoFactorTotp(
		c: AppContext,
		dto: { password?: string; recentAuthToken?: string },
	) {
		const authContext = await this.support.getAuthenticatedContext(c);
		const user = await this.support.users.findById(authContext.userId);
		if (!user) {
			throw new AppException({ code: "AUTH_TOKEN_EXPIRED", message: "User not found", status: 401 });
		}
		if (user.two_factor_enabled === 1) {
			throw new AppException({ code: "CONFLICT", message: "2FA is already enabled", status: 409 });
		}

		let recentAuthToken = dto.recentAuthToken;
		if (dto.password) {
			if (!(await verifyPassword(dto.password, user.password_hash))) {
				throw new AppException({
					code: "AUTH_REAUTH_REQUIRED",
					message: "Invalid password",
					status: 401,
				});
			}
			recentAuthToken = await this.support.issueRecentAuthToken(user.id, authContext.sessionId);
		} else if (recentAuthToken) {
			await this.support.verifyRecentAuthToken(recentAuthToken, authContext);
		} else {
			throw new AppException({
				code: "AUTH_REAUTH_REQUIRED",
				message: "Fresh proof missing",
				status: 401,
			});
		}

		const { secret, otpauthUrl } = generateTotpSecret(user.email);
		const encryptedSecret = await encryptTwoFactorSecret(secret, this.encryptionKey());

		await this.support.twoFactor.upsert({
			userId: user.id,
			secretEncrypted: encryptedSecret,
			isVerified: false,
			isEnabled: false,
		});

		return {
			twoFactor: { enabled: false, verified: false, method: "totp" },
			totpSetup: { secret, otpauthUrl },
			recentAuthToken,
			recentAuthExpiresIn: this.support.config.auth.recentAuthExpiresInSeconds,
		};
	}

	async verifyTwoFactorTotp(
		c: AppContext,
		dto: { recentAuthToken: string; code: string },
	) {
		const authContext = await this.support.getAuthenticatedContext(c);
		const user = await this.support.users.findById(authContext.userId);
		if (user) this.support.assertUserCanLogin(user);

		await this.support.verifyRecentAuthToken(dto.recentAuthToken, authContext);
		await this.support.rateLimit.assertTotpVerifyAllowed(authContext.sessionId, "enroll");

		const secretRecord = await this.support.twoFactor.findByUserId(authContext.userId);
		if (!secretRecord || secretRecord.is_verified === 1) {
			throw new AppException({ code: "CONFLICT", message: "No pending setup exists", status: 409 });
		}

		const secret = await decryptTwoFactorSecret(secretRecord.secret_encrypted as string, this.encryptionKey());
		const isValid = verifyTotpCode(
			secret,
			dto.code,
			this.support.config.auth.totpTimeStepSeconds,
			this.support.config.auth.totpAllowedSkewSteps,
		);

		if (!isValid) {
			await this.support.rateLimit.recordTotpVerifyFailure(authContext.sessionId, "enroll");
			throw new AppException({ code: "AUTH_2FA_INVALID", message: "Invalid code.", status: 401 });
		}

		await this.support.twoFactor.enableForUser(authContext.userId);
		await this.support.users.updateUser(authContext.userId, { twoFactorEnabled: true });

		await this.support.audit.log({
			eventType: "TWO_FACTOR_ENABLED",
			userId: authContext.userId,
			sessionId: authContext.sessionId,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		return {
			twoFactor: { enabled: true, verified: true, method: "totp" },
		};
	}

	async disableTwoFactor(
		c: AppContext,
		dto: { password: string },
	) {
		const authContext = await this.support.getAuthenticatedContext(c);
		const user = await this.support.users.findById(authContext.userId);
		if (!user) {
			throw new AppException({ code: "AUTH_TOKEN_EXPIRED", message: "User not found", status: 401 });
		}

		if (!(await verifyPassword(dto.password, user.password_hash))) {
			throw new AppException({
				code: "AUTH_INVALID_CREDENTIALS",
				message: "Invalid password.",
				status: 401,
			});
		}

		await this.support.twoFactor.disableForUser(authContext.userId);

		await this.support.audit.log({
			eventType: "TWO_FACTOR_DISABLED",
			userId: authContext.userId,
			sessionId: authContext.sessionId,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		return {
			twoFactor: { enabled: false, verified: false, method: null },
		};
	}
}
