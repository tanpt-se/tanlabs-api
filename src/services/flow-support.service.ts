import { ADMIN_ROLE, SUPER_ADMIN_ROLE } from "../common/access-control";
import type { ApiRuntimeConfig } from "../config/runtime";
import type { UserRecord } from "../db/types";
import { RbacRepository } from "../db/repositories/rbac.repository";
import { UserRepository } from "../db/repositories/user.repository";
import {
	AuthIdentityRepository,
	AuditRepository,
	PasswordResetRepository,
	TwoFactorRepository,
} from "../db/repositories/misc.repository";
import { decryptTwoFactorSecret, encryptTwoFactorSecret, randomHex, sha256Hex } from "../lib/crypto";
import { AppException } from "../lib/errors";
import {
	assertAccessTokenContext,
	getBearerToken,
	invalidAccessToken,
	missingAccessToken,
	signAccessToken,
	verifyAccessToken,
} from "../lib/jwt";
import { verifyPassword } from "../lib/password";
import { verifyTotpCode } from "../lib/totp";
import type { AppContext } from "../types";
import {
	getHeaderValue,
	getRequestIp,
	resolveAuthClient,
	resolveRequestOrigin,
	resolveSessionClient,
} from "../lib/request-policy";
import type { ChallengeService } from "./challenge.service";
import type { RateLimitService } from "./rate-limit.service";
import type { SessionsService } from "./sessions.service";
import type { JWTPayload } from "jose";
import type { EphemeralStore } from "../lib/ephemeral-store";

export interface AccessTokenPayload extends JWTPayload {
	user_id: string;
	email: string;
	role: string;
	permissions: string[];
	session_id: string;
	jti: string;
}

export interface RecentAuthTokenPayload extends JWTPayload {
	user_id: string;
	session_id: string;
	recent_auth_token_id: string;
	scope: "2fa_setup";
	type: "recent_auth";
}

export interface RecentAuthState {
	userId: string;
	sessionId: string;
	scope: "2fa_setup";
	expiresAt: string;
}

export interface VerificationContextPayload extends JWTPayload {
	user_id: string;
	purpose: "signup_email_verification" | "account_email_verification";
	type: "verification_context";
}

export class FlowSupportService {
	constructor(
		public readonly env: Env,
		public readonly config: ApiRuntimeConfig,
		public readonly users: UserRepository,
		public readonly rbac: RbacRepository,
		public readonly audit: AuditRepository,
		public readonly passwordReset: PasswordResetRepository,
		public readonly twoFactor: TwoFactorRepository,
		public readonly authIdentities: AuthIdentityRepository,
		public readonly sessions: SessionsService,
		public readonly challenges: ChallengeService,
		public readonly rateLimit: RateLimitService,
		public readonly store: EphemeralStore,
	) {}

	normalizeEmail(email: string): string {
		return email.trim().toLowerCase();
	}

	async hashEmailForLogs(email: string): Promise<string> {
		return (await sha256Hex(this.normalizeEmail(email))).slice(0, 16);
	}

	assertClientLoginAuthorized(user: UserRecord, clientId: ReturnType<typeof resolveAuthClient>): void {
		if (clientId !== "admin") return;
		const roleName = user.role?.name;
		if (roleName !== ADMIN_ROLE && roleName !== SUPER_ADMIN_ROLE) {
			throw new AppException({
				code: "AUTH_ADMIN_REQUIRED",
				message: "Admin access is required.",
				status: 403,
			});
		}
	}

	assertUserCanLogin(user: UserRecord): void {
		if (user.status === "LOCKED" || user.status === "DISABLED") {
			throw new AppException({
				code: "AUTH_ACCOUNT_LOCKED",
				message: "Account access is restricted.",
				status: 401,
			});
		}
		if (user.must_set_password === 1) {
			throw new AppException({
				code: "AUTH_ACCOUNT_SETUP_REQUIRED",
				message: "Account setup is required.",
				status: 401,
			});
		}
		if (!user.email_verified_at) {
			throw new AppException({
				code: "AUTH_EMAIL_NOT_VERIFIED",
				message: "Email verification is required.",
				status: 401,
			});
		}
	}

	async buildAuthResponse(user: UserRecord, sessionId: string) {
		const permissions = await this.rbac.getPermissionsForRole(user.role_id);
		const accessToken = await signAccessToken<AccessTokenPayload>(
			this.env,
			{
				user_id: user.id,
				email: user.email,
				role: user.role!.name,
				permissions,
				session_id: sessionId,
				jti: crypto.randomUUID(),
			},
			this.config.auth.accessTokenExpiresInSeconds,
		);

		return {
			accessToken,
			expiresIn: this.config.auth.accessTokenExpiresInSeconds,
			session: { id: sessionId, status: "active" as const },
			user: {
				id: user.id,
				email: user.email,
				permissions,
				role: user.role!.name,
			},
		};
	}

	async getAuthenticatedContext(c: AppContext): Promise<{ userId: string; sessionId: string }> {
		const bearerToken = getBearerToken(c.req.header("authorization"));
		if (!bearerToken) throw missingAccessToken();

		try {
			const payload = await verifyAccessToken<AccessTokenPayload>(this.env, bearerToken);
			if (!payload.user_id || !payload.session_id || !payload.jti) throw new Error("Invalid payload");
			assertAccessTokenContext(payload);
			await this.sessions.validateAccessTokenSession(payload.session_id, payload.user_id);
			return { userId: payload.user_id, sessionId: payload.session_id };
		} catch {
			throw invalidAccessToken();
		}
	}

	async getAuthenticatedUserId(c: AppContext): Promise<string> {
		return (await this.getAuthenticatedContext(c)).userId;
	}

	async issueRecentAuthToken(userId: string, sessionId: string): Promise<string> {
		const recentAuthTokenId = crypto.randomUUID();
		await this.invalidateRecentAuthTokens(
			(state) => state.userId === userId && state.sessionId === sessionId && state.scope === "2fa_setup",
		);
		await this.store.set<RecentAuthState>(
			`${this.config.auth.recentAuthPrefix}:${recentAuthTokenId}`,
			{
				userId,
				sessionId,
				scope: "2fa_setup",
				expiresAt: new Date(Date.now() + this.config.auth.recentAuthExpiresInSeconds * 1000).toISOString(),
			},
			this.config.auth.recentAuthExpiresInSeconds * 1000,
		);

		return signAccessToken<RecentAuthTokenPayload>(
			this.env,
			{
				user_id: userId,
				session_id: sessionId,
				recent_auth_token_id: recentAuthTokenId,
				scope: "2fa_setup",
				type: "recent_auth",
			},
			this.config.auth.recentAuthExpiresInSeconds,
		);
	}

	async verifyRecentAuthToken(
		recentAuthToken: string,
		context: { userId: string; sessionId: string },
	): Promise<void> {
		let payload: RecentAuthTokenPayload;
		try {
			payload = await verifyAccessToken<RecentAuthTokenPayload>(this.env, recentAuthToken);
			if (
				!payload.user_id ||
				!payload.session_id ||
				!payload.recent_auth_token_id ||
				payload.scope !== "2fa_setup" ||
				payload.type !== "recent_auth"
			) {
				throw new Error("Invalid payload");
			}
		} catch {
			throw new AppException({
				code: "AUTH_REAUTH_REQUIRED",
				message: "Fresh proof expired",
				status: 401,
			});
		}

		if (
			payload.user_id !== context.userId ||
			payload.session_id !== context.sessionId
		) {
			throw new AppException({
				code: "AUTH_REAUTH_REQUIRED",
				message: "Fresh proof invalid for this session.",
				status: 401,
			});
		}

		const state = await this.store.get<RecentAuthState>(
			`${this.config.auth.recentAuthPrefix}:${payload.recent_auth_token_id}`,
		);
		if (
			!state ||
			state.userId !== context.userId ||
			state.sessionId !== context.sessionId ||
			state.scope !== "2fa_setup"
		) {
			throw new AppException({
				code: "AUTH_REAUTH_REQUIRED",
				message: "Fresh proof invalid for this session.",
				status: 401,
			});
		}
	}

	private async invalidateRecentAuthTokens(
		predicate: (state: RecentAuthState) => boolean,
	): Promise<void> {
		const entries = await this.store.listByPrefix<RecentAuthState>(`${this.config.auth.recentAuthPrefix}:`);
		for (const entry of entries) {
			if (predicate(entry.value)) await this.store.delete(entry.key);
		}
	}

	async issueVerificationContextToken(
		userId: string,
		purpose: VerificationContextPayload["purpose"],
	): Promise<string> {
		return signAccessToken<VerificationContextPayload>(
			this.env,
			{ user_id: userId, purpose, type: "verification_context" },
			Math.max(60, Math.ceil(this.config.auth.passwordResetTokenExpiresInMs / 1000)),
		);
	}

	async verifyVerificationContextToken(
		token: string,
		expectedPurpose: VerificationContextPayload["purpose"],
	): Promise<VerificationContextPayload> {
		let payload: VerificationContextPayload;
		try {
			payload = await verifyAccessToken<VerificationContextPayload>(this.env, token);
		} catch {
			throw new AppException({
				code: "AUTH_2FA_CHALLENGE_INVALID",
				message: "Verification context is invalid.",
				status: 401,
			});
		}

		if (
			payload.type !== "verification_context" ||
			payload.purpose !== expectedPurpose ||
			!payload.user_id
		) {
			throw new AppException({
				code: "AUTH_2FA_CHALLENGE_INVALID",
				message: "Verification context is invalid.",
				status: 401,
			});
		}
		return payload;
	}

	async issueEmailVerificationChallenge(
		user: UserRecord,
		purpose: "signup_email_verification" | "account_email_verification",
	) {
		const challenge = await this.challenges.issueEmailOtpChallenge(
			user.id,
			user.email,
			`${purpose}:${user.id}`,
			purpose === "signup_email_verification" ? "SIGNUP_EMAIL_VERIFICATION" : "ACCOUNT_EMAIL_VERIFICATION",
		);
		return {
			...challenge,
			verificationContextToken: await this.issueVerificationContextToken(user.id, purpose),
		};
	}

	generatePasswordResetToken(): string {
		return randomHex(32);
	}

	async createPasswordActionToken(params: {
		userId: string;
		purpose: "PASSWORD_RESET" | "ACCOUNT_SETUP";
	}) {
		const now = new Date();
		const rawToken = this.generatePasswordResetToken();
		const tokenHash = await this.sessions.hashOpaqueToken(rawToken);
		const expiresAt = new Date(Date.now() + this.config.auth.passwordResetTokenExpiresInMs).toISOString();

		await this.passwordReset.revokeActiveForUser(params.userId, params.purpose, now.toISOString());
		const token = await this.passwordReset.create({
			userId: params.userId,
			tokenHash,
			purpose: params.purpose,
			expiresAt,
		});

		return { rawToken, token, expiresAt: new Date(expiresAt) };
	}

	buildRequestAuditMetadata(c: AppContext, metadata?: Record<string, unknown>) {
		return {
			requestId: c.get("requestId"),
			clientId: resolveAuthClient(c),
			origin: resolveRequestOrigin(c),
			...metadata,
		};
	}

	shouldUseEmailOtpFallback(twoFactorSecret: { is_verified: number; is_enabled: number } | null): boolean {
		return (
			this.config.auth.emailOtpFallbackEnabled &&
			(!twoFactorSecret?.is_verified || !twoFactorSecret?.is_enabled)
		);
	}

	async requireTotpLogin(
		user: UserRecord,
		dto: { email: string; password: string; twoFactorCode?: string; twoFactorMethod?: string },
		c: AppContext,
		twoFactorSecret: { is_verified: number; is_enabled: number; secret_encrypted: string } | null,
	) {
		if (!dto.twoFactorCode || dto.twoFactorMethod !== "totp") {
			await this.audit.log({
				eventType: "LOGIN_2FA_REQUIRED",
				userId: user.id,
				ipAddress: getRequestIp(c),
				userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			});
			throw new AppException({
				code: "AUTH_2FA_REQUIRED",
				message: "Two-factor authentication is required.",
				status: 401,
				details: { twoFactorMethod: "totp" },
			});
		}

		const secret = twoFactorSecret
			? await decryptTwoFactorSecret(
					twoFactorSecret.secret_encrypted,
					this.env.TWO_FACTOR_SECRET_ENCRYPTION_KEY ?? "dev-two-factor-secret-key",
				)
			: null;

		const isValid =
			twoFactorSecret?.is_verified &&
			twoFactorSecret?.is_enabled &&
			secret &&
			verifyTotpCode(
				secret,
				dto.twoFactorCode,
				this.config.auth.totpTimeStepSeconds,
				this.config.auth.totpAllowedSkewSteps,
			);

		if (isValid) return;

		const normalizedEmail = this.normalizeEmail(dto.email);
		await this.rateLimit.recordLoginFailure(getRequestIp(c), normalizedEmail);
		await this.audit.log({
			eventType: "LOGIN_2FA_FAILED",
			userId: user.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			metadata: { reason: "AUTH_2FA_INVALID" },
		});
		throw new AppException({
			code: "AUTH_2FA_INVALID",
			message: "Invalid two-factor code.",
			status: 401,
		});
	}

	async buildLoginFingerprint(
		userId: string,
		password: string,
		c: AppContext,
	): Promise<string> {
		const raw = [
			userId,
			password,
			getHeaderValue(c.req.raw.headers, "user-agent") ?? "unknown-agent",
			getRequestIp(c) ?? "unknown-ip",
		].join(":");
		return this.sessions.hashOpaqueToken(raw);
	}

	async assertValidNewPassword(user: UserRecord, newPassword: string): Promise<void> {
		if (newPassword.length < 10 || newPassword.length > 128) {
			throw new AppException({
				code: "VALIDATION_ERROR",
				message: "Password must be between 10 and 128 characters.",
				status: 400,
			});
		}
		if (user.email && newPassword.toLowerCase().includes(user.email.toLowerCase())) {
			throw new AppException({
				code: "VALIDATION_ERROR",
				message: "Password must not contain your email.",
				status: 400,
			});
		}
		if (await verifyPassword(newPassword, user.password_hash)) {
			throw new AppException({
				code: "VALIDATION_ERROR",
				message: "Password must be different from the current password.",
				status: 400,
			});
		}
	}
}
