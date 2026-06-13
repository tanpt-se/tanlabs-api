import { getCookie } from "hono/cookie";
import type { AppContext } from "../types";
import { AppException } from "../lib/errors";
import {
	assertCsrfToken,
	assertInternalRefreshReplayGuard,
	assertNoInternalRefreshHeadersOnPublicRoute,
	assertOriginIfPresent,
	assertTrustedInternalRefreshRequest,
	clearCsrfCookie,
	clearRefreshTokenCookie,
	getHeaderValue,
	getRequestIp,
	issueCsrfCookie,
	resolveAuthClient,
	resolveRefreshTokenCookieName,
	resolveSessionClient,
	setRefreshTokenCookie,
} from "../lib/request-policy";
import { getBearerToken, verifyAccessToken } from "../lib/jwt";
import { verifyPassword } from "../lib/password";
import type { AccessTokenPayload, FlowSupportService } from "./flow-support.service";

export class SessionFlowService {
	constructor(private readonly support: FlowSupportService) {}

	async login(
		c: AppContext,
		dto: {
			email: string;
			password: string;
			twoFactorCode?: string;
			twoFactorMethod?: "totp" | "email_otp";
			twoFactorChallengeId?: string;
		},
	) {
		const normalizedEmail = this.support.normalizeEmail(dto.email);
		await this.support.rateLimit.assertLoginAllowed(getRequestIp(c), normalizedEmail);

		const user = await this.support.users.findByNormalizedEmail(normalizedEmail);
		if (!user || !(await verifyPassword(dto.password, user.password_hash))) {
			await this.support.rateLimit.recordLoginFailure(getRequestIp(c), normalizedEmail);
			await this.support.audit.log({
				eventType: "LOGIN_FAILED",
				userId: user?.id,
				ipAddress: getRequestIp(c),
				userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
				metadata: await this.support.buildRequestAuditMetadata(c, {
					reason: "AUTH_INVALID_CREDENTIALS",
					emailHash: await this.support.hashEmailForLogs(dto.email),
				}),
			});
			throw new AppException({
				code: "AUTH_INVALID_CREDENTIALS",
				message: "Invalid email or password.",
				status: 401,
			});
		}

		this.support.assertUserCanLogin(user);
		const sessionClient = resolveSessionClient(c);
		this.support.assertClientLoginAuthorized(user, resolveAuthClient(c));

		if (user.two_factor_enabled === 1) {
			const twoFactorSecret = await this.support.twoFactor.findByUserId(user.id);
			const loginFingerprint = await this.support.buildLoginFingerprint(user.id, dto.password, c);
			const useEmailOtpFallback = this.support.shouldUseEmailOtpFallback(twoFactorSecret);

			if (useEmailOtpFallback) {
				if (dto.twoFactorMethod !== "email_otp" || !dto.twoFactorCode || !dto.twoFactorChallengeId) {
					const challenge = await this.support.challenges.issueEmailOtpChallenge(
						user.id,
						user.email,
						loginFingerprint,
						"LOGIN_2FA",
					);
					throw new AppException({
						code: "AUTH_2FA_REQUIRED",
						message: "Two-factor authentication is required.",
						status: 401,
						details: {
							twoFactorMethod: "email_otp",
							twoFactorChallengeId: challenge.challengeId,
							expiresIn: challenge.expiresIn,
							resendAvailableIn: challenge.resendAvailableIn,
						},
					});
				}
				await this.support.challenges.verifyEmailOtpChallenge({
					challengeId: dto.twoFactorChallengeId,
					userId: user.id,
					purpose: "LOGIN_2FA",
					contextKey: loginFingerprint,
					code: dto.twoFactorCode,
				});
			} else {
				await this.support.requireTotpLogin(user, dto, c, twoFactorSecret);
			}
		}

		await this.support.rateLimit.clearLoginFailures(getRequestIp(c), normalizedEmail);

		const { session, replacedSessionId } = await this.support.sessions.createAuthenticatedSession(user.id, {
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			deviceLabel: getHeaderValue(c.req.raw.headers, "user-agent") ?? "Unknown device",
			client: sessionClient,
		});

		const refreshToken = await this.support.sessions.issueRefreshToken(session.id);
		const payload = await this.support.buildAuthResponse(user, session.id);

		setRefreshTokenCookie(c, this.support.config, refreshToken.token, refreshToken.expiresAt);
		issueCsrfCookie(c, this.support.config, refreshToken.expiresAt);

		await this.support.audit.log({
			eventType: "LOGIN_SUCCESS",
			userId: user.id,
			sessionId: session.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			metadata: this.support.buildRequestAuditMetadata(c),
		});

		if (replacedSessionId) {
			await this.support.audit.log({
				eventType: "SESSION_REPLACED",
				userId: user.id,
				sessionId: session.id,
				metadata: this.support.buildRequestAuditMetadata(c, {
					replacedSessionId,
					newSessionId: session.id,
				}),
			});
		}

		return payload;
	}

	async refresh(c: AppContext) {
		assertNoInternalRefreshHeadersOnPublicRoute(c);
		await this.support.rateLimit.assertRefreshAllowed(getRequestIp(c));
		await this.support.rateLimit.recordRefreshAttempt(getRequestIp(c));

		const rawRefreshToken = getCookie(c, resolveRefreshTokenCookieName(c, this.support.config));
		if (rawRefreshToken) assertOriginIfPresent(c, this.support.config);

		if (!rawRefreshToken) {
			throw new AppException({
				code: "AUTH_REFRESH_INVALID",
				message: "Refresh token is missing.",
				status: 401,
			});
		}

		let validation;
		try {
			validation = await this.support.sessions.validateRefreshToken(rawRefreshToken);
		} catch (error) {
			clearRefreshTokenCookie(c, this.support.config);
			clearCsrfCookie(c, this.support.config);
			throw error;
		}

		const user = await this.support.users.findById(validation.session.user_id);
		if (!user) {
			clearRefreshTokenCookie(c, this.support.config);
			clearCsrfCookie(c, this.support.config);
			throw new AppException({
				code: "AUTH_SESSION_REVOKED",
				message: "Session has been revoked.",
				status: 401,
			});
		}

		const rotated = await this.support.sessions.rotateRefreshToken(validation.token.id, validation.session);
		const payload = await this.support.buildAuthResponse(user, rotated.session.id);

		setRefreshTokenCookie(c, this.support.config, rotated.token, rotated.expiresAt);
		issueCsrfCookie(c, this.support.config, rotated.expiresAt);

		await this.support.audit.log({
			eventType: "REFRESH_SUCCESS",
			userId: user.id,
			sessionId: rotated.session.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			metadata: this.support.buildRequestAuditMetadata(c, { refreshMode: "rotate" }),
		});

		return {
			accessToken: payload.accessToken,
			expiresIn: payload.expiresIn,
			session: payload.session,
		};
	}

	async internalRefresh(c: AppContext) {
		await this.support.rateLimit.assertRefreshAllowed(getRequestIp(c));
		await this.support.rateLimit.recordRefreshAttempt(getRequestIp(c));
		await assertTrustedInternalRefreshRequest(c, this.support.config);
		await assertInternalRefreshReplayGuard(c, this.support.config, this.support.store);

		const rawRefreshToken = getCookie(c, resolveRefreshTokenCookieName(c, this.support.config));
		if (!rawRefreshToken) {
			throw new AppException({
				code: "AUTH_REFRESH_INVALID",
				message: "Refresh token is missing.",
				status: 401,
			});
		}

		const { session } = await this.support.sessions.validateRefreshToken(rawRefreshToken);
		const user = await this.support.users.findById(session.user_id);
		if (!user) {
			throw new AppException({
				code: "AUTH_SESSION_REVOKED",
				message: "Session has been revoked.",
				status: 401,
			});
		}

		const payload = await this.support.buildAuthResponse(user, session.id);
		await this.support.audit.log({
			eventType: "REFRESH_SUCCESS",
			userId: user.id,
			sessionId: session.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			metadata: { refreshMode: "access-only" },
		});

		return {
			accessToken: payload.accessToken,
			expiresIn: payload.expiresIn,
			session: payload.session,
		};
	}

	async logout(c: AppContext) {
		assertOriginIfPresent(c, this.support.config);
		const bearerToken = getBearerToken(c.req.header("authorization"));
		const rawRefreshToken = getCookie(c, resolveRefreshTokenCookieName(c, this.support.config));
		if (rawRefreshToken) assertOriginIfPresent(c, this.support.config);
		assertCsrfToken(c, this.support.config);

		let sessionId: string | null = null;
		let userId: string | null = null;

		if (bearerToken) {
			try {
				const payload = await verifyAccessToken<AccessTokenPayload>(this.support.env, bearerToken);
				if (payload.user_id && payload.session_id) {
					sessionId = payload.session_id;
					userId = payload.user_id;
				}
			} catch {
				sessionId = null;
			}
		}

		if (!sessionId && rawRefreshToken) {
			const session = await this.support.sessions.findSessionFromRefreshToken(rawRefreshToken);
			sessionId = session?.id ?? null;
			userId = session?.user_id ?? null;
		}

		if (!sessionId) {
			clearRefreshTokenCookie(c, this.support.config);
			throw new AppException({
				code: "AUTH_REFRESH_INVALID",
				message: "Authenticated context is missing.",
				status: 401,
			});
		}

		await this.support.sessions.revokeSession(sessionId, "REVOKED");
		clearRefreshTokenCookie(c, this.support.config);
		clearCsrfCookie(c, this.support.config);

		await this.support.audit.log({
			eventType: "LOGOUT_SUCCESS",
			userId,
			sessionId,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
		});

		return { success: true };
	}
}
