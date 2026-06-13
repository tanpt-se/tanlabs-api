export type CookieSameSite = "strict" | "lax" | "none";

export interface ApiRuntimeConfig {
	app: {
		corsAllowedOrigins: string[];
		isProduction: boolean;
	};
	maintenance: {
		cleanupEnabled: boolean;
		expiredArtifactRetentionDays: number;
		transientStateRetentionDays: number;
		auditLogRetentionDays: number;
	};
	auth: {
		accessTokenExpiresInSeconds: number;
		refreshCookieName: string;
		passwordResetTokenExpiresInMs: number;
		recentAuthExpiresInSeconds: number;
		recentAuthPrefix: string;
		emailOtpFallbackEnabled: boolean;
		totpTimeStepSeconds: number;
		totpAllowedSkewSteps: number;
		allowedBrowserOrigins: string[];
		accessOnlyRefreshSecret: string | undefined;
		internalRefreshAllowedServices: string[];
		internalRefreshMaxSkewMs: number;
		internalRefreshReplayPrefix: string;
		csrfProtectionEnabled: boolean;
		csrfCookieName: string;
		refreshCookieSecure: boolean;
		refreshCookieSameSite: CookieSameSite;
		refreshCookieDomain: string | undefined;
		argon2MemoryCost: number;
		argon2TimeCost: number;
		argon2Parallelism: number;
		turnstileSecretKey: string | undefined;
		turnstileVerifyUrl: string;
	};
	oauth: {
		adminOrigin: string;
		callbackStateTtlMs: number;
		webOrigin: string;
		webFailureRedirectPath: string;
		google: {
			clientId: string | undefined;
			clientSecret: string | undefined;
			redirectUri: string | undefined;
		};
	};
	challenge: {
		challengePrefix: string;
		challengeTtlMs: number;
		resendCooldownMs: number;
		maxAttempts: number;
		maxSends: number;
	};
	emailOtpDelivery: {
		mode: "console" | "resend";
		resendApiKey: string | undefined;
		smtpFromEmail: string;
	};
	passwordResetDelivery: {
		enabled: boolean;
		resetUrlOrigin: string;
		resetUrlPath: string;
		tokenQueryParam: string;
	};
	rateLimit: {
		loginWindowMs: number;
		loginPerIpMax: number;
		loginPerAccountMax: number;
		rateLimitPrefix: string;
		forgotPasswordWindowMs: number;
		forgotPasswordPerIpMax: number;
		forgotPasswordPerEmailMax: number;
		refreshWindowMs: number;
		refreshPerIpMax: number;
		resetPasswordWindowMs: number;
		resetPasswordPerIpMax: number;
		resetPasswordPerAccountMax: number;
		resetPasswordPerTokenMax: number;
		totpVerifyWindowMs: number;
		totpVerifyPerSessionMax: number;
		signupWindowMs: number;
		signupPerIpMax: number;
		signupPerEmailMax: number;
	};
	sessions: {
		recentAuthPrefix: string;
		slidingSessionMs: number;
		absoluteSessionMs: number;
		refreshTokenMs: number;
		maxActiveSessions: number;
		tokenHashSecret: string | undefined;
	};
}

function readEnvValue(env: Env, key: string): unknown {
	return (env as unknown as Record<string, unknown>)[key];
}

function getEnv(env: Env, key: keyof Env | string, fallback?: string): string | undefined {
	const value = readEnvValue(env, key);
	if (typeof value === "string" && value.length > 0) return value;
	return fallback;
}

function getRequiredEnv(env: Env, key: keyof Env | string, message: string): string {
	const value = getEnv(env, key);
	if (!value) throw new Error(message);
	return value;
}

function getBool(env: Env, key: keyof Env | string, fallback: boolean): boolean {
	const value = getEnv(env, key);
	if (value === undefined) return fallback;
	return value === "true" || value === "1";
}

function getInt(env: Env, key: keyof Env | string, fallback: number): number {
	const value = getEnv(env, key);
	if (!value) return fallback;
	const parsed = Number.parseInt(value, 10);
	return Number.isFinite(parsed) ? parsed : fallback;
}

function getStringList(env: Env, key: keyof Env | string, fallback: string[]): string[] {
	const value = getEnv(env, key);
	if (!value) return fallback;
	return value
		.split(",")
		.map((item) => item.trim())
		.filter(Boolean);
}

function parseCookieSameSite(env: Env): CookieSameSite {
	const sameSite = (getEnv(env, "REFRESH_TOKEN_COOKIE_SAME_SITE", "strict") ?? "strict").toLowerCase();
	if (sameSite === "lax" || sameSite === "none") return sameSite;
	return "strict";
}

export function getApiRuntimeConfig(env: Env): ApiRuntimeConfig {
	const challengePrefix = getEnv(env, "AUTH_CHALLENGE_PREFIX", "auth:challenge")!;
	const isProduction = env.ENVIRONMENT === "production";

	return {
		app: {
			corsAllowedOrigins: getStringList(env, "CORS_ALLOWED_ORIGINS", [
				env.APP_ORIGIN ?? "http://localhost:5101",
				env.ADMIN_APP_ORIGIN ?? "http://localhost:5102",
			]),
			isProduction,
		},
		maintenance: {
			cleanupEnabled: getBool(env, "AUTH_CLEANUP_ENABLED", true),
			expiredArtifactRetentionDays: getInt(env, "AUTH_EXPIRED_ARTIFACT_RETENTION_DAYS", 30),
			transientStateRetentionDays: getInt(env, "AUTH_TRANSIENT_RETENTION_DAYS", 7),
			auditLogRetentionDays: getInt(env, "AUDIT_LOG_RETENTION_DAYS", 180),
		},
		auth: {
			accessTokenExpiresInSeconds: getInt(env, "ACCESS_TOKEN_EXPIRES_IN", 900),
			refreshCookieName: getEnv(env, "REFRESH_TOKEN_COOKIE_NAME", "refresh_token")!,
			passwordResetTokenExpiresInMs: getInt(env, "PASSWORD_RESET_TOKEN_EXPIRES_IN", 900_000),
			recentAuthExpiresInSeconds: getInt(env, "RECENT_AUTH_TOKEN_EXPIRES_IN", 300),
			recentAuthPrefix: `${challengePrefix}:recent-auth`,
			emailOtpFallbackEnabled: getBool(env, "AUTH_EMAIL_OTP_FALLBACK_ENABLED", true),
			totpTimeStepSeconds: getInt(env, "TOTP_TIME_STEP_SECONDS", 30),
			totpAllowedSkewSteps: getInt(env, "TOTP_ALLOWED_SKEW_STEPS", 1),
			allowedBrowserOrigins: getStringList(env, "CORS_ALLOWED_ORIGINS", []),
			accessOnlyRefreshSecret:
				getEnv(env, "ACCESS_ONLY_REFRESH_SECRET") ??
				(isProduction ? undefined : "dev-access-only-refresh-secret"),
			internalRefreshAllowedServices: getStringList(env, "INTERNAL_REFRESH_ALLOWED_SERVICES", [
				"web-app",
			]),
			internalRefreshMaxSkewMs: getInt(env, "INTERNAL_REFRESH_MAX_SKEW_SECONDS", 60) * 1000,
			internalRefreshReplayPrefix: getEnv(
				env,
				"INTERNAL_REFRESH_REPLAY_PREFIX",
				"auth:internal-refresh:replay",
			)!,
			csrfProtectionEnabled: getBool(env, "AUTH_CSRF_PROTECTION_ENABLED", !isProduction ? false : true),
			csrfCookieName: getEnv(env, "AUTH_CSRF_COOKIE_NAME", "auth_csrf_token")!,
			refreshCookieSecure: getBool(env, "REFRESH_TOKEN_COOKIE_SECURE", isProduction),
			refreshCookieSameSite: parseCookieSameSite(env),
			refreshCookieDomain: getEnv(env, "REFRESH_TOKEN_COOKIE_DOMAIN"),
			argon2MemoryCost: Math.max(65536, getInt(env, "ARGON2_MEMORY_COST", 65536)),
			argon2TimeCost: Math.max(3, getInt(env, "ARGON2_TIME_COST", 3)),
			argon2Parallelism: Math.max(1, getInt(env, "ARGON2_PARALLELISM", 1)),
			turnstileSecretKey: getEnv(env, "TURNSTILE_SECRET_KEY"),
			turnstileVerifyUrl: getEnv(
				env,
				"TURNSTILE_VERIFY_URL",
				"https://challenges.cloudflare.com/turnstile/v0/siteverify",
			)!,
		},
		oauth: {
			adminOrigin: getEnv(env, "ADMIN_APP_ORIGIN", "http://localhost:5102")!,
			callbackStateTtlMs: getInt(env, "OAUTH_CALLBACK_STATE_TTL", 600_000),
			webOrigin: getEnv(env, "APP_ORIGIN", "http://localhost:5101")!,
			webFailureRedirectPath: getEnv(env, "OAUTH_WEB_FAILURE_REDIRECT_PATH", "/login")!,
			google: {
				clientId: getEnv(env, "GOOGLE_OAUTH_CLIENT_ID"),
				clientSecret: getEnv(env, "GOOGLE_OAUTH_CLIENT_SECRET"),
				redirectUri: getEnv(env, "GOOGLE_OAUTH_REDIRECT_URI"),
			},
		},
		challenge: {
			challengePrefix,
			challengeTtlMs: getInt(env, "EMAIL_OTP_CHALLENGE_EXPIRES_IN", 300_000),
			resendCooldownMs: getInt(env, "EMAIL_OTP_RESEND_COOLDOWN_SECONDS", 60) * 1000,
			maxAttempts: getInt(env, "EMAIL_OTP_MAX_ATTEMPTS", 5),
			maxSends: getInt(env, "EMAIL_OTP_MAX_SENDS", 3),
		},
		emailOtpDelivery: {
			mode: (getEnv(env, "EMAIL_DELIVERY_MODE", "console") as "console" | "resend") ?? "console",
			resendApiKey: getEnv(env, "EMAIL_API_KEY"),
			smtpFromEmail: getEnv(env, "SMTP_FROM_EMAIL", "no-reply@tanlabs.local")!,
		},
		passwordResetDelivery: {
			enabled: getBool(env, "PASSWORD_RESET_DELIVERY_ENABLED", true),
			resetUrlOrigin: getEnv(env, "PASSWORD_RESET_URL_ORIGIN", env.APP_ORIGIN ?? "http://localhost:5101")!,
			resetUrlPath: getEnv(env, "PASSWORD_RESET_URL_PATH", "/reset-password")!,
			tokenQueryParam: getEnv(env, "PASSWORD_RESET_TOKEN_QUERY_PARAM", "token")!,
		},
		rateLimit: {
			loginWindowMs: getInt(env, "LOGIN_RATE_LIMIT_WINDOW_MS", isProduction ? 900_000 : 60_000),
			loginPerIpMax: getInt(env, "LOGIN_RATE_LIMIT_IP_MAX_ATTEMPTS", 10),
			loginPerAccountMax: getInt(env, "LOGIN_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS", 5),
			rateLimitPrefix: getEnv(env, "RATE_LIMIT_PREFIX", "auth:rate-limit")!,
			forgotPasswordWindowMs: getInt(env, "FORGOT_PASSWORD_RATE_LIMIT_WINDOW_MINUTES", 15) * 60_000,
			forgotPasswordPerIpMax: getInt(env, "FORGOT_PASSWORD_RATE_LIMIT_IP_MAX_ATTEMPTS", 5),
			forgotPasswordPerEmailMax: getInt(env, "FORGOT_PASSWORD_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS", 3),
			refreshWindowMs: getInt(env, "REFRESH_RATE_LIMIT_WINDOW_MINUTES", 5) * 60_000,
			refreshPerIpMax: getInt(env, "REFRESH_RATE_LIMIT_IP_MAX_ATTEMPTS", 30),
			resetPasswordWindowMs: getInt(env, "RESET_PASSWORD_RATE_LIMIT_WINDOW_MINUTES", 15) * 60_000,
			resetPasswordPerIpMax: getInt(env, "RESET_PASSWORD_RATE_LIMIT_IP_MAX_ATTEMPTS", 10),
			resetPasswordPerAccountMax: getInt(env, "RESET_PASSWORD_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS", 5),
			resetPasswordPerTokenMax: getInt(env, "RESET_PASSWORD_RATE_LIMIT_TOKEN_MAX_ATTEMPTS", 5),
			totpVerifyWindowMs: getInt(env, "TOTP_VERIFY_RATE_LIMIT_WINDOW_MINUTES", 5) * 60_000,
			totpVerifyPerSessionMax: getInt(env, "TOTP_VERIFY_RATE_LIMIT_MAX_ATTEMPTS", 5),
			signupWindowMs: getInt(env, "SIGNUP_RATE_LIMIT_WINDOW_MINUTES", 15) * 60_000,
			signupPerIpMax: getInt(env, "SIGNUP_RATE_LIMIT_IP_MAX_ATTEMPTS", 5),
			signupPerEmailMax: getInt(env, "SIGNUP_RATE_LIMIT_EMAIL_MAX_ATTEMPTS", 3),
		},
		sessions: {
			recentAuthPrefix: `${challengePrefix}:recent-auth`,
			slidingSessionMs: getInt(env, "SESSION_SLIDING_EXPIRES_IN", 7 * 86_400_000),
			absoluteSessionMs: getInt(env, "SESSION_ABSOLUTE_EXPIRES_IN", 30 * 86_400_000),
			refreshTokenMs: getInt(env, "REFRESH_TOKEN_EXPIRES_IN", 7 * 86_400_000),
			maxActiveSessions: Math.max(1, getInt(env, "MAX_ACTIVE_SESSIONS", 2)),
			tokenHashSecret: getEnv(env, "TOKEN_HASH_SECRET") ?? (isProduction ? undefined : "dev-token-hash-secret"),
		},
	};
}

export function assertProductionSecrets(env: Env): void {
	if (env.ENVIRONMENT !== "production") return;
	getRequiredEnv(env, "ACCESS_TOKEN_SECRET", "ACCESS_TOKEN_SECRET is required.");
	getRequiredEnv(env, "TOKEN_HASH_SECRET", "TOKEN_HASH_SECRET is required.");
	getRequiredEnv(env, "ACCESS_ONLY_REFRESH_SECRET", "ACCESS_ONLY_REFRESH_SECRET is required.");
	getRequiredEnv(env, "TWO_FACTOR_SECRET_ENCRYPTION_KEY", "TWO_FACTOR_SECRET_ENCRYPTION_KEY is required.");
}
