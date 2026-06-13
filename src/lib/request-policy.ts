import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { Context } from "hono";
import type { ApiRuntimeConfig } from "../config/runtime";
import { AppException } from "./errors";
import {
	getAuthClientCookieIdentity,
	resolveAuthClientByOrigin,
	toSessionClient,
	type AuthClientId,
} from "./client-identity";
import { hmacSha256Hex, randomHex, timingSafeEqual } from "./crypto";

export function getHeaderValue(headers: Headers, key: string): string | undefined {
	return headers.get(key) ?? undefined;
}

export function normalizeOrigin(rawValue: string): string | null {
	try {
		return new URL(rawValue).origin;
	} catch {
		return null;
	}
}

export function resolveRequestOrigin(c: Context): string | null {
	const originHeader = c.req.header("origin");
	if (originHeader) return normalizeOrigin(originHeader);

	const refererHeader = c.req.header("referer");
	if (refererHeader) return normalizeOrigin(refererHeader);

	return null;
}

export function resolveAuthClient(c: Context): AuthClientId {
	const authClientHeader = c.req.header("x-auth-client");
	if (authClientHeader === "web" || authClientHeader === "admin") {
		return authClientHeader;
	}
	return resolveAuthClientByOrigin(resolveRequestOrigin(c), c.env);
}

export function resolveSessionClient(c: Context) {
	return toSessionClient(resolveAuthClient(c));
}

export function resolveRefreshTokenCookieName(c: Context, config: ApiRuntimeConfig): string {
	const authClient = resolveAuthClient(c);
	if (authClient !== "default") {
		return getAuthClientCookieIdentity(authClient).refresh;
	}
	return config.auth.refreshCookieName;
}

export function resolveCsrfCookieName(c: Context, config: ApiRuntimeConfig): string {
	const authClient = resolveAuthClient(c);
	if (authClient !== "default") {
		return getAuthClientCookieIdentity(authClient).csrf;
	}
	return config.auth.csrfCookieName;
}

function cookieBaseOptions(config: ApiRuntimeConfig, expires?: Date) {
	return {
		path: "/",
		secure: config.auth.refreshCookieSecure,
		sameSite: config.auth.refreshCookieSameSite,
		domain: config.auth.refreshCookieDomain,
		...(expires ? { expires } : {}),
	};
}

export function setRefreshTokenCookie(
	c: Context,
	config: ApiRuntimeConfig,
	token: string,
	expiresAt: Date,
): void {
	setCookie(c, resolveRefreshTokenCookieName(c, config), token, {
		...cookieBaseOptions(config, expiresAt),
		httpOnly: true,
	});
}

export function clearRefreshTokenCookie(c: Context, config: ApiRuntimeConfig): void {
	deleteCookie(c, resolveRefreshTokenCookieName(c, config), cookieBaseOptions(config));
}

export function issueCsrfCookie(c: Context, config: ApiRuntimeConfig, expiresAt: Date): void {
	if (!config.auth.csrfProtectionEnabled) return;
	const csrfToken = randomHex(24);
	setCookie(c, resolveCsrfCookieName(c, config), csrfToken, {
		...cookieBaseOptions(config, expiresAt),
		httpOnly: false,
	});
}

export function clearCsrfCookie(c: Context, config: ApiRuntimeConfig): void {
	if (!config.auth.csrfProtectionEnabled) return;
	deleteCookie(c, resolveCsrfCookieName(c, config), cookieBaseOptions(config));
}

export function assertTrustedBrowserOrigin(c: Context, config: ApiRuntimeConfig): void {
	const origin = resolveRequestOrigin(c);
	if (!origin) {
		if (!config.app.isProduction) return;
		throw new AppException({
			code: "AUTH_ORIGIN_FORBIDDEN",
			message: "Origin is not allowed.",
			status: 403,
		});
	}

	const allowed = config.auth.allowedBrowserOrigins;
	if (allowed.length > 0 && !allowed.includes(origin)) {
		throw new AppException({
			code: "AUTH_ORIGIN_FORBIDDEN",
			message: "Origin is not allowed.",
			status: 403,
		});
	}
}

export function assertOriginIfPresent(c: Context, config: ApiRuntimeConfig): void {
	const origin = resolveRequestOrigin(c);
	if (!origin) return;
	assertTrustedBrowserOrigin(c, config);
}

export function assertCsrfToken(c: Context, config: ApiRuntimeConfig): void {
	if (!config.auth.csrfProtectionEnabled) return;

	const csrfHeader = c.req.header("x-csrf-token");
	const csrfCookie = getCookie(c, resolveCsrfCookieName(c, config));

	if (!csrfHeader || !csrfCookie) {
		throw new AppException({
			code: "AUTH_CSRF_INVALID",
			message: "CSRF token is invalid.",
			status: 403,
		});
	}

	if (csrfHeader !== csrfCookie) {
		throw new AppException({
			code: "AUTH_CSRF_INVALID",
			message: "CSRF token is invalid.",
			status: 403,
		});
	}
}

export function assertNoInternalRefreshHeadersOnPublicRoute(c: Context): void {
	const hasInternalHeaders =
		c.req.header("x-auth-internal-refresh-secret") ||
		c.req.header("x-auth-refresh-mode") ||
		c.req.header("x-auth-service-id") ||
		c.req.header("x-auth-timestamp") ||
		c.req.header("x-auth-signature");

	if (hasInternalHeaders) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_FORBIDDEN",
			message: "Internal refresh headers are not allowed on this route.",
			status: 403,
		});
	}
}

export async function assertTrustedInternalRefreshRequest(
	c: Context,
	config: ApiRuntimeConfig,
): Promise<void> {
	const secret = config.auth.accessOnlyRefreshSecret;
	if (!secret) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_UNAVAILABLE",
			message: "Internal refresh is not configured.",
			status: 503,
		});
	}

	const providedSecret = c.req.header("x-auth-internal-refresh-secret");
	if (providedSecret !== secret) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_FORBIDDEN",
			message: "Internal refresh request is not authorized.",
			status: 403,
		});
	}

	const mode = c.req.header("x-auth-refresh-mode");
	if (mode !== "access-only") {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_INVALID",
			message: "Internal refresh mode is invalid.",
			status: 400,
		});
	}

	const serviceId = c.req.header("x-auth-service-id");
	if (!serviceId || !config.auth.internalRefreshAllowedServices.includes(serviceId)) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_FORBIDDEN",
			message: "Internal refresh service is not allowed.",
			status: 403,
		});
	}

	const timestampHeader = c.req.header("x-auth-timestamp");
	const signature = c.req.header("x-auth-signature");
	if (!timestampHeader || !signature) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_INVALID",
			message: "Internal refresh signature is missing.",
			status: 400,
		});
	}

	const timestamp = Number.parseInt(timestampHeader, 10);
	if (!Number.isFinite(timestamp)) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_INVALID",
			message: "Internal refresh timestamp is invalid.",
			status: 400,
		});
	}

	const skew = Math.abs(Date.now() - timestamp);
	if (skew > config.auth.internalRefreshMaxSkewMs) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_EXPIRED",
			message: "Internal refresh request expired.",
			status: 401,
		});
	}

	const expectedSignature = await hmacSha256Hex(
		secret,
		`${serviceId}:${timestampHeader}:${mode}`,
	);
	if (!(await timingSafeEqual(signature, expectedSignature))) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_FORBIDDEN",
			message: "Internal refresh signature is invalid.",
			status: 403,
		});
	}
}

export async function assertInternalRefreshReplayGuard(
	c: Context,
	config: ApiRuntimeConfig,
	store: { setIfAbsent: (key: string, value: unknown, ttlMs?: number) => Promise<boolean> },
): Promise<void> {
	const serviceId = c.req.header("x-auth-service-id") ?? "unknown";
	const timestamp = c.req.header("x-auth-timestamp") ?? "0";
	const replayKey = `${config.auth.internalRefreshReplayPrefix}:${serviceId}:${timestamp}`;
	const accepted = await store.setIfAbsent(replayKey, { ok: true }, config.auth.internalRefreshMaxSkewMs);
	if (!accepted) {
		throw new AppException({
			code: "AUTH_INTERNAL_REFRESH_REPLAY",
			message: "Internal refresh replay detected.",
			status: 409,
		});
	}
}

export function getRequestIp(c: Context): string | null {
	return c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for")?.split(",")[0]?.trim() ?? null;
}
