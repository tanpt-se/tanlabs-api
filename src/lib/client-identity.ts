import type { SessionClient } from "../db/types";

export type AuthClientId = "web" | "admin" | "default";

export function toSessionClient(clientId: AuthClientId): SessionClient {
	return clientId === "admin" ? "ADMIN" : "WEB";
}

export interface AuthClientCookieIdentity {
	auth?: string;
	csrf: string;
	refresh: string;
}

const AUTH_CLIENT_COOKIE_IDENTITIES: Record<AuthClientId, AuthClientCookieIdentity> = {
	default: {
		refresh: "refresh_token",
		csrf: "auth_csrf_token",
	},
	web: {
		auth: "auth_session",
		refresh: "web_refresh_token",
		csrf: "web_auth_csrf_token",
	},
	admin: {
		auth: "admin_auth",
		refresh: "admin_refresh_token",
		csrf: "admin_auth_csrf_token",
	},
};

export function getAuthClientCookieIdentity(clientId: AuthClientId): AuthClientCookieIdentity {
	return AUTH_CLIENT_COOKIE_IDENTITIES[clientId];
}

function parseOrigin(origin: string | undefined): URL | null {
	if (!origin) return null;
	try {
		return new URL(origin);
	} catch {
		return null;
	}
}

function isSameOrigin(origin: URL, configuredOrigin: string | undefined): boolean {
	const parsed = parseOrigin(configuredOrigin);
	if (!parsed) return false;
	return origin.origin === parsed.origin;
}

export function resolveAuthClientByOrigin(
	origin: string | null,
	env: Env,
): AuthClientId {
	if (!origin) return "default";

	try {
		const originUrl = new URL(origin);
		const hostname = originUrl.hostname.toLowerCase();

		if (isSameOrigin(originUrl, env.ADMIN_APP_ORIGIN)) return "admin";
		if (isSameOrigin(originUrl, env.APP_ORIGIN)) return "web";

		if (originUrl.port === "5102") return "admin";
		if (originUrl.port === "5101") return "web";

		if (
			hostname === "admin-tanlabs.example.com" ||
			hostname.startsWith("admin-tanlabs.") ||
			hostname.startsWith("tanlabs-admin.") ||
			hostname.includes("admin.")
		) {
			return "admin";
		}

		if (
			hostname === "tanlabs.example.com" ||
			hostname.startsWith("tanlabs.") ||
			hostname.startsWith("tanlabs-client.") ||
			hostname.startsWith("client.")
		) {
			return "web";
		}
	} catch {
		return "default";
	}

	return "default";
}
