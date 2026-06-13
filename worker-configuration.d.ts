/// <reference types="@cloudflare/workers-types" />

// Generated types — extend via `pnpm cf-typegen`
interface Env {
	DB: D1Database;
	AUTH_KV: KVNamespace;
	ENVIRONMENT?: string;
	APP_ORIGIN?: string;
	ADMIN_APP_ORIGIN?: string;
	CORS_ALLOWED_ORIGINS?: string;
	ACCESS_TOKEN_SECRET?: string;
	ACCESS_TOKEN_PREVIOUS_SECRET?: string;
	ACCESS_TOKEN_ACTIVE_KID?: string;
	ACCESS_TOKEN_PREVIOUS_KID?: string;
	TOKEN_HASH_SECRET?: string;
	ACCESS_ONLY_REFRESH_SECRET?: string;
	TWO_FACTOR_SECRET_ENCRYPTION_KEY?: string;
	TURNSTILE_SECRET_KEY?: string;
	GOOGLE_OAUTH_CLIENT_ID?: string;
	GOOGLE_OAUTH_CLIENT_SECRET?: string;
	GOOGLE_OAUTH_REDIRECT_URI?: string;
	EMAIL_API_KEY?: string;
	EMAIL_DELIVERY_MODE?: string;
	SMTP_FROM_EMAIL?: string;
	AUTH_CSRF_PROTECTION_ENABLED?: string;
	REFRESH_TOKEN_COOKIE_SECURE?: string;
	REFRESH_TOKEN_COOKIE_SAME_SITE?: string;
	REFRESH_TOKEN_COOKIE_DOMAIN?: string;
	INTERNAL_REFRESH_ALLOWED_SERVICES?: string;
	SEED_USER_EMAIL?: string;
	SEED_USER_PASSWORD?: string;
	SEED_ADMIN_EMAIL?: string;
	SEED_ADMIN_PASSWORD?: string;
}
