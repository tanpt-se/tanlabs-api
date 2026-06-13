import type { ApiRuntimeConfig } from "../config/runtime";
import { AppException } from "../lib/errors";
import { buildCodeChallenge } from "../lib/crypto";

export interface SocialProfile {
	provider: "google";
	subject: string;
	email: string;
	emailVerified: boolean;
	name: string | null;
	pictureUrl: string | null;
}

export class GoogleOAuthProvider {
	readonly key = "google" as const;

	constructor(private readonly config: ApiRuntimeConfig) {}

	private assertConfigured() {
		const { clientId, clientSecret, redirectUri } = this.config.oauth.google;
		if (!clientId || !clientSecret || !redirectUri) {
			throw new AppException({
				code: "AUTH_PROVIDER_UNAVAILABLE",
				message: "Google authentication is not configured.",
				status: 503,
			});
		}
		return { clientId, clientSecret, redirectUri };
	}

	buildAuthorizationUrl(input: { state: string; codeChallenge: string }): string {
		const { clientId, redirectUri } = this.assertConfigured();
		const params = new URLSearchParams({
			client_id: clientId,
			redirect_uri: redirectUri,
			response_type: "code",
			scope: "openid email profile",
			state: input.state,
			code_challenge: input.codeChallenge,
			code_challenge_method: "S256",
			access_type: "offline",
			prompt: "select_account",
		});
		return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
	}

	async exchangeCode(code: string, codeVerifier: string): Promise<SocialProfile> {
		const { clientId, clientSecret, redirectUri } = this.assertConfigured();

		const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				client_id: clientId,
				client_secret: clientSecret,
				code,
				code_verifier: codeVerifier,
				grant_type: "authorization_code",
				redirect_uri: redirectUri,
			}),
		});

		const tokenData = (await tokenResponse.json()) as {
			access_token?: string;
			error?: string;
		};

		if (!tokenResponse.ok || !tokenData.access_token) {
			console.error("[oauth:google] token exchange failed:", tokenData.error ?? tokenResponse.status);
			throw new AppException({
				code: "AUTH_PROVIDER_EXCHANGE_FAILED",
				message: "Google token exchange failed.",
				status: 401,
				details: { provider: this.key },
			});
		}

		const userInfoResponse = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
			headers: { Authorization: `Bearer ${tokenData.access_token}` },
		});
		const userInfo = (await userInfoResponse.json()) as {
			email?: string;
			email_verified?: boolean;
			name?: string;
			picture?: string;
			sub?: string;
		};

		if (!userInfoResponse.ok || !userInfo.sub || !userInfo.email) {
			throw new AppException({
				code: "AUTH_PROVIDER_PROFILE_FAILED",
				message: "Google profile lookup failed.",
				status: 401,
				details: { provider: this.key },
			});
		}

		return {
			provider: "google",
			subject: userInfo.sub,
			email: userInfo.email,
			emailVerified: Boolean(userInfo.email_verified),
			name: userInfo.name ?? null,
			pictureUrl: userInfo.picture ?? null,
		};
	}
}
