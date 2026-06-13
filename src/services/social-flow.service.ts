import {
	ADMIN_ROLE,
	DEFAULT_CLIENT_ROLE,
	SUPER_ADMIN_ROLE,
} from "../common/access-control";
import type { SessionClient } from "../db/types";
import type { AppContext } from "../types";
import { AppException, isAppException } from "../lib/errors";
import {
	buildCodeChallenge,
} from "../lib/crypto";
import {
	getHeaderValue,
	getRequestIp,
	issueCsrfCookie,
	resolveAuthClient,
	setRefreshTokenCookie,
} from "../lib/request-policy";
import { hashPassword } from "../lib/password";
import type { FlowSupportService } from "./flow-support.service";
import { GoogleOAuthProvider, type SocialProfile } from "./google-oauth.provider";

interface OAuthStatePayload {
	audience: "admin" | "web";
	codeVerifier: string;
	intent: "login" | "register" | "link";
	linkedUserId?: string;
	nextPath: string;
	provider: "google";
}

export class SocialFlowService {
	private readonly google: GoogleOAuthProvider;

	constructor(private readonly support: FlowSupportService) {
		this.google = new GoogleOAuthProvider(support.config);
	}

	private providerFor(provider: string): GoogleOAuthProvider {
		if (provider === this.google.key) return this.google;
		throw new AppException({
			code: "AUTH_PROVIDER_UNSUPPORTED",
			message: "Authentication provider is not supported.",
			status: 404,
		});
	}

	private oauthStateKey(state: string): string {
		return `auth:social-oauth:state:${state}`;
	}

	private sanitizeNextPath(nextPath: string | undefined, audience: "admin" | "web"): string {
		if (!nextPath || !nextPath.startsWith("/") || nextPath.startsWith("//")) {
			return audience === "admin" ? "/" : "/dashboard";
		}
		return nextPath;
	}

	private buildRedirectUrl(
		audience: "admin" | "web",
		path: string,
		params?: Record<string, string>,
	): string {
		const url = new URL(
			path,
			audience === "admin"
				? this.support.config.oauth.adminOrigin
				: this.support.config.oauth.webOrigin,
		);
		if (params) {
			for (const [key, value] of Object.entries(params)) {
				url.searchParams.set(key, value);
			}
		}
		return url.toString();
	}

	private buildFailureRedirect(audience: "admin" | "web", reason: string): string {
		return this.buildFailureRedirectForIntent(audience, "login", reason);
	}

	private buildFailureRedirectForIntent(
		audience: "admin" | "web",
		intent: "login" | "register" | "link",
		reason: string,
		nextPath?: string,
	): string {
		let path: string;
		if (audience === "web" && intent === "register") path = "/register";
		else if (audience === "web" && intent === "link") path = nextPath ?? "/my-account";
		else path = this.support.config.oauth.webFailureRedirectPath;
		return this.buildRedirectUrl(audience, path, { reason });
	}

	async buildAuthorizationUrl(
		providerName: string,
		nextPath?: string,
		audience: "admin" | "web" = "web",
		intent: "login" | "register" = "login",
	): Promise<string> {
		const provider = this.providerFor(providerName);
		const codeVerifier = this.support.generatePasswordResetToken();
		const state = this.support.generatePasswordResetToken();

		await this.support.store.set<OAuthStatePayload>(
			this.oauthStateKey(state),
			{
				audience,
				codeVerifier,
				intent,
				nextPath: this.sanitizeNextPath(nextPath, audience),
				provider: provider.key,
			},
			this.support.config.oauth.callbackStateTtlMs,
		);

		return provider.buildAuthorizationUrl({
			state,
			codeChallenge: await buildCodeChallenge(codeVerifier),
		});
	}

	async buildLinkAuthorizationUrl(providerName: string, userId: string, nextPath?: string) {
		const provider = this.providerFor(providerName);
		const codeVerifier = this.support.generatePasswordResetToken();
		const state = this.support.generatePasswordResetToken();

		await this.support.store.set<OAuthStatePayload>(
			this.oauthStateKey(state),
			{
				audience: "web",
				codeVerifier,
				intent: "link",
				linkedUserId: userId,
				nextPath: nextPath ?? "/my-account",
				provider: provider.key,
			},
			this.support.config.oauth.callbackStateTtlMs,
		);

		return provider.buildAuthorizationUrl({
			state,
			codeChallenge: await buildCodeChallenge(codeVerifier),
		});
	}

	private async createUserFromSocialProfile(profile: SocialProfile) {
		const role = await this.support.users.findRoleByName(DEFAULT_CLIENT_ROLE);
		if (!role) {
			throw new AppException({
				code: "AUTH_ROLE_MISSING",
				message: "Default client role is not configured.",
				status: 500,
			});
		}

		const passwordHash = await hashPassword(
			this.support.generatePasswordResetToken(),
			this.support.config.auth,
		);

		const user = await this.support.users.createUser({
			email: profile.email,
			emailNormalized: this.support.normalizeEmail(profile.email),
			displayName: profile.name,
			passwordHash,
			roleId: role.id,
			emailVerifiedAt: new Date().toISOString(),
		});

		await this.support.authIdentities.create({
			userId: user.id,
			provider: "GOOGLE",
			providerSubject: profile.subject,
			providerEmail: profile.email,
		});

		return this.support.users.findById(user.id);
	}

	async getLinkedIdentities(userId: string) {
		const identities = await this.support.authIdentities.findByUserId(userId);
		return identities.map((identity) => ({
			provider: String(identity.provider).toLowerCase(),
			providerEmail: identity.provider_email ?? null,
		}));
	}

	async unlinkSocialIdentity(userId: string, providerName: string, currentPassword: string) {
		const user = await this.support.users.findById(userId);
		const { verifyPassword } = await import("../lib/password");
		if (!user || !(await verifyPassword(currentPassword, user.password_hash))) {
			throw new AppException({
				code: "AUTH_INVALID_CREDENTIALS",
				message: "Invalid credentials.",
				status: 401,
			});
		}

		this.providerFor(providerName);
		const deleted = await this.support.authIdentities.deleteByUserAndProvider(userId, "GOOGLE");
		if (deleted === 0) {
			throw new AppException({
				code: "AUTH_SOCIAL_NOT_LINKED",
				message: "This social account is not linked.",
				status: 404,
			});
		}
	}

	private async linkSocialIdentityToUser(userId: string, profile: SocialProfile) {
		const existing = await this.support.authIdentities.findByProviderSubject("GOOGLE", profile.subject);
		if (existing) {
			if (existing.user_id === userId) {
				throw new AppException({
					code: "AUTH_SOCIAL_ALREADY_LINKED",
					message: "This social account is already linked to your account.",
					status: 409,
				});
			}
			throw new AppException({
				code: "AUTH_SOCIAL_IDENTITY_TAKEN",
				message: "This social account is already linked to another account.",
				status: 409,
			});
		}

		await this.support.authIdentities.create({
			userId,
			provider: "GOOGLE",
			providerSubject: profile.subject,
			providerEmail: profile.email,
		});
	}

	private isAdminUser(roleName: string): boolean {
		return roleName === ADMIN_ROLE || roleName === SUPER_ADMIN_ROLE;
	}

	private async resolveUserForSocialProfile(
		profile: SocialProfile,
		audience: "admin" | "web",
		intent: "login" | "register",
	) {
		const providerIdentity = await this.support.authIdentities.findByProviderSubject(
			"GOOGLE",
			profile.subject,
		);

		if (providerIdentity) {
			const user = await this.support.users.findById(providerIdentity.user_id as string);
			if (user) {
				if (audience === "admin" && !this.isAdminUser(user.role!.name)) {
					throw new AppException({
						code: "AUTH_ADMIN_REQUIRED",
						message: "Admin access is required.",
						status: 403,
					});
				}
				return user;
			}
		}

		const existingUser = await this.support.users.findByNormalizedEmail(
			this.support.normalizeEmail(profile.email),
		);

		if (existingUser) {
			if (audience === "admin" && !this.isAdminUser(existingUser.role!.name)) {
				throw new AppException({
					code: "AUTH_ADMIN_REQUIRED",
					message: "Admin access is required.",
					status: 403,
				});
			}
			if (intent === "login") {
				throw new AppException({
					code: "AUTH_SOCIAL_REGISTRATION_REQUIRED",
					message: "Social account must be registered before sign-in.",
					status: 403,
				});
			}
			throw new AppException({
				code: "AUTH_SOCIAL_EMAIL_IN_USE",
				message: "Email is already used by another account.",
				status: 409,
			});
		}

		if (audience === "admin") {
			throw new AppException({
				code: "AUTH_ADMIN_REQUIRED",
				message: "Admin access is required.",
				status: 403,
			});
		}

		if (intent === "login") {
			throw new AppException({
				code: "AUTH_SOCIAL_REGISTRATION_REQUIRED",
				message: "Social account must be registered before sign-in.",
				status: 403,
			});
		}

		return this.createUserFromSocialProfile(profile);
	}

	async authenticateWithProviderCallback(c: AppContext, params: {
		code?: string;
		error?: string;
		providerName: string;
		state?: string;
	}): Promise<string> {
		const { code, error, providerName, state } = params;
		let audience: "admin" | "web" = "web";
		const provider = this.providerFor(providerName);
		const storedState = state
			? await this.support.store.get<OAuthStatePayload>(this.oauthStateKey(state))
			: null;

		if (state) await this.support.store.delete(this.oauthStateKey(state));

		if (error || !code || !state) {
			if (storedState) {
				return this.buildFailureRedirectForIntent(
					storedState.audience,
					storedState.intent,
					"social-auth-failed",
				);
			}
			return this.buildFailureRedirect(audience, "social-auth-failed");
		}

		if (!storedState || storedState.provider !== provider.key) {
			return this.buildFailureRedirectForIntent(audience, "login", "social-auth-failed");
		}

		audience = storedState.audience;
		const intent = storedState.intent;
		const profile = await provider.exchangeCode(code, storedState.codeVerifier);

		if (!profile.emailVerified) {
			return this.buildFailureRedirectForIntent(audience, intent, "social-auth-email-unverified");
		}

		if (intent === "link") {
			const linkedUserId = storedState.linkedUserId;
			if (!linkedUserId) {
				return this.buildFailureRedirectForIntent(audience, intent, "social-link-failed", storedState.nextPath);
			}
			try {
				await this.linkSocialIdentityToUser(linkedUserId, profile);
			} catch (error) {
				if (isAppException(error)) {
					if (error.code === "AUTH_SOCIAL_ALREADY_LINKED") {
						return this.buildFailureRedirectForIntent(audience, intent, "social-link-already-linked", storedState.nextPath);
					}
					if (error.code === "AUTH_SOCIAL_IDENTITY_TAKEN") {
						return this.buildFailureRedirectForIntent(audience, intent, "social-link-identity-taken", storedState.nextPath);
					}
				}
				throw error;
			}
			return this.buildRedirectUrl(audience, storedState.nextPath, { reason: "social-link-success" });
		}

		let user;
		try {
			user = await this.resolveUserForSocialProfile(profile, audience, intent);
			if (!user) throw new AppException({ code: "NOT_FOUND", message: "User not found", status: 404 });
			this.support.assertUserCanLogin(user);
		} catch (error) {
			if (isAppException(error)) {
				if (error.code === "AUTH_SOCIAL_REGISTRATION_REQUIRED") {
					return this.buildFailureRedirectForIntent(audience, intent, "social-auth-registration-required");
				}
				if (error.code === "AUTH_SOCIAL_EMAIL_IN_USE") {
					return this.buildFailureRedirectForIntent(audience, intent, "social-auth-email-in-use");
				}
				if (error.code === "AUTH_ACCOUNT_LOCKED") {
					return this.buildFailureRedirectForIntent(audience, intent, "social-auth-account-locked");
				}
				if (error.status === 403) {
					return this.buildFailureRedirect(audience, "social-auth-admin-required");
				}
			}
			throw error;
		}

		const sessionClient: SessionClient = audience === "admin" ? "ADMIN" : "WEB";
		const { session, replacedSessionId } = await this.support.sessions.createAuthenticatedSession(user.id, {
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			deviceLabel: `${provider.key} OAuth`,
			client: sessionClient,
		});

		const refreshToken = await this.support.sessions.issueRefreshToken(session.id);
		c.req.raw.headers.set("x-auth-client", audience);
		setRefreshTokenCookie(c, this.support.config, refreshToken.token, refreshToken.expiresAt);
		issueCsrfCookie(c, this.support.config, refreshToken.expiresAt);

		await this.support.audit.log({
			eventType: "LOGIN_SUCCESS",
			userId: user.id,
			sessionId: session.id,
			ipAddress: getRequestIp(c),
			userAgent: getHeaderValue(c.req.raw.headers, "user-agent") ?? null,
			metadata: this.support.buildRequestAuditMetadata(c, {
				authProvider: provider.key,
				loginMethod: "oauth",
			}),
		});

		if (replacedSessionId) {
			await this.support.audit.log({
				eventType: "SESSION_REPLACED",
				userId: user.id,
				sessionId: session.id,
				metadata: this.support.buildRequestAuditMetadata(c, {
					authProvider: provider.key,
					replacedSessionId,
					newSessionId: session.id,
				}),
			});
		}

		return this.buildRedirectUrl(audience, storedState.nextPath);
	}
}
