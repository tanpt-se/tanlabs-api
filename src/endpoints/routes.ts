import { contentJson } from "chanfana";
import { z } from "zod";
import type { AppContext } from "../types";
import { AppException } from "../lib/errors";
import {
	changePasswordSchema,
	disableTwoFactorSchema,
	forgotPasswordSchema,
	loginSchema,
	registerSchema,
	resendEmailSchema,
	resetPasswordSchema,
	setupAccountSchema,
	setupTwoFactorSchema,
	unlinkSocialSchema,
	verifyEmailSchema,
	verifyTwoFactorSchema,
} from "../modules/auth/schemas";
import { resolveAuthClient } from "../lib/request-policy";
import {
	apiErrorResponse,
	AuthOpenAPIRoute,
	bearerAuthHeaders,
	jsonResponse,
	successSchema,
} from "./openapi-common";

const jsonBody = z.record(z.unknown());

export class AuthLogin extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Login with email and password",
		request: {
			body: contentJson(loginSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Login success or 2FA challenge", jsonBody),
			"400": apiErrorResponse(),
			"401": apiErrorResponse(),
			"429": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").sessionFlow.login(c, data.body));
	}
}

export class AuthRefresh extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Refresh access token using refresh cookie",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("New tokens", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		return c.json(await c.get("services").sessionFlow.refresh(c));
	}
}

export class AuthInternalRefresh extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Internal service refresh",
		request: {
			headers: z
				.object({
					"X-Auth-Internal-Refresh-Secret": z.string(),
					"X-Auth-Refresh-Mode": z.string().nullish(),
				})
				.passthrough(),
		},
		responses: {
			"200": jsonResponse("New tokens", jsonBody),
			"401": apiErrorResponse(),
			"403": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		return c.json(await c.get("services").sessionFlow.internalRefresh(c));
	}
}

export class AuthLogout extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Logout current session",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("Logout result", successSchema),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		return c.json(await c.get("services").sessionFlow.logout(c));
	}
}

export class AuthRegister extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Register a new user",
		request: {
			body: contentJson(registerSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"201": jsonResponse("Registration started", jsonBody),
			"400": apiErrorResponse(),
			"409": apiErrorResponse(),
			"429": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").registrationFlow.register(c, data.body), 201);
	}
}

export class AuthVerifyEmail extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Verify email with OTP",
		request: { body: contentJson(verifyEmailSchema) },
		responses: {
			"200": jsonResponse("Verification result", jsonBody),
			"400": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").registrationFlow.verifyEmailVerification(data.body));
	}
}

export class AuthResendEmailVerification extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Resend email verification OTP",
		request: { body: contentJson(resendEmailSchema) },
		responses: {
			"200": jsonResponse("Resend result", jsonBody),
			"400": apiErrorResponse(),
			"429": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").registrationFlow.resendEmailVerification(data.body));
	}
}

export class AuthForgotPassword extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Request password reset email",
		request: {
			body: contentJson(forgotPasswordSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Request accepted", jsonBody),
			"400": apiErrorResponse(),
			"429": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").passwordFlow.forgotPassword(c, data.body));
	}
}

export class AuthResetPassword extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Reset password with token",
		request: {
			body: contentJson(resetPasswordSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Password reset result", jsonBody),
			"400": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").passwordFlow.resetPassword(c, data.body));
	}
}

export class AuthSetupAccount extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth"],
		summary: "Complete invited account setup",
		request: {
			body: contentJson(setupAccountSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Account setup result", jsonBody),
			"400": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").passwordFlow.setupAccount(c, data.body));
	}
}

export class AuthOAuthStart extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth", "OAuth"],
		summary: "Start OAuth authorization",
		request: {
			params: z.object({ provider: z.string() }),
			query: z.object({
				next: z.string().optional(),
				audience: z.enum(["web", "admin"]).optional(),
				intent: z.enum(["login", "register"]).optional(),
			}),
		},
		responses: {
			"302": { description: "Redirect to OAuth provider" },
			"400": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		const audience = (data.query?.audience === "admin" ? "admin" : "web") as "admin" | "web";
		const intent = (data.query?.intent === "register" ? "register" : "login") as "login" | "register";
		const url = await c
			.get("services")
			.socialFlow.buildAuthorizationUrl(data.params.provider, data.query?.next, audience, intent);
		return c.redirect(url, 302);
	}
}

export class AuthOAuthCallback extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth", "OAuth"],
		summary: "OAuth provider callback",
		request: {
			params: z.object({ provider: z.string() }),
			query: z.object({
				code: z.string().optional(),
				error: z.string().optional(),
				state: z.string().optional(),
			}),
		},
		responses: {
			"302": { description: "Redirect after OAuth" },
			"400": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		const redirectUrl = await c.get("services").socialFlow.authenticateWithProviderCallback(c, {
			code: data.query?.code,
			error: data.query?.error,
			providerName: data.params.provider,
			state: data.query?.state,
		});
		return c.redirect(redirectUrl, 302);
	}
}

export class AuthTwoFactorStatus extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth", "2FA"],
		summary: "Get 2FA status",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("2FA status", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		return c.json(await c.get("services").twoFactorFlow.getTwoFactorStatus(c));
	}
}

export class AuthTwoFactorTotpSetup extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth", "2FA"],
		summary: "Start TOTP setup",
		request: {
			body: contentJson(setupTwoFactorSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("TOTP setup payload", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").twoFactorFlow.setupTwoFactorTotp(c, data.body));
	}
}

export class AuthTwoFactorTotpVerify extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth", "2FA"],
		summary: "Verify and enable TOTP",
		request: {
			body: contentJson(verifyTwoFactorSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Verification result", jsonBody),
			"400": apiErrorResponse(),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").twoFactorFlow.verifyTwoFactorTotp(c, data.body));
	}
}

export class AuthTwoFactorDisable extends AuthOpenAPIRoute {
	schema = {
		tags: ["Auth", "2FA"],
		summary: "Disable 2FA",
		request: {
			body: contentJson(disableTwoFactorSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Disable result", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").twoFactorFlow.disableTwoFactor(c, data.body));
	}
}

export class UsersMe extends AuthOpenAPIRoute {
	schema = {
		tags: ["Users"],
		summary: "Get current user profile",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("Current user", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const userId = await c.get("services").support.getAuthenticatedUserId(c);
		const user = await c.get("services").users.findById(userId);
		if (!user) {
			throw new AppException({ code: "AUTH_TOKEN_EXPIRED", message: "User not found", status: 401 });
		}
		const permissions = await c.get("services").rbac.getPermissionsForRole(user.role_id);
		return c.json({
			user: {
				id: user.id,
				email: user.email,
				displayName: user.display_name,
				role: user.role?.name,
				permissions,
				emailVerified: Boolean(user.email_verified_at),
				twoFactorEnabled: user.two_factor_enabled === 1,
			},
		});
	}
}

export class UsersChangePassword extends AuthOpenAPIRoute {
	schema = {
		tags: ["Users"],
		summary: "Change password for current user",
		request: {
			body: contentJson(changePasswordSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Change password result", jsonBody),
			"400": apiErrorResponse(),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		return c.json(await c.get("services").passwordFlow.changePassword(c, data.body));
	}
}

export class UsersLinkedIdentities extends AuthOpenAPIRoute {
	schema = {
		tags: ["Users", "OAuth"],
		summary: "List linked social identities",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("Linked identities", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const userId = await c.get("services").support.getAuthenticatedUserId(c);
		return c.json({
			identities: await c.get("services").socialFlow.getLinkedIdentities(userId),
		});
	}
}

export class UsersSocialLinkStart extends AuthOpenAPIRoute {
	schema = {
		tags: ["Users", "OAuth"],
		summary: "Start linking a social provider",
		request: {
			params: z.object({ provider: z.string() }),
			query: z.object({ next: z.string().optional() }),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Authorization URL", z.object({ authorizationUrl: z.string() })),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		const userId = await c.get("services").support.getAuthenticatedUserId(c);
		const url = await c
			.get("services")
			.socialFlow.buildLinkAuthorizationUrl(data.params.provider, userId, data.query?.next);
		return c.json({ authorizationUrl: url });
	}
}

export class UsersSocialUnlink extends AuthOpenAPIRoute {
	schema = {
		tags: ["Users", "OAuth"],
		summary: "Unlink a social provider",
		request: {
			params: z.object({ provider: z.string() }),
			body: contentJson(unlinkSocialSchema),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Unlink result", successSchema),
			"400": apiErrorResponse(),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		const userId = await c.get("services").support.getAuthenticatedUserId(c);
		await c
			.get("services")
			.socialFlow.unlinkSocialIdentity(userId, data.params.provider, data.body.currentPassword);
		return c.json({ success: true });
	}
}

export class SessionsList extends AuthOpenAPIRoute {
	schema = {
		tags: ["Sessions"],
		summary: "List active sessions",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("Session list", jsonBody),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const authContext = await c.get("services").support.getAuthenticatedContext(c);
		const client =
			resolveAuthClient(c) === "admin" ? "ADMIN" : resolveAuthClient(c) === "web" ? "WEB" : undefined;
		const sessions = await c.get("services").sessions.findSessionsForUser(authContext.userId, client);
		return c.json({
			sessions: sessions.map((session) => ({
				id: session.id,
				status: session.status.toLowerCase(),
				client: session.client.toLowerCase(),
				deviceLabel: session.device_label,
				ipAddress: session.ip_address,
				lastActivityAt: session.last_activity_at,
				createdAt: session.created_at,
				isCurrent: session.id === authContext.sessionId,
			})),
		});
	}
}

export class SessionsRevokeOthers extends AuthOpenAPIRoute {
	schema = {
		tags: ["Sessions"],
		summary: "Revoke all other sessions",
		request: { headers: bearerAuthHeaders },
		responses: {
			"200": jsonResponse("Revoke result", z.object({ success: z.boolean(), revokedCount: z.number() })),
			"401": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const authContext = await c.get("services").support.getAuthenticatedContext(c);
		const client =
			resolveAuthClient(c) === "admin" ? "ADMIN" : resolveAuthClient(c) === "web" ? "WEB" : undefined;
		const revokedCount = await c
			.get("services")
			.sessions.revokeAllOtherSessions(authContext.userId, authContext.sessionId, client);
		return c.json({ success: true, revokedCount });
	}
}

export class SessionsRevokeOne extends AuthOpenAPIRoute {
	schema = {
		tags: ["Sessions"],
		summary: "Revoke a specific session",
		request: {
			params: z.object({ id: z.string() }),
			headers: bearerAuthHeaders,
		},
		responses: {
			"200": jsonResponse("Revoke result", successSchema),
			"401": apiErrorResponse(),
			"404": apiErrorResponse(),
		},
	};

	async handle(c: AppContext) {
		const data = await this.getValidatedData<typeof this.schema>();
		const authContext = await c.get("services").support.getAuthenticatedContext(c);
		const session = await c.get("services").sessionsRepo.findById(data.params.id);
		if (!session || session.user_id !== authContext.userId) {
			throw new AppException({ code: "NOT_FOUND", message: "Session not found.", status: 404 });
		}
		await c.get("services").sessions.revokeSession(session.id, "REVOKED");
		return c.json({ success: true });
	}
}

export class HealthLive extends AuthOpenAPIRoute {
	schema = {
		tags: ["Health"],
		summary: "Liveness probe",
		responses: {
			"200": jsonResponse(
				"Service is alive",
				z.object({ status: z.string(), timestamp: z.string() }),
			),
		},
	};

	async handle(c: AppContext) {
		return c.json({ status: "ok", timestamp: new Date().toISOString() });
	}
}

export class HealthReady extends AuthOpenAPIRoute {
	schema = {
		tags: ["Health"],
		summary: "Readiness probe",
		responses: {
			"200": jsonResponse("Service is ready", jsonBody),
			"503": jsonResponse("Service is unhealthy", jsonBody),
		},
	};

	async handle(c: AppContext) {
		const services = c.get("services");
		let dbStatus: "healthy" | "unhealthy" = "healthy";
		let redisStatus: "healthy" | "unhealthy" = "healthy";
		let mailStatus: "healthy" | "degraded" | "disabled" | "unhealthy" = "disabled";

		try {
			await c.env.DB.prepare("SELECT 1").first();
		} catch {
			dbStatus = "unhealthy";
		}

		try {
			const key = `health:ready:${Date.now()}`;
			await services.store.set(key, { ok: true }, 5000);
			const value = await services.store.get<{ ok: boolean }>(key);
			await services.store.delete(key);
			redisStatus = value?.ok ? "healthy" : "unhealthy";
		} catch {
			redisStatus = "unhealthy";
		}

		const emailEnabled =
			services.config.auth.emailOtpFallbackEnabled || services.config.passwordResetDelivery.enabled;
		if (emailEnabled) {
			mailStatus =
				services.config.emailOtpDelivery.mode === "console" ||
				services.config.emailOtpDelivery.resendApiKey
					? "healthy"
					: "unhealthy";
		}

		const status =
			dbStatus === "unhealthy" || redisStatus === "unhealthy" || mailStatus === "unhealthy"
				? "unhealthy"
				: "healthy";

		const payload = {
			status,
			checks: {
				db: { status: dbStatus },
				redis: { status: redisStatus },
				mail: { status: mailStatus },
			},
			timestamp: new Date().toISOString(),
		};

		return c.json(payload, status === "unhealthy" ? 503 : 200);
	}
}
