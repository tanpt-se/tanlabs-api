import { Hono } from "hono";
import { fromHono } from "chanfana";
import type { AppVariables } from "../types";
import {
	AuthForgotPassword,
	AuthInternalRefresh,
	AuthLogin,
	AuthLogout,
	AuthOAuthCallback,
	AuthOAuthStart,
	AuthRefresh,
	AuthRegister,
	AuthResendEmailVerification,
	AuthResetPassword,
	AuthSetupAccount,
	AuthTwoFactorDisable,
	AuthTwoFactorStatus,
	AuthTwoFactorTotpSetup,
	AuthTwoFactorTotpVerify,
	AuthVerifyEmail,
	HealthLive,
	HealthReady,
	SessionsList,
	SessionsRevokeOne,
	SessionsRevokeOthers,
	UsersChangePassword,
	UsersLinkedIdentities,
	UsersMe,
	UsersSocialLinkStart,
	UsersSocialUnlink,
} from "./routes";

export const authRouter = fromHono(new Hono<{ Bindings: Env; Variables: AppVariables }>());
authRouter.post("/login", AuthLogin);
authRouter.post("/refresh", AuthRefresh);
authRouter.post("/internal/refresh", AuthInternalRefresh);
authRouter.post("/logout", AuthLogout);
authRouter.post("/register", AuthRegister);
authRouter.post("/email-verification/verify", AuthVerifyEmail);
authRouter.post("/email-verification/resend", AuthResendEmailVerification);
authRouter.post("/forgot-password", AuthForgotPassword);
authRouter.post("/reset-password", AuthResetPassword);
authRouter.post("/account-setup", AuthSetupAccount);
authRouter.get("/oauth/:provider/start", AuthOAuthStart);
authRouter.get("/oauth/:provider/callback", AuthOAuthCallback);
authRouter.get("/2fa", AuthTwoFactorStatus);
authRouter.post("/2fa/totp/setup", AuthTwoFactorTotpSetup);
authRouter.post("/2fa/totp/verify", AuthTwoFactorTotpVerify);
authRouter.post("/2fa/disable", AuthTwoFactorDisable);

export const usersRouter = fromHono(new Hono<{ Bindings: Env; Variables: AppVariables }>());
usersRouter.get("/me", UsersMe);
usersRouter.post("/me/change-password", UsersChangePassword);
usersRouter.get("/me/linked-identities", UsersLinkedIdentities);
usersRouter.post("/me/social-link/:provider", UsersSocialLinkStart);
usersRouter.delete("/me/social-link/:provider", UsersSocialUnlink);

export const sessionsRouter = fromHono(new Hono<{ Bindings: Env; Variables: AppVariables }>());
sessionsRouter.get("/", SessionsList);
sessionsRouter.delete("/", SessionsRevokeOthers);
sessionsRouter.delete("/:id", SessionsRevokeOne);

export const healthRouter = fromHono(new Hono<{ Bindings: Env; Variables: AppVariables }>());
healthRouter.get("/live", HealthLive);
healthRouter.get("/ready", HealthReady);
