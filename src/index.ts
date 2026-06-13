import { ApiException, fromHono } from "chanfana";
import { Hono } from "hono";
import { cors } from "hono/cors";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { getApiRuntimeConfig } from "./config/runtime";
import type { AppVariables } from "./types";
import {
	authRouter,
	healthRouter,
	sessionsRouter,
	usersRouter,
} from "./endpoints/router";
import { isAppException } from "./lib/errors";
import { createServices } from "./services/container";
import { runAuthMaintenance } from "./cron/auth-maintenance";

const app = new Hono<{ Bindings: Env; Variables: AppVariables }>();

app.use("*", async (c, next) => {
	const config = getApiRuntimeConfig(c.env);
	const services = createServices(c.env);
	c.set("config", config);
	c.set("services", services);
	c.set("requestId", crypto.randomUUID());
	await next();
});

app.use(
	"*",
	cors({
		origin: (origin, c) => {
			const allowed = c.get("config").app.corsAllowedOrigins;
			if (!origin) return "*";
			return allowed.includes(origin) ? origin : "";
		},
		allowHeaders: [
			"Content-Type",
			"Authorization",
			"X-CSRF-Token",
			"X-Auth-Client",
			"X-Auth-Internal-Refresh-Secret",
			"X-Auth-Refresh-Mode",
			"X-Auth-Service-Id",
			"X-Auth-Timestamp",
			"X-Auth-Signature",
		],
		allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
		credentials: true,
	}),
);

app.onError((err, c) => {
	if (err instanceof ApiException) {
		return c.json(
			{ success: false, errors: err.buildResponse() },
			err.status as ContentfulStatusCode,
		);
	}
	if (isAppException(err)) {
		return c.json(err.toJSON(), err.status as ContentfulStatusCode);
	}
	console.error("Global error handler caught:", err instanceof Error ? err.message : err);
	return c.json(
		{ code: "INTERNAL_ERROR", message: "Internal Server Error", status: 500 },
		500,
	);
});

const openapi = fromHono(app, {
	docs_url: "/",
	openapi_url: "/openapi.json",
	raiseUnknownParameters: false,
	schema: {
		info: {
			title: "TanLabs Auth API",
			version: "1.0.0",
			description:
				"Authentication and session management API on Cloudflare Workers + D1.",
		},
	},
});

openapi.route("/auth", authRouter);
openapi.route("/users", usersRouter);
openapi.route("/auth/sessions", sessionsRouter);
openapi.route("/health", healthRouter);

export default {
	fetch: app.fetch,
	scheduled: async (event: ScheduledEvent, env: Env, ctx: ExecutionContext) => {
		ctx.waitUntil(runAuthMaintenance(env));
	},
};
