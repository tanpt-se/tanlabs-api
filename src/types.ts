import type { Context } from "hono";
import type { ApiRuntimeConfig } from "./config/runtime";
import type { AppServices } from "./services/container";

export type AppVariables = {
	services: AppServices;
	config: ApiRuntimeConfig;
	requestId: string;
};

export type AppContext = Context<{ Bindings: Env; Variables: AppVariables }>;
