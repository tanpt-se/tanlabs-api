import { contentJson, OpenAPIRoute } from "chanfana";
import { z } from "zod";
import type { AppContext } from "../types";
import { AppException } from "../lib/errors";

export type HandleArgs = [AppContext];

export const apiErrorSchema = z.object({
	code: z.string(),
	message: z.string(),
	status: z.number(),
	details: z.record(z.unknown()).optional(),
});

export const successSchema = z.object({
	success: z.boolean(),
});

export function jsonResponse<T extends z.ZodTypeAny>(description: string, schema: T) {
	return {
		description,
		...contentJson(schema),
	};
}

export function apiErrorResponse(description = "Error response") {
	return jsonResponse(description, apiErrorSchema);
}

export const bearerAuthHeaders = z
	.object({
		Authorization: z.string().nullish().describe("Bearer access token"),
		Cookie: z.string().nullish().describe("Session cookies"),
		"X-CSRF-Token": z.string().nullish(),
		"X-Auth-Client": z.enum(["web", "admin"]).nullish(),
	})
	.passthrough();

export abstract class AuthOpenAPIRoute extends OpenAPIRoute<HandleArgs> {
	handleValidationError(): Response {
		return Response.json(
			{
				code: "VALIDATION_ERROR",
				message: "Request validation failed.",
				status: 400,
			},
			{ status: 400 },
		);
	}

	async execute(...args: HandleArgs): Promise<Response> {
		try {
			return await super.execute(...args);
		} catch (error) {
			if (error instanceof AppException) {
				return Response.json(error.toJSON(), { status: error.status });
			}
			throw error;
		}
	}
}
