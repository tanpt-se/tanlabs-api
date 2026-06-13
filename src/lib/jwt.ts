import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import { AppException } from "./errors";

const DEFAULT_ACTIVE_KID = "access-v1";
const DEFAULT_PREVIOUS_KID = "access-v0";

function getTextEncoderSecret(secret: string): Uint8Array {
	return new TextEncoder().encode(secret);
}

function getActiveSigningKey(env: Env): { kid: string; secret: Uint8Array } {
	return {
		kid: env.ACCESS_TOKEN_ACTIVE_KID ?? DEFAULT_ACTIVE_KID,
		secret: getTextEncoderSecret(env.ACCESS_TOKEN_SECRET ?? "dev-access-token-secret"),
	};
}

function getVerificationKeys(env: Env): Array<{ kid: string; secret: Uint8Array }> {
	const active = getActiveSigningKey(env);
	const previousSecret = env.ACCESS_TOKEN_PREVIOUS_SECRET;
	const previousKid = env.ACCESS_TOKEN_PREVIOUS_KID ?? DEFAULT_PREVIOUS_KID;

	if (!previousSecret || previousSecret === env.ACCESS_TOKEN_SECRET) {
		return [active];
	}

	return [active, { kid: previousKid, secret: getTextEncoderSecret(previousSecret) }];
}

export function getBearerToken(authorization: string | undefined): string | null {
	if (!authorization || !authorization.startsWith("Bearer ")) return null;
	return authorization.slice("Bearer ".length);
}

export function missingAccessToken(message = "Missing token"): AppException {
	return new AppException({ code: "AUTH_TOKEN_EXPIRED", message, status: 401 });
}

export function invalidAccessToken(message = "Invalid token"): AppException {
	return new AppException({ code: "AUTH_TOKEN_EXPIRED", message, status: 401 });
}

export async function signAccessToken<T extends JWTPayload>(
	env: Env,
	payload: T,
	expiresInSeconds: number,
): Promise<string> {
	const activeKey = getActiveSigningKey(env);
	return new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256", kid: activeKey.kid })
		.setIssuedAt()
		.setExpirationTime(`${expiresInSeconds}s`)
		.sign(activeKey.secret);
}

export async function verifyAccessToken<T extends JWTPayload>(
	env: Env,
	token: string,
): Promise<T> {
	const keys = getVerificationKeys(env);
	let lastError: unknown;

	for (const candidate of keys) {
		try {
			const { payload } = await jwtVerify(token, candidate.secret, {
				algorithms: ["HS256"],
			});
			return payload as T;
		} catch (error) {
			lastError = error;
		}
	}

	throw lastError ?? new Error("Token verification failed.");
}

export function assertAccessTokenContext(
	payload: { user_id?: string; session_id?: string } | null | undefined,
): asserts payload is { user_id: string; session_id: string } {
	if (!payload?.user_id || !payload?.session_id) {
		throw invalidAccessToken();
	}
}
