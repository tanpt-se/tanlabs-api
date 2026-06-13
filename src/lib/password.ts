import type { ApiRuntimeConfig } from "../config/runtime";

const PBKDF2_PREFIX = "pbkdf2-sha256";
const DEFAULT_ITERATIONS = 100_000;

function bytesToBase64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value: string): Uint8Array {
	return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

async function derivePbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
	const keyMaterial = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(password),
		"PBKDF2",
		false,
		["deriveBits"],
	);
	const bits = await crypto.subtle.deriveBits(
		{ name: "PBKDF2", salt, iterations, hash: "SHA-256" },
		keyMaterial,
		256,
	);
	return new Uint8Array(bits);
}

export function resolveArgon2Options(config: ApiRuntimeConfig["auth"]) {
	return {
		parallelism: config.argon2Parallelism,
		iterations: config.argon2TimeCost,
		memorySize: config.argon2MemoryCost,
	};
}

export async function hashPassword(
	password: string,
	_config?: ApiRuntimeConfig["auth"],
): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const hash = await derivePbkdf2(password, salt, DEFAULT_ITERATIONS);
	return `${PBKDF2_PREFIX}$${DEFAULT_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(hash)}`;
}

export async function verifyPassword(password: string, passwordHash: string): Promise<boolean> {
	if (!passwordHash.startsWith(`${PBKDF2_PREFIX}$`)) {
		return false;
	}

	const parts = passwordHash.split("$");
	const iterations = Number.parseInt(parts[1] ?? "", 10);
	const saltB64 = parts[2];
	const hashB64 = parts[3];
	if (!iterations || !saltB64 || !hashB64) return false;

	const salt = base64ToBytes(saltB64);
	const expected = base64ToBytes(hashB64);
	const actual = await derivePbkdf2(password, salt, iterations);
	if (actual.length !== expected.length) return false;

	let diff = 0;
	for (let i = 0; i < actual.length; i++) {
		diff |= actual[i]! ^ expected[i]!;
	}
	return diff === 0;
}
