export async function hmacSha256Hex(secret: string, value: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
	return [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomHex(bytes = 32): string {
	const buffer = new Uint8Array(bytes);
	crypto.getRandomValues(buffer);
	return [...buffer].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomBase64Url(bytes = 18): string {
	const buffer = new Uint8Array(bytes);
	crypto.getRandomValues(buffer);
	const base64 = btoa(String.fromCharCode(...buffer));
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export async function sha256Hex(value: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
	if (a.length !== b.length) return false;
	const aBytes = new TextEncoder().encode(a);
	const bBytes = new TextEncoder().encode(b);
	let diff = 0;
	for (let i = 0; i < aBytes.length; i++) {
		diff |= aBytes[i]! ^ bBytes[i]!;
	}
	return diff === 0;
}

const TWO_FACTOR_ENCRYPTION_PREFIX = "enc:v1";

async function deriveTwoFactorKey(raw: string): Promise<globalThis.CryptoKey> {
	const trimmed = raw.trim();
	let keyMaterial: Uint8Array;

	if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
		const decoded = new Uint8Array(trimmed.length / 2);
		for (let i = 0; i < trimmed.length; i += 2) {
			decoded[i / 2] = Number.parseInt(trimmed.slice(i, i + 2), 16);
		}
		keyMaterial = decoded.length >= 32 ? decoded.slice(0, 32) : await sha256Bytes(trimmed);
	} else {
		try {
			const decoded = Uint8Array.from(atob(trimmed), (c) => c.charCodeAt(0));
			keyMaterial = decoded.length >= 32 ? decoded.slice(0, 32) : await sha256Bytes(trimmed);
		} catch {
			keyMaterial = await sha256Bytes(trimmed);
		}
	}

	return crypto.subtle.importKey("raw", keyMaterial, { name: "AES-GCM" }, false, [
		"encrypt",
		"decrypt",
	]);
}

async function sha256Bytes(value: string): Promise<Uint8Array> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
	return new Uint8Array(digest);
}

function bytesToBase64(bytes: Uint8Array): string {
	return btoa(String.fromCharCode(...bytes));
}

function base64ToBytes(value: string): Uint8Array {
	return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}

export async function encryptTwoFactorSecret(secret: string, encryptionKey: string): Promise<string> {
	const key = await deriveTwoFactorKey(encryptionKey);
	const iv = crypto.getRandomValues(new Uint8Array(12));
	const encrypted = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		key,
		new TextEncoder().encode(secret),
	);
	const encryptedBytes = new Uint8Array(encrypted);
	const tag = encryptedBytes.slice(-16);
	const payload = encryptedBytes.slice(0, -16);
	return `${TWO_FACTOR_ENCRYPTION_PREFIX}:${bytesToBase64(iv)}:${bytesToBase64(tag)}:${bytesToBase64(payload)}`;
}

export async function decryptTwoFactorSecret(
	secretEncrypted: string,
	encryptionKey: string,
): Promise<string> {
	if (!secretEncrypted.startsWith(`${TWO_FACTOR_ENCRYPTION_PREFIX}:`)) {
		return secretEncrypted;
	}

	const parts = secretEncrypted.split(":");
	const ivPart = parts[2];
	const tagPart = parts[3];
	const payloadPart = parts[4];
	if (!ivPart || !tagPart || !payloadPart) {
		throw new Error("Invalid encrypted two-factor secret payload.");
	}

	const iv = base64ToBytes(ivPart);
	const tag = base64ToBytes(tagPart);
	const payload = base64ToBytes(payloadPart);
	const combined = new Uint8Array(payload.length + tag.length);
	combined.set(payload);
	combined.set(tag, payload.length);

	const key = await deriveTwoFactorKey(encryptionKey);
	const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, combined);
	return new TextDecoder().decode(decrypted);
}

export function encodeCodeChallenge(codeVerifier: string): string {
	// base64url(sha256(codeVerifier)) - sync version using subtle in async wrapper
	return codeVerifier;
}

export async function buildCodeChallenge(codeVerifier: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
	const bytes = new Uint8Array(digest);
	const base64 = btoa(String.fromCharCode(...bytes));
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
