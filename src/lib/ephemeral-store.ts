import { AppException } from "./errors";
import { nowIso } from "../db/types";

interface StoredValue<T> {
	expiresAt: number | null;
	value: T;
}

export class EphemeralStore {
	constructor(
		private readonly db: D1Database,
		private readonly kv: KVNamespace,
	) {}

	private serialize<T>(value: T, ttlMs?: number): string {
		const payload: StoredValue<T> = {
			value,
			expiresAt: ttlMs ? Date.now() + ttlMs : null,
		};
		return JSON.stringify(payload);
	}

	private deserialize<T>(raw: string): StoredValue<T> {
		return JSON.parse(raw) as StoredValue<T>;
	}

	private isExpired(entry: StoredValue<unknown>): boolean {
		return entry.expiresAt !== null && entry.expiresAt <= Date.now();
	}

	private throwUnavailable(operation: string, key: string, error: unknown): never {
		console.error(`[ephemeral-store] ${operation} failed for key=${key}:`, error);
		throw new AppException({
			code: "AUTH_STATE_UNAVAILABLE",
			message: "Authentication state store is unavailable.",
			status: 503,
		});
	}

	async set<T>(key: string, value: T, ttlMs?: number): Promise<void> {
		const payload = this.serialize(value, ttlMs);
		const expiresAt = ttlMs ? new Date(Date.now() + ttlMs).toISOString() : null;

		try {
			if (ttlMs) {
				await this.kv.put(key, payload, {
					expirationTtl: Math.max(60, Math.ceil(ttlMs / 1000)),
				});
			} else {
				await this.kv.put(key, payload);
			}
		} catch (error) {
			this.throwUnavailable("set", key, error);
		}

		await this.db
			.prepare(
				`INSERT INTO auth_ephemeral_state (key, value_json, expires_at, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, expires_at = excluded.expires_at`,
			)
			.bind(key, payload, expiresAt, nowIso())
			.run();
	}

	async setIfAbsent<T>(key: string, value: T, ttlMs?: number): Promise<boolean> {
		const existing = await this.get<T>(key);
		if (existing !== null) return false;
		await this.set(key, value, ttlMs);
		return true;
	}

	async get<T>(key: string): Promise<T | null> {
		try {
			const raw = await this.kv.get(key);
			if (!raw) return null;
			const entry = this.deserialize<T>(raw);
			if (this.isExpired(entry)) {
				await this.delete(key);
				return null;
			}
			return entry.value;
		} catch (error) {
			this.throwUnavailable("get", key, error);
		}
	}

	async delete(key: string): Promise<void> {
		try {
			await this.kv.delete(key);
		} catch (error) {
			this.throwUnavailable("delete", key, error);
		}
		await this.db.prepare("DELETE FROM auth_ephemeral_state WHERE key = ?").bind(key).run();
	}

	async has(key: string): Promise<boolean> {
		return (await this.get(key)) !== null;
	}

	async listByPrefix<T>(prefix: string): Promise<Array<{ key: string; value: T }>> {
		const now = nowIso();
		const result = await this.db
			.prepare(
				`SELECT key, value_json FROM auth_ephemeral_state
         WHERE key LIKE ? AND (expires_at IS NULL OR expires_at > ?)`,
			)
			.bind(`${prefix}%`, now)
			.all<{ key: string; value_json: string }>();

		const entries: Array<{ key: string; value: T }> = [];
		for (const row of result.results) {
			try {
				const parsed = this.deserialize<T>(row.value_json);
				if (!this.isExpired(parsed)) {
					entries.push({ key: row.key, value: parsed.value });
				}
			} catch {
				// skip corrupt entries
			}
		}
		return entries;
	}

	async cleanupExpired(): Promise<number> {
		const now = nowIso();
		const result = await this.db
			.prepare("DELETE FROM auth_ephemeral_state WHERE expires_at IS NOT NULL AND expires_at <= ?")
			.bind(now)
			.run();
		return result.meta.changes ?? 0;
	}
}
