import { createId } from "@paralleldrive/cuid2";
import type { RefreshTokenRecord, SessionRecord } from "../types";
import { nowIso } from "../types";

export class RefreshTokenRepository {
	constructor(private readonly db: D1Database) {}

	async create(sessionId: string, tokenHash: string, expiresAt: string): Promise<RefreshTokenRecord> {
		const id = createId();
		const now = nowIso();
		await this.db
			.prepare(
				`INSERT INTO refresh_tokens (id, session_id, token_hash, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)`,
			)
			.bind(id, sessionId, tokenHash, expiresAt, now)
			.run();

		const token = await this.findById(id);
		if (!token) throw new Error("Failed to create refresh token");
		return token;
	}

	async findById(id: string): Promise<RefreshTokenRecord | null> {
		return this.db
			.prepare("SELECT * FROM refresh_tokens WHERE id = ?")
			.bind(id)
			.first<RefreshTokenRecord>();
	}

	async findWithSessionByTokenHash(tokenHash: string): Promise<{
		token: RefreshTokenRecord;
		session: SessionRecord;
	} | null> {
		const row = await this.db
			.prepare(
				`SELECT rt.*, s.id as s_id, s.user_id, s.status as s_status, s.client, s.last_activity_at,
            s.sliding_expires_at, s.absolute_expires_at, s.device_label, s.ip_address, s.user_agent, s.created_at as s_created_at
         FROM refresh_tokens rt
         JOIN sessions s ON s.id = rt.session_id
         WHERE rt.token_hash = ?`,
			)
			.bind(tokenHash)
			.first<Record<string, unknown>>();

		if (!row) return null;

		return {
			token: {
				id: row.id as string,
				session_id: row.session_id as string,
				token_hash: row.token_hash as string,
				expires_at: row.expires_at as string,
				revoked_at: (row.revoked_at as string | null) ?? null,
				replaced_by_token_id: (row.replaced_by_token_id as string | null) ?? null,
				created_at: row.created_at as string,
			},
			session: {
				id: row.s_id as string,
				user_id: row.user_id as string,
				status: row.s_status as SessionRecord["status"],
				client: row.client as SessionRecord["client"],
				last_activity_at: row.last_activity_at as string,
				sliding_expires_at: row.sliding_expires_at as string,
				absolute_expires_at: row.absolute_expires_at as string,
				device_label: (row.device_label as string | null) ?? null,
				ip_address: (row.ip_address as string | null) ?? null,
				user_agent: (row.user_agent as string | null) ?? null,
				created_at: row.s_created_at as string,
			},
		};
	}

	async revokeActiveTokensForSession(sessionId: string, revokedAt: string): Promise<void> {
		await this.db
			.prepare("UPDATE refresh_tokens SET revoked_at = ? WHERE session_id = ? AND revoked_at IS NULL")
			.bind(revokedAt, sessionId)
			.run();
	}

	async claimRotationCandidate(id: string, revokedAt: string): Promise<number> {
		const result = await this.db
			.prepare(
				`UPDATE refresh_tokens SET revoked_at = ?
         WHERE id = ? AND revoked_at IS NULL AND replaced_by_token_id IS NULL`,
			)
			.bind(revokedAt, id)
			.run();
		return result.meta.changes ?? 0;
	}

	async linkReplacement(currentRefreshTokenId: string, nextRefreshTokenId: string): Promise<void> {
		await this.db
			.prepare("UPDATE refresh_tokens SET replaced_by_token_id = ? WHERE id = ?")
			.bind(nextRefreshTokenId, currentRefreshTokenId)
			.run();
	}
}
