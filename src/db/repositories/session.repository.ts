import { createId } from "@paralleldrive/cuid2";
import type { SessionClient, SessionRecord, SessionStatus } from "../types";
import { nowIso } from "../types";

export class SessionRepository {
	constructor(private readonly db: D1Database) {}

	async findActiveSessionsForUser(userId: string, client?: SessionClient): Promise<SessionRecord[]> {
		const query = client
			? `SELECT * FROM sessions WHERE user_id = ? AND status = 'ACTIVE' AND client = ? ORDER BY last_activity_at ASC, created_at ASC`
			: `SELECT * FROM sessions WHERE user_id = ? AND status = 'ACTIVE' ORDER BY last_activity_at ASC, created_at ASC`;
		const stmt = this.db.prepare(query).bind(...(client ? [userId, client] : [userId]));
		const result = await stmt.all<SessionRecord>();
		return result.results;
	}

	async createActiveSession(
		userId: string,
		context: {
			client: SessionClient;
			deviceLabel?: string | null;
			ipAddress?: string | null;
			userAgent?: string | null;
		},
		slidingExpiresAt: string,
		absoluteExpiresAt: string,
		now: string,
	): Promise<SessionRecord> {
		const id = createId();
		await this.db
			.prepare(
				`INSERT INTO sessions (id, user_id, status, client, last_activity_at, sliding_expires_at,
         absolute_expires_at, device_label, ip_address, user_agent, created_at)
         VALUES (?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.bind(
				id,
				userId,
				context.client,
				now,
				slidingExpiresAt,
				absoluteExpiresAt,
				context.deviceLabel ?? null,
				context.ipAddress ?? null,
				context.userAgent ?? null,
				now,
			)
			.run();

		const session = await this.findById(id);
		if (!session) throw new Error("Failed to create session");
		return session;
	}

	async findById(id: string): Promise<SessionRecord | null> {
		return this.db.prepare("SELECT * FROM sessions WHERE id = ?").bind(id).first<SessionRecord>();
	}

	async updateSessionActivity(id: string, lastActivityAt: string, slidingExpiresAt: string): Promise<SessionRecord> {
		await this.db
			.prepare("UPDATE sessions SET last_activity_at = ?, sliding_expires_at = ? WHERE id = ?")
			.bind(lastActivityAt, slidingExpiresAt, id)
			.run();
		const session = await this.findById(id);
		if (!session) throw new Error("Session not found");
		return session;
	}

	async findSessionsForUser(userId: string, client?: SessionClient): Promise<SessionRecord[]> {
		const query = client
			? `SELECT * FROM sessions WHERE user_id = ? AND client = ? ORDER BY last_activity_at DESC, created_at DESC`
			: `SELECT * FROM sessions WHERE user_id = ? ORDER BY last_activity_at DESC, created_at DESC`;
		const result = await this.db
			.prepare(query)
			.bind(...(client ? [userId, client] : [userId]))
			.all<SessionRecord>();
		return result.results;
	}

	async markActiveSessionStatus(id: string, status: SessionStatus): Promise<number> {
		const result = await this.db
			.prepare("UPDATE sessions SET status = ? WHERE id = ? AND status = 'ACTIVE'")
			.bind(status, id)
			.run();
		return result.meta.changes ?? 0;
	}

	async findOtherActiveSessions(
		userId: string,
		currentSessionId: string,
		client?: SessionClient,
	): Promise<Array<{ id: string }>> {
		const query = client
			? `SELECT id FROM sessions WHERE user_id = ? AND status = 'ACTIVE' AND client = ? AND id != ?`
			: `SELECT id FROM sessions WHERE user_id = ? AND status = 'ACTIVE' AND id != ?`;
		const result = await this.db
			.prepare(query)
			.bind(...(client ? [userId, client, currentSessionId] : [userId, currentSessionId]))
			.all<{ id: string }>();
		return result.results;
	}

	async findActiveSessionIdsForUser(userId: string, client?: SessionClient): Promise<Array<{ id: string }>> {
		const query = client
			? `SELECT id FROM sessions WHERE user_id = ? AND status = 'ACTIVE' AND client = ?`
			: `SELECT id FROM sessions WHERE user_id = ? AND status = 'ACTIVE'`;
		const result = await this.db
			.prepare(query)
			.bind(...(client ? [userId, client] : [userId]))
			.all<{ id: string }>();
		return result.results;
	}
}
