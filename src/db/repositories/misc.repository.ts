import { createId } from "@paralleldrive/cuid2";
import type {
	AuthIdentityProvider,
	AuthIdentityRecord,
	PasswordResetTokenPurpose,
	PasswordResetTokenRecord,
	TwoFactorSecretRecord,
} from "../types";
import { nowIso } from "../types";

export class AuditRepository {
	constructor(private readonly db: D1Database) {}

	async log(params: {
		eventType: string;
		userId?: string | null;
		sessionId?: string | null;
		actorUserId?: string | null;
		ipAddress?: string | null;
		userAgent?: string | null;
		metadata?: Record<string, unknown>;
	}): Promise<void> {
		await this.db
			.prepare(
				`INSERT INTO audit_logs (id, event_type, user_id, session_id, actor_user_id, ip_address, user_agent, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.bind(
				createId(),
				params.eventType,
				params.userId ?? null,
				params.sessionId ?? null,
				params.actorUserId ?? null,
				params.ipAddress ?? null,
				params.userAgent ?? null,
				params.metadata ? JSON.stringify(params.metadata) : null,
				nowIso(),
			)
			.run();
	}

	async deleteOlderThan(cutoffIso: string): Promise<number> {
		const result = await this.db
			.prepare("DELETE FROM audit_logs WHERE created_at < ?")
			.bind(cutoffIso)
			.run();
		return result.meta.changes ?? 0;
	}
}

export class AuthIdentityRepository {
	constructor(private readonly db: D1Database) {}

	async findByUserId(userId: string): Promise<AuthIdentityRecord[]> {
		const result = await this.db
			.prepare("SELECT * FROM auth_identities WHERE user_id = ? ORDER BY created_at ASC")
			.bind(userId)
			.all<AuthIdentityRecord>();
		return result.results;
	}

	async findByProviderSubject(provider: AuthIdentityProvider, providerSubject: string) {
		return this.db
			.prepare("SELECT * FROM auth_identities WHERE provider = ? AND provider_subject = ?")
			.bind(provider, providerSubject)
			.first();
	}

	async create(data: {
		userId: string;
		provider: AuthIdentityProvider;
		providerSubject: string;
		providerEmail?: string | null;
	}) {
		const id = createId();
		const now = nowIso();
		await this.db
			.prepare(
				`INSERT INTO auth_identities (id, user_id, provider, provider_subject, provider_email, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
			)
			.bind(id, data.userId, data.provider, data.providerSubject, data.providerEmail ?? null, now, now)
			.run();
		return this.findById(id);
	}

	async findById(id: string) {
		return this.db.prepare("SELECT * FROM auth_identities WHERE id = ?").bind(id).first();
	}

	async deleteByUserAndProvider(userId: string, provider: AuthIdentityProvider): Promise<number> {
		const result = await this.db
			.prepare("DELETE FROM auth_identities WHERE user_id = ? AND provider = ?")
			.bind(userId, provider)
			.run();
		return result.meta.changes ?? 0;
	}
}

export class PasswordResetRepository {
	constructor(private readonly db: D1Database) {}

	async revokeActiveForUser(userId: string, purpose: PasswordResetTokenPurpose, now: string): Promise<void> {
		await this.db
			.prepare(
				`UPDATE password_reset_tokens SET revoked_at = ?
         WHERE user_id = ? AND purpose = ? AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?`,
			)
			.bind(now, userId, purpose, now)
			.run();
	}

	async create(data: {
		userId: string;
		tokenHash: string;
		purpose: PasswordResetTokenPurpose;
		expiresAt: string;
	}): Promise<PasswordResetTokenRecord> {
		const id = createId();
		const now = nowIso();
		await this.db
			.prepare(
				`INSERT INTO password_reset_tokens (id, user_id, token_hash, purpose, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
			)
			.bind(id, data.userId, data.tokenHash, data.purpose, data.expiresAt, now)
			.run();
		const token = await this.findById(id);
		if (!token) throw new Error("Failed to create password reset token");
		return token;
	}

	async findByTokenHash(tokenHash: string): Promise<PasswordResetTokenRecord | null> {
		return this.db
			.prepare("SELECT * FROM password_reset_tokens WHERE token_hash = ?")
			.bind(tokenHash)
			.first<PasswordResetTokenRecord>();
	}

	async findById(id: string): Promise<PasswordResetTokenRecord | null> {
		return this.db
			.prepare("SELECT * FROM password_reset_tokens WHERE id = ?")
			.bind(id)
			.first<PasswordResetTokenRecord>();
	}

	async markUsed(id: string, usedAt: string): Promise<void> {
		await this.db
			.prepare("UPDATE password_reset_tokens SET used_at = ? WHERE id = ?")
			.bind(usedAt, id)
			.run();
	}

	async markRevoked(id: string, revokedAt: string): Promise<void> {
		await this.db
			.prepare("UPDATE password_reset_tokens SET revoked_at = ? WHERE id = ?")
			.bind(revokedAt, id)
			.run();
	}

	async deleteExpiredBefore(cutoffIso: string): Promise<number> {
		const result = await this.db
			.prepare("DELETE FROM password_reset_tokens WHERE expires_at < ?")
			.bind(cutoffIso)
			.run();
		return result.meta.changes ?? 0;
	}
}

export class TwoFactorRepository {
	constructor(private readonly db: D1Database) {}

	async findByUserId(userId: string): Promise<TwoFactorSecretRecord | null> {
		return this.db
			.prepare("SELECT * FROM two_factor_secrets WHERE user_id = ?")
			.bind(userId)
			.first<TwoFactorSecretRecord>();
	}

	async upsert(data: {
		userId: string;
		secretEncrypted: string;
		isVerified: boolean;
		isEnabled: boolean;
	}) {
		const existing = await this.findByUserId(data.userId);
		const now = nowIso();
		if (existing) {
			await this.db
				.prepare(
					`UPDATE two_factor_secrets SET secret_encrypted = ?, is_verified = ?, is_enabled = ?, updated_at = ?
           WHERE user_id = ?`,
				)
				.bind(
					data.secretEncrypted,
					data.isVerified ? 1 : 0,
					data.isEnabled ? 1 : 0,
					now,
					data.userId,
				)
				.run();
		} else {
			await this.db
				.prepare(
					`INSERT INTO two_factor_secrets (id, user_id, secret_encrypted, is_verified, is_enabled, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
				)
				.bind(
					createId(),
					data.userId,
					data.secretEncrypted,
					data.isVerified ? 1 : 0,
					data.isEnabled ? 1 : 0,
					now,
					now,
				)
				.run();
		}
		return this.findByUserId(data.userId);
	}

	async enableForUser(userId: string): Promise<void> {
		const now = nowIso();
		await this.db
			.prepare(
				`UPDATE two_factor_secrets SET is_verified = 1, is_enabled = 1, updated_at = ? WHERE user_id = ?`,
			)
			.bind(now, userId)
			.run();
	}

	async disableForUser(userId: string): Promise<void> {
		const now = nowIso();
		await this.db
			.prepare("DELETE FROM two_factor_secrets WHERE user_id = ?")
			.bind(userId)
			.run();
		await this.db
			.prepare("UPDATE users SET two_factor_enabled = 0, updated_at = ? WHERE id = ?")
			.bind(now, userId)
			.run();
	}
}
