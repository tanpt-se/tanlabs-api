import { createId } from "@paralleldrive/cuid2";
import type { RoleRecord, UserRecord } from "../types";
import { nowIso } from "../types";

export class UserRepository {
	constructor(private readonly db: D1Database) {}

	async findByNormalizedEmail(emailNormalized: string): Promise<UserRecord | null> {
		const row = await this.db
			.prepare(
				`SELECT u.*, r.id as role_id_join, r.name as role_name, r.description as role_description,
            r.created_at as role_created_at, r.updated_at as role_updated_at
         FROM users u
         JOIN roles r ON r.id = u.role_id
         WHERE u.email_normalized = ?`,
			)
			.bind(emailNormalized)
			.first<Record<string, unknown>>();

		return row ? this.mapUser(row) : null;
	}

	async findById(userId: string): Promise<UserRecord | null> {
		const row = await this.db
			.prepare(
				`SELECT u.*, r.name as role_name, r.description as role_description,
            r.created_at as role_created_at, r.updated_at as role_updated_at
         FROM users u
         JOIN roles r ON r.id = u.role_id
         WHERE u.id = ?`,
			)
			.bind(userId)
			.first<Record<string, unknown>>();

		return row ? this.mapUser(row) : null;
	}

	async findRoleByName(roleName: string): Promise<RoleRecord | null> {
		return this.db
			.prepare("SELECT * FROM roles WHERE name = ?")
			.bind(roleName)
			.first<RoleRecord>();
	}

	async createUser(data: {
		email: string;
		emailNormalized: string;
		displayName?: string | null;
		passwordHash: string;
		roleId: string;
		mustSetPassword?: boolean;
		emailVerifiedAt?: string | null;
	}): Promise<UserRecord> {
		const id = createId();
		const now = nowIso();
		await this.db
			.prepare(
				`INSERT INTO users (id, email, email_normalized, display_name, password_hash, must_set_password,
         email_verified_at, two_factor_enabled, status, role_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'ACTIVE', ?, ?, ?)`,
			)
			.bind(
				id,
				data.email,
				data.emailNormalized,
				data.displayName ?? null,
				data.passwordHash,
				data.mustSetPassword ? 1 : 0,
				data.emailVerifiedAt ?? null,
				data.roleId,
				now,
				now,
			)
			.run();

		const user = await this.findById(id);
		if (!user) throw new Error("Failed to create user");
		return user;
	}

	async updateUser(
		userId: string,
		data: Partial<{
			passwordHash: string;
			passwordChangedAt: string;
			emailVerifiedAt: string;
			mustSetPassword: boolean;
			twoFactorEnabled: boolean;
			status: string;
			displayName: string;
		}>,
	): Promise<void> {
		const fields: string[] = [];
		const values: unknown[] = [];

		if (data.passwordHash !== undefined) {
			fields.push("password_hash = ?");
			values.push(data.passwordHash);
		}
		if (data.passwordChangedAt !== undefined) {
			fields.push("password_changed_at = ?");
			values.push(data.passwordChangedAt);
		}
		if (data.emailVerifiedAt !== undefined) {
			fields.push("email_verified_at = ?");
			values.push(data.emailVerifiedAt);
		}
		if (data.mustSetPassword !== undefined) {
			fields.push("must_set_password = ?");
			values.push(data.mustSetPassword ? 1 : 0);
		}
		if (data.twoFactorEnabled !== undefined) {
			fields.push("two_factor_enabled = ?");
			values.push(data.twoFactorEnabled ? 1 : 0);
		}
		if (data.status !== undefined) {
			fields.push("status = ?");
			values.push(data.status);
		}
		if (data.displayName !== undefined) {
			fields.push("display_name = ?");
			values.push(data.displayName);
		}

		fields.push("updated_at = ?");
		values.push(nowIso());
		values.push(userId);

		await this.db
			.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`)
			.bind(...values)
			.run();
	}

	private mapUser(row: Record<string, unknown>): UserRecord {
		return {
			id: row.id as string,
			email: row.email as string,
			email_normalized: row.email_normalized as string,
			display_name: (row.display_name as string | null) ?? null,
			password_hash: row.password_hash as string,
			password_changed_at: (row.password_changed_at as string | null) ?? null,
			email_verified_at: (row.email_verified_at as string | null) ?? null,
			must_set_password: row.must_set_password as number,
			two_factor_enabled: row.two_factor_enabled as number,
			status: row.status as UserRecord["status"],
			role_id: row.role_id as string,
			created_at: row.created_at as string,
			updated_at: row.updated_at as string,
			role: {
				id: row.role_id as string,
				name: row.role_name as string,
				description: (row.role_description as string | null) ?? null,
				created_at: row.role_created_at as string,
				updated_at: row.role_updated_at as string,
			},
		};
	}
}
