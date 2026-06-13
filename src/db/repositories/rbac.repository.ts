import { createId } from "@paralleldrive/cuid2";
import {
	adminPermissionCatalog,
	clientPermissionCatalog,
	sharedPermissionCatalog,
	ADMIN_ROLE,
	DEFAULT_CLIENT_ROLE,
	SUPER_ADMIN_ROLE,
} from "../../common/access-control";
import { nowIso } from "../types";

export class RbacRepository {
	constructor(private readonly db: D1Database) {}

	async getPermissionsForRole(roleId: string): Promise<string[]> {
		const result = await this.db
			.prepare(
				`SELECT p.key FROM role_permissions rp
         JOIN permissions p ON p.id = rp.permission_id
         WHERE rp.role_id = ?
         ORDER BY p.key ASC`,
			)
			.bind(roleId)
			.all<{ key: string }>();
		return result.results.map((row) => row.key);
	}

	async bootstrapReferenceData(): Promise<void> {
		const now = nowIso();
		const userRoleId = await this.upsertRole(DEFAULT_CLIENT_ROLE, "Default authenticated user role", now);
		const adminRoleId = await this.upsertRole(ADMIN_ROLE, "Administrative role for auth console access", now);
		const superAdminRoleId = await this.upsertRole(
			SUPER_ADMIN_ROLE,
			"Top-level administrative role with unrestricted system access",
			now,
		);

		const permissionIds = new Map<string, string>();
		for (const key of sharedPermissionCatalog) {
			permissionIds.set(key, await this.upsertPermission(key, now));
		}

		await this.syncRolePermissions(
			userRoleId,
			clientPermissionCatalog.map((key) => permissionIds.get(key)!),
		);
		await this.syncRolePermissions(
			adminRoleId,
			adminPermissionCatalog.map((key) => permissionIds.get(key)!),
		);
		await this.syncRolePermissions(superAdminRoleId, [...permissionIds.values()]);
	}

	private async upsertRole(name: string, description: string, now: string): Promise<string> {
		const existing = await this.db
			.prepare("SELECT id FROM roles WHERE name = ?")
			.bind(name)
			.first<{ id: string }>();
		if (existing) {
			await this.db
				.prepare("UPDATE roles SET description = ?, updated_at = ? WHERE id = ?")
				.bind(description, now, existing.id)
				.run();
			return existing.id;
		}

		const id = createId();
		await this.db
			.prepare("INSERT INTO roles (id, name, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
			.bind(id, name, description, now, now)
			.run();
		return id;
	}

	private async upsertPermission(key: string, now: string): Promise<string> {
		const existing = await this.db
			.prepare("SELECT id FROM permissions WHERE key = ?")
			.bind(key)
			.first<{ id: string }>();
		if (existing) {
			await this.db
				.prepare("UPDATE permissions SET description = ?, updated_at = ? WHERE id = ?")
				.bind(key, now, existing.id)
				.run();
			return existing.id;
		}

		const id = createId();
		await this.db
			.prepare("INSERT INTO permissions (id, key, description, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
			.bind(id, key, key, now, now)
			.run();
		return id;
	}

	private async syncRolePermissions(roleId: string, permissionIds: string[]): Promise<void> {
		const existing = await this.db
			.prepare("SELECT permission_id FROM role_permissions WHERE role_id = ?")
			.bind(roleId)
			.all<{ permission_id: string }>();
		const existingIds = new Set(existing.results.map((row) => row.permission_id));
		const desiredIds = new Set(permissionIds);

		for (const permissionId of existingIds) {
			if (!desiredIds.has(permissionId)) {
				await this.db
					.prepare("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?")
					.bind(roleId, permissionId)
					.run();
			}
		}

		for (const permissionId of desiredIds) {
			if (!existingIds.has(permissionId)) {
				await this.db
					.prepare("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)")
					.bind(roleId, permissionId)
					.run();
			}
		}
	}
}
