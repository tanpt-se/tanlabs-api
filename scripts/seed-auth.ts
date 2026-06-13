/**
 * Seed auth reference data and demo users into D1.
 *
 * Local:  pnpm seedAuth
 * Remote: SEED_USER_PASSWORD=... SEED_ADMIN_PASSWORD=... pnpm seedAuth:remote
 */
import { execFileSync } from "node:child_process";
import { writeFileSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createId } from "@paralleldrive/cuid2";
import { hashPassword } from "../src/lib/password";
import {
	ADMIN_ROLE,
	DEFAULT_CLIENT_ROLE,
	SUPER_ADMIN_ROLE,
} from "../src/common/access-control";

const WRANGLER = resolve(process.cwd(), "node_modules/.bin/wrangler");
const isRemote = process.argv.includes("--remote");
const wranglerEnv = process.argv.includes("--env")
	? process.argv[process.argv.indexOf("--env") + 1]
	: isRemote
		? "production"
		: undefined;

function d1Exec(sql: string): void {
	const file = join(tmpdir(), `tanlabs-seed-${process.pid}.sql`);
	writeFileSync(file, sql, "utf8");
	const args = ["d1", "execute", "DB", "--file", file];
	if (isRemote) {
		args.push("--remote");
		if (wranglerEnv) args.push("--env", wranglerEnv);
	} else {
		args.push("--local");
	}

	try {
		execFileSync(WRANGLER, args, {
			cwd: process.cwd(),
			stdio: ["ignore", "ignore", "pipe"],
		});
	} catch (error) {
		const stderr =
			error && typeof error === "object" && "stderr" in error
				? String((error as { stderr: Buffer }).stderr)
				: "";
		throw new Error(stderr || "D1 seed failed.");
	} finally {
		unlinkSync(file);
	}
}

function sqlString(value: string): string {
	return `'${value.replace(/'/g, "''")}'`;
}

function resolveSeedCredentials() {
	const defaultUserEmail = isRemote ? "user@nikinpham.com" : "user@example.com";
	const defaultAdminEmail = isRemote ? "admin@nikinpham.com" : "admin@example.com";
	const seedUserEmail = process.env.SEED_USER_EMAIL ?? defaultUserEmail;
	const seedAdminEmail = process.env.SEED_ADMIN_EMAIL ?? defaultAdminEmail;
	const seedUserPassword = process.env.SEED_USER_PASSWORD ?? (isRemote ? "" : "Password123!");
	const seedAdminPassword = process.env.SEED_ADMIN_PASSWORD ?? (isRemote ? "" : "Password123!");

	if (isRemote) {
		if (!seedUserPassword || seedUserPassword.length < 10) {
			throw new Error("Remote seed requires SEED_USER_PASSWORD (min 10 chars).");
		}
		if (!seedAdminPassword || seedAdminPassword.length < 10) {
			throw new Error("Remote seed requires SEED_ADMIN_PASSWORD (min 10 chars).");
		}
	}

	return { seedUserEmail, seedAdminEmail, seedUserPassword, seedAdminPassword };
}

async function main() {
	const { seedUserEmail, seedAdminEmail, seedUserPassword, seedAdminPassword } =
		resolveSeedCredentials();
	const target = isRemote ? `remote${wranglerEnv ? ` (${wranglerEnv})` : ""}` : "local";
	const now = new Date().toISOString();
	const statements: string[] = [
		"DELETE FROM audit_logs;",
		"DELETE FROM auth_identities;",
		"DELETE FROM refresh_tokens;",
		"DELETE FROM sessions;",
		"DELETE FROM password_reset_tokens;",
		"DELETE FROM two_factor_secrets;",
		"DELETE FROM users;",
		"DELETE FROM role_permissions;",
		"DELETE FROM permissions;",
		"DELETE FROM roles;",
	];

	const roles = [
		{ name: DEFAULT_CLIENT_ROLE, description: "Default authenticated user role" },
		{ name: ADMIN_ROLE, description: "Administrative role for auth console access" },
		{
			name: SUPER_ADMIN_ROLE,
			description: "Top-level administrative role with unrestricted system access",
		},
	];

	const roleIds = new Map<string, string>();
	for (const role of roles) {
		const id = createId();
		roleIds.set(role.name, id);
		statements.push(
			`INSERT OR REPLACE INTO roles (id, name, description, created_at, updated_at) VALUES (${sqlString(id)}, ${sqlString(role.name)}, ${sqlString(role.description)}, ${sqlString(now)}, ${sqlString(now)});`,
		);
	}

	const permissions = [
		"client.dashboard.read",
		"client.session.read",
		"client.account.read",
		"admin.session.revoke",
	];
	const permissionIds = new Map<string, string>();
	for (const key of permissions) {
		const id = createId();
		permissionIds.set(key, id);
		statements.push(
			`INSERT OR REPLACE INTO permissions (id, key, description, created_at, updated_at) VALUES (${sqlString(id)}, ${sqlString(key)}, ${sqlString(key)}, ${sqlString(now)}, ${sqlString(now)});`,
		);
	}

	const userRoleId = roleIds.get(DEFAULT_CLIENT_ROLE)!;
	const adminRoleId = roleIds.get(ADMIN_ROLE)!;
	const superAdminRoleId = roleIds.get(SUPER_ADMIN_ROLE)!;

	for (const key of ["client.dashboard.read", "client.session.read", "client.account.read"]) {
		statements.push(
			`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (${sqlString(userRoleId)}, ${sqlString(permissionIds.get(key)!)});`,
		);
	}
	statements.push(
		`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (${sqlString(adminRoleId)}, ${sqlString(permissionIds.get("admin.session.revoke")!)});`,
	);
	for (const key of permissions) {
		statements.push(
			`INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (${sqlString(superAdminRoleId)}, ${sqlString(permissionIds.get(key)!)});`,
		);
	}

	const passwordHash = await hashPassword(seedUserPassword);
	const adminPasswordHash = await hashPassword(seedAdminPassword);

	for (const [email, roleId, hash, displayName] of [
		[seedUserEmail, userRoleId, passwordHash, "Client User"],
		[seedAdminEmail, adminRoleId, adminPasswordHash, "Admin User"],
	] as const) {
		const normalized = email.trim().toLowerCase();
		const id = createId();
		statements.push(
			`INSERT OR REPLACE INTO users (id, email, email_normalized, display_name, password_hash, email_verified_at, must_set_password, two_factor_enabled, status, role_id, created_at, updated_at)
       VALUES (${sqlString(id)}, ${sqlString(email)}, ${sqlString(normalized)}, ${sqlString(displayName)}, ${sqlString(hash)}, ${sqlString(now)}, 0, 0, 'ACTIVE', ${sqlString(roleId)}, ${sqlString(now)}, ${sqlString(now)});`,
		);
	}

	d1Exec(statements.join("\n"));
	console.log(`Auth seed completed (${target}).`);
	console.log(`Client: ${seedUserEmail}`);
	console.log(`Admin:  ${seedAdminEmail}`);
	if (!isRemote) {
		console.log("Password: Password123! (local default)");
	}
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : error);
	process.exitCode = 1;
});
