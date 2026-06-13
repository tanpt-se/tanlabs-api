import { getApiRuntimeConfig } from "../config/runtime";
import { RbacRepository } from "../db/repositories/rbac.repository";
import { EphemeralStore } from "../lib/ephemeral-store";

export async function runAuthMaintenance(env: Env): Promise<void> {
	const config = getApiRuntimeConfig(env);
	if (!config.maintenance.cleanupEnabled) return;

	const store = new EphemeralStore(env.DB, env.AUTH_KV);
	await store.cleanupExpired();

	const now = Date.now();
	const expiredArtifactCutoff = new Date(
		now - config.maintenance.expiredArtifactRetentionDays * 86_400_000,
	).toISOString();

	await env.DB.prepare("DELETE FROM refresh_tokens WHERE expires_at < ?")
		.bind(expiredArtifactCutoff)
		.run();
	await env.DB.prepare("DELETE FROM password_reset_tokens WHERE expires_at < ?")
		.bind(expiredArtifactCutoff)
		.run();

	const auditCutoff = new Date(
		now - config.maintenance.auditLogRetentionDays * 86_400_000,
	).toISOString();
	const rbac = new RbacRepository(env.DB);
	await rbac.bootstrapReferenceData();
	await env.DB.prepare("DELETE FROM audit_logs WHERE created_at < ?").bind(auditCutoff).run();
}
