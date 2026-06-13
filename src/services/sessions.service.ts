import type { ApiRuntimeConfig } from "../config/runtime";
import type { SessionClient, SessionRecord, SessionStatus } from "../db/types";
import { RefreshTokenRepository } from "../db/repositories/refresh-token.repository";
import { SessionRepository } from "../db/repositories/session.repository";
import { hmacSha256Hex, randomHex } from "../lib/crypto";
import { AppException } from "../lib/errors";
import type { EphemeralStore } from "../lib/ephemeral-store";

export class SessionsService {
	constructor(
		private readonly env: Env,
		private readonly config: ApiRuntimeConfig,
		private readonly sessions: SessionRepository,
		private readonly refreshTokens: RefreshTokenRepository,
		private readonly store: EphemeralStore,
	) {}

	hashOpaqueToken(token: string): Promise<string> {
		const secret = this.config.sessions.tokenHashSecret;
		if (!secret) {
			throw new AppException({
				code: "INTERNAL_ERROR",
				message: "Token hash secret is missing.",
				status: 500,
			});
		}
		return hmacSha256Hex(secret, token);
	}

	generateRefreshToken(): string {
		return randomHex(32);
	}

	private isExpired(now: Date, slidingExpiresAt: string, absoluteExpiresAt: string): boolean {
		return now >= new Date(slidingExpiresAt) || now >= new Date(absoluteExpiresAt);
	}

	private buildExpiryWindow(now: Date) {
		return {
			slidingExpiresAt: new Date(now.getTime() + this.config.sessions.slidingSessionMs).toISOString(),
			absoluteExpiresAt: new Date(now.getTime() + this.config.sessions.absoluteSessionMs).toISOString(),
		};
	}

	private computeNextSlidingExpiry(now: Date, absoluteExpiresAt: string): string {
		const candidate = new Date(now.getTime() + this.config.sessions.slidingSessionMs);
		const absolute = new Date(absoluteExpiresAt);
		return (candidate < absolute ? candidate : absolute).toISOString();
	}

	async createAuthenticatedSession(
		userId: string,
		context: {
			client: SessionClient;
			deviceLabel?: string | null;
			ipAddress?: string | null;
			userAgent?: string | null;
		},
	): Promise<{ session: SessionRecord; replacedSessionId?: string }> {
		const now = new Date();
		const expiry = this.buildExpiryWindow(now);
		const activeSessions = await this.sessions.findActiveSessionsForUser(userId, context.client);

		let replacedSessionId: string | undefined;
		if (activeSessions.length >= this.config.sessions.maxActiveSessions) {
			const oldest = activeSessions[0];
			if (oldest) {
				replacedSessionId = oldest.id;
				await this.revokeSession(oldest.id, "REVOKED");
			}
		}

		const session = await this.sessions.createActiveSession(
			userId,
			context,
			expiry.slidingExpiresAt,
			expiry.absoluteExpiresAt,
			now.toISOString(),
		);

		return { session, replacedSessionId };
	}

	async issueRefreshToken(sessionId: string): Promise<{ token: string; expiresAt: Date }> {
		const token = this.generateRefreshToken();
		const tokenHash = await this.hashOpaqueToken(token);
		const expiresAt = new Date(Date.now() + this.config.sessions.refreshTokenMs);
		await this.refreshTokens.create(sessionId, tokenHash, expiresAt.toISOString());
		return { token, expiresAt };
	}

	async validateRefreshToken(rawToken: string) {
		const tokenHash = await this.hashOpaqueToken(rawToken);
		const validation = await this.refreshTokens.findWithSessionByTokenHash(tokenHash);

		if (!validation) {
			throw new AppException({
				code: "AUTH_REFRESH_INVALID",
				message: "Refresh token is invalid.",
				status: 401,
			});
		}

		if (validation.token.replaced_by_token_id) {
			await this.revokeAllActiveSessionsForUser(validation.session.user_id, validation.session.client);
			throw new AppException({
				code: "AUTH_REFRESH_REUSED",
				message: "Refresh token reuse detected.",
				status: 401,
			});
		}

		if (validation.token.revoked_at || validation.session.status !== "ACTIVE") {
			throw new AppException({
				code: "AUTH_SESSION_REVOKED",
				message: "Session has been revoked.",
				status: 401,
			});
		}

		const now = new Date();
		if (
			new Date(validation.token.expires_at) <= now ||
			this.isExpired(now, validation.session.sliding_expires_at, validation.session.absolute_expires_at)
		) {
			await this.revokeSession(validation.session.id, "EXPIRED");
			throw new AppException({
				code: "AUTH_TOKEN_EXPIRED",
				message: "Refresh token has expired.",
				status: 401,
			});
		}

		return validation;
	}

	async rotateRefreshToken(currentRefreshTokenId: string, session: SessionRecord) {
		const now = new Date();
		const nextToken = this.generateRefreshToken();
		const nextTokenHash = await this.hashOpaqueToken(nextToken);
		const nextSlidingExpiresAt = this.computeNextSlidingExpiry(now, session.absolute_expires_at);
		const expiresAt = new Date(Date.now() + this.config.sessions.refreshTokenMs);

		const claimed = await this.refreshTokens.claimRotationCandidate(
			currentRefreshTokenId,
			now.toISOString(),
		);
		if (claimed !== 1) {
			throw new AppException({
				code: "AUTH_REFRESH_REUSED",
				message: "Refresh token reuse detected.",
				status: 401,
			});
		}

		const nextRefreshToken = await this.refreshTokens.create(
			session.id,
			nextTokenHash,
			expiresAt.toISOString(),
		);
		const updatedSession = await this.sessions.updateSessionActivity(
			session.id,
			now.toISOString(),
			nextSlidingExpiresAt,
		);
		await this.refreshTokens.linkReplacement(currentRefreshTokenId, nextRefreshToken.id);

		return { token: nextToken, expiresAt, session: updatedSession };
	}

	async revokeSession(sessionId: string, status: SessionStatus = "REVOKED"): Promise<void> {
		const now = new Date().toISOString();
		await this.sessions.markActiveSessionStatus(sessionId, status);
		await this.refreshTokens.revokeActiveTokensForSession(sessionId, now);
		await this.invalidateRecentAuthForSession(sessionId);
	}

	async revokeAllActiveSessionsForUser(userId: string, client?: SessionClient): Promise<void> {
		const sessions = await this.sessions.findActiveSessionIdsForUser(userId, client);
		await Promise.all(sessions.map((s) => this.revokeSession(s.id)));
		await this.invalidateRecentAuthForUser(userId);
	}

	async revokeAllOtherSessions(
		userId: string,
		currentSessionId: string,
		client?: SessionClient,
	): Promise<number> {
		const sessions = await this.sessions.findOtherActiveSessions(userId, currentSessionId, client);
		await Promise.all(sessions.map((s) => this.revokeSession(s.id)));
		return sessions.length;
	}

	async findSessionFromRefreshToken(rawToken: string): Promise<SessionRecord | null> {
		const tokenHash = await this.hashOpaqueToken(rawToken);
		const validation = await this.refreshTokens.findWithSessionByTokenHash(tokenHash);
		return validation?.session ?? null;
	}

	async validateAccessTokenSession(sessionId: string, userId?: string): Promise<SessionRecord> {
		const session = await this.sessions.findById(sessionId);
		if (!session || (userId && session.user_id !== userId)) {
			throw new AppException({
				code: "AUTH_TOKEN_EXPIRED",
				message: "Token expired or invalid.",
				status: 401,
			});
		}

		if (session.status !== "ACTIVE") {
			throw new AppException({
				code: "AUTH_TOKEN_EXPIRED",
				message: "Token expired or invalid.",
				status: 401,
			});
		}

		const now = new Date();
		if (this.isExpired(now, session.sliding_expires_at, session.absolute_expires_at)) {
			await this.revokeSession(session.id, "EXPIRED");
			throw new AppException({
				code: "AUTH_TOKEN_EXPIRED",
				message: "Token expired or invalid.",
				status: 401,
			});
		}

		return session;
	}

	async findSessionsForUser(userId: string, client?: SessionClient) {
		return this.sessions.findSessionsForUser(userId, client);
	}

	private async invalidateRecentAuthForSession(sessionId: string): Promise<void> {
		const entries = await this.store.listByPrefix<{ userId: string; sessionId: string }>(
			`${this.config.sessions.recentAuthPrefix}:`,
		);
		for (const entry of entries) {
			if (entry.value.sessionId === sessionId) {
				await this.store.delete(entry.key);
			}
		}
	}

	private async invalidateRecentAuthForUser(userId: string): Promise<void> {
		const entries = await this.store.listByPrefix<{ userId: string; sessionId: string }>(
			`${this.config.sessions.recentAuthPrefix}:`,
		);
		for (const entry of entries) {
			if (entry.value.userId === userId) {
				await this.store.delete(entry.key);
			}
		}
	}
}
