import type { ApiRuntimeConfig } from "../config/runtime";
import type { EphemeralStore } from "../lib/ephemeral-store";
import { AppException } from "../lib/errors";

interface CounterState {
	count: number;
	expiresAt: number;
}

interface LoginPenaltyState {
	escalationLevel: number;
}

export class RateLimitService {
	private static readonly LOGIN_RETRY_ATTEMPTS_AFTER_BAN = 2;
	private static readonly LOGIN_ESCALATION_MULTIPLIER = 5;
	private static readonly LOGIN_MAX_ESCALATION_LEVEL = 2;
	private static readonly LOGIN_PENALTY_STATE_TTL_MS = 30 * 86_400_000;

	constructor(
		private readonly store: EphemeralStore,
		private readonly config: ApiRuntimeConfig,
	) {}

	private buildKey(scope: string, ...parts: string[]): string {
		return [this.config.rateLimit.rateLimitPrefix, scope, ...parts].join(":");
	}

	private async incrementCounter(key: string, windowMs: number): Promise<number> {
		const now = Date.now();
		const current = (await this.store.get<CounterState>(key)) ?? { count: 0, expiresAt: now + windowMs };
		if (current.expiresAt <= now) {
			current.count = 0;
			current.expiresAt = now + windowMs;
		}
		current.count += 1;
		await this.store.set(key, current, windowMs);
		return current.count;
	}

	private async getCounter(key: string, windowMs: number): Promise<number> {
		const now = Date.now();
		const current = await this.store.get<CounterState>(key);
		if (!current || current.expiresAt <= now) return 0;
		return current.count;
	}

	private async clearCounter(key: string): Promise<void> {
		await this.store.delete(key);
	}

	async assertLoginAllowed(ip: string | null, emailNormalized: string): Promise<void> {
		const penalty =
			(await this.store.get<LoginPenaltyState>(this.buildKey("login", "penalty", "account", emailNormalized))) ??
			{ escalationLevel: 0 };
		const windowMs =
			this.config.rateLimit.loginWindowMs *
			RateLimitService.LOGIN_ESCALATION_MULTIPLIER **
				Math.min(penalty.escalationLevel, RateLimitService.LOGIN_MAX_ESCALATION_LEVEL);
		const accountMax =
			penalty.escalationLevel === 0
				? this.config.rateLimit.loginPerAccountMax
				: RateLimitService.LOGIN_RETRY_ATTEMPTS_AFTER_BAN;

		if (ip) {
			const ipCount = await this.getCounter(this.buildKey("login", "ip", ip), windowMs);
			if (ipCount >= this.config.rateLimit.loginPerIpMax) {
				throw new AppException({
					code: "AUTH_RATE_LIMITED",
					message: "Too many login attempts.",
					status: 429,
				});
			}
		}

		const accountCount = await this.getCounter(
			this.buildKey("login", "account", emailNormalized),
			windowMs,
		);
		if (accountCount >= accountMax) {
			throw new AppException({
				code: "AUTH_RATE_LIMITED",
				message: "Too many login attempts.",
				status: 429,
			});
		}
	}

	async recordLoginFailure(ip: string | null, emailNormalized: string): Promise<void> {
		const penaltyKey = this.buildKey("login", "penalty", "account", emailNormalized);
		const penalty =
			(await this.store.get<LoginPenaltyState>(penaltyKey)) ?? { escalationLevel: 0 };
		const windowMs =
			this.config.rateLimit.loginWindowMs *
			RateLimitService.LOGIN_ESCALATION_MULTIPLIER **
				Math.min(penalty.escalationLevel, RateLimitService.LOGIN_MAX_ESCALATION_LEVEL);

		if (ip) {
			await this.incrementCounter(this.buildKey("login", "ip", ip), windowMs);
		}

		const accountCount = await this.incrementCounter(
			this.buildKey("login", "account", emailNormalized),
			windowMs,
		);
		const accountMax =
			penalty.escalationLevel === 0
				? this.config.rateLimit.loginPerAccountMax
				: RateLimitService.LOGIN_RETRY_ATTEMPTS_AFTER_BAN;

		if (accountCount >= accountMax) {
			penalty.escalationLevel = Math.min(
				penalty.escalationLevel + 1,
				RateLimitService.LOGIN_MAX_ESCALATION_LEVEL,
			);
			await this.store.set(penaltyKey, penalty, RateLimitService.LOGIN_PENALTY_STATE_TTL_MS);
		}
	}

	async clearLoginFailures(ip: string | null, emailNormalized: string): Promise<void> {
		if (ip) await this.clearCounter(this.buildKey("login", "ip", ip));
		await this.clearCounter(this.buildKey("login", "account", emailNormalized));
		await this.store.delete(this.buildKey("login", "penalty", "account", emailNormalized));
	}

	async assertRefreshAllowed(ip: string | null): Promise<void> {
		if (!ip) return;
		const count = await this.getCounter(
			this.buildKey("refresh", "ip", ip),
			this.config.rateLimit.refreshWindowMs,
		);
		if (count >= this.config.rateLimit.refreshPerIpMax) {
			throw new AppException({
				code: "AUTH_RATE_LIMITED",
				message: "Too many refresh attempts.",
				status: 429,
			});
		}
	}

	async recordRefreshAttempt(ip: string | null): Promise<void> {
		if (!ip) return;
		await this.incrementCounter(
			this.buildKey("refresh", "ip", ip),
			this.config.rateLimit.refreshWindowMs,
		);
	}

	async assertSignupAllowed(ip: string | null, emailNormalized: string): Promise<void> {
		if (ip) {
			const ipCount = await this.getCounter(
				this.buildKey("signup", "ip", ip),
				this.config.rateLimit.signupWindowMs,
			);
			if (ipCount >= this.config.rateLimit.signupPerIpMax) {
				throw new AppException({ code: "AUTH_RATE_LIMITED", message: "Too many signups.", status: 429 });
			}
		}
		const emailCount = await this.getCounter(
			this.buildKey("signup", "email", emailNormalized),
			this.config.rateLimit.signupWindowMs,
		);
		if (emailCount >= this.config.rateLimit.signupPerEmailMax) {
			throw new AppException({ code: "AUTH_RATE_LIMITED", message: "Too many signups.", status: 429 });
		}
	}

	async recordSignupAttempt(ip: string | null, emailNormalized: string): Promise<void> {
		if (ip) {
			await this.incrementCounter(this.buildKey("signup", "ip", ip), this.config.rateLimit.signupWindowMs);
		}
		await this.incrementCounter(
			this.buildKey("signup", "email", emailNormalized),
			this.config.rateLimit.signupWindowMs,
		);
	}

	async clearSignupAttempts(ip: string | null, emailNormalized: string): Promise<void> {
		if (ip) await this.clearCounter(this.buildKey("signup", "ip", ip));
		await this.clearCounter(this.buildKey("signup", "email", emailNormalized));
	}

	async isForgotPasswordLimited(ip: string | null, emailNormalized: string): Promise<boolean> {
		if (ip) {
			const ipCount = await this.getCounter(
				this.buildKey("forgot", "ip", ip),
				this.config.rateLimit.forgotPasswordWindowMs,
			);
			if (ipCount >= this.config.rateLimit.forgotPasswordPerIpMax) return true;
		}
		const emailCount = await this.getCounter(
			this.buildKey("forgot", "email", emailNormalized),
			this.config.rateLimit.forgotPasswordWindowMs,
		);
		return emailCount >= this.config.rateLimit.forgotPasswordPerEmailMax;
	}

	async recordForgotPasswordAttempt(ip: string | null, emailNormalized: string): Promise<void> {
		if (ip) {
			await this.incrementCounter(
				this.buildKey("forgot", "ip", ip),
				this.config.rateLimit.forgotPasswordWindowMs,
			);
		}
		await this.incrementCounter(
			this.buildKey("forgot", "email", emailNormalized),
			this.config.rateLimit.forgotPasswordWindowMs,
		);
	}

	async assertResetPasswordAllowed(
		ip: string | null,
		accountKey: string | undefined,
		tokenHash: string,
	): Promise<void> {
		if (ip) {
			const ipCount = await this.getCounter(
				this.buildKey("reset", "ip", ip),
				this.config.rateLimit.resetPasswordWindowMs,
			);
			if (ipCount >= this.config.rateLimit.resetPasswordPerIpMax) {
				throw new AppException({ code: "AUTH_RATE_LIMITED", message: "Too many attempts.", status: 429 });
			}
		}
		if (accountKey) {
			const accountCount = await this.getCounter(
				this.buildKey("reset", "account", accountKey),
				this.config.rateLimit.resetPasswordWindowMs,
			);
			if (accountCount >= this.config.rateLimit.resetPasswordPerAccountMax) {
				throw new AppException({ code: "AUTH_RATE_LIMITED", message: "Too many attempts.", status: 429 });
			}
		}
		const tokenCount = await this.getCounter(
			this.buildKey("reset", "token", tokenHash),
			this.config.rateLimit.resetPasswordWindowMs,
		);
		if (tokenCount >= this.config.rateLimit.resetPasswordPerTokenMax) {
			throw new AppException({ code: "AUTH_RATE_LIMITED", message: "Too many attempts.", status: 429 });
		}
	}

	async recordResetPasswordAttempt(
		ip: string | null,
		accountKey: string | undefined,
		tokenHash: string,
	): Promise<void> {
		if (ip) {
			await this.incrementCounter(
				this.buildKey("reset", "ip", ip),
				this.config.rateLimit.resetPasswordWindowMs,
			);
		}
		if (accountKey) {
			await this.incrementCounter(
				this.buildKey("reset", "account", accountKey),
				this.config.rateLimit.resetPasswordWindowMs,
			);
		}
		await this.incrementCounter(
			this.buildKey("reset", "token", tokenHash),
			this.config.rateLimit.resetPasswordWindowMs,
		);
	}

	async assertTotpVerifyAllowed(sessionId: string, scope: string): Promise<void> {
		const count = await this.getCounter(
			this.buildKey("totp", scope, sessionId),
			this.config.rateLimit.totpVerifyWindowMs,
		);
		if (count >= this.config.rateLimit.totpVerifyPerSessionMax) {
			throw new AppException({ code: "AUTH_RATE_LIMITED", message: "Too many attempts.", status: 429 });
		}
	}

	async recordTotpVerifyFailure(sessionId: string, scope: string): Promise<void> {
		await this.incrementCounter(
			this.buildKey("totp", scope, sessionId),
			this.config.rateLimit.totpVerifyWindowMs,
		);
	}
}
