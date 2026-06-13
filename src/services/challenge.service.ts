import type { ApiRuntimeConfig } from "../config/runtime";
import { AUTH_MAIL_SUBJECTS } from "../common/access-control";
import { randomBase64Url, sha256Hex } from "../lib/crypto";
import { sendEmail } from "../lib/email";
import { AppException } from "../lib/errors";
import type { EphemeralStore } from "../lib/ephemeral-store";

type EmailOtpChallengeStatus = "PENDING" | "VERIFIED" | "EXPIRED" | "REVOKED";
type EmailOtpChallengePurpose =
	| "LOGIN_2FA"
	| "SIGNUP_EMAIL_VERIFICATION"
	| "ACCOUNT_EMAIL_VERIFICATION";

interface EmailOtpChallenge {
	id: string;
	userId: string;
	purpose: EmailOtpChallengePurpose;
	contextKey: string;
	codeHash: string;
	expiresAt: string;
	resendAvailableAt: string;
	attemptCount: number;
	maxAttempts: number;
	sendCount: number;
	maxSends: number;
	status: EmailOtpChallengeStatus;
	createdAt: string;
}

export class ChallengeService {
	constructor(
		private readonly store: EphemeralStore,
		private readonly config: ApiRuntimeConfig,
	) {}

	private buildChallengeKey(challengeId: string): string {
		return `${this.config.challenge.challengePrefix}:${challengeId}`;
	}

	private generateChallengeId(): string {
		return randomBase64Url(18);
	}

	private generateEmailOtpCode(): string {
		const value = crypto.getRandomValues(new Uint32Array(1))[0]! % 1_000_000;
		return String(value).padStart(6, "0");
	}

	async issueEmailOtpChallenge(
		userId: string,
		email: string,
		contextKey: string,
		purpose: EmailOtpChallengePurpose,
	): Promise<{ challengeId: string; expiresIn: number; resendAvailableIn: number }> {
		const now = new Date();
		const code = this.generateEmailOtpCode();
		const codeHash = await sha256Hex(code);
		const challengeId = this.generateChallengeId();
		const expiresAt = new Date(now.getTime() + this.config.challenge.challengeTtlMs).toISOString();
		const resendAvailableAt = new Date(now.getTime() + this.config.challenge.resendCooldownMs).toISOString();

		const challenge: EmailOtpChallenge = {
			id: challengeId,
			userId,
			purpose,
			contextKey,
			codeHash,
			expiresAt,
			resendAvailableAt,
			attemptCount: 0,
			maxAttempts: this.config.challenge.maxAttempts,
			sendCount: 1,
			maxSends: this.config.challenge.maxSends,
			status: "PENDING",
			createdAt: now.toISOString(),
		};

		await this.store.set(this.buildChallengeKey(challengeId), challenge, this.config.challenge.challengeTtlMs);

		const subject =
			purpose === "LOGIN_2FA"
				? AUTH_MAIL_SUBJECTS.login2fa
				: purpose === "SIGNUP_EMAIL_VERIFICATION"
					? AUTH_MAIL_SUBJECTS.signupVerification
					: AUTH_MAIL_SUBJECTS.accountVerification;

		await sendEmail({
			config: this.config,
			to: email,
			subject,
			text: `Your verification code is ${code}. It expires in ${Math.ceil(this.config.challenge.challengeTtlMs / 1000)} seconds.`,
		});

		return {
			challengeId,
			expiresIn: Math.ceil(this.config.challenge.challengeTtlMs / 1000),
			resendAvailableIn: Math.ceil(this.config.challenge.resendCooldownMs / 1000),
		};
	}

	async verifyEmailOtpChallenge(params: {
		challengeId: string;
		userId: string;
		purpose: EmailOtpChallengePurpose;
		contextKey: string;
		code: string;
	}): Promise<void> {
		const challenge = await this.store.get<EmailOtpChallenge>(this.buildChallengeKey(params.challengeId));
		if (!challenge) {
			throw new AppException({
				code: "AUTH_2FA_CHALLENGE_INVALID",
				message: "Challenge is invalid.",
				status: 401,
			});
		}

		if (
			challenge.userId !== params.userId ||
			challenge.purpose !== params.purpose ||
			challenge.contextKey !== params.contextKey ||
			challenge.status !== "PENDING"
		) {
			throw new AppException({
				code: "AUTH_2FA_CHALLENGE_INVALID",
				message: "Challenge is invalid.",
				status: 401,
			});
		}

		if (new Date(challenge.expiresAt).getTime() <= Date.now()) {
			challenge.status = "EXPIRED";
			await this.store.set(this.buildChallengeKey(params.challengeId), challenge, 60_000);
			throw new AppException({
				code: "AUTH_2FA_CHALLENGE_EXPIRED",
				message: "Challenge has expired.",
				status: 401,
			});
		}

		const codeHash = await sha256Hex(params.code);
		if (codeHash !== challenge.codeHash) {
			challenge.attemptCount += 1;
			if (challenge.attemptCount >= challenge.maxAttempts) {
				challenge.status = "REVOKED";
			}
			await this.store.set(this.buildChallengeKey(params.challengeId), challenge, this.config.challenge.challengeTtlMs);
			throw new AppException({
				code: "AUTH_2FA_INVALID",
				message: "Invalid verification code.",
				status: 401,
			});
		}

		challenge.status = "VERIFIED";
		await this.store.set(this.buildChallengeKey(params.challengeId), challenge, 60_000);
	}
}
