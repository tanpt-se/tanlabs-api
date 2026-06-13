import { getApiRuntimeConfig } from "../config/runtime";
import { RbacRepository } from "../db/repositories/rbac.repository";
import { RefreshTokenRepository } from "../db/repositories/refresh-token.repository";
import { SessionRepository } from "../db/repositories/session.repository";
import { UserRepository } from "../db/repositories/user.repository";
import {
	AuditRepository,
	AuthIdentityRepository,
	PasswordResetRepository,
	TwoFactorRepository,
} from "../db/repositories/misc.repository";
import { EphemeralStore } from "../lib/ephemeral-store";
import { ChallengeService } from "./challenge.service";
import { FlowSupportService } from "./flow-support.service";
import { PasswordFlowService } from "./password-flow.service";
import { RateLimitService } from "./rate-limit.service";
import { RegistrationFlowService } from "./registration-flow.service";
import { SessionFlowService } from "./session-flow.service";
import { SessionsService } from "./sessions.service";
import { SocialFlowService } from "./social-flow.service";
import { TwoFactorFlowService } from "./two-factor-flow.service";

export class AppServices {
	readonly store: EphemeralStore;
	readonly users: UserRepository;
	readonly sessionsRepo: SessionRepository;
	readonly refreshTokens: RefreshTokenRepository;
	readonly rbac: RbacRepository;
	readonly audit: AuditRepository;
	readonly passwordReset: PasswordResetRepository;
	readonly twoFactor: TwoFactorRepository;
	readonly authIdentities: AuthIdentityRepository;
	readonly sessions: SessionsService;
	readonly rateLimit: RateLimitService;
	readonly challenges: ChallengeService;
	readonly support: FlowSupportService;
	readonly sessionFlow: SessionFlowService;
	readonly registrationFlow: RegistrationFlowService;
	readonly passwordFlow: PasswordFlowService;
	readonly twoFactorFlow: TwoFactorFlowService;
	readonly socialFlow: SocialFlowService;

	constructor(
		public readonly env: Env,
		public readonly config: ReturnType<typeof getApiRuntimeConfig>,
	) {
		this.store = new EphemeralStore(env.DB, env.AUTH_KV);
		this.users = new UserRepository(env.DB);
		this.sessionsRepo = new SessionRepository(env.DB);
		this.refreshTokens = new RefreshTokenRepository(env.DB);
		this.rbac = new RbacRepository(env.DB);
		this.audit = new AuditRepository(env.DB);
		this.passwordReset = new PasswordResetRepository(env.DB);
		this.twoFactor = new TwoFactorRepository(env.DB);
		this.authIdentities = new AuthIdentityRepository(env.DB);
		this.sessions = new SessionsService(env, config, this.sessionsRepo, this.refreshTokens, this.store);
		this.rateLimit = new RateLimitService(this.store, config);
		this.challenges = new ChallengeService(this.store, config);
		this.support = new FlowSupportService(
			env,
			config,
			this.users,
			this.rbac,
			this.audit,
			this.passwordReset,
			this.twoFactor,
			this.authIdentities,
			this.sessions,
			this.challenges,
			this.rateLimit,
			this.store,
		);
		this.sessionFlow = new SessionFlowService(this.support);
		this.registrationFlow = new RegistrationFlowService(this.support);
		this.passwordFlow = new PasswordFlowService(this.support);
		this.twoFactorFlow = new TwoFactorFlowService(this.support);
		this.socialFlow = new SocialFlowService(this.support);
	}
}

export function createServices(env: Env): AppServices {
	const config = getApiRuntimeConfig(env);
	return new AppServices(env, config);
}
