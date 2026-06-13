export type UserStatus = "ACTIVE" | "LOCKED" | "DISABLED";
export type SessionStatus = "ACTIVE" | "REVOKED" | "EXPIRED" | "COMPROMISED";
export type SessionClient = "WEB" | "ADMIN";
export type AuthIdentityProvider = "GOOGLE" | "GITHUB";
export type PasswordResetTokenPurpose = "PASSWORD_RESET" | "ACCOUNT_SETUP";

export interface RoleRecord {
	id: string;
	name: string;
	description: string | null;
	created_at: string;
	updated_at: string;
}

export interface UserRecord {
	id: string;
	email: string;
	email_normalized: string;
	display_name: string | null;
	password_hash: string;
	password_changed_at: string | null;
	email_verified_at: string | null;
	must_set_password: number;
	two_factor_enabled: number;
	status: UserStatus;
	role_id: string;
	created_at: string;
	updated_at: string;
	role?: RoleRecord;
}

export interface SessionRecord {
	id: string;
	user_id: string;
	status: SessionStatus;
	client: SessionClient;
	last_activity_at: string;
	sliding_expires_at: string;
	absolute_expires_at: string;
	device_label: string | null;
	ip_address: string | null;
	user_agent: string | null;
	created_at: string;
}

export interface RefreshTokenRecord {
	id: string;
	session_id: string;
	token_hash: string;
	expires_at: string;
	revoked_at: string | null;
	replaced_by_token_id: string | null;
	created_at: string;
}

export interface AuthIdentityRecord {
	id: string;
	user_id: string;
	provider: AuthIdentityProvider;
	provider_subject: string;
	provider_email: string | null;
	created_at: string;
	updated_at: string;
}

export interface TwoFactorSecretRecord {
	id: string;
	user_id: string;
	secret_encrypted: string;
	is_enabled: number;
	is_verified: number;
	last_used_at: string | null;
	created_at: string;
	updated_at: string;
}

export interface PasswordResetTokenRecord {
	id: string;
	user_id: string;
	token_hash: string;
	purpose: PasswordResetTokenPurpose;
	expires_at: string;
	used_at: string | null;
	revoked_at: string | null;
	created_at: string;
}

export function nowIso(): string {
	return new Date().toISOString();
}

export function parseDate(value: string): Date {
	return new Date(value);
}

export function boolFromInt(value: number): boolean {
	return value === 1;
}

export function intFromBool(value: boolean): number {
	return value ? 1 : 0;
}
