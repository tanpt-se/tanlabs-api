export const SUPER_ADMIN_ROLE = "super_admin";
export const ADMIN_ROLE = "admin";
export const DEFAULT_CLIENT_ROLE = "user";

export const adminPermissionKeys = {
	revokeSessions: "admin.session.revoke",
} as const;

export const clientPermissionKeys = {
	viewDashboard: "client.dashboard.read",
	viewSessions: "client.session.read",
	manageAccount: "client.account.read",
} as const;

export const adminPermissionCatalog = Object.values(adminPermissionKeys);
export const clientPermissionCatalog = Object.values(clientPermissionKeys);
export const sharedPermissionCatalog = [
	...adminPermissionCatalog,
	...clientPermissionCatalog,
] as const;

export const BRAND = {
	totpIssuer: "TanLabs",
} as const;

export const AUTH_MAIL_SUBJECTS = {
	login2fa: "Your TanLabs login code",
	signupVerification: "Verify your TanLabs email",
	accountVerification: "Verify your TanLabs email",
	passwordReset: "Reset your TanLabs password",
} as const;
