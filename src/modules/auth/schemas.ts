import { z } from "zod";

export const loginSchema = z.object({
	email: z.string().email(),
	password: z.string().min(1).max(255),
	twoFactorCode: z.string().length(6).optional(),
	twoFactorMethod: z.enum(["totp", "email_otp"]).optional(),
	twoFactorChallengeId: z.string().optional(),
});

export const registerSchema = z.object({
	email: z.string().email(),
	displayName: z.string().min(1).max(255),
	password: z.string().min(10).max(128),
	captchaToken: z.string(),
});

export const verifyEmailSchema = z.object({
	challengeId: z.string(),
	verificationContextToken: z.string(),
	code: z.string().length(6),
});

export const resendEmailSchema = z.object({
	verificationContextToken: z.string(),
});

export const forgotPasswordSchema = z.object({
	email: z.string().email(),
});

export const resetPasswordSchema = z.object({
	token: z.string().min(1).max(512),
	newPassword: z.string().min(10).max(128),
});

export const setupAccountSchema = z.object({
	token: z.string().min(1).max(512),
	newPassword: z.string().min(10).max(128),
});

export const changePasswordSchema = z.object({
	currentPassword: z.string().min(1).max(255),
	newPassword: z.string().min(10).max(128),
});

export const setupTwoFactorSchema = z.object({
	password: z.string().optional(),
	recentAuthToken: z.string().optional(),
});

export const verifyTwoFactorSchema = z.object({
	recentAuthToken: z.string(),
	code: z.string().length(6),
});

export const disableTwoFactorSchema = z.object({
	password: z.string(),
});

export const unlinkSocialSchema = z.object({
	currentPassword: z.string(),
});
