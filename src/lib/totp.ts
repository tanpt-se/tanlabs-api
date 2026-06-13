import * as OTPAuth from "otpauth";
import { BRAND } from "../common/access-control";

export function generateTotpSecret(email: string): { secret: string; otpauthUrl: string } {
	const secret = new OTPAuth.Secret({ size: 20 });
	const totp = new OTPAuth.TOTP({
		issuer: BRAND.totpIssuer,
		label: email,
		algorithm: "SHA1",
		digits: 6,
		period: 30,
		secret,
	});

	return {
		secret: secret.base32,
		otpauthUrl: totp.toString(),
	};
}

export function verifyTotpCode(
	secret: string,
	code: string,
	stepSeconds: number,
	allowedSkewSteps: number,
): boolean {
	const totp = new OTPAuth.TOTP({
		issuer: BRAND.totpIssuer,
		algorithm: "SHA1",
		digits: 6,
		period: stepSeconds,
		secret: OTPAuth.Secret.fromBase32(secret),
	});

	const delta = totp.validate({ token: code, window: allowedSkewSteps });
	return delta !== null;
}
