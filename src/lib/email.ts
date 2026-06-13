import type { ApiRuntimeConfig } from "../config/runtime";

export async function sendEmail(params: {
	config: ApiRuntimeConfig;
	to: string;
	subject: string;
	text: string;
}): Promise<void> {
	const { config, to, subject, text } = params;
	const delivery = config.emailOtpDelivery;

	if (delivery.mode === "console" || !delivery.resendApiKey) {
		console.log(`[email] to=${to} subject=${subject} (${text.length} bytes, body omitted)`);
		return;
	}

	const response = await fetch("https://api.resend.com/emails", {
		method: "POST",
		headers: {
			Authorization: `Bearer ${delivery.resendApiKey}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			from: delivery.smtpFromEmail,
			to: [to],
			subject,
			text,
		}),
	});

	if (!response.ok) {
		const body = await response.text();
		console.error(`[email] delivery failed: ${response.status}`);
		throw new Error(`Email delivery failed with status ${response.status}: ${body.slice(0, 200)}`);
	}
}
