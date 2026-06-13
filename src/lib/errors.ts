export interface AppExceptionOptions {
	code: string;
	message: string;
	status: number;
	details?: Record<string, unknown>;
}

export class AppException extends Error {
	readonly code: string;
	readonly status: number;
	readonly details?: Record<string, unknown>;

	constructor(options: AppExceptionOptions) {
		super(options.message);
		this.name = "AppException";
		this.code = options.code;
		this.status = options.status;
		this.details = options.details;
	}

	toJSON() {
		return {
			code: this.code,
			message: this.message,
			status: this.status,
			...(this.details ? { details: this.details } : {}),
		};
	}
}

export function isAppException(error: unknown): error is AppException {
	return error instanceof AppException;
}
