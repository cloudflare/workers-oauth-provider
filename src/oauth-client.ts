import type { AuthRequest } from './oauth-provider';

/**
 * OAuth 2.1 compliant error class.
 * Represents errors that occur during OAuth operations with standardized error codes and descriptions.
 */
export class OAuthError extends Error {
	/**
	 * Creates a new OAuthError
	 * @param code - The OAuth error code (e.g., "invalid_request", "invalid_grant")
	 * @param description - Human-readable error description
	 * @param statusCode - HTTP status code to return (defaults to 400)
	 */
	constructor(
		public code: string,
		public description: string,
		public statusCode: number = 400,
	) {
		super(description);
		this.name = "OAuthError";
	}

	/**
	 * Converts the error to a standardized OAuth error response
	 * @returns HTTP Response with JSON error body
	 */
	toResponse(): Response {
		return new Response(
			JSON.stringify({
				error: this.code,
				error_description: this.description,
			}),
			{
				status: this.statusCode,
				headers: { "Content-Type": "application/json" },
			},
		);
	}
}

/**
 * Configuration options for OAuthClient
 */
export interface OAuthClientOptions {
	/**
	 * Cloudflare KV namespace for storing OAuth state data
	 */
	kv: KVNamespace;

	/**
	 * Secret key used for signing and verifying cookie data.
	 * Should be a long, random string kept secure.
	 */
	cookieSecret: string;

	/**
	 * Optional client identifier to namespace cookies and KV keys.
	 * Useful when running multiple OAuth providers in the same Worker.
	 *
	 * Examples:
	 * - "github" → cookies: __Host-CSRF_TOKEN-github, KV: oauth:github:state:...
	 * - "google" → cookies: __Host-CSRF_TOKEN-google, KV: oauth:google:state:...
	 *
	 * Must contain only alphanumeric characters, hyphens, or underscores.
	 * Defaults to "mcp" for Model Context Protocol OAuth flows.
	 */
	clientName?: string;

	/**
	 * Time-to-live for OAuth state in seconds.
	 * Defaults to 600 (10 minutes)
	 */
	stateTTL?: number;
}

/**
 * Result from createOAuthState containing the state token and cookie header
 */
export interface OAuthStateResult {
	/**
	 * The generated state token to be used in OAuth authorization requests
	 */
	stateToken: string;

	/**
	 * Set-Cookie header value to send to the client
	 */
	setCookie: string;
}

/**
 * Result from validateOAuthState containing the original OAuth request info and cookie to clear
 */
export interface ValidateStateResult {
	/**
	 * The original OAuth request information that was stored with the state token
	 */
	oauthReqInfo: AuthRequest;

	/**
	 * Set-Cookie header value to clear the state cookie
	 */
	clearCookie: string;
}

/**
 * Result from generateCSRFProtection containing the CSRF token and cookie header
 */
export interface CSRFProtectionResult {
	/**
	 * The generated CSRF token to be embedded in forms
	 */
	token: string;

	/**
	 * Set-Cookie header value to send to the client
	 */
	setCookie: string;
}

/**
 * Result from validateCSRFToken containing the cookie to clear
 */
export interface ValidateCSRFResult {
	/**
	 * Set-Cookie header value to clear the CSRF cookie (one-time use per RFC 9700)
	 */
	clearCookie: string;
}

/**
 * OAuth client for handling OAuth 2.1 client-side flows.
 * Provides methods for managing OAuth operations like CSRF protection,
 * state management, and client approval tracking.
 *
 * @example
 * ```typescript
 * const oauthClient = new OAuthClient({
 *   kv: env.KV_NAMESPACE,
 *   cookieSecret: env.COOKIE_SECRET,
 *   stateTTL: 600
 * });
 *
 * const { token, setCookie } = oauthClient.generateCSRFProtection();
 * ```
 */
export class OAuthClient {
	private kv: KVNamespace;
	private cookieSecret: string;
	private clientName: string;
	private csrfCookieName: string;
	private stateCookieName: string;
	private approvedClientsCookieName: string;
	private stateTTL: number;

	/**
	 * Creates a new OAuthClient instance
	 * @param options - Configuration options for the OAuth client
	 */
	constructor(options: OAuthClientOptions) {
		this.kv = options.kv;
		this.cookieSecret = options.cookieSecret;

		// Validate and set clientName
		const clientName = options.clientName || "mcp";
		if (!/^[a-zA-Z0-9_-]+$/.test(clientName)) {
			throw new Error(
				"clientName must contain only alphanumeric characters, hyphens, or underscores"
			);
		}
		this.clientName = clientName;

		// Generate namespaced cookie names
		this.csrfCookieName = `__Host-CSRF_TOKEN-${this.clientName}`;
		this.stateCookieName = `__Host-CONSENTED_STATE-${this.clientName}`;
		this.approvedClientsCookieName = `__Host-MCP_APPROVED_CLIENTS-${this.clientName}`;

		this.stateTTL = options.stateTTL || 600;
	}

	/**
	 * Sanitizes text content for safe display in HTML by escaping special characters.
	 * Use this for client names, descriptions, and other text content.
	 *
	 * @param text - The unsafe text that might contain HTML special characters
	 * @returns A safe string with HTML special characters escaped
	 *
	 * @example
	 * ```typescript
	 * const safeName = OAuthClient.sanitizeText("<script>alert('xss')</script>");
	 * // Returns: "&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;"
	 * ```
	 */
	static sanitizeText(text: string): string {
		return text
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;")
			.replace(/"/g, "&quot;")
			.replace(/'/g, "&#039;");
	}

	/**
	 * Validates a URL for security.
	 *
	 * Implements RFC compliance:
	 * - RFC 3986: Rejects control characters (not in allowed character set)
	 * - RFC 3986: Validates URI structure using URL parser
	 * - RFC 7591 §2: Client metadata URIs must point to valid web resources
	 * - RFC 7591 §5: Protect users from malicious content (whitelist approach)
	 *
	 * Uses whitelist security: Only allows https: and http: schemes.
	 * All other schemes (javascript:, data:, file:, etc.) are rejected.
	 *
	 * NOTE: This function only validates the URL structure and scheme. It does NOT
	 * perform HTML escaping. If you need to use the URL in HTML context (href, src),
	 * you must also call sanitizeText() on the result.
	 *
	 * @param url - The URL to validate
	 * @returns The validated URL string, or empty string if validation fails
	 *
	 * @example
	 * ```typescript
	 * const validUrl = OAuthClient.sanitizeUrl("https://example.com");
	 * // Returns: "https://example.com"
	 *
	 * const blocked = OAuthClient.sanitizeUrl("javascript:alert('xss')");
	 * // Returns: "" (rejected - not in whitelist)
	 *
	 * // For use in HTML, also escape:
	 * const htmlSafeUrl = OAuthClient.sanitizeText(OAuthClient.sanitizeUrl(userInput));
	 * ```
	 */
	static sanitizeUrl(url: string): string {
		const normalized = url.trim();

		if (normalized.length === 0) {
			return "";
		}

		// RFC 3986: Control characters are not in the allowed character set
		// Check C0 (0x00-0x1F) and C1 (0x7F-0x9F) control characters
		for (let i = 0; i < normalized.length; i++) {
			const code = normalized.charCodeAt(i);
			if ((code >= 0x00 && code <= 0x1f) || (code >= 0x7f && code <= 0x9f)) {
				return "";
			}
		}

		// RFC 3986: Validate URI structure (scheme and path required)
		let parsedUrl: URL;
		try {
			parsedUrl = new URL(normalized);
		} catch {
			return "";
		}

		// RFC 7591 §2: Client metadata URIs must point to valid web pages/resources
		// RFC 7591 §5: Protect users from malicious content
		// Whitelist only http/https schemes for web resources
		const allowedSchemes = ["https", "http"];

		const scheme = parsedUrl.protocol.slice(0, -1).toLowerCase();
		if (!allowedSchemes.includes(scheme)) {
			return "";
		}

		// Return validated URL without HTML escaping
		// Caller should use sanitizeText() if HTML escaping is needed
		return normalized;
	}

	/**
	 * Generates a new CSRF token and corresponding cookie for form protection
	 * @returns Object containing the token and Set-Cookie header value
	 */
	generateCSRFProtection(): CSRFProtectionResult {
		const token = crypto.randomUUID();
		const setCookie = `${this.csrfCookieName}=${token}; HttpOnly; Secure; Path=/authorize; SameSite=Lax; Max-Age=600`;
		return { token, setCookie };
	}

	/**
	 * Validates that the CSRF token from the form matches the token in the cookie.
	 * Per RFC 9700 Section 2.1, CSRF tokens must be one-time use.
	 *
	 * @param request - The HTTP request containing form data and cookies
	 * @returns Object containing clearCookie header to invalidate the token
	 * @throws {OAuthError} If CSRF token is missing or mismatched
	 */
	async validateCSRFToken(request: Request): Promise<ValidateCSRFResult> {
		const formData = await request.formData();
		const tokenFromForm = formData.get("csrf_token");

		if (!tokenFromForm || typeof tokenFromForm !== "string") {
			throw new OAuthError(
				"invalid_request",
				"Missing CSRF token in form data",
				400,
			);
		}

		const cookieHeader = request.headers.get("Cookie") || "";
		const cookies = cookieHeader.split(";").map((c) => c.trim());
		const csrfCookie = cookies.find((c) =>
			c.startsWith(`${this.csrfCookieName}=`),
		);
		const tokenFromCookie = csrfCookie
			? csrfCookie.substring(this.csrfCookieName.length + 1)
			: null;

		if (!tokenFromCookie) {
			throw new OAuthError(
				"invalid_request",
				"Missing CSRF token cookie",
				400,
			);
		}

		if (tokenFromForm !== tokenFromCookie) {
			throw new OAuthError("invalid_request", "CSRF token mismatch", 400);
		}

		// RFC 9700: CSRF tokens must be one-time use
		// Clear the cookie to prevent reuse
		const clearCookie = `${this.csrfCookieName}=; HttpOnly; Secure; Path=/authorize; SameSite=Lax; Max-Age=0`;

		return { clearCookie };
	}

	/**
	 * Creates and stores OAuth state information, returning a state token and cookie
	 * @param oauthReqInfo - OAuth request information to store with the state
	 * @returns Object containing the state token and Set-Cookie header value
	 */
	async createOAuthState(oauthReqInfo: AuthRequest): Promise<OAuthStateResult> {
		const stateToken = crypto.randomUUID();

		await this.kv.put(
			`oauth:${this.clientName}:state:${stateToken}`,
			JSON.stringify(oauthReqInfo),
			{ expirationTtl: this.stateTTL },
		);

		const setCookie = `${this.stateCookieName}=${stateToken}; HttpOnly; Secure; Path=/callback; SameSite=Lax; Max-Age=${this.stateTTL}`;

		return { stateToken, setCookie };
	}

	/**
	 * Validates OAuth state from the request, ensuring the state parameter matches the cookie
	 * and retrieving the stored OAuth request information
	 * @param request - The HTTP request containing state parameter and cookies
	 * @returns Object containing the original OAuth request info and cookie to clear
	 * @throws {OAuthError} If state is missing, mismatched, or expired
	 */
	async validateOAuthState(request: Request): Promise<ValidateStateResult> {
		const url = new URL(request.url);
		const stateFromQuery = url.searchParams.get("state");

		if (!stateFromQuery) {
			throw new OAuthError("invalid_request", "Missing state parameter", 400);
		}

		const cookieHeader = request.headers.get("Cookie") || "";
		const cookies = cookieHeader.split(";").map((c) => c.trim());
		const stateCookie = cookies.find((c) =>
			c.startsWith(`${this.stateCookieName}=`),
		);
		const stateFromCookie = stateCookie
			? stateCookie.substring(this.stateCookieName.length + 1)
			: null;

		if (!stateFromCookie) {
			throw new OAuthError(
				"invalid_request",
				"Missing consent state cookie",
				400,
			);
		}

		if (stateFromQuery !== stateFromCookie) {
			throw new OAuthError("invalid_request", "State mismatch", 400);
		}

		const storedDataJson = await this.kv.get(`oauth:${this.clientName}:state:${stateFromQuery}`);
		if (!storedDataJson) {
			throw new OAuthError(
				"invalid_request",
				"Invalid or expired state",
				400,
			);
		}

		let oauthReqInfo: AuthRequest;
		try {
			oauthReqInfo = JSON.parse(storedDataJson) as AuthRequest;
		} catch (e) {
			throw new OAuthError("server_error", "Invalid state data", 500);
		}

		await this.kv.delete(`oauth:${this.clientName}:state:${stateFromQuery}`);

		const clearCookie = `${this.stateCookieName}=; HttpOnly; Secure; Path=/callback; SameSite=Lax; Max-Age=0`;

		return { oauthReqInfo, clearCookie };
	}

	/**
	 * Checks if a client has been previously approved by the user
	 * @param request - The HTTP request containing cookies
	 * @param clientId - The OAuth client ID to check
	 * @returns True if the client is in the user's approved clients list
	 */
	async isClientApproved(
		request: Request,
		clientId: string,
	): Promise<boolean> {
		const approvedClients = await this.getApprovedClientsFromCookie(request);
		return approvedClients?.includes(clientId) ?? false;
	}

	/**
	 * Adds a client to the user's list of approved clients
	 * @param request - The HTTP request containing existing cookies
	 * @param clientId - The OAuth client ID to add
	 * @returns Set-Cookie header value with the updated approved clients list
	 */
	async addApprovedClient(
		request: Request,
		clientId: string,
	): Promise<string> {
		const existingApprovedClients =
			(await this.getApprovedClientsFromCookie(request)) || [];
		const updatedApprovedClients = Array.from(
			new Set([...existingApprovedClients, clientId]),
		);

		const payload = JSON.stringify(updatedApprovedClients);
		const signature = await this.signData(payload);
		const cookieValue = `${signature}.${btoa(payload)}`;

		return `${this.approvedClientsCookieName}=${cookieValue}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=31536000`;
	}

	private async getApprovedClientsFromCookie(
		request: Request,
	): Promise<string[] | null> {
		const cookieHeader = request.headers.get("Cookie");
		if (!cookieHeader) return null;

		const cookies = cookieHeader.split(";").map((c) => c.trim());
		const targetCookie = cookies.find((c) =>
			c.startsWith(`${this.approvedClientsCookieName}=`),
		);

		if (!targetCookie) return null;

		const cookieValue = targetCookie.substring(
			this.approvedClientsCookieName.length + 1,
		);
		const parts = cookieValue.split(".");

		if (parts.length !== 2) return null;

		const [signatureHex, base64Payload] = parts;
		const payload = atob(base64Payload);

		const isValid = await this.verifySignature(signatureHex, payload);

		if (!isValid) return null;

		try {
			const approvedClients = JSON.parse(payload);
			if (
				!Array.isArray(approvedClients) ||
				!approvedClients.every((item) => typeof item === "string")
			) {
				return null;
			}
			return approvedClients as string[];
		} catch (e) {
			return null;
		}
	}

	private async signData(data: string): Promise<string> {
		const key = await this.importKey();
		const enc = new TextEncoder();
		const signatureBuffer = await crypto.subtle.sign(
			"HMAC",
			key,
			enc.encode(data),
		);
		return Array.from(new Uint8Array(signatureBuffer))
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
	}

	private async verifySignature(
		signatureHex: string,
		data: string,
	): Promise<boolean> {
		const key = await this.importKey();
		const enc = new TextEncoder();
		try {
			const signatureBytes = new Uint8Array(
				signatureHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)),
			);
			return await crypto.subtle.verify(
				"HMAC",
				key,
				signatureBytes.buffer,
				enc.encode(data),
			);
		} catch (e) {
			return false;
		}
	}

	private async importKey(): Promise<CryptoKey> {
		if (!this.cookieSecret) {
			throw new Error("cookieSecret is required for signing cookies");
		}
		const enc = new TextEncoder();
		return crypto.subtle.importKey(
			"raw",
			enc.encode(this.cookieSecret),
			{ hash: "SHA-256", name: "HMAC" },
			false,
			["sign", "verify"],
		);
	}
}
