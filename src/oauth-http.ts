import { version } from '../package.json';

/**
 * `User-Agent` sent on the library's own outbound fetches (EMA JWKS, Client ID Metadata Documents).
 * Workers' `fetch` sends none by default, and common WAF rule sets (AWS WAF's `NoUserAgent_HEADER`,
 * for one) block requests without it, so an IdP or client behind one would answer `403`. The RFC 9110
 * product token carries the release, and the comment points an operator at who is calling.
 */
export const OUTBOUND_USER_AGENT = `workers-oauth-provider/${version} (+https://github.com/cloudflare/workers-oauth-provider)`;
