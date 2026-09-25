// Prints a new ES256 (EC P-256) private JWK for the auth server's JWT_SIGNING_KEY secret.
//
//   node generate-signing-key.mjs | npx wrangler secret put JWT_SIGNING_KEY
//
// The key goes straight to the secret store; don't save it to a file or commit it.
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const { kty, crv, x, y, d } = await crypto.subtle.exportKey('jwk', pair.privateKey);
// The kid names the key in the JWKS. A date makes rotation easy to follow.
const kid = new Date().toISOString().slice(0, 10);
process.stdout.write(JSON.stringify({ kty, crv, x, y, d, kid }));
