// Customer / API key storage in D1.
// Keys are matched by SHA-256 hash. The full customer key (so the admin can copy it
// again) and any dedicated upstream key are AES-GCM encrypted with the DATA_KEY secret.

const AUTH_CACHE_TTL_MS = 30_000;
const AUTH_CACHE_MAX = 5_000;
const authCache = new Map();

export function newApiKey() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return 'sk-fg-' + base64url(bytes);
}

export function hint(key) {
  return key ? key.slice(0, 6) + '…' + key.slice(-4) : '';
}

export async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Resolve a client key to { customerId, customer, upstreamKey } or null.
// Results (including misses) are cached per isolate for a short time, so a
// disabled customer stops working within AUTH_CACHE_TTL_MS.
export async function lookupKey(env, key) {
  const hash = await sha256Hex(key);
  const hit = authCache.get(hash);
  if (hit && hit.exp > Date.now()) return hit.value;

  const row = await env.DB.prepare(
    `SELECT c.id AS customer_id, c.name, c.upstream_key_enc
       FROM api_keys k JOIN customers c ON c.id = k.customer_id
      WHERE k.key_hash = ?1 AND k.revoked_at IS NULL AND c.status = 'active'`,
  ).bind(hash).first();

  const value = row
    ? { customerId: row.customer_id, customer: row.name, upstreamKey: row.upstream_key_enc ? await decrypt(env, row.upstream_key_enc) : '' }
    : null;
  if (authCache.size >= AUTH_CACHE_MAX) authCache.clear();
  authCache.set(hash, { value, exp: Date.now() + AUTH_CACHE_TTL_MS });
  return value;
}

export function forgetCachedKeys() {
  authCache.clear();
}

// --- encryption ---

let cryptoKey = null;
async function dataKey(env) {
  if (!env.DATA_KEY) throw new Error('DATA_KEY secret is not set');
  if (!cryptoKey) {
    const raw = Uint8Array.from(atob(env.DATA_KEY), (c) => c.charCodeAt(0));
    cryptoKey = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  return cryptoKey;
}

export async function encrypt(env, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await dataKey(env), new TextEncoder().encode(text)));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  return btoa(String.fromCharCode(...out));
}

export async function decrypt(env, b64) {
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, await dataKey(env), bytes.slice(12));
  return new TextDecoder().decode(pt);
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
