// AI clients (Claude Code, Codex, Muse, ...) allowed to call /mcp.
// Managed only from HaruSelf; an AI cannot issue tokens to itself.

import { sha256Hex, hint } from './store.js';
import { audit, UserError } from './customers.js';

const NAME_RE = /^[a-z0-9][a-z0-9_-]{1,31}$/;

function newToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return 'haru-mcp-' + btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const shape = (r) => ({ name: r.name, hint: r.token_hint, canWrite: !!r.can_write, enabled: !!r.enabled, createdAt: r.created_at, lastUsedAt: r.last_used_at });

export async function listClients(env) {
  const { results } = await env.DB.prepare('SELECT * FROM mcp_clients ORDER BY created_at').all();
  return results.map(shape);
}

// Returns the token once; only its hash is stored.
export async function createClient(env, { name, canWrite = true }, actor) {
  const n = String(name ?? '').trim().toLowerCase();
  if (!NAME_RE.test(n)) throw new UserError('名字只能用小写字母、数字、- 和 _，2–32 个字符');
  if (await env.DB.prepare('SELECT 1 FROM mcp_clients WHERE name = ?1').bind(n).first()) throw new UserError(`“${n}”已经存在`);
  const token = newToken();
  await env.DB.prepare('INSERT INTO mcp_clients (name, token_hash, token_hint, can_write, enabled, created_at) VALUES (?1, ?2, ?3, ?4, 1, ?5)')
    .bind(n, await sha256Hex(token), hint(token), canWrite ? 1 : 0, new Date().toISOString()).run();
  await audit(env, actor, 'create_mcp_client', n, { canWrite: !!canWrite });
  return { name: n, token };
}

export async function updateClient(env, { name, enabled, canWrite }, actor) {
  const c = await env.DB.prepare('SELECT * FROM mcp_clients WHERE name = ?1').bind(name).first();
  if (!c) throw new UserError(`找不到“${name}”`);
  const en = enabled === undefined ? c.enabled : enabled ? 1 : 0;
  const cw = canWrite === undefined ? c.can_write : canWrite ? 1 : 0;
  await env.DB.prepare('UPDATE mcp_clients SET enabled = ?1, can_write = ?2 WHERE name = ?3').bind(en, cw, name).run();
  await audit(env, actor, 'update_mcp_client', name, { enabled: !!en, canWrite: !!cw });
  return { ok: true };
}

export async function rotateClient(env, { name }, actor) {
  const c = await env.DB.prepare('SELECT 1 FROM mcp_clients WHERE name = ?1').bind(name).first();
  if (!c) throw new UserError(`找不到“${name}”`);
  const token = newToken();
  await env.DB.prepare('UPDATE mcp_clients SET token_hash = ?1, token_hint = ?2 WHERE name = ?3').bind(await sha256Hex(token), hint(token), name).run();
  await audit(env, actor, 'rotate_mcp_client', name);
  return { name, token };
}

export async function deleteClient(env, { name }, actor) {
  await env.DB.prepare('DELETE FROM mcp_clients WHERE name = ?1').bind(name).run();
  await audit(env, actor, 'delete_mcp_client', name);
  return { ok: true };
}

// Bearer token → { name, canWrite } for an enabled client, or null.
export async function authenticateClient(env, token, ctx) {
  if (!token || token.length > 200) return null;
  const c = await env.DB.prepare('SELECT name, can_write FROM mcp_clients WHERE token_hash = ?1 AND enabled = 1').bind(await sha256Hex(token)).first();
  if (!c) return null;
  ctx.waitUntil(env.DB.prepare('UPDATE mcp_clients SET last_used_at = ?1 WHERE name = ?2').bind(new Date().toISOString(), c.name).run());
  return { name: c.name, canWrite: !!c.can_write };
}
