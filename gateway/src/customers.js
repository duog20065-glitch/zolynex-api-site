// Customer management: the single implementation behind both the HaruSelf admin
// page (via the AdminRPC service binding) and the /mcp endpoint for AI tools.
// Every change is written to audit_log with the acting party.

import { newApiKey, hint, sha256Hex, encrypt, decrypt, forgetCachedKeys } from './store.js';

export class UserError extends Error {}

const cleanName = (s) => String(s ?? '').replace(/[\r\n]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);
const nowIso = () => new Date().toISOString();

export async function audit(env, actor, action, target, detail) {
  await env.DB.prepare('INSERT INTO audit_log (at, actor, action, target, detail) VALUES (?1, ?2, ?3, ?4, ?5)')
    .bind(nowIso(), actor, action, target ?? null, detail ? JSON.stringify(detail) : null).run();
}

// Find a customer by id or exact name.
async function resolve(env, ref) {
  const r = String(ref ?? '').trim();
  if (!r) throw new UserError('请指定客户（名字或 id）');
  const c = await env.DB.prepare('SELECT * FROM customers WHERE id = ?1 OR name = ?1').bind(r).first();
  if (!c) throw new UserError(`找不到客户“${r}”`);
  return c;
}

function shape(row) {
  return {
    id: row.id, name: row.name, note: row.note, status: row.status,
    upstream: row.upstream_key_enc ? { dedicated: true, hint: row.upstream_key_hint } : { dedicated: false },
    createdAt: row.created_at, updatedAt: row.updated_at,
  };
}

export async function listCustomers(env, { includeKeys = false } = {}) {
  const { results } = await env.DB.prepare(
    `SELECT c.*, k.id AS key_id, k.key_enc, k.key_hint, k.created_at AS key_created_at
       FROM customers c
       LEFT JOIN api_keys k ON k.customer_id = c.id AND k.revoked_at IS NULL
      ORDER BY c.created_at DESC`,
  ).all();
  const byId = new Map();
  for (const r of results) {
    if (!byId.has(r.id)) byId.set(r.id, { ...shape(r), keys: [] });
    if (r.key_id) {
      const k = { id: r.key_id, hint: r.key_hint, createdAt: r.key_created_at };
      if (includeKeys) k.key = await decrypt(env, r.key_enc);
      byId.get(r.id).keys.push(k);
    }
  }
  return [...byId.values()];
}

export async function getCustomer(env, ref) {
  const c = await resolve(env, ref);
  const k = await env.DB.prepare('SELECT key_enc, key_hint, created_at FROM api_keys WHERE customer_id = ?1 AND revoked_at IS NULL ORDER BY created_at DESC').bind(c.id).first();
  return { ...shape(c), key: k ? await decrypt(env, k.key_enc) : null, keyCreatedAt: k?.created_at ?? null };
}

export async function createCustomer(env, input, actor) {
  const name = cleanName(input.name);
  if (!name) throw new UserError('客户名不能为空');
  if (await env.DB.prepare('SELECT 1 FROM customers WHERE name = ?1').bind(name).first()) throw new UserError(`客户“${name}”已经存在`);

  const upstreamKey = String(input.upstreamKey ?? '').trim();
  if (upstreamKey) await checkUpstreamKey(env, upstreamKey);

  // input.key lets an existing key be imported (migration); otherwise generate one.
  const key = String(input.key ?? '').trim() || newApiKey();
  const keyHash = await sha256Hex(key);
  if (await env.DB.prepare('SELECT 1 FROM api_keys WHERE key_hash = ?1').bind(keyHash).first()) throw new UserError('这个 Key 已经被使用');

  const now = nowIso();
  const id = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO customers (id, name, note, status, upstream_key_enc, upstream_key_hint, created_at, updated_at)
       VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6, ?6)`,
    ).bind(id, name, String(input.note ?? ''), upstreamKey ? await encrypt(env, upstreamKey) : null, upstreamKey ? hint(upstreamKey) : null, now),
    env.DB.prepare('INSERT INTO api_keys (id, customer_id, key_hash, key_enc, key_hint, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(crypto.randomUUID(), id, keyHash, await encrypt(env, key), hint(key), now),
  ]);
  await audit(env, actor, 'create_customer', name, { dedicatedUpstream: !!upstreamKey, imported: !!input.key });
  return { id, name, key };
}

// patch: { name?, note?, status?: 'active'|'disabled', upstreamKey?: string ('' = shared) }
export async function updateCustomer(env, ref, patch, actor) {
  const c = await resolve(env, ref);
  const sets = [];
  const args = [];
  const changed = {};
  const set = (col, val) => { args.push(val); sets.push(`${col} = ?${args.length}`); };

  if (patch.name !== undefined) {
    const name = cleanName(patch.name);
    if (!name) throw new UserError('客户名不能为空');
    if (name !== c.name && (await env.DB.prepare('SELECT 1 FROM customers WHERE name = ?1').bind(name).first())) throw new UserError(`客户“${name}”已经存在`);
    set('name', name);
    changed.name = { from: c.name, to: name };
  }
  if (patch.note !== undefined) { set('note', String(patch.note)); changed.note = true; }
  if (patch.status !== undefined) {
    if (!['active', 'disabled'].includes(patch.status)) throw new UserError('状态只能是 active 或 disabled');
    set('status', patch.status);
    changed.status = patch.status;
  }
  if (patch.upstreamKey !== undefined) {
    const upstreamKey = String(patch.upstreamKey).trim();
    if (upstreamKey) await checkUpstreamKey(env, upstreamKey);
    set('upstream_key_enc', upstreamKey ? await encrypt(env, upstreamKey) : null);
    set('upstream_key_hint', upstreamKey ? hint(upstreamKey) : null);
    changed.upstream = upstreamKey ? 'dedicated' : 'shared';
  }
  if (!sets.length) throw new UserError('没有要修改的内容');
  set('updated_at', nowIso());
  args.push(c.id);
  await env.DB.prepare(`UPDATE customers SET ${sets.join(', ')} WHERE id = ?${args.length}`).bind(...args).run();
  forgetCachedKeys();
  await audit(env, actor, 'update_customer', c.name, changed);
  return { ok: true, customer: changed.name?.to ?? c.name };
}

export async function rotateKey(env, ref, actor) {
  const c = await resolve(env, ref);
  const key = newApiKey();
  const now = nowIso();
  await env.DB.batch([
    env.DB.prepare('UPDATE api_keys SET revoked_at = ?1 WHERE customer_id = ?2 AND revoked_at IS NULL').bind(now, c.id),
    env.DB.prepare('INSERT INTO api_keys (id, customer_id, key_hash, key_enc, key_hint, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(crypto.randomUUID(), c.id, await sha256Hex(key), await encrypt(env, key), hint(key), now),
    env.DB.prepare('UPDATE customers SET updated_at = ?1 WHERE id = ?2').bind(now, c.id),
  ]);
  forgetCachedKeys();
  await audit(env, actor, 'rotate_key', c.name);
  return { customer: c.name, key };
}

export async function deleteCustomer(env, ref, actor) {
  const c = await resolve(env, ref);
  if (c.status !== 'disabled') throw new UserError('请先停用这个客户，再删除');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM api_keys WHERE customer_id = ?1').bind(c.id),
    env.DB.prepare('DELETE FROM customers WHERE id = ?1').bind(c.id),
  ]);
  forgetCachedKeys();
  await audit(env, actor, 'delete_customer', c.name);
  return { ok: true };
}

export async function listAudit(env, limit = 50) {
  const n = Math.min(Math.max(parseInt(limit, 10) || 50, 1), 500);
  const { results } = await env.DB.prepare('SELECT at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT ?1').bind(n).all();
  return results.map((r) => ({ ...r, detail: r.detail ? JSON.parse(r.detail) : null }));
}

// Gateway health: database reachable, customer counts, shared upstream key valid.
export async function health(env) {
  const counts = await env.DB.prepare(
    "SELECT COUNT(*) AS total, SUM(status = 'active') AS active, SUM(upstream_key_enc IS NOT NULL) AS dedicated FROM customers",
  ).first();
  let upstream;
  try {
    const res = await fetch(env.UPSTREAM_BASE_URL.replace(/\/+$/, '') + '/models', { headers: { authorization: 'Bearer ' + env.UPSTREAM_API_KEY } });
    const j = res.ok ? await res.json().catch(() => ({})) : {};
    upstream = { ok: res.ok, status: res.status, models: (j.data || []).map((m) => m.id) };
  } catch {
    upstream = { ok: false, status: 0, models: [] };
  }
  return {
    database: 'ok',
    customers: { total: counts.total || 0, active: counts.active || 0, dedicatedUpstream: counts.dedicated || 0 },
    sharedUpstreamKey: upstream,
    publicBaseUrl: 'https://api.zolynexstudio.com/v1',
  };
}

// Ask the upstream for its model list (no tokens used) to confirm the key works.
async function checkUpstreamKey(env, key) {
  if (/[\s,]/.test(key)) throw new UserError('上游 Key 里有空格或逗号，可能复制错了');
  let res;
  try {
    res = await fetch(env.UPSTREAM_BASE_URL.replace(/\/+$/, '') + '/models', { headers: { authorization: 'Bearer ' + key } });
  } catch {
    throw new UserError('暂时连不上上游，稍后再试');
  }
  if (!res.ok) throw new UserError(`上游 Key 无效（上游返回 ${res.status}），请确认复制完整且没有被禁用`);
}
