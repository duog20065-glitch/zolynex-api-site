// Admin API for managing customers and their keys.
// Reachable only on the workers.dev hostname (the api.* route covers /v1/* only)
// and only with the ADMIN_TOKEN secret. Later the account manager (HaruSelf)
// can call this through a service binding instead of over the public internet.
//
//   GET    /admin/customers                 list
//   POST   /admin/customers                 { name, note?, upstreamKey?, key? }  create (+ first key)
//   PATCH  /admin/customers/:id             { name?, note?, status?, upstreamKey? }  ('' = shared upstream)
//   POST   /admin/customers/:id/rotate      revoke current keys, issue a new one
//   DELETE /admin/customers/:id             delete (must be disabled first)

import { newApiKey, hint, sha256Hex, encrypt, decrypt, forgetCachedKeys } from './store.js';

const ADMIN_CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, PATCH, DELETE, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-max-age': '86400',
};

export async function handleAdmin(request, env, url) {
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: ADMIN_CORS });
  if (!(await adminAuthorized(request, env))) return json({ error: '管理密码不对' }, 401);
  if (!env.DB || !env.DATA_KEY) return json({ error: '服务端缺少数据库或加密配置' }, 503);

  const parts = url.pathname.replace(/\/+$/, '').split('/').filter(Boolean); // ['admin','customers',id?,action?]
  if (parts[1] !== 'customers') return json({ error: 'Not found' }, 404);
  const customerId = parts[2];
  const sub = parts[3];

  try {
    if (!customerId && request.method === 'GET') return json({ customers: await listCustomers(env) });
    if (!customerId && request.method === 'POST') return await createCustomer(env, await readJson(request));
    if (customerId && !sub && request.method === 'PATCH') return await updateCustomer(env, customerId, await readJson(request));
    if (customerId && sub === 'rotate' && request.method === 'POST') return await rotateKey(env, customerId);
    if (customerId && !sub && request.method === 'DELETE') return await deleteCustomer(env, customerId);
    return json({ error: 'Not found' }, 404);
  } catch (err) {
    if (err instanceof UserError) return json({ error: err.message }, err.status);
    console.error(JSON.stringify({ stage: 'admin', error: String(err && err.stack || err) }));
    return json({ error: '服务端出错' }, 500);
  }
}

async function listCustomers(env) {
  const { results } = await env.DB.prepare(
    `SELECT c.*, k.id AS key_id, k.key_enc, k.key_hint, k.created_at AS key_created_at
       FROM customers c
       LEFT JOIN api_keys k ON k.customer_id = c.id AND k.revoked_at IS NULL
      ORDER BY c.created_at DESC`,
  ).all();
  const byId = new Map();
  for (const r of results) {
    if (!byId.has(r.id)) {
      byId.set(r.id, {
        id: r.id, name: r.name, note: r.note, status: r.status,
        upstream: r.upstream_key_enc ? { dedicated: true, hint: r.upstream_key_hint } : { dedicated: false },
        createdAt: r.created_at, updatedAt: r.updated_at, keys: [],
      });
    }
    if (r.key_id) byId.get(r.id).keys.push({ id: r.key_id, key: await decrypt(env, r.key_enc), hint: r.key_hint, createdAt: r.key_created_at });
  }
  return [...byId.values()];
}

async function createCustomer(env, body) {
  const name = cleanName(body.name);
  if (!name) throw new UserError('客户名不能为空');
  if (await env.DB.prepare('SELECT 1 FROM customers WHERE name = ?1').bind(name).first()) throw new UserError(`客户“${name}”已经存在`, 409);

  const upstreamKey = (body.upstreamKey || '').trim();
  if (upstreamKey) await checkUpstreamKey(env, upstreamKey);

  // `key` lets an existing key be imported (migration); otherwise generate one.
  const key = (body.key || '').trim() || newApiKey();
  const keyHash = await sha256Hex(key);
  if (await env.DB.prepare('SELECT 1 FROM api_keys WHERE key_hash = ?1').bind(keyHash).first()) throw new UserError('这个 Key 已经被使用', 409);

  const now = new Date().toISOString();
  const id = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO customers (id, name, note, status, upstream_key_enc, upstream_key_hint, created_at, updated_at)
       VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?6, ?6)`,
    ).bind(id, name, String(body.note || ''), upstreamKey ? await encrypt(env, upstreamKey) : null, upstreamKey ? hint(upstreamKey) : null, now),
    env.DB.prepare(
      'INSERT INTO api_keys (id, customer_id, key_hash, key_enc, key_hint, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)',
    ).bind(crypto.randomUUID(), id, keyHash, await encrypt(env, key), hint(key), now),
  ]);
  return json({ id, name, key }, 201);
}

async function updateCustomer(env, id, body) {
  const c = await env.DB.prepare('SELECT * FROM customers WHERE id = ?1').bind(id).first();
  if (!c) throw new UserError('客户不存在', 404);

  const sets = [];
  const args = [];
  const set = (col, val) => { args.push(val); sets.push(`${col} = ?${args.length}`); };

  if (body.name !== undefined) {
    const name = cleanName(body.name);
    if (!name) throw new UserError('客户名不能为空');
    if (name !== c.name && (await env.DB.prepare('SELECT 1 FROM customers WHERE name = ?1').bind(name).first())) throw new UserError(`客户“${name}”已经存在`, 409);
    set('name', name);
  }
  if (body.note !== undefined) set('note', String(body.note));
  if (body.status !== undefined) {
    if (!['active', 'disabled'].includes(body.status)) throw new UserError('状态只能是 active 或 disabled');
    set('status', body.status);
  }
  if (body.upstreamKey !== undefined) {
    const upstreamKey = String(body.upstreamKey).trim();
    if (upstreamKey) await checkUpstreamKey(env, upstreamKey);
    set('upstream_key_enc', upstreamKey ? await encrypt(env, upstreamKey) : null);
    set('upstream_key_hint', upstreamKey ? hint(upstreamKey) : null);
  }
  if (!sets.length) throw new UserError('没有要修改的内容');
  set('updated_at', new Date().toISOString());
  args.push(id);
  await env.DB.prepare(`UPDATE customers SET ${sets.join(', ')} WHERE id = ?${args.length}`).bind(...args).run();
  forgetCachedKeys();
  return json({ ok: true });
}

async function rotateKey(env, id) {
  const c = await env.DB.prepare('SELECT id FROM customers WHERE id = ?1').bind(id).first();
  if (!c) throw new UserError('客户不存在', 404);
  const key = newApiKey();
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare('UPDATE api_keys SET revoked_at = ?1 WHERE customer_id = ?2 AND revoked_at IS NULL').bind(now, id),
    env.DB.prepare('INSERT INTO api_keys (id, customer_id, key_hash, key_enc, key_hint, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)')
      .bind(crypto.randomUUID(), id, await sha256Hex(key), await encrypt(env, key), hint(key), now),
    env.DB.prepare('UPDATE customers SET updated_at = ?1 WHERE id = ?2').bind(now, id),
  ]);
  forgetCachedKeys();
  return json({ key });
}

async function deleteCustomer(env, id) {
  const c = await env.DB.prepare('SELECT status FROM customers WHERE id = ?1').bind(id).first();
  if (!c) throw new UserError('客户不存在', 404);
  if (c.status !== 'disabled') throw new UserError('请先停用这个客户，再删除');
  await env.DB.batch([
    env.DB.prepare('DELETE FROM api_keys WHERE customer_id = ?1').bind(id),
    env.DB.prepare('DELETE FROM customers WHERE id = ?1').bind(id),
  ]);
  forgetCachedKeys();
  return json({ ok: true });
}

// Ask the upstream for its model list (no tokens used) to confirm the key works.
async function checkUpstreamKey(env, key) {
  if (/[\s,]/.test(key)) throw new UserError('上游 Key 里有空格或逗号，可能复制错了');
  let res;
  try {
    res = await fetch(env.UPSTREAM_BASE_URL.replace(/\/+$/, '') + '/models', { headers: { authorization: 'Bearer ' + key } });
  } catch {
    throw new UserError('暂时连不上上游，稍后再试', 502);
  }
  if (!res.ok) throw new UserError(`上游 Key 无效（上游返回 ${res.status}），请确认复制完整且没有被禁用`);
}

async function adminAuthorized(request, env) {
  const given = (request.headers.get('authorization') || '').match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  if (!given || !env.ADMIN_TOKEN) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([crypto.subtle.digest('SHA-256', enc.encode(given)), crypto.subtle.digest('SHA-256', enc.encode(env.ADMIN_TOKEN))]);
  return crypto.subtle.timingSafeEqual(a, b);
}

class UserError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const cleanName = (s) => String(s || '').replace(/[\r\n]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 80);

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    throw new UserError('请求格式不对');
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...ADMIN_CORS, 'content-type': 'application/json; charset=utf-8' } });
}
