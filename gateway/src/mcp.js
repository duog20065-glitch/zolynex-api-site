// MCP endpoint (Streamable HTTP, stateless, JSON responses only) for AI tools.
// Auth: `Authorization: Bearer <token>` issued per client in HaruSelf (mcp_clients).
// Read-only clients only see read tools. Every write is audited as mcp:<client>.

import * as svc from './customers.js';
import { authenticateClient } from './clients.js';

const VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS =
  'Admin tools for Haru-api (FlashGate), an OpenAI-compatible API gateway that resells upstream model access to customers. ' +
  'Customers call https://api.zolynexstudio.com/v1 with a gateway key (sk-fg-...). Start with haru_overview. ' +
  'Write tools (create_customer, update_customer, set_customer_status, set_customer_upstream_key, rotate_customer_key, delete_customer) ' +
  'change who can use the paid API right now and are logged with your client name; confirm with the owner before using them. ' +
  'Customer keys are secrets: only show a full key when the owner asks for it, and never post keys anywhere else. ' +
  'Upstream keys are never returned by these tools; do not ask for them unless the owner wants to set one. ' +
  'Never reveal the upstream provider to customers.';

const customerRef = { type: 'string', description: 'Customer name (exact) or id' };

const TOOLS = [
  { name: 'haru_overview', title: 'Gateway overview', write: false,
    description: 'Health and counts: database status, number of customers (active / with dedicated upstream key), whether the shared upstream key works and which models it offers.',
    inputSchema: { type: 'object', properties: {} },
    run: (env) => svc.health(env) },
  { name: 'list_customers', title: 'List customers', write: false,
    description: 'List customers with status, upstream mode (shared or dedicated) and a masked key hint. Full keys are not included; use get_customer.',
    inputSchema: { type: 'object', properties: {
      status: { type: 'string', enum: ['all', 'active', 'disabled'], description: 'Filter by status (default all)' },
      search: { type: 'string', description: 'Case-insensitive match on name or note' } } },
    run: async (env, a) => {
      const q = String(a.search || '').toLowerCase();
      return (await svc.listCustomers(env)).filter((c) =>
        (!a.status || a.status === 'all' || c.status === a.status) && (!q || (c.name + ' ' + c.note).toLowerCase().includes(q)));
    } },
  { name: 'get_customer', title: 'Get customer', write: false,
    description: "One customer's details including the full current API key and the ready-to-send connection text (base_url, key, model).",
    inputSchema: { type: 'object', properties: { customer: customerRef }, required: ['customer'] },
    run: async (env, a) => {
      const c = await svc.getCustomer(env, a.customer);
      return { ...c, connectionText: c.key ? connectionText(c.key) : null };
    } },
  { name: 'create_customer', title: 'Create customer', write: true,
    description: 'Create a customer and issue their API key (active immediately). Optionally bind a dedicated upstream key, which is validated first. Returns the new key and the text to send to the customer.',
    inputSchema: { type: 'object', properties: {
      name: { type: 'string', description: 'Customer name, unique' },
      note: { type: 'string', description: 'Free-text note, e.g. prepaid amount' },
      upstream_key: { type: 'string', description: 'Optional dedicated upstream key; omit to use the shared one' } }, required: ['name'] },
    run: async (env, a, actor) => {
      const r = await svc.createCustomer(env, { name: a.name, note: a.note, upstreamKey: a.upstream_key }, actor);
      return { ...r, connectionText: connectionText(r.key) };
    } },
  { name: 'update_customer', title: 'Rename / edit note', write: true,
    description: "Change a customer's name and/or note.",
    inputSchema: { type: 'object', properties: { customer: customerRef, name: { type: 'string' }, note: { type: 'string' } }, required: ['customer'] },
    run: (env, a, actor) => svc.updateCustomer(env, a.customer, { name: a.name, note: a.note }, actor) },
  { name: 'set_customer_status', title: 'Enable / disable customer', write: true,
    description: "Disable (key stops working within ~30s) or re-enable a customer. The key itself is kept.",
    inputSchema: { type: 'object', properties: { customer: customerRef, status: { type: 'string', enum: ['active', 'disabled'] } }, required: ['customer', 'status'] },
    run: (env, a, actor) => svc.updateCustomer(env, a.customer, { status: a.status }, actor) },
  { name: 'set_customer_upstream_key', title: 'Set dedicated upstream key', write: true,
    description: "Bind a dedicated upstream key to a customer (validated first), or pass an empty string to switch back to the shared upstream key. The customer's own key does not change.",
    inputSchema: { type: 'object', properties: { customer: customerRef, upstream_key: { type: 'string', description: "New upstream key, or '' for shared" } }, required: ['customer', 'upstream_key'] },
    run: (env, a, actor) => svc.updateCustomer(env, a.customer, { upstreamKey: a.upstream_key }, actor) },
  { name: 'rotate_customer_key', title: 'Issue new key', write: true,
    description: "Revoke the customer's current key and issue a new one (use when a key leaked). The customer must switch to the new key.",
    inputSchema: { type: 'object', properties: { customer: customerRef }, required: ['customer'] },
    run: async (env, a, actor) => {
      const r = await svc.rotateKey(env, a.customer, actor);
      return { ...r, connectionText: connectionText(r.key) };
    } },
  { name: 'delete_customer', title: 'Delete customer', write: true, destructive: true,
    description: 'Permanently delete a customer and their keys. The customer must be disabled first. Cannot be undone.',
    inputSchema: { type: 'object', properties: { customer: customerRef }, required: ['customer'] },
    run: (env, a, actor) => svc.deleteCustomer(env, a.customer, actor) },
  { name: 'list_audit_log', title: 'Audit log', write: false,
    description: 'Recent changes (who did what, newest first): customer and AI-client changes from HaruSelf and from MCP clients.',
    inputSchema: { type: 'object', properties: { limit: { type: 'integer', minimum: 1, maximum: 500, description: 'Default 50' } } },
    run: (env, a) => svc.listAudit(env, a.limit) },
];

function connectionText(key) {
  return `base_url: https://api.zolynexstudio.com/v1\nAPI key: ${key}\nmodel: deepseek-v4.1-flash-1017`;
}

async function one(env, client, message) {
  const reply = (result) => ({ jsonrpc: '2.0', id: message.id, result });
  const fail = (code, text) => ({ jsonrpc: '2.0', id: message?.id ?? null, error: { code, message: text } });
  if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') return fail(-32600, 'Invalid Request');
  if (message.id === undefined) return null; // notifications need no reply
  const visible = TOOLS.filter((t) => client.canWrite || !t.write);
  switch (message.method) {
    case 'initialize': {
      const asked = message.params?.protocolVersion;
      return reply({
        protocolVersion: VERSIONS.includes(asked) ? asked : VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'haru-api', title: 'Haru-api Admin', version: '1.0.0' },
        instructions: INSTRUCTIONS,
      });
    }
    case 'ping': return reply({});
    case 'tools/list':
      return reply({ tools: visible.map((t) => ({
        name: t.name, title: t.title, description: t.description, inputSchema: t.inputSchema,
        annotations: { title: t.title, readOnlyHint: !t.write, destructiveHint: !!t.destructive, idempotentHint: !t.write, openWorldHint: false },
      })) });
    case 'tools/call': {
      const tool = visible.find((t) => t.name === message.params?.name);
      if (!tool) return fail(-32602, 'Unknown tool: ' + message.params?.name);
      try {
        const data = await tool.run(env, message.params?.arguments || {}, 'mcp:' + client.name);
        return reply({ content: [{ type: 'text', text: JSON.stringify(data ?? null, null, 2) }], structuredContent: { result: data ?? null } });
      } catch (err) {
        const msg = err instanceof svc.UserError ? err.message : '服务端出错，请稍后再试';
        if (!(err instanceof svc.UserError)) console.error(JSON.stringify({ stage: 'mcp', tool: tool.name, error: String(err && err.stack || err) }));
        return reply({ content: [{ type: 'text', text: msg }], isError: true });
      }
    }
    default: return fail(-32601, 'Method not found: ' + message.method);
  }
}

export async function handleMcp(request, env, ctx) {
  const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });
  // Browsers send Origin; AI tools do not. Refuse browser-originated calls.
  if (request.headers.get('origin')) return json({ error: 'forbidden-origin' }, 403);
  if (request.method === 'GET' || request.method === 'DELETE') return new Response(null, { status: 405, headers: { allow: 'POST' } });
  if (request.method !== 'POST') return json({ error: 'method' }, 405);

  const token = (request.headers.get('authorization') || '').match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  const client = await authenticateClient(env, token, ctx);
  if (!client) return json({ error: 'unauthorized' }, 401);

  let body;
  try {
    body = JSON.parse(await request.text());
  } catch {
    return json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, 400);
  }
  const list = Array.isArray(body) ? body : [body];
  const replies = (await Promise.all(list.map((m) => one(env, client, m)))).filter(Boolean);
  if (!replies.length) return new Response(null, { status: 202 });
  return json(Array.isArray(body) ? replies : replies[0]);
}
