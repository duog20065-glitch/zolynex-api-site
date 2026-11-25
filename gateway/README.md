# FlashGate API gateway (Haru-api)

An OpenAI-compatible API gateway on Cloudflare Workers. Customers call it with a key we issue;
the Worker forwards to the upstream provider server-side. The upstream URL and keys exist only in
Worker secrets and encrypted D1 rows, never in this (public) repository.

> **This repo is public.** Never commit the upstream provider's name, URL, any key or token.

## Endpoints

| URL | Who | What |
|---|---|---|
| `https://api.zolynexstudio.com/v1/chat/completions` | customers | Chat completions, normal + streaming (`stream: true`). Route `api.zolynexstudio.com/v1/*`; every other path on that host is the GitHub Pages landing site. |
| `https://flashgate-gateway.duog20065.workers.dev/v1/...` | testing | Same gateway, workers.dev host. |
| `https://flashgate-gateway.duog20065.workers.dev/mcp` | AI tools | MCP (Streamable HTTP, stateless JSON). `Authorization: Bearer <per-client token>`. Only on the workers.dev host. |
| `AdminRPC` entrypoint | HaruSelf only | Service-binding RPC used by the admin page at `https://haru.zolynexstudio.com/haru-api/` (behind Cloudflare Access). Not reachable from the internet. |

## Layout

```
gateway/
├── wrangler.toml            Worker config: route, D1 binding (DB), observability
├── migrations/              D1 schema (apply: wrangler d1 migrations apply haru-api --remote)
│   ├── 0001_customers.sql   customers, api_keys
│   └── 0002_mcp_audit.sql   mcp_clients, audit_log
├── src/
│   ├── index.js             fetch handler: auth, forwarding, header allowlist, error rewriting, /mcp routing
│   ├── store.js             key hashing, AES-GCM encryption, key lookup with 30 s cache
│   ├── customers.js         customer operations + audit log (single implementation for RPC and MCP)
│   ├── clients.js           MCP client tokens (hash-only storage)
│   ├── mcp.js               MCP JSON-RPC handler and tool definitions
│   └── rpc.js               AdminRPC WorkerEntrypoint for HaruSelf
└── test/
    ├── smoke.mjs            end-to-end check: normal/stream/auth/errors + leak scan
    └── mock-upstream.mjs    local fake upstream that deliberately leaks, for wrangler dev
```

## Request flow

1. `authorize` → `lookupKey`: SHA-256 of the client key, looked up in `api_keys` joined with an
   `active` customer. Cached per isolate for 30 s, so disabling a customer takes effect within 30 s.
2. Upstream key = the customer's dedicated key (decrypted) or the shared `UPSTREAM_API_KEY`.
3. Successful responses are passed through **byte-for-byte** (the response `model`, `id`, `usage`
   and content are exactly what the upstream returned; by the OpenAI/DeepSeek API definition,
   `model` is "the model used", so we never rewrite it).
4. Only `content-type` is kept from upstream headers; we add `x-request-id`.
5. Upstream errors are rewritten into our own OpenAI-style error objects; upstream identifiers and
   `(request id: ...)` are scrubbed. 401/402/5xx from upstream → generic 502.
6. Each request logs `requestId, customer, dedicatedUpstream, model, stream, status, upstreamMs, colo`.

## Data (D1 `haru-api`, binding `DB`)

| Table | Notes |
|---|---|
| `customers` | name (unique), note, status `active`/`disabled`, optional `upstream_key_enc` + hint |
| `api_keys` | `key_hash` (lookup), `key_enc` (so the owner can copy it again), `revoked_at` on rotation |
| `mcp_clients` | AI clients: name, `token_hash` only, `can_write`, `enabled`, `last_used_at` |
| `audit_log` | every change: `actor` = `haruself` / `mcp:<client>` / `setup`; never contains keys |

## Secrets (`wrangler secret put NAME`)

| Name | Purpose |
|---|---|
| `UPSTREAM_BASE_URL` | upstream OpenAI-compatible base URL (ends with `/v1`) |
| `UPSTREAM_API_KEY` | shared upstream key |
| `UPSTREAM_SCRUB` | comma-separated words to redact from error messages |
| `DATA_KEY` | base64 AES-256 key for `key_enc` / `upstream_key_enc`. **Losing it makes stored keys unreadable.** |

## MCP tools

Read: `haru_overview`, `list_customers`, `get_customer`, `list_audit_log`.
Write (hidden from read-only clients): `create_customer`, `update_customer`, `set_customer_status`,
`set_customer_upstream_key`, `rotate_customer_key`, `delete_customer` (customer must be disabled first).
MCP clients and their tokens are managed only in HaruSelf (an AI cannot issue tokens).

## Deploy and test

```bash
cd gateway
npx wrangler deploy                      # if npx hangs, use a locally installed wrangler binary
npx wrangler d1 migrations apply haru-api --remote
node test/smoke.mjs https://flashgate-gateway.duog20065.workers.dev/v1 <customer key> <model> <leak,words>
npx wrangler tail flashgate-gateway      # live logs
```

The HaruSelf side (admin page, `/api/haru-api` proxy, service binding `HARU_API`) lives in the
private HaruSelf repository.
