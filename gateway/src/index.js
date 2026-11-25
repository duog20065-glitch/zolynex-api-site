// FlashGate API gateway (private beta).
// Clients call this Worker with an OpenAI-compatible request and a FlashGate key;
// the Worker calls the upstream provider server-side. Upstream URL, key and any
// upstream-identifying strings live only in Worker secrets, never in this file.
//
// Secrets:
//   UPSTREAM_BASE_URL  e.g. https://upstream.example.com/v1
//   UPSTREAM_API_KEY   upstream bearer key
//   DATA_KEY           base64 AES-256 key encrypting stored customer/upstream keys
//   UPSTREAM_SCRUB     optional, comma-separated extra words to redact from responses
//
// Customers and their keys live in D1 (binding DB). Management: AdminRPC (rpc.js) for
// HaruSelf over a service binding, and /mcp (mcp.js) for AI tools; both use customers.js.

import { lookupKey } from './store.js';
import { handleMcp } from './mcp.js';

export { AdminRPC } from './rpc.js';

const MAX_BODY_BYTES = 2 * 1024 * 1024;

// Only these upstream response headers reach the client; everything else
// (upstream request ids, server/version headers, cookies, rate-limit internals) is dropped.
const PASS_HEADERS = ['content-type'];

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'authorization, content-type, x-api-key',
  'access-control-max-age': '86400',
  'access-control-expose-headers': 'x-request-id',
};

export default {
  async fetch(request, env, ctx) {
    const requestId = 'req_' + crypto.randomUUID().replace(/-/g, '');
    try {
      return await handle(request, env, ctx, requestId);
    } catch (err) {
      console.error(JSON.stringify({ requestId, stage: 'unhandled', error: String(err && err.stack || err) }));
      return errorResponse(500, 'Internal error.', 'server_error', 'internal_error', requestId);
    }
  },
};

async function handle(request, env, ctx, requestId) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, '');

  // MCP for AI tools, only on the workers.dev hostname, never on the customer-facing domain.
  if (path === '/mcp' && url.hostname.endsWith('.workers.dev')) return handleMcp(request, env, ctx);

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });

  if (path !== '/v1/chat/completions') {
    return errorResponse(404, `Unknown endpoint: ${request.method} ${path || '/'}`, 'invalid_request_error', 'not_found', requestId);
  }
  if (request.method !== 'POST') {
    return errorResponse(405, 'Use POST for this endpoint.', 'invalid_request_error', 'method_not_allowed', requestId);
  }

  const auth = await authorize(request, env);
  if (auth === null) {
    return errorResponse(401, 'Invalid API key.', 'invalid_request_error', 'invalid_api_key', requestId);
  }
  const { customer } = auth;
  const upstreamKey = auth.upstreamKey || env.UPSTREAM_API_KEY;

  if (!env.UPSTREAM_BASE_URL || !upstreamKey) {
    console.error(JSON.stringify({ requestId, stage: 'config', error: 'upstream secrets missing' }));
    return errorResponse(503, 'Service temporarily unavailable.', 'server_error', 'service_unavailable', requestId);
  }

  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return errorResponse(413, 'Request body too large.', 'invalid_request_error', 'body_too_large', requestId);
  }
  let body;
  try {
    body = JSON.parse(raw);
  } catch {
    return errorResponse(400, 'Request body must be valid JSON.', 'invalid_request_error', 'invalid_json', requestId);
  }
  if (!body || typeof body !== 'object' || Array.isArray(body) || typeof body.model !== 'string' || !Array.isArray(body.messages)) {
    return errorResponse(400, 'Request must include "model" (string) and "messages" (array).', 'invalid_request_error', 'invalid_body', requestId);
  }
  const stream = body.stream === true;

  const upstreamUrl = env.UPSTREAM_BASE_URL.replace(/\/+$/, '') + '/chat/completions';
  let upstream;
  const upstreamStart = Date.now();
  try {
    upstream = await fetch(upstreamUrl, {
      method: 'POST',
      headers: {
        authorization: 'Bearer ' + upstreamKey,
        'content-type': 'application/json',
        accept: stream ? 'text/event-stream' : 'application/json',
      },
      body: raw,
      signal: request.signal,
    });
  } catch (err) {
    console.error(JSON.stringify({ requestId, stage: 'upstream_fetch', error: String(err) }));
    return errorResponse(502, 'Upstream service unavailable. Please retry.', 'server_error', 'upstream_unavailable', requestId);
  }

  const scrub = makeScrubber(env);
  // Time until upstream response headers arrive (for streams: roughly time to first byte).
  const upstreamMs = Date.now() - upstreamStart;
  console.log(JSON.stringify({ requestId, customer, dedicatedUpstream: !!auth.upstreamKey, model: body.model, stream, status: upstream.status, upstreamMs, colo: request.cf?.colo }));

  if (!upstream.ok) {
    const text = await upstream.text().catch(() => '');
    console.error(JSON.stringify({ requestId, stage: 'upstream_status', status: upstream.status, body: text.slice(0, 2000) }));
    return upstreamError(upstream.status, text, scrub, requestId);
  }

  const headers = cleanHeaders(upstream.headers, requestId);

  // Successful completions are passed through byte-for-byte: `model`, `id`,
  // `usage` and content are exactly what the upstream returned. Per the OpenAI /
  // DeepSeek API references, response `model` is "the model used for the chat
  // completion", so the gateway must not rewrite it. Only headers and error
  // objects are replaced.
  if (stream && upstream.body) {
    headers.set('content-type', 'text/event-stream; charset=utf-8');
    headers.set('cache-control', 'no-cache');
    return new Response(upstream.body.pipeThrough(sseErrorStream(scrub)), { status: 200, headers });
  }

  return new Response(upstream.body, { status: upstream.status, headers });
}

// --- auth ---

// Returns { customerId, customer, upstreamKey } for a valid key, or null.
// upstreamKey is '' when the customer uses the shared upstream key.
async function authorize(request, env) {
  const auth = request.headers.get('authorization') || '';
  const given = (auth.match(/^Bearer\s+(.+)$/i)?.[1] || request.headers.get('x-api-key') || '').trim();
  if (!given || given.length > 200 || !env.DB) return null;
  return lookupKey(env, given);
}

// --- response sanitising ---

function cleanHeaders(upstreamHeaders, requestId) {
  const headers = new Headers(CORS);
  for (const name of PASS_HEADERS) {
    const v = upstreamHeaders.get(name);
    if (v) headers.set(name, v);
  }
  headers.set('x-request-id', requestId);
  return headers;
}

function makeScrubber(env) {
  const words = new Set();
  try {
    const host = new URL(env.UPSTREAM_BASE_URL).hostname;
    words.add(host);
    // Also the registrable name, e.g. "example" from api.example.com.
    const parts = host.split('.');
    if (parts.length >= 2) words.add(parts[parts.length - 2]);
  } catch {}
  for (const w of (env.UPSTREAM_SCRUB || '').split(',')) if (w.trim()) words.add(w.trim());

  const patterns = [...words]
    .filter((w) => w.length >= 3)
    .map((w) => new RegExp(w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'));

  return (text) => {
    let out = text.replace(/\s*\(request id: [^)]*\)/gi, '');
    for (const re of patterns) out = out.replace(re, 'upstream');
    return out;
  };
}

// Line-buffered SSE pass-through. Normal chunks are forwarded unchanged; only an
// in-stream error event is rewritten into our own (redacted) error shape.
function sseErrorStream(scrub) {
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  let buffer = '';

  const processLine = (line) => {
    if (line.startsWith('data:')) {
      const payload = line.slice(5).trim();
      if (payload && payload !== '[DONE]') {
        try {
          const obj = JSON.parse(payload);
          if (obj && obj.error) {
            return 'data: ' + JSON.stringify(normaliseError(obj.error, scrub, 'server_error'));
          }
        } catch {}
      }
    }
    return line;
  };

  return new TransformStream({
    transform(chunk, controller) {
      buffer += decoder.decode(chunk, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();
      if (lines.length) controller.enqueue(encoder.encode(lines.map(processLine).join('\n') + '\n'));
    },
    flush(controller) {
      buffer += decoder.decode();
      if (buffer) controller.enqueue(encoder.encode(processLine(buffer)));
    },
  });
}

// Map upstream failures onto client-facing statuses. Problems with *our* upstream
// account (401, 402, 5xx) are hidden behind a generic message; request-level
// problems (bad params, unknown model, rate limit) keep a redacted message.
function upstreamError(status, text, scrub, requestId) {
  let upstreamErr = null;
  try {
    upstreamErr = JSON.parse(text).error || null;
  } catch {}

  if (status === 429) {
    return errorResponse(429, 'Rate limit reached. Please slow down and retry.', 'rate_limit_error', 'rate_limited', requestId);
  }
  if (status === 401 || status === 402 || status >= 500) {
    return errorResponse(502, 'Upstream service error. Please retry later.', 'server_error', 'upstream_error', requestId);
  }
  if (status === 403 && upstreamErr && /model/i.test(upstreamErr.message || '')) {
    return errorResponse(404, 'The requested model is not available for this key.', 'invalid_request_error', 'model_not_found', requestId);
  }
  const msg = upstreamErr && typeof upstreamErr.message === 'string' && upstreamErr.message.trim()
    ? scrub(upstreamErr.message).slice(0, 500)
    : 'Invalid request.';
  const outStatus = status === 403 ? 403 : status >= 400 && status < 500 ? status : 400;
  return errorResponse(outStatus, msg, 'invalid_request_error', null, requestId);
}

function normaliseError(err, scrub, type) {
  const message = typeof err.message === 'string' ? scrub(err.message).slice(0, 500) : 'Upstream error.';
  return { error: { message, type, code: null } };
}

function errorResponse(status, message, type, code, requestId) {
  const headers = new Headers(CORS);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('x-request-id', requestId);
  return new Response(JSON.stringify({ error: { message, type, code } }), { status, headers });
}
