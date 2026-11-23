// Smoke test for the gateway: normal + streaming chat completions, auth, and
// a leak check over every response header and body.
//   node test/smoke.mjs <base_url> <gateway_key> <model> [leak words, comma-separated]
const [base, key, model, leakArg = ''] = process.argv.slice(2);
if (!base || !key || !model) {
  console.error('usage: node test/smoke.mjs <base_url> <gateway_key> <model> [leak,words]');
  process.exit(2);
}
const leakWords = leakArg.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const ALLOWED_HEADERS = new Set(['content-type', 'content-length', 'cache-control', 'x-request-id', 'date', 'connection', 'server', 'cf-ray',
  'transfer-encoding', 'content-encoding', 'vary', 'alt-svc', 'nel', 'report-to', 'keep-alive', 'cf-cache-status', 'speculation-rules',
  'access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-max-age']);

let failed = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  — ' + detail : ''}`);
  if (!ok) failed++;
};

function leakCheck(name, res, text) {
  const extra = [...res.headers.keys()].filter((h) => !ALLOWED_HEADERS.has(h));
  check(`${name}: no unexpected headers`, extra.length === 0, extra.join(', '));
  const hay = (JSON.stringify([...res.headers]) + text).toLowerCase();
  const hits = leakWords.filter((w) => hay.includes(w));
  check(`${name}: no upstream identifiers`, hits.length === 0, hits.join(', '));
  if (res.headers.get('server') && res.headers.get('server') !== 'cloudflare') check(`${name}: server header`, false, res.headers.get('server'));
}

async function call(name, { auth = key, body }) {
  const res = await fetch(base.replace(/\/+$/, '') + '/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(auth ? { authorization: 'Bearer ' + auth } : {}) },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  const text = await res.text();
  leakCheck(name, res, text);
  return { res, text };
}

const msg = [{ role: 'user', content: 'Reply with the single word: pong' }];

{
  const { res, text } = await call('non-stream', { body: { model, messages: msg, max_tokens: 16 } });
  let j = {};
  try { j = JSON.parse(text); } catch {}
  check('non-stream: 200 + content', res.status === 200 && typeof j.choices?.[0]?.message?.content === 'string', `status ${res.status} ${text.slice(0, 200)}`);
  console.log('      reply:', JSON.stringify(j.choices?.[0]?.message?.content), 'usage:', JSON.stringify(j.usage));
}
{
  const { res, text } = await call('stream', { body: { model, messages: msg, max_tokens: 16, stream: true, stream_options: { include_usage: true } } });
  const events = text.split('\n').filter((l) => l.startsWith('data:'));
  const content = events.map((l) => { try { return JSON.parse(l.slice(5)).choices?.[0]?.delta?.content || ''; } catch { return ''; } }).join('');
  check('stream: 200 + event-stream', res.status === 200 && (res.headers.get('content-type') || '').includes('text/event-stream'), `status ${res.status}`);
  check('stream: chunks + [DONE]', events.length >= 2 && events.at(-1).includes('[DONE]'), `${events.length} events`);
  console.log('      reply:', JSON.stringify(content));
}
{
  const { res } = await call('bad key', { auth: 'sk-wrong', body: { model, messages: msg } });
  check('bad key: 401', res.status === 401);
}
{
  const { res } = await call('no key', { auth: '', body: { model, messages: msg } });
  check('no key: 401', res.status === 401);
}
{
  const { res, text } = await call('unknown model', { body: { model: 'missing', messages: msg, max_tokens: 4 } });
  check('unknown model: 4xx, OpenAI error shape', res.status >= 400 && res.status < 500 && !!JSON.parse(text).error, `status ${res.status} ${text.slice(0, 200)}`);
}
{
  const { res } = await call('bad json', { body: '{not json' });
  check('bad json: 400', res.status === 400);
}

console.log(failed ? `\n${failed} check(s) failed` : '\nall checks passed');
process.exit(failed ? 1 : 0);
