// Local stand-in for the upstream provider. It deliberately leaks identifying
// headers and error text so the gateway's sanitising can be checked.
import http from 'node:http';

const port = Number(process.argv[2] || 8788);
const LEAK = { 'x-upstream-request-id': 'leak-123', 'x-leaky-version': 'leaky-host.example', server: 'leaky-host.example' };

http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => (body += c));
  req.on('end', () => {
    if (req.headers.authorization !== 'Bearer up-secret') {
      res.writeHead(401, { 'content-type': 'application/json', ...LEAK });
      return res.end(JSON.stringify({ error: { message: 'bad key at leaky-host.example', type: 'leaky_api_error' } }));
    }
    const j = JSON.parse(body);
    if (j.model === 'missing') {
      res.writeHead(403, { 'content-type': 'application/json', ...LEAK });
      return res.end(JSON.stringify({ error: { message: `This token has no access to model missing (request id: 2026abc)`, type: 'leaky_api_error' } }));
    }
    if (j.model === 'boom') {
      res.writeHead(500, { 'content-type': 'application/json', ...LEAK });
      return res.end(JSON.stringify({ error: { message: 'panic in leaky-host.example', type: 'leaky_api_error' } }));
    }
    if (j.stream) {
      res.writeHead(200, { 'content-type': 'text/event-stream', ...LEAK });
      const parts = ['Hel', 'lo'];
      for (const p of parts) res.write(`data: ${JSON.stringify({ id: 'c1', object: 'chat.completion.chunk', choices: [{ index: 0, delta: { content: p } }] })}\n\n`);
      if (j.model === 'stream-error') res.write(`data: ${JSON.stringify({ error: { message: 'mid-stream fail at leaky-host.example (request id: x9)', type: 'leaky_api_error' } })}\n\n`);
      res.write('data: [DONE]\n\n');
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'application/json', ...LEAK });
    res.end(JSON.stringify({ id: 'c1', object: 'chat.completion', model: j.model, choices: [{ index: 0, message: { role: 'assistant', content: 'Hello' }, finish_reason: 'stop' }], usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 } }));
  });
}).listen(port, () => console.log('mock upstream on', port));
