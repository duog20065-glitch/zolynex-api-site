// Admin RPC entrypoint for HaruSelf (service binding, not reachable from the internet).
// HaruSelf has already verified the owner via Cloudflare Access before calling.
//   [[services]] binding = "HARU_API", service = "flashgate-gateway", entrypoint = "AdminRPC"
//   await env.HARU_API.run('listCustomers', {}, 'haruself')

import { WorkerEntrypoint } from 'cloudflare:workers';
import * as svc from './customers.js';
import * as clients from './clients.js';

const OPS = {
  health: (env) => svc.health(env),
  listCustomers: (env) => svc.listCustomers(env, { includeKeys: true }),
  createCustomer: (env, a, actor) => svc.createCustomer(env, a, actor),
  updateCustomer: (env, a, actor) => svc.updateCustomer(env, a.customer, a.patch || {}, actor),
  rotateKey: (env, a, actor) => svc.rotateKey(env, a.customer, actor),
  deleteCustomer: (env, a, actor) => svc.deleteCustomer(env, a.customer, actor),
  listAudit: (env, a) => svc.listAudit(env, a.limit),
  listMcpClients: (env) => clients.listClients(env),
  createMcpClient: (env, a, actor) => clients.createClient(env, a, actor),
  updateMcpClient: (env, a, actor) => clients.updateClient(env, a, actor),
  rotateMcpClient: (env, a, actor) => clients.rotateClient(env, a, actor),
  deleteMcpClient: (env, a, actor) => clients.deleteClient(env, a, actor),
};

export class AdminRPC extends WorkerEntrypoint {
  async run(op, args, actor) {
    const fn = OPS[op];
    if (!fn) throw new Error('unknown op: ' + op);
    return fn(this.env, args || {}, String(actor || 'haruself'));
  }
}
