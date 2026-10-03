import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runConformance, validateConfig } from '../conformance.js';

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 'oce-conformance-'));
  const adminKeyFile = join(directory, 'admin.key');
  const restrictedKeyFile = join(directory, 'restricted.key');
  await writeFile(adminKeyFile, 'admin-key-1234567890', { mode: 0o600 });
  await writeFile(restrictedKeyFile, 'restricted-key-1234567890', { mode: 0o600 });
  return { baseUrl: 'https://occ.example.com', adminKeyFile, restrictedKeyFile,
    allowedNamespace: 'ns_allowed', allowedAgent: 'agt_allowed',
    foreignNamespace: 'ns_foreign', foreignAgent: 'agt_foreign', deploymentId: 'dep_active' };
}

const now = Date.parse('2026-10-03T12:00:00.000Z');
function fakeFetch({ foreignStatus = 403, ready = true, warnings = [] } = {}) {
  return async (url, options) => {
    assert.equal(options.method, undefined);
    const path = new URL(url).pathname;
    const restricted = options.headers['x-api-key'].startsWith('restricted');
    let status = 200;
    let data;
    if (path === '/installation') data = { id: 'ins_installation' };
    else if (path === '/namespaces/ns_allowed') data = { id: 'ns_allowed', status: 'ready' };
    else if (path === '/namespaces/ns_foreign') {
      if (restricted) status = foreignStatus;
      else data = { id: 'ns_foreign' };
    } else if (path === '/namespaces/ns_allowed/agents/agt_allowed') data = { id: 'agt_allowed', activeRevisionId: 'rev_live' };
    else if (path === '/namespaces/ns_foreign/agents/agt_foreign') {
      if (restricted) status = foreignStatus;
      else data = { id: 'agt_foreign' };
    } else if (path.endsWith('/runtime')) data = { revisionId: 'rev_live', observedAt: '2026-10-03T11:59:30.000Z', pods: [{ ready }] };
    else if (path.endsWith('/dep_active')) data = { deploymentId: 'dep_active', namespaceId: 'ns_allowed', agentId: 'agt_allowed', status: 'succeeded', warnings };
    else throw new Error(`unexpected route: ${path}`);
    return { ok: status === 200, status, async json() { return { data, meta: { requestId: 'req_test' } }; } };
  };
}

test('passes only with isolated tenant, durable deployment, ready runtime, and nonce model reply', async () => {
  const config = { ...(await fixture()), probeCommand: ['probe', '{nonce}'] };
  const report = await runConformance(config, {
    fetchImpl: fakeFetch(), now: () => now,
    probe: async (_command, nonce) => ({ nonce, reply: `Model answer: ${nonce}` }),
  });
  assert.equal(report.status, 'pass');
  assert.equal(report.checks.length, 10);
  assert.equal(JSON.stringify(report).includes('restricted-key'), false);
});

test('missing model probe is incomplete, while tenant leakage and unready pods fail', async () => {
  const config = await fixture();
  const incomplete = await runConformance(config, { fetchImpl: fakeFetch(), now: () => now });
  assert.equal(incomplete.status, 'incomplete');
  const failed = await runConformance(config, { fetchImpl: fakeFetch({ foreignStatus: 200, ready: false }), now: () => now });
  assert.equal(failed.status, 'fail');
  assert.equal(failed.checks.find((item) => item.name === 'restricted_foreign_agent_denied').status, 'fail');
  assert.equal(failed.checks.find((item) => item.name === 'runtime_observed_ready').status, 'fail');
});

test('rejects credentials in URL and permissive key files', async () => {
  const config = await fixture();
  assert.throws(() => validateConfig({ ...config, baseUrl: 'http://remote.example' }), /E_HTTPS_REQUIRED/);
  await chmod(config.adminKeyFile, 0o644);
  await assert.rejects(runConformance(config, { fetchImpl: fakeFetch() }), /E_KEY_PERMISSIONS/);
});

test('gateway probe rejects unauthenticated access before checking the model nonce', async () => {
  const { probeGateway } = await import('../gateway-probe.js');
  const directory = await mkdtemp(join(tmpdir(), 'oce-gateway-probe-'));
  const passwordFile = join(directory, 'gateway.key');
  await writeFile(passwordFile, 'gateway-password', { mode: 0o600 });
  const nonce = 'a'.repeat(32);
  const calls = [];
  const reply = await probeGateway({ passwordFile, nonce, fetchImpl: async (_url, options) => {
    calls.push(options);
    if (calls.length === 1) return { status: 401 };
    return { ok: true, async json() { return { choices: [{ message: { content: `Verified ${nonce}` } }] }; } };
  } });
  assert.equal(reply.nonce, nonce);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].headers.authorization, undefined);
  assert.equal(calls[1].headers.authorization, 'Bearer gateway-password');
  await assert.rejects(probeGateway({ passwordFile, nonce, fetchImpl: async () => ({ status: 200 }) }), /E_UNAUTHENTICATED_ACCESS/);
});
