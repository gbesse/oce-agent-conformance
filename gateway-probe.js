#!/usr/bin/env node
import { readFile, stat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export async function probeGateway({ url = 'http://127.0.0.1:18789/v1/chat/completions', passwordFile, nonce, fetchImpl = fetch }) {
  const target = new URL(url);
  if (target.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(target.hostname) || target.username || target.password || target.search || target.hash || target.pathname !== '/v1/chat/completions') throw new Error('E_GATEWAY_URL');
  if (typeof nonce !== 'string' || !/^[a-f0-9]{32}$/.test(nonce)) throw new Error('E_NONCE');
  if (!passwordFile) throw new Error('E_PASSWORD_FILE');
  const info = await stat(passwordFile);
  if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error('E_PASSWORD_PERMISSIONS');
  const password = (await readFile(passwordFile, 'utf8')).trim();
  if (!password || password.length > 4096) throw new Error('E_PASSWORD_FORMAT');
  const unauthenticated = await fetchImpl(url, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'openclaw/default', messages: [] }),
    signal: AbortSignal.timeout(15000),
  });
  if (![401, 403].includes(unauthenticated.status)) throw new Error('E_UNAUTHENTICATED_ACCESS');
  const response = await fetchImpl(url, {
    method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${password}` },
    body: JSON.stringify({ model: 'openclaw/default', stream: false, messages: [
      { role: 'user', content: `Reply with exactly this nonce and no other text: ${nonce}` },
    ] }),
    signal: AbortSignal.timeout(180000),
  });
  if (!response.ok) throw new Error('E_MODEL_REQUEST');
  const body = await response.json();
  const reply = body?.choices?.[0]?.message?.content;
  if (typeof reply !== 'string' || !reply.includes(nonce)) throw new Error('E_NONCE_NOT_RETURNED');
  return { nonce, reply };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = await probeGateway({
      url: process.env.OCE_GATEWAY_URL,
      passwordFile: process.env.OCE_GATEWAY_PASSWORD_FILE,
      nonce: process.argv[2] ?? process.env.OCE_PROBE_NONCE,
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`oce-gateway-probe:${error.message?.startsWith('E_') ? error.message : 'E_PROBE_FAILED'}\n`);
    process.exitCode = 1;
  }
}
