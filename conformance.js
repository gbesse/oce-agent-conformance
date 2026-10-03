import { randomBytes } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { spawn } from 'node:child_process';

const required = ['baseUrl', 'adminKeyFile', 'restrictedKeyFile', 'allowedNamespace', 'allowedAgent', 'foreignNamespace', 'foreignAgent', 'deploymentId'];
const segment = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);
const endpoint = (namespace, agent) => `/namespaces/${namespace}/agents/${agent}`;

export function validateConfig(config) {
  if (!config || typeof config !== 'object' || required.some((key) => !config[key])) throw new Error('E_CONFIG_REQUIRED');
  const base = new URL(config.baseUrl);
  if (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(base.hostname))) throw new Error('E_HTTPS_REQUIRED');
  if (base.username || base.password || base.search || base.hash) throw new Error('E_URL_CREDENTIALS');
  for (const key of ['allowedNamespace', 'allowedAgent', 'foreignNamespace', 'foreignAgent', 'deploymentId']) {
    if (!segment(config[key])) throw new Error('E_CONFIG_ID');
  }
  if (config.allowedNamespace === config.foreignNamespace) throw new Error('E_DISTINCT_NAMESPACE');
  if (config.probeCommand !== undefined && (!Array.isArray(config.probeCommand) || !config.probeCommand.length || config.probeCommand.some((item) => typeof item !== 'string' || !item))) throw new Error('E_PROBE_COMMAND');
  const maxAgeSeconds = config.maxObservationAgeSeconds ?? 300;
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 1 || maxAgeSeconds > 86400) throw new Error('E_AGE');
  return { ...config, baseUrl: base.toString().replace(/\/$/, ''), maxObservationAgeSeconds: maxAgeSeconds };
}

export async function readKey(path) {
  const info = await stat(path);
  if (!info.isFile() || (info.mode & 0o077) !== 0) throw new Error('E_KEY_PERMISSIONS');
  const raw = (await readFile(path, 'utf8')).trim();
  let key = raw;
  if (raw.startsWith('{')) {
    const parsed = JSON.parse(raw);
    key = parsed?.data?.key ?? parsed?.key;
  }
  if (typeof key !== 'string' || !/^[A-Za-z0-9._~+/-]{16,4096}$/.test(key)) throw new Error('E_KEY_FORMAT');
  return key;
}

async function get(baseUrl, key, path, fetchImpl) {
  const response = await fetchImpl(`${baseUrl}${path}`, { headers: { 'x-api-key': key, accept: 'application/json' }, signal: AbortSignal.timeout(15000) });
  if (!response.ok) return { status: response.status, data: null };
  const body = await response.json();
  if (!body || typeof body !== 'object' || !body.meta?.requestId || !('data' in body)) throw new Error('E_API_SHAPE');
  return { status: response.status, data: body.data };
}

function processProbe(command, nonce) {
  return new Promise((resolve, reject) => {
    const [file, ...args] = command.map((value) => value.replaceAll('{nonce}', nonce));
    const child = spawn(file, args, { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, OCE_PROBE_NONCE: nonce } });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; if (output.length > 65536) child.kill(); });
    child.stderr.on('data', () => {});
    child.on('error', reject);
    const timer = setTimeout(() => child.kill(), 200000);
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error('E_PROBE_PROCESS'));
      try { resolve(JSON.parse(output)); } catch { reject(new Error('E_PROBE_OUTPUT')); }
    });
  });
}

export async function runConformance(input, { fetchImpl = fetch, probe = processProbe, now = () => Date.now() } = {}) {
  const config = validateConfig(input);
  const [adminKey, restrictedKey] = await Promise.all([readKey(config.adminKeyFile), readKey(config.restrictedKeyFile)]);
  if (adminKey === restrictedKey) throw new Error('E_DISTINCT_KEYS');
  const checks = [];
  const add = (name, passed, evidence) => checks.push({ name, status: passed ? 'pass' : 'fail', evidence });
  const { baseUrl, allowedNamespace: ns, allowedAgent: agent, foreignNamespace: foreignNs, foreignAgent, deploymentId } = config;
  const allowed = endpoint(ns, agent);
  const foreign = endpoint(foreignNs, foreignAgent);
  const deploymentPath = `${allowed}/deployments/${deploymentId}`;
  const [installation, namespace, agentState, foreignState, deployment, runtime, restrictedAllowed, restrictedForeign, restrictedForeignNs] = await Promise.all([
    get(baseUrl, adminKey, '/installation', fetchImpl),
    get(baseUrl, adminKey, `/namespaces/${ns}`, fetchImpl),
    get(baseUrl, adminKey, allowed, fetchImpl),
    get(baseUrl, adminKey, foreign, fetchImpl),
    get(baseUrl, adminKey, deploymentPath, fetchImpl),
    get(baseUrl, adminKey, `${deploymentPath}/runtime`, fetchImpl),
    get(baseUrl, restrictedKey, allowed, fetchImpl),
    get(baseUrl, restrictedKey, foreign, fetchImpl),
    get(baseUrl, restrictedKey, `/namespaces/${foreignNs}`, fetchImpl),
  ]);
  add('installation', installation.status === 200 && typeof installation.data?.id === 'string', `HTTP ${installation.status}`);
  add('namespace', namespace.status === 200 && namespace.data?.id === ns && namespace.data?.status === 'ready', `HTTP ${namespace.status}`);
  add('agent', agentState.status === 200 && agentState.data?.id === agent && typeof agentState.data?.activeRevisionId === 'string', `HTTP ${agentState.status}`);
  add('foreign_exists_for_admin', foreignState.status === 200 && foreignState.data?.id === foreignAgent, `HTTP ${foreignState.status}`);
  add('restricted_allowed', restrictedAllowed.status === 200 && restrictedAllowed.data?.id === agent, `HTTP ${restrictedAllowed.status}`);
  add('restricted_foreign_agent_denied', [403, 404].includes(restrictedForeign.status), `HTTP ${restrictedForeign.status}`);
  add('restricted_foreign_namespace_denied', [403, 404].includes(restrictedForeignNs.status), `HTTP ${restrictedForeignNs.status}`);
  const deploymentOk = deployment.status === 200 && deployment.data?.status === 'succeeded' && deployment.data?.deploymentId === deploymentId && deployment.data?.namespaceId === ns && deployment.data?.agentId === agent && (!deployment.data?.warnings || deployment.data.warnings.length === 0);
  add('deployment_succeeded', deploymentOk, `HTTP ${deployment.status}; status ${deployment.data?.status ?? 'unknown'}; warnings ${deployment.data?.warnings?.length ?? 'unknown'}`);
  const observedAt = Date.parse(runtime.data?.observedAt);
  const age = (now() - observedAt) / 1000;
  const pods = runtime.data?.pods;
  const runtimeOk = runtime.status === 200 && runtime.data?.revisionId === agentState.data?.activeRevisionId && Number.isFinite(age) && age >= -30 && age <= config.maxObservationAgeSeconds && Array.isArray(pods) && pods.length > 0 && pods.every((pod) => pod.ready === true);
  add('runtime_observed_ready', runtimeOk, `HTTP ${runtime.status}; age ${Number.isFinite(age) ? Math.round(age) : 'unknown'}s; pods ${Array.isArray(pods) ? pods.length : 'unknown'}`);
  if (config.probeCommand) {
    const nonce = randomBytes(16).toString('hex');
    try {
      const answer = await probe(config.probeCommand, nonce);
      add('model_turn', answer?.nonce === nonce && typeof answer.reply === 'string' && answer.reply.includes(nonce) && answer.reply.length > nonce.length, 'nonce checked in a trusted model probe response');
    } catch (error) {
      add('model_turn', false, error.code ?? error.message ?? 'probe failed');
    }
  } else {
    checks.push({ name: 'model_turn', status: 'no_signal', evidence: 'probeCommand absent' });
  }
  return { schema: 'oce-conformance.v1', status: checks.every((item) => item.status === 'pass') ? 'pass' : checks.some((item) => item.status === 'fail') ? 'fail' : 'incomplete', checks };
}
