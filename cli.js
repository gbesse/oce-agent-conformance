#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { runConformance } from './conformance.js';

if (process.argv.includes('--help')) {
  process.stdout.write('Utilisation / Usage / Uso: node cli.js config.json [report.json]\n');
  process.exit(0);
}
try {
  const config = JSON.parse(await readFile(process.argv[2], 'utf8'));
  const report = await runConformance(config);
  const serialized = `${JSON.stringify(report, null, 2)}\n`;
  if (process.argv[3]) await writeFile(process.argv[3], serialized, { mode: 0o600 });
  process.stdout.write(serialized);
  process.exitCode = report.status === 'pass' ? 0 : report.status === 'incomplete' ? 2 : 1;
} catch (error) {
  process.stderr.write(`oce-conformance:${error.message?.startsWith('E_') ? error.message : 'E_RUN_FAILED'}\n`);
  process.exitCode = 1;
}
