/**
 * Runs tests/run-tests.php inside a WASM PHP runtime when no local PHP binary
 * is available (e.g. this sandbox or a minimal CI image).
 *
 * Requires: npm install php-wasm  (dev-only; never shipped)
 * Usage:    node tests/tools/php-wasm-runner.mjs [--php=8.3] [--json=docs/evidence/phpunit-results.json]
 */
import { PhpNode } from 'php-wasm/PhpNode';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..', '..');
const args = process.argv.slice(2);
const phpVersion = (args.find((a) => a.startsWith('--php=')) || '--php=8.4').split('=')[1];
const jsonHostPath = path.resolve(
  root,
  (args.find((a) => a.startsWith('--json=')) || '--json=docs/evidence/phpunit-results.json').split('=')[1],
);

const SKIP_DIRS = new Set(['.git', 'node_modules', 'tests/.runtime', '.arena']);
const SKIP_EXT = new Set(['.png', '.jpg', '.jpeg', '.webp', '.gif', '.zip', '.svg', '.wasm', '.ico', '.ttf', '.woff', '.woff2']);

function collect(dir, list = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    const rel = path.relative(root, full).split(path.sep).join('/');
    if (entry.isDirectory()) {
      if (['assets/img', 'languages'].some((p) => rel === p || rel.startsWith(p + '/'))) continue;
      collect(full, list);
    } else if (!SKIP_EXT.has(path.extname(entry.name).toLowerCase())) {
      list.push([rel, full]);
    }
  }
  return list;
}

const php = new PhpNode({ version: phpVersion });
await php.refresh();

let output = '';
php.addEventListener('output', (e) => {
  output += e.detail.join('');
});

const files = collect(root).filter(([rel]) => rel.endsWith('.php') || rel.endsWith('.json'));
const ensured = new Set();
async function ensureDir(dir) {
  if (ensured.has(dir) || dir === '/repo') return;
  await ensureDir(path.posix.dirname(dir));
  ensured.add(dir);
  try {
    await php.mkdir(dir);
  } catch {
    /* already exists */
  }
}

try {
  await php.mkdir('/repo');
} catch {
  /* already exists */
}
await ensureDir('/repo/docs/evidence');
for (const [rel, full] of files) {
  const target = '/repo/' + rel;
  try {
    await ensureDir(path.posix.dirname(target));
    await php.writeFile(target, fs.readFileSync(full, 'utf8'));
  } catch (error) {
    process.stderr.write(`FAILED mirroring ${rel}: ${error.message}\n`);
    throw error;
  }
}

await php.writeFile(
  '/repo/run.php',
  `<?php chdir('/repo');
define('GW_LINT_EMBEDDED', true);
$argv = array('lint.php', '/repo'); $argc = 2; require '/repo/tests/lint.php';
$argv = array('run-tests.php', '--json=/repo/docs/evidence/phpunit-results.json'); $argc = 2; require '/repo/tests/run-tests.php';
`,
);

await php.run(`<?php require '/repo/run.php';`);
process.stdout.write(output);

for (const evidence of ['phpunit-results.json', 'lint.json']) {
  try {
    const rawEvidence = await php.readFile('/repo/docs/evidence/' + evidence);
    const text = typeof rawEvidence === 'string' ? rawEvidence : new TextDecoder().decode(rawEvidence);
    fs.mkdirSync(path.join(root, 'docs/evidence'), { recursive: true });
    fs.writeFileSync(path.join(root, 'docs/evidence', evidence), text);
  } catch (error) {
    process.stderr.write(`Could not copy ${evidence}: ${error.message}\n`);
    process.exitCode = 1;
  }
}
try {
  const raw = await php.readFile('/repo/docs/evidence/phpunit-results.json');
  const json = typeof raw === 'string' ? raw : new TextDecoder().decode(raw);
  fs.mkdirSync(path.dirname(jsonHostPath), { recursive: true });
  fs.writeFileSync(jsonHostPath, json);
  process.stdout.write(`\nCopied evidence to ${path.relative(root, jsonHostPath)}\n`);
} catch (error) {
  process.stderr.write(`\nCould not copy evidence JSON: ${error.message}\n`);
  process.exitCode = 1;
}
