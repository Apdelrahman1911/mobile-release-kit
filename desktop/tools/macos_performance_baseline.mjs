// Credential-free source fixture. No app, browser, native port or project IO.
// Run: node --expose-gc desktop/tools/macos_performance_baseline.mjs
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const started = performance.now();
const { gitSamePaths, parseGitObservation } = await import('../src/gitRepositoryProtocol.ts');
const { GitRepositoryController } = await import('../src/gitRepositoryController.ts');
const importMs = performance.now() - started;
if (!global.gc) throw Error('Run this test fixture with --expose-gc');
const paths = Array.from({ length: 512 }, (_, i) => `source/module-${String(i).padStart(4, '0')}/file-${i}.kt`);
const reversed = [...paths].reverse();
let completed = 0;
function measure(work, count = 100) {
  for (let i = 0; i < 100; i++) completed += !!work();
  const samples = [];
  for (let sample = 0; sample < 25; sample++) {
    const start = performance.now();
    for (let i = 0; i < count; i++) completed += !!work();
    samples.push((performance.now() - start) / count);
  }
  samples.sort((a, b) => a - b);
  return { medianMs: samples[12], p95Ms: samples[23] };
}
const legacy = measure(() => paths.length === reversed.length && paths.every((p) => reversed.includes(p)));
const current = measure(() => gitSamePaths(paths, reversed));
const observation = { revision: 'a'.repeat(64), head: 'b'.repeat(40), branch: 'refs/heads/fixture',
  unborn: false, detached: false, remotes: ['origin'], restrictions: [],
  changes: paths.map((path) => ({ path, index: 'M', worktree: ' ', kind: 'file', conflict: false })) };
if (!parseGitObservation(observation)) throw Error('Synthetic project does not satisfy the real bound');
const largeProjectParse = measure(() => parseGitObservation(observation), 10);
const churn = [];
for (let batch = 0; batch < 10; batch++) {
  for (let i = 0; i < 1000; i++) {
    const controller = new GitRepositoryController('fixture-project', null);
    const unsubscribe = controller.subscribe(() => { completed++; });
    controller.editDraft('message', 'Synthetic fixture ' + i);
    controller.setActive(false);
    unsubscribe();
  }
  global.gc();
  churn.push(process.memoryUsage());
}
const source = spawnSync(process.execPath, ['--expose-gc', '--import',
  fileURLToPath(new URL('../tests/helpers/workspace-jsx-loader.mjs', import.meta.url)),
  fileURLToPath(new URL('../tests/helpers/workspace-performance-fixture.mjs', import.meta.url))],
  { encoding: 'utf8', timeout: 30000, maxBuffer: 128 * 1024 });
if (source.status !== 0 || source.stderr) throw Error('Isolated source renderer did not complete cleanly');
const workspace = JSON.parse(source.stdout);
process.stdout.write(JSON.stringify({ schema: 1, scope: 'isolated-node-public-data-not-installed-app',
  node: process.versions.node, platform: process.platform, arch: process.arch, importMs,
  pathCount: paths.length, legacy, current, largeProjectParse, churnControllers: 10000,
  postGcMemory: churn, workspace, completed }, null, 2) + '\n');
