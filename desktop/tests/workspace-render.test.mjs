import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

test('actual helper views render approval transitions and the boundary survives secondary error accessors', () => {
  // A separate process keeps JSX hooks and renderer globals out of the existing
  // shared Node contract-test process. This is synthetic rendering, not native
  // registration, an OS prompt, or an installed-app acceptance claim.
  const result = spawnSync(process.execPath, ['--experimental-strip-types', '--import',
    fileURLToPath(new URL('./helpers/workspace-jsx-loader.mjs', import.meta.url)),
    fileURLToPath(new URL('./helpers/workspace-render-fixture.mjs', import.meta.url))], { encoding: 'utf8', timeout: 20_000, maxBuffer: 1024 * 1024 });
  assert.equal(result.error, undefined); assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout.trim());
  assert.deepEqual(report.helperStatesRendered, ['requires-approval', 'enabled', 'not-registered', 'unavailable']);
  assert.equal(report.nativeCalls, 0); assert.equal(report.persistentBoundaryFallback, 'PASS');
});
