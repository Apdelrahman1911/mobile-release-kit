import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';

test('workspace survives native status backlogs, helper approval return and project ABA without losing Git drafts', {skip: process.platform !== 'darwin', timeout: 120_000}, () => {
  const result = spawnSync(process.execPath, ['--experimental-strip-types',
    fileURLToPath(new URL('./helpers/workspace-native-status-runner.mjs', import.meta.url))], {
    encoding: 'utf8', timeout: 115_000, maxBuffer: 1024 * 1024,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const report = JSON.parse(result.stdout.trim());
  assert.equal(report.ok, true);
  assert.equal(report.fatal, false);
  assert.equal(report.failure, null);
  assert.equal(report.bootstraps, 1, 'A status notification must not reconnect the app');
  assert.equal(report.ticks, 900);
  assert.equal(report.deliveries, 3_600);
  assert.equal(report.preservedProjectDrafts, true);
  assert.deepEqual(report.transitions, ['no-project-status-backlog', 'selected-project-status-backlog', 'two-project-drafts-and-rapid-ABA', 'helper-approval-focus-return-backlog']);
  assert.deepEqual(report.helperCalls, ['check_android_tool_service', 'request_android_tool_service_registration', 'open_android_tool_service_approval_settings', 'check_android_tool_service']);
});
