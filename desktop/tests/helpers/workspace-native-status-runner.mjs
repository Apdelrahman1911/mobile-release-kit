// Build and execute this regression in a clean process: other frontend contract
// tests intentionally install window/document doubles in their own Node process.
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, writeFile, rm, realpath} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
async function run() {
  const {build} = await import('vite');
  const desktop = fileURLToPath(new URL('../../', import.meta.url));
  const helpers = fileURLToPath(new URL('./', import.meta.url));
  const temp = await realpath(await mkdtemp(join(tmpdir(), 'mrk-workspace-native-')));
  try {
    await writeFile(join(temp, 'index.html'), '<!doctype html><html><head><meta charset="utf-8"></head><body><div id="root"></div><script type="module" src="/entry.mjs"></script></body></html>');
    await writeFile(join(temp, 'entry.mjs'), `import ${JSON.stringify(join(helpers, 'workspace-native-status-entry.mjs'))};`);
    await build({root: temp, configFile: false, logLevel: 'silent', esbuild: {jsx: 'automatic'}, resolve: {alias: {
      '@tauri-apps/api/core': join(helpers, 'workspace-native-core.mjs'),
      '@tauri-apps/api/event': join(helpers, 'workspace-native-event.mjs'),
      react: join(desktop, 'node_modules/react'), 'react-dom': join(desktop, 'node_modules/react-dom'),
    }}, build: {outDir: join(temp, 'output'), target: 'es2022', minify: false, chunkSizeWarningLimit: 10_000}});
    const probe = join(temp, 'workspace-native-probe');
    const cache = join(temp, 'swift-module-cache');
    await mkdir(cache);
    const compiled = spawnSync('xcrun', ['swiftc', '-module-cache-path', cache, '-o', probe, join(helpers, 'WorkspaceNativeProbe.swift')], {encoding: 'utf8', timeout: 60_000, maxBuffer: 1024 * 1024});
    assert.equal(compiled.error, undefined);
    assert.equal(compiled.status, 0, compiled.stderr);
    const result = spawnSync(probe, [join(temp, 'output')], {encoding: 'utf8', timeout: 25_000, maxBuffer: 1024 * 1024});
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const report = JSON.parse(result.stdout.trim());
    return report;
  } finally {
    // Only this test's freshly created private directory is removed.
    await rm(temp, {recursive: true, force: true});
  }
}
console.log(JSON.stringify(await run()));
