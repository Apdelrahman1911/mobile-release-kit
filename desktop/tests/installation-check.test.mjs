// Inert UI protocol, routing and controlled-Promise contracts only. No native
// installation read, process, service, credential, project or Store is opened.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { InstallationCheckController } from '../src/installationController.ts';
import { installationCheckActive, installationCheckError, installationCheckHelp, INSTALLATION_CHECK_GUIDANCE,
  parseInstallationCancel, parseInstallationStatus } from '../src/installation.ts';

const initial = (revision = 1, patch = {}) => ({ schemaVersion: 1, statusRevision: revision,
  available: true, canStart: true, operationId: null, phase: 'not-checked', reason: 'none', settlement: 'not-started', assessment: null, ...patch });
const checking = (revision = 2, id = 1) => initial(revision, { canStart: false, operationId: id, phase: 'checking', settlement: 'pending' });
const observed = (revision = 4, id = 1) => initial(revision, { operationId: id, phase: 'observed', settlement: 'known',
  assessment: { files: 5, bytes: 100, assurance: 'read-only-correspondence', maintenance: 'unavailable' } });
const stopped = (revision = 3, id = 1) => ({ ...checking(revision, id), phase: 'stopping', reason: 'cancelled' });
const refused = (revision = 4, id = 1) => ({ ...stopped(revision, id), canStart: true, phase: 'refused', settlement: 'known' });
const unknown = (revision = 4, id = 1) => ({ ...stopped(revision, id), phase: 'unknown', reason: 'cleanup-unknown', settlement: 'unknown' });
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const flush = async () => { for (let n = 0; n < 24; n += 1) await Promise.resolve(); };
function harness(enabled = true) {
  const calls = [];
  const call = (kind, input) => { const task = deferred(); calls.push({ kind, input, ...task }); return task.promise; };
  const api = { installationStatus: () => call('status'), inspectInstallation: () => call('start'),
    cancelInstallation: (input) => call('cancel', input) };
  const controller = new InstallationCheckController(api, enabled);
  const frames = [];
  controller.attach((view) => frames.push(view));
  return { controller, calls, frames, by: (kind) => calls.filter((item) => item.kind === kind),
    last: (kind) => calls.filter((item) => item.kind === kind).at(-1) };
}

test('installation DTOs are closed, bounded and cannot claim maintenance or successful unknown cleanup', () => {
  for (const value of [initial(), checking(), stopped(), observed(), refused(), unknown(),
    { ...unknown(5), settlement: 'late-known' }, initial(1, { available: false, canStart: false, reason: 'unavailable-profile' })]) {
    assert.deepEqual(parseInstallationStatus(value), value);
    assert.notEqual(parseInstallationStatus(value), value);
  }
  const invalid = [
    { ...initial(), path: '/inert-no-read' }, { ...initial(), statusRevision: 2 ** 32 },
    { ...initial(), statusRevision: NaN }, { ...initial(), available: false },
    { ...checking(), canStart: true }, { ...checking(), operationId: 0 },
    { ...checking(), settlement: 'known' }, { ...stopped(), reason: 'none' },
    { ...unknown(), canStart: true }, { ...unknown(), reason: 'none' },
    { ...refused(), reason: 'none' }, { ...refused(), settlement: 'pending' },
    { ...observed(), reason: 'cancelled' }, { ...observed(), settlement: 'late-known' },
    { ...observed(), assessment: null }, { ...initial(), assessment: observed().assessment },
    { ...initial(), operationId: 1 }, { ...observed(), operationId: null },
    ...[0, 2049, 1.5, Infinity].map((files) => ({ ...observed(), assessment: { ...observed().assessment, files } })),
    ...[-1, 512 * 1024 * 1024 + 1, NaN].map((bytes) => ({ ...observed(), assessment: { ...observed().assessment, bytes } })),
    { ...observed(), assessment: { ...observed().assessment, assurance: 'signature-verified' } },
    { ...observed(), assessment: { ...observed().assessment, maintenance: 'repair-authorized' } },
  ];
  let reads = 0;
  const getter = { ...observed(), get assessment() { reads += 1; return observed().assessment; } };
  for (const value of [null, [], new Date(), getter, ...invalid]) assert.equal(parseInstallationStatus(value), null);
  assert.equal(reads, 0);
  const parsed = parseInstallationStatus(observed());
  const source = observed(); const copied = parseInstallationStatus(source);
  source.assessment.files = 9;
  assert.equal(copied.assessment.files, parsed.assessment.files);
  for (const value of [null, {}, { operationId: 0 }, { operationId: -1 }, { operationId: 1.5 },
    { operationId: 2 ** 32 }, { operationId: '1' }, { operationId: 1, path: 'elsewhere' }]) assert.equal(parseInstallationCancel(value), null);
  assert.deepEqual(parseInstallationCancel({ operationId: 0xffffffff }), { operationId: 0xffffffff });
});

test('native commands are fixed and preview/unavailable cannot invoke installation reads or cancellation', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, input) => { calls.push({ command, input }); return checking(); });
  await api.installationStatus(); await api.inspectInstallation(); await api.cancelInstallation({ operationId: 1 });
  assert.deepEqual(calls, [
    { command: 'installation_status', input: {} }, { command: 'inspect_installation', input: {} },
    { command: 'cancel_installation', input: { operationId: 1 } },
  ]);
  await assert.rejects(api.cancelInstallation({ operationId: 1, file: 'no' }));
  assert.equal(calls.length, 3);
  const unavailable = createNativeApi('unavailable', async () => assert.fail('no fallback invocation'));
  for (const client of [previewApi, unavailable]) {
    await assert.rejects(client.installationStatus(), (error) => error.code === 'installation_check_unavailable');
    await assert.rejects(client.inspectInstallation(), (error) => error.code === 'installation_check_unavailable');
    await assert.rejects(client.cancelInstallation({ operationId: 1 }), (error) => error.code === 'installation_check_unavailable');
  }
  const bad = createNativeApi('native', async () => ({ ...observed(), sourcePath: 'INERT_PRIVATE_CANARY' }));
  await assert.rejects(bad.installationStatus(), (error) => error.code === 'installation_check_unconfirmed'
    && !JSON.stringify(error).includes('INERT_PRIVATE_CANARY'));
  assert(!JSON.stringify(installationCheckError({ code: 'unrecognized', message: 'INERT_PRIVATE_CANARY' })).includes('INERT_PRIVATE_CANARY'));
});

test('mount makes one status request; coalesced refreshes never overlap or implicitly start', async () => {
  const h = harness(), disabled = harness(false);
  try {
    assert.equal(h.calls.length, 1); assert.equal(disabled.calls.length, 0);
    assert.equal(h.controller.start(), false); assert.equal(h.controller.cancel(), false);
    void h.controller.refresh(); void h.controller.refresh();
    assert.equal(h.calls.length, 1);
    h.last('status').resolve(initial()); await flush();
    assert.equal(h.calls.length, 2);
    h.last('status').resolve(initial()); await flush();
    assert.equal(h.calls.length, 2);
    assert.equal(h.controller.snapshot().refreshing, false);
    assert.equal(h.by('start').length, 0);
  } finally { h.controller.dispose(); disabled.controller.dispose(); }
});

test('status may overtake Start; stale acknowledgements cannot replace the current exact-id Cancel', async () => {
  const h = harness();
  try {
    h.last('status').resolve(initial()); await flush();
    assert.equal(h.controller.start(), true); assert.equal(h.controller.start(), false); await flush();
    void h.controller.refresh();
    h.last('status').resolve(checking(3)); await flush();
    h.last('start').resolve(checking(2)); await flush();
    assert.equal(h.controller.snapshot().status.statusRevision, 3);
    h.last('status').resolve(checking(3)); await flush();
    assert.equal(h.controller.cancel(), true); assert.equal(h.controller.cancel(), false); await flush();
    assert.deepEqual(h.last('cancel').input, { operationId: 1 });
    h.last('cancel').resolve(stopped(4)); await flush();
    h.last('status').resolve(refused(5)); await flush();
    assert.equal(h.controller.snapshot().status.phase, 'refused');
    assert.equal(h.controller.cancel(), false);
    assert.equal(h.by('start').length, 1); assert.equal(h.by('cancel').length, 1);
  } finally { h.controller.dispose(); }
});

test('lost Start acknowledgement reconciles DATA once, never retries Start and never uses raw rejection details', async () => {
  const h = harness();
  try {
    h.last('status').resolve(initial()); await flush();
    assert.equal(h.controller.start(), true); await flush();
    h.last('start').reject({ code: 'unknown', message: 'INERT_PRIVATE_CANARY' }); await flush();
    assert.equal(h.by('start').length, 1);
    assert.equal(h.by('status').length, 2);
    assert.equal(h.controller.start(), false);
    assert(!JSON.stringify(h.controller.snapshot()).includes('INERT_PRIVATE_CANARY'));
    h.last('status').resolve(checking()); await flush();
    assert.equal(h.controller.snapshot().error, null);
    assert.equal(h.controller.snapshot().status.operationId, 1);
    assert.equal(h.by('start').length, 1);
  } finally { h.controller.dispose(); }
});

test('same-revision contradictions, older operation ids and success after STOP/Unknown are refused', async () => {
  for (const [before, after] of [
    [initial(), initial(1, { canStart: false })],
    [observed(4, 2), checking(5, 1)],
    [stopped(4), observed(5)],
    [refused(4), checking(5)],
    [unknown(4), observed(5)],
    [{ ...unknown(4), settlement: 'late-known' }, checking(5, 2)],
  ]) {
    const h = harness();
    try {
      h.last('status').resolve(before); await flush();
      void h.controller.refresh(); h.last('status').resolve(after); await flush();
      assert.deepEqual(h.controller.snapshot().status, before);
      assert.equal(h.controller.snapshot().error.code, 'installation_check_unconfirmed');
      assert.equal(h.controller.start(), false);
    } finally { h.controller.dispose(); }
  }
});

test('active-only timer, one outstanding status request and disposal do not become native cancellation', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const h = harness();
  try {
    h.last('status').resolve(checking()); await flush();
    t.mock.timers.tick(499); assert.equal(h.by('status').length, 1);
    t.mock.timers.tick(1); assert.equal(h.by('status').length, 2);
    t.mock.timers.tick(5000); assert.equal(h.by('status').length, 2);
    h.last('status').resolve(observed(3)); await flush();
    assert.equal(installationCheckActive(h.controller.snapshot().status), false);
    t.mock.timers.tick(5000); assert.equal(h.by('status').length, 2);
    void h.controller.refresh();
    const frames = h.frames.length, retained = h.controller.snapshot();
    h.controller.dispose(); h.last('status').resolve(checking(4, 2)); await flush(); t.mock.timers.tick(5000);
    assert.equal(h.frames.length, frames); assert.equal(h.controller.snapshot(), retained);
    assert.equal(h.by('cancel').length, 0);
  } finally { h.controller.dispose(); t.mock.timers.reset(); }
});

test('dispose during UI publication prevents a not-yet-issued Start; synchronous API errors are sanitized', async () => {
  const h = harness();
  h.last('status').resolve(initial()); await flush();
  assert.equal(h.controller.start(), true); h.controller.dispose(); await flush();
  assert.equal(h.by('start').length, 0);
  assert.equal(h.by('cancel').length, 0);
  let calls = 0;
  const controller = new InstallationCheckController({
    installationStatus: async () => initial(),
    inspectInstallation: () => { calls += 1; throw { code: 'busy', message: 'INERT_PRIVATE_CANARY' }; },
    cancelInstallation: async () => assert.fail('no automatic cancellation'),
  }, true);
  try {
    controller.attach(() => {}); await flush();
    assert.equal(controller.start(), true); await flush();
    assert.equal(calls, 1); assert.equal(controller.snapshot().action, null);
    assert(!JSON.stringify(controller.snapshot()).includes('INERT_PRIVATE_CANARY'));
  } finally { controller.dispose(); }
});

test('contextual help explains where, limits, and non-maintenance recovery without claiming release readiness', () => {
  for (const key of ['what', 'why', 'where', 'format', 'failure', 'requiredWhen']) {
    assert.equal(typeof installationCheckHelp[key], 'string'); assert(installationCheckHelp[key].length > 20);
  }
  assert.match(installationCheckHelp.format, /30-second/);
  assert.match(installationCheckHelp.failure, /not signing\/notarization verification or release readiness/);
  assert.match(INSTALLATION_CHECK_GUIDANCE.incomplete, /Keep the partial installation intact/);
  assert.match(INSTALLATION_CHECK_GUIDANCE.protection, /Do not change permissions/);
  assert.match(INSTALLATION_CHECK_GUIDANCE['cleanup-unknown'], /original owner/);
});
