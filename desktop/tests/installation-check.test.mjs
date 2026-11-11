// Inert UI protocol, routing and controlled-Promise contracts only. No native
// installation read, process, service, credential, project or Store is opened.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';
import { InstallationCheckController } from '../src/installationController.ts';
import { InstallationPreparationController, InstallationPreparationConnection } from '../src/installationController.ts';
import { installationCheckActive, installationCheckError, installationCheckHelp, INSTALLATION_CHECK_GUIDANCE,
  parseInstallationCancel, parseInstallationStatus } from '../src/installation.ts';
import { PREPARE_QUIT_CONFIRMATION, parseInstallationPreparationRequest, parseInstallationPreparationStatus,
  installationPreparationHelp, installationPreparationError, parsePreparationDiagnostic, installationPreparationDiagnosticLines } from '../src/installation.ts';

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
    ...[0, 16_385, 1.5, Infinity].map((files) => ({ ...observed(), assessment: { ...observed().assessment, files } })),
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

test('complete Mac runtime file counts survive native bridge and installation display without granting maintenance', async () => {
  // 8,622 is the native inventory regression's Store+Python-sized fixture;
  // 16,384 is macos_install_record::FILE_LIMIT, not a renderer roster allocation.
  for (const files of [8622, 16_384]) {
    const result = { ...observed(), assessment: { ...observed().assessment, files, bytes: 512 * 1024 * 1024 } };
    const calls = [];
    const api = createNativeApi('native', async (command, input) => {
      calls.push({ command, input });
      assert.equal(command, 'installation_status');
      return result;
    });
    const controller = new InstallationCheckController(api, true);
    try {
      // Refresh only: no implicit inspect, cancellation, repair or release.
      await controller.refresh();
      assert.equal(controller.snapshot().error, null);
      assert.deepEqual(controller.snapshot().status, result);
      assert.equal(controller.snapshot().status.assessment.maintenance, 'unavailable');
      assert.deepEqual(calls, [{ command: 'installation_status', input: {} }]);
    } finally { controller.dispose(); }
  }
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

const prepInitial = (patch = {}) => ({ schemaVersion: 1, available: true, canStart: true,
  operationId: null, generation: null, phase: 'not-started', reason: 'none', newWorkClosed: false,
  assurance: 'preparation-status-only', diagnostic: { first: null, cleanup: null }, ...patch });
const prepRunning = (generation = 1, patch = {}) => prepInitial({ canStart: false, operationId: '12'.repeat(16),
  generation, phase: 'preparing', newWorkClosed: true, ...patch });
const prepRefused = (generation = 1) => prepRunning(generation, { phase: 'refused', reason: 'native', newWorkClosed: false, canStart: true });
function prepHarness(enabled = true) {
  const calls = [], frames = [];
  const call = (kind, input) => { const task = deferred(); calls.push({ kind, input, ...task }); return task.promise; };
  const controller = new InstallationPreparationController({ installationPreparationStatus: () => call('status'),
    prepareInstallationQuit: (input) => call('start', input) }, enabled);
  controller.attach((view) => frames.push(view));
  return { controller, calls, frames, by: (kind) => calls.filter((item) => item.kind === kind),
    last: (kind) => calls.filter((item) => item.kind === kind).at(-1) };
}

test('maintenance preparation protocol requires exact consent and excludes invented authority or completion', () => {
  for (const value of [prepInitial(), prepInitial({ available: false, canStart: false, reason: 'unavailable-profile' }),
    prepRunning(), prepRunning(1, { phase: 'unregistering' }), prepRunning(1, { phase: 'settling', reason: 'cancelled' }),
    prepRunning(1, { phase: 'prepared' }), prepRefused(), prepRunning(1, { phase: 'refused', reason: 'native' }),
    prepRunning(1, { phase: 'unknown', reason: 'cleanup-unknown' })]) assert.deepEqual(parseInstallationPreparationStatus(value), value);
  let reads = 0;
  for (const value of [null, [], { ...prepInitial(), get reason() { reads += 1; return 'none'; } },
    { ...prepInitial(), path: '/inert' }, { ...prepInitial(), assurance: 'installer-authorized' },
    { ...prepInitial(), available: false }, { ...prepInitial(), reason: 'busy' }, { ...prepInitial(), newWorkClosed: true },
    { ...prepRunning(), operationId: '0'.repeat(32) }, { ...prepRunning(), operationId: 'A'.repeat(32) },
    { ...prepRunning(), operationId: null }, { ...prepRunning(), generation: null },
    ...[0, -1, 1.5, 0xffffffff, NaN, true].map((generation) => ({ ...prepRunning(), generation })),
    { ...prepRunning(), canStart: true }, { ...prepRunning(), newWorkClosed: false },
    { ...prepRunning(), phase: 'prepared', reason: 'deadline' },
    { ...prepRunning(), phase: 'unknown', reason: 'none' }, { ...prepRunning(), phase: 'refused', reason: 'none' }]) {
    assert.equal(parseInstallationPreparationStatus(value), null);
  }
  assert.equal(reads, 0);
  assert.deepEqual(parseInstallationPreparationRequest({ confirmation: PREPARE_QUIT_CONFIRMATION }), { confirmation: PREPARE_QUIT_CONFIRMATION });
  for (const value of [null, {}, { confirmation: true }, { confirmation: 'yes' }, { confirmation: PREPARE_QUIT_CONFIRMATION + ' ' },
    { confirmation: PREPARE_QUIT_CONFIRMATION, path: '/inert' }]) assert.equal(parseInstallationPreparationRequest(value), null);
  for (const key of ['what', 'why', 'where', 'format', 'failure', 'requiredWhen']) assert(installationPreparationHelp[key].length > 20);
  assert.match(installationPreparationHelp.failure, /does not install, repair, update or uninstall/);
});

test('maintenance preparation bridge fixes both commands and refuses preview or arbitrary fields without invoking', async () => {
  const calls = [];
  const api = createNativeApi('native', async (command, input) => { calls.push({ command, input }); return prepRunning(); });
  await api.installationPreparationStatus();
  await api.prepareInstallationQuit({ confirmation: PREPARE_QUIT_CONFIRMATION });
  assert.deepEqual(calls, [{ command: 'installation_preparation_status', input: {} },
    { command: 'prepare_installation_quit', input: { confirmation: PREPARE_QUIT_CONFIRMATION } }]);
  await assert.rejects(api.prepareInstallationQuit({ confirmation: PREPARE_QUIT_CONFIRMATION, verified: true }),
    (error) => error.code === 'installation_preparation_invalid');
  assert.equal(calls.length, 2);
  for (const client of [previewApi, createNativeApi('unavailable', async () => assert.fail('no fallback'))]) {
    await assert.rejects(client.installationPreparationStatus(), (error) => error.code === 'macos_maintenance_unavailable');
    await assert.rejects(client.prepareInstallationQuit({ confirmation: PREPARE_QUIT_CONFIRMATION }),
      (error) => error.code === 'macos_maintenance_unavailable');
  }
  const bad = createNativeApi('native', async () => ({ ...prepRunning(), privatePath: 'INERT_PRIVATE_CANARY' }));
  await assert.rejects(bad.installationPreparationStatus(), (error) => error.code === 'installation_preparation_unconfirmed'
    && !JSON.stringify(error).includes('INERT_PRIVATE_CANARY'));
  assert(!JSON.stringify(installationPreparationError({ message: 'INERT_PRIVATE_CANARY' })).includes('INERT_PRIVATE_CANARY'));
  assert.equal(installationPreparationError(installationPreparationError({ code: 'busy' })).code, 'macos_maintenance_busy');
});

test('maintenance preparation serializes refresh with one explicitly confirmed Start and no acknowledgement overtaking', async () => {
  const h = prepHarness(), disabled = prepHarness(false);
  try {
    assert.equal(disabled.calls.length, 0); assert.equal(h.controller.start(true), false);
    h.last('status').resolve(prepInitial()); await flush();
    assert.equal(h.controller.start(false), false);
    assert.equal(h.controller.start(true), true); assert.equal(h.controller.start(true), false); await flush();
    assert.deepEqual(h.last('start').input, { confirmation: PREPARE_QUIT_CONFIRMATION });
    void h.controller.refresh(); void h.controller.refresh();
    assert.equal(h.by('status').length, 1);
    h.last('start').resolve(prepRunning()); await flush();
    assert.equal(h.by('status').length, 2); assert.equal(h.by('start').length, 1);
    h.last('status').resolve(prepRunning(1, { phase: 'settling' })); await flush();
    assert.equal(h.controller.snapshot().status.phase, 'settling');
    assert.equal(h.controller.start(true), false);
  } finally { h.controller.dispose(); disabled.controller.dispose(); }
});

test('maintenance preparation lost or displaced Start reply only reconciles the original status and never retries', async () => {
  for (const reply of ['reject', prepInitial(), prepRefused(1)]) {
    const h = prepHarness();
    try {
      const baseline = reply === 'reject' ? prepInitial() : prepRefused(1);
      h.last('status').resolve(baseline); await flush();
      assert.equal(h.controller.start(true), true); await flush();
      if (reply === 'reject') h.last('start').reject({ message: 'INERT_PRIVATE_CANARY' });
      else h.last('start').resolve(reply);
      await flush();
      assert.equal(h.by('start').length, 1); assert.equal(h.by('status').length, 2);
      assert.equal(h.controller.start(true), false);
      assert(!JSON.stringify(h.controller.snapshot()).includes('INERT_PRIVATE_CANARY'));
      h.last('status').resolve(prepRunning(baseline.generation === null ? 1 : 2)); await flush();
      assert.equal(h.controller.snapshot().error, null);
      assert.equal(h.by('start').length, 1);
    } finally { h.controller.dispose(); }
  }
});

test('failed preparation keeps its error and replay veto when automatic or explicit status remains unchanged', async () => {
  for (const failure of [{ code: 'macos_maintenance_unavailable' }, { code: 'cleanup_unknown' }, 'malformed']) {
    const h = prepHarness();
    try {
      h.last('status').resolve(prepInitial()); await flush();
      assert.equal(h.controller.start(true), true); await flush();
      if (failure === 'malformed') h.last('start').resolve(prepInitial());
      else h.last('start').reject(failure);
      await flush();
      const originalError = h.controller.snapshot().error;
      assert(originalError);
      h.last('status').resolve(prepInitial()); await flush();
      assert.equal(h.controller.snapshot().status.phase, 'not-started');
      assert.deepEqual(h.controller.snapshot().error, originalError);
      assert.equal(h.controller.start(true), false);
      void h.controller.refresh(); h.last('status').resolve(prepInitial()); await flush();
      assert.deepEqual(h.controller.snapshot().error, originalError);
      assert.equal(h.controller.start(true), false);
      assert.equal(h.by('start').length, 1);
      void h.controller.refresh(); h.last('status').reject({ code: 'busy' }); await flush();
      assert.deepEqual(h.controller.snapshot().error, originalError);
    } finally { h.controller.dispose(); }
  }
});

test('failed preparation from a refused baseline clears only on a valid newer native original', async () => {
  const h = prepHarness();
  try {
    h.last('status').resolve(prepRefused(1)); await flush();
    assert.equal(h.controller.start(true), true); await flush();
    h.last('start').reject({ code: 'macos_maintenance_unavailable' }); await flush();
    const originalError = h.controller.snapshot().error;
    h.last('status').resolve(prepRefused(1)); await flush();
    assert.deepEqual(h.controller.snapshot().error, originalError);
    assert.equal(h.controller.start(true), false);
    void h.controller.refresh(); h.last('status').resolve(prepRunning(2)); await flush();
    assert.equal(h.controller.snapshot().error, null);
    assert.equal(h.controller.snapshot().status.generation, 2);
    assert.equal(h.controller.start(true), false);
    assert.equal(h.by('start').length, 1);
  } finally { h.controller.dispose(); }
});

test('maintenance preparation refuses foreign generations, regressing phases and success or reopening after failure', async () => {
  const failed = prepRunning(1, { reason: 'cancelled' });
  const unknown = prepRunning(1, { phase: 'unknown', reason: 'cleanup-unknown' });
  for (const [before, after] of [
    [prepRunning(), prepRunning(1, { operationId: '34'.repeat(16) })],
    [prepRunning(2), prepRunning(1)], [prepRunning(), prepRunning(2)],
    [prepRunning(1, { phase: 'settling' }), prepRunning()],
    [failed, prepRunning(1, { phase: 'prepared' })],
    [unknown, prepRunning(1, { phase: 'prepared' })], [unknown, prepRunning(2)],
    [prepRefused(), prepRunning()],
    [prepRunning(1, { phase: 'refused', reason: 'native' }), prepRefused()],
  ]) {
    const h = prepHarness();
    try {
      h.last('status').resolve(before); await flush();
      void h.controller.refresh(); h.last('status').resolve(after); await flush();
      assert.deepEqual(h.controller.snapshot().status, before);
      assert.equal(h.controller.snapshot().error.code, 'installation_preparation_unconfirmed');
      assert.equal(h.controller.start(true), false);
    } finally { h.controller.dispose(); }
  }
  const h = prepHarness();
  try {
    h.last('status').resolve(prepRefused()); await flush();
    assert.equal(h.controller.start(true), true); await flush();
    h.last('start').resolve(prepRunning(2)); await flush();
    h.last('status').resolve(prepRunning(2)); await flush();
    assert.equal(h.controller.snapshot().status.generation, 2); assert.equal(h.controller.snapshot().error, null);
  } finally { h.controller.dispose(); }
});

test('maintenance preparation connection disposal and status never become native Quit', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const h = prepHarness(), notIssued = prepHarness();
  try {
    notIssued.last('status').resolve(prepInitial()); await flush();
    assert.equal(notIssued.controller.start(true), true); notIssued.controller.dispose(); await flush();
    assert.equal(notIssued.by('start').length, 0);
    h.last('status').resolve(prepRunning()); await flush();
    t.mock.timers.tick(1000); assert.equal(h.by('status').length, 2);
    t.mock.timers.tick(5000); assert.equal(h.by('status').length, 2);
    h.last('status').resolve(prepRunning(1, { phase: 'prepared' })); await flush();
    t.mock.timers.tick(5000); assert.equal(h.by('status').length, 2);
    void h.controller.refresh(); const frames = h.frames.length, view = h.controller.snapshot();
    h.controller.dispose(); h.last('status').resolve(prepRunning(2)); await flush(); t.mock.timers.tick(5000);
    assert.equal(h.frames.length, frames); assert.equal(h.controller.snapshot(), view);
    assert.equal(h.by('start').length, 0); assert(h.calls.every((call) => call.kind === 'status'));
  } finally { h.controller.dispose(); notIssued.controller.dispose(); t.mock.timers.reset(); }
});


function prepConnectionHarness() {
  const connection = new InstallationPreparationConnection(), calls = [];
  const makeApi = (identity) => {
    const call = (kind, input) => { const task = deferred(); calls.push({ identity, kind, input, ...task }); return task.promise; };
    return { installationPreparationStatus: () => call('status'), prepareInstallationQuit: (input) => call('start', input) };
  };
  const api = makeApi('original');
  assert.equal(connection.connect(api, true), true);
  const controller = connection.current(api);
  const mount = (owner = controller) => {
    const frames = [], detach = owner.attach((view) => frames.push(view));
    return { frames, detach };
  };
  return { connection, api, controller, makeApi, mount, calls,
    by: (kind) => calls.filter((row) => row.kind === kind),
    last: (kind) => calls.filter((row) => row.kind === kind).at(-1),
  };
}

test('app connection retains one pending preparation across panel detach/remount and stops hidden polling', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const h = prepConnectionHarness();
  try {
    const first = h.mount(); h.last('status').resolve(prepInitial()); await flush();
    assert.equal(h.controller.start(true), true); await flush();
    const original = h.last('start'); first.detach();
    const frameCount = first.frames.length, second = h.mount();
    assert.equal(second.frames[0].starting, true);
    assert.equal(h.controller.start(true), false);
    assert.equal(h.by('start').length, 1); assert.equal(h.by('status').length, 1);
    original.resolve(prepRunning()); await flush();
    assert.equal(first.frames.length, frameCount);
    assert.equal(h.by('status').length, 2);
    h.last('status').resolve(prepRunning(1, { phase: 'settling' })); await flush();
    second.detach(); t.mock.timers.tick(5000); await flush();
    assert.equal(h.by('status').length, 2);
    const third = h.mount();
    assert.equal(third.frames[0].status.phase, 'settling');
    assert.equal(h.by('status').length, 3);
    h.last('status').resolve(prepRunning(1, { phase: 'prepared' })); await flush();
    t.mock.timers.tick(5000); await flush();
    assert.equal(h.controller.start(true), false); assert.equal(h.by('start').length, 1);
    assert.equal(h.by('status').length, 3);
  } finally { h.connection.dispose(); t.mock.timers.reset(); }
});

test('failed preparation stays visible across remount, unchanged automatic/manual status and read errors', async () => {
  for (const failure of [{ code: 'macos_maintenance_unavailable' }, { code: 'cleanup_unknown' }, 'malformed']) {
    const h = prepConnectionHarness();
    try {
      const first = h.mount(); h.last('status').resolve(prepInitial()); await flush();
      h.controller.start(true); await flush();
      if (failure === 'malformed') h.last('start').resolve(prepInitial()); else h.last('start').reject(failure);
      await flush(); const error = h.controller.snapshot().error; assert(error);
      first.detach(); h.last('status').resolve(prepInitial()); await flush();
      const second = h.mount(); assert.deepEqual(second.frames[0].error, error);
      h.last('status').resolve(prepInitial()); await flush();
      assert.equal(h.controller.start(true), false);
      void h.controller.refresh(); h.last('status').reject({ code: 'busy', message: 'INERT_PRIVATE_CANARY' }); await flush();
      assert.deepEqual(h.controller.snapshot().error, error);
      void h.controller.refresh(); h.last('status').resolve(prepInitial()); await flush();
      assert.deepEqual(h.controller.snapshot().error, error);
      assert.equal(h.controller.start(true), false); assert.equal(h.by('start').length, 1);
      assert(!JSON.stringify(h.controller.snapshot()).includes('INERT_PRIVATE_CANARY'));
      assert(h.connection.reconnectionError());
    } finally { h.connection.dispose(); }
  }
});

test('an original preparation rejection while hidden is retained and reconciled once without publishing to the old panel', async () => {
  const h = prepConnectionHarness();
  try {
    const first = h.mount(); h.last('status').resolve(prepInitial()); await flush(); h.controller.start(true); await flush();
    first.detach(); const frameCount = first.frames.length;
    h.last('start').reject({ code: 'macos_maintenance_unavailable' }); await flush();
    assert.equal(first.frames.length, frameCount); assert.equal(h.by('status').length, 2);
    h.last('status').resolve(prepInitial()); await flush();
    const second = h.mount();
    assert.equal(second.frames[0].error.code, 'macos_maintenance_unavailable');
    h.last('status').resolve(prepInitial()); await flush();
    assert.equal(h.controller.start(true), false); assert.equal(h.by('start').length, 1);
  } finally { h.connection.dispose(); }
});

test('reattached failed preparation clears only for valid newer native generation and needs new explicit consent', async () => {
  const h = prepConnectionHarness();
  try {
    const first = h.mount(); h.last('status').resolve(prepRefused(1)); await flush(); h.controller.start(true); await flush();
    h.last('start').reject({ code: 'macos_maintenance_unavailable' }); await flush();
    h.last('status').resolve(prepRefused(1)); await flush(); const error = h.controller.snapshot().error;
    first.detach(); h.mount(); h.last('status').resolve(prepRunning(2, { extra: true })); await flush();
    assert.deepEqual(h.controller.snapshot().error, error); assert.equal(h.controller.start(true), false);
    void h.controller.refresh(); h.last('status').resolve(prepRefused(1)); await flush();
    assert.deepEqual(h.controller.snapshot().error, error);
    void h.controller.refresh(); h.last('status').resolve(prepRefused(2)); await flush();
    assert.equal(h.controller.snapshot().error, null); assert.equal(h.connection.reconnectionError(), null);
    assert.equal(h.by('start').length, 1); assert.equal(h.controller.start(false), false);
    assert.equal(h.controller.start(true), true); assert.equal(h.controller.start(true), false); await flush();
    assert.equal(h.by('start').length, 2);
    h.last('start').resolve(prepRunning(3)); await flush(); h.last('status').resolve(prepRunning(3)); await flush();
    assert.equal(h.controller.snapshot().status.generation, 3); assert.equal(h.controller.start(true), false);
  } finally { h.connection.dispose(); }
});

test('connection replacement cannot erase a pending, failed or closed preparation and never redirects its original API', async () => {
  const h = prepConnectionHarness(), replacement = h.makeApi('replacement');
  try {
    h.mount(); h.last('status').resolve(prepInitial()); await flush(); h.controller.start(true); await flush();
    assert.equal(h.connection.connect(h.api, true), true);
    assert.equal(h.connection.connect(replacement, true), false); assert.equal(h.connection.current(replacement), null);
    assert.equal(h.connection.current(h.api), h.controller);
    h.last('start').reject({ code: 'macos_maintenance_unavailable' }); await flush();
    h.last('status').resolve(prepInitial()); await flush();
    assert.equal(h.connection.connect(replacement, true), false);
    void h.controller.refresh(); h.last('status').resolve(prepRunning()); await flush();
    assert.equal(h.controller.snapshot().error, null);
    assert.equal(h.connection.connect(replacement, true), false);
    void h.controller.refresh(); h.last('status').resolve(prepRunning(1, { phase: 'prepared' })); await flush();
    assert.equal(h.connection.connect(replacement, true), false);
    assert(h.calls.every((row) => row.identity === 'original'));
  } finally { h.connection.dispose(); }
});

test('a settled idle connection can be replaced once and retired controller cannot publish or start', async () => {
  const h = prepConnectionHarness(), replacement = h.makeApi('replacement');
  try {
    const first = h.mount(); assert.equal(h.connection.connect(replacement, true), false);
    h.last('status').resolve(prepInitial()); await flush();
    assert.equal(h.connection.reconnectionError(), null); assert.equal(h.connection.connect(replacement, true), true);
    assert.equal(h.connection.current(h.api), null); assert.equal(h.controller.start(true), false);
    const frameCount = first.frames.length; let retiredPublications = 0;
    h.controller.attach(() => { retiredPublications += 1; }); await h.controller.refresh();
    assert.equal(retiredPublications, 0); assert.equal(first.frames.length, frameCount);
    const next = h.connection.current(replacement), panel = h.mount(next);
    assert.equal(panel.frames[0].status, null); assert.equal(panel.frames[0].error, null);
    assert.equal(h.last('status').identity, 'replacement'); h.last('status').resolve(prepInitial()); await flush();
    assert.equal(next.start(true), true); await flush(); assert.equal(h.last('start').identity, 'replacement');
  } finally { h.connection.dispose(); }
});

test('stale detach cannot disconnect a newer panel and detachment cannot cancel already confirmed queued Start', async () => {
  const h = prepConnectionHarness();
  try {
    const first = h.mount(); h.last('status').resolve(prepInitial()); await flush();
    const second = h.mount(); first.detach(); h.last('status').resolve(prepInitial()); await flush();
    assert.equal(second.frames.at(-1).refreshing, false);
    assert.equal(h.controller.start(true), true); second.detach(); await flush();
    assert.equal(h.by('start').length, 1); assert.equal(h.controller.start(true), false);
    h.last('start').reject({ code: 'macos_maintenance_unavailable' }); await flush();
    h.last('status').resolve(prepInitial()); await flush();
    const third = h.mount(); assert.equal(third.frames[0].error.code, 'macos_maintenance_unavailable');
  } finally { h.connection.dispose(); }
});

test('actual app connection teardown suppresses unissued Start and late replies without native cancellation or exit', async () => {
  for (const issued of [false, true]) {
    const h = prepConnectionHarness(); h.mount(); h.last('status').resolve(prepInitial()); await flush();
    assert.equal(h.controller.start(true), true); if (issued) await flush();
    const retained = h.controller.snapshot(); h.connection.dispose();
    if (issued) h.last('start').reject({ code: 'cleanup_unknown' });
    await flush();
    assert.equal(h.by('start').length, issued ? 1 : 0); assert.equal(h.by('status').length, 1);
    assert.equal(h.controller.snapshot(), retained); assert.equal(h.connection.current(h.api), null);
    assert.equal(h.connection.connect(h.makeApi('after-teardown'), true), false);
    assert.equal(h.controller.start(true), false);
  }
});


test('fixed preparation diagnostics preserve first work failure through terminal unknown without changing authority', () => {
  const native = { firstCall: 7, firstCode: 71, calls: 8, returns: 8, callbacks: 1, callbackReturns: 1, nativeCall: 0, unknown: 1, slots: [4,4,4,4,4,4,0,2] };
  const first = { phase: 'B', failure: 'native', native };
  const cleanup = { phase: 'cleanup', failure: 'unknown', native: null };
  const input = prepRunning(1, { phase: 'unknown', reason: 'cleanup-unknown', diagnostic: { first, cleanup } });
  const parsed = parseInstallationPreparationStatus(input);
  assert(JSON.stringify(parsed.diagnostic).length < 2048);
  assert.deepEqual(parsed, input); assert.equal(parsed.canStart, false); assert.equal(parsed.newWorkClosed, true);
  assert.match(installationPreparationDiagnosticLines(parsed.diagnostic).join(' '), /phase B; Rust failure native/);
  assert.match(installationPreparationDiagnosticLines(parsed.diagnostic).join(' '), /Cleanup failure: phase cleanup/);
  assert.deepEqual(parseInstallationPreparationStatus({ ...input, diagnostic: undefined }).diagnostic, { first:null, cleanup:null });
  const legacy = { ...input }; delete legacy.diagnostic;
  assert.equal(parseInstallationPreparationStatus(legacy).canStart, false);
  assert.deepEqual(parseInstallationPreparationStatus(legacy).diagnostic, { first:null, cleanup:null });
  for (const bad of [{ ...native, pid: 123 }, { ...native, firstCode: -1 }, { ...native, slots: [6,4,4,4,4,4,0,2] }, { ...native, returns: 9 }]) {
    const diagnostic = parsePreparationDiagnostic({ first: { ...first, native: bad }, cleanup });
    assert.deepEqual(diagnostic.first, { ...first, native: null });
    assert.match(installationPreparationDiagnosticLines(diagnostic).join(' '), /Cached native facts: unavailable/);
  }
  assert.deepEqual(parsePreparationDiagnostic({ first: { ...first, rawError: '/private/user-secret' }, cleanup }), { first:null, cleanup:null });
  assert.deepEqual(parsePreparationDiagnostic({ first: null, cleanup }), { first:null, cleanup:null });
  let reads = 0; const slots = [...native.slots]; Object.defineProperty(slots, '0', { get(){ reads++; return 4; } });
  assert.equal(parsePreparationDiagnostic({ first: { ...first, native: { ...native, slots } }, cleanup }).first.native, null);
  assert.equal(reads, 0);
  for (const diagnostic of [{ first:null, cleanup:null }, { first, cleanup }, { first: { phase:'begin',failure:'unavailable',native:null },cleanup:null }]) {
    const idle = parseInstallationPreparationStatus(prepInitial({ diagnostic }));
    assert.equal(idle.canStart, true); assert.equal(idle.phase, 'not-started');
    const unknown = parseInstallationPreparationStatus({ ...input, diagnostic });
    assert.equal(unknown.canStart, false); assert.equal(unknown.phase, 'unknown');
  }
});


test('same original refresh retains the first diagnostic while unknown keeps new work closed', async () => {
  const h = prepConnectionHarness();
  const first = { phase: 'watch', failure: 'native', native: null };
  const cleanup = { phase: 'cleanup', failure: 'unknown', native: null };
  const terminal = (diagnostic) => prepRunning(1, { phase: 'unknown', reason: 'cleanup-unknown', diagnostic });
  try {
    h.mount(); h.last('status').resolve(terminal({ first, cleanup: null })); await flush();
    assert.equal(h.controller.start(true), false);
    void h.controller.refresh(); h.last('status').resolve(terminal({ first: null, cleanup: null })); await flush();
    assert.deepEqual(h.controller.snapshot().status.diagnostic, { first, cleanup: null });
    void h.controller.refresh(); h.last('status').resolve(terminal({ first: { phase:'B', failure:'binding', native:null }, cleanup })); await flush();
    assert.deepEqual(h.controller.snapshot().status.diagnostic, { first, cleanup });
    assert.equal(h.controller.snapshot().status.newWorkClosed, true); assert.equal(h.controller.start(true), false);
    assert.equal(h.by('start').length, 0);
  } finally { h.connection.dispose(); }
});


test('native failure before first entry preserves code with ordinal zero', () => {
  const native = { firstCall:0,firstCode:22,calls:0,returns:0,callbacks:0,callbackReturns:0,nativeCall:0,unknown:1,slots:[0,0,0,0,0,0,0,0] };
  const first = { phase:'begin',failure:'native',native };
  const parsed = parsePreparationDiagnostic({ first,cleanup:null });
  assert.deepEqual(parsed.first,first);
  assert.match(installationPreparationDiagnosticLines(parsed).join(' '), /first native call ordinal 0; code 22/);
  assert.equal(parsePreparationDiagnostic({ first:{...first,native:{...native,firstCall:2,calls:1,returns:1}},cleanup:null }).first.native,null);
});


test('pre-client identity refusal remains distinct from later cleanup error', () => {
  const cleanup = {phase:'cleanup',failure:'unknown',native:null};
  const value = parsePreparationDiagnostic({preClient:'identity-check',first:cleanup,cleanup});
  assert.equal(value.preClient,'identity-check');
  assert.match(installationPreparationDiagnosticLines(value).join(' '), /Client.begin not entered: original identity-check refusal/);
  assert.equal(value.first.phase,'cleanup');
});
