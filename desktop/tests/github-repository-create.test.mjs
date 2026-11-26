// Inert DATA, deferred original IPC and the real composed bridge only.
// No GitHub, tokens, native services, repository writes or real journal files.
import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubRepositoryCreateController } from '../src/githubRepositoryCreateController.ts';
import { createRepositoryCreatePort } from '../src/githubRepositoryCreateNative.ts';
import { encodeRepositoryCreateRequest, parseRepositoryCreateStatus, repositoryCreateConfirmation,
  repositoryCreateCoordinate, repositoryCreateError } from '../src/githubRepositoryCreateProtocol.ts';
import { createNativeApi } from '../src/bridge.ts';
import { previewApi } from '../src/preview.ts';

const copy = structuredClone, marker = 'a'.repeat(32), consentId = 'b'.repeat(32);
function connection() {
  return { mode: 'native', context: { documentId: 'doc-a', projectId: 'project-a', projectGeneration: 1, repository: 'owner/new-app' },
    status: { revision: 12, session: { id: 'session-a', projectId: 'project-a', targetRepository: 'owner/new-app', state: 'connected' },
      account: { state: 'observed', value: { id: '11', login: 'owner' } }, repository: { state: 'unavailable', value: null, reason: 'repository-unavailable' } },
    busy: null, uncertain: false, blocked: false, retirementPending: false, observing: false, error: null };
}
function target(visibility = 'private', ownerKind = 'user') {
  return { projectBinding: 'd'.repeat(64), repository: ownerKind === 'user' ? 'owner/new-app' : 'example-org/new-app',
    accountId: '11', accountLogin: 'owner', ownerKind, visibility, marker };
}
function prepared(visibility = 'private', ownerKind = 'user') {
  const t = target(visibility, ownerKind);
  return { target: t, ownerId: ownerKind === 'user' ? '11' : '22', membership: ownerKind === 'user' ? 'self' : 'active-member',
    repositoryObservation: 'not-found-or-inaccessible', creationPermission: 'not-proven', autoInit: false, confirmation: repositoryCreateConfirmation(t) };
}
function idle(revision = 1) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, consent: null, pending: [], observed: null }; }
function operation(kind, phase, revision, reason = 'none', effect = kind === 'create' ? 'not-sent' : 'none', t = target()) {
  return { ...idle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
    operation: { id: `${kind}-a`, projectId: 'project-a', kind, target: t, phase, reason, effect } };
}
function review(revision = 3, visibility = 'private', ownerKind = 'user') {
  return { ...operation('prepare', 'settled', revision, 'none', 'none', target(visibility, ownerKind)),
    consent: { id: consentId, expiresAt: '2026-10-20T20:02:00Z', prepared: prepared(visibility, ownerKind) } };
}
function observed(revision = 5, kind = 'create') {
  return { ...operation(kind, 'settled', revision, 'none', 'created-observed'),
    observed: { id: '33', fullName: 'owner/new-app', ownerId: '11', visibility: 'private', url: 'https://github.com/owner/new-app' } };
}
function pending(revision = 7) { return { ...operation('pending', 'settled', revision), pending: [{ prepared: prepared(), claimed: true, acknowledged: null }] }; }
function deferred() {
  let yes, no; const d = { ended: false };
  d.promise = new Promise((resolve, reject) => { yes = resolve; no = reject; });
  d.resolve = (v) => { d.ended = true; yes(v); }; d.reject = (e) => { d.ended = true; no(e); }; return d;
}
async function flush() { for (let n = 0; n < 18; n++) await Promise.resolve(); }
const harnesses = [];
function harness() {
  let current = idle(), view = connection(), listener = null, detached = 0, peer = null;
  const calls = [], h = { deferredStatus: false, unlistenThrows: false };
  const request = (kind, args) => { const d = deferred(); Object.assign(d, { kind, args: copy(args) }); calls.push(d); return d.promise; };
  const port = { mode: 'native', subscribe: async (fn) => { listener = fn; return () => {
    if (h.unlistenThrows) throw new Error('INERT PRIVATE DETAIL'); listener = null; detached++;
  }; }, status: () => {
    if (h.deferredStatus) return request('status', {});
    calls.push({ kind: 'status', ended: true }); return Promise.resolve(copy(current));
  } };
  for (const kind of ['prepare', 'create', 'pending', 'reconcile', 'discard', 'cancel']) port[kind] = (args) => request(kind, args);
  const controller = new GitHubRepositoryCreateController(() => view, () => typeof peer === 'function' ? peer() : peer);
  Object.assign(h, { port, controller, calls, count: (k) => calls.filter((c) => c.kind === k).length,
    last: (k) => calls.filter((c) => c.kind === k).at(-1), emit(s) { current = copy(s); listener?.(copy(s)); },
    rawEmit(s) { listener?.(s); }, retain(s) { current = copy(s); }, respond(k, s) { current = copy(s); this.last(k).resolve(copy(s)); },
    context(v) { view = v; controller.syncContext(); }, peer(v) { peer = v; }, currentConnection: () => view });
  Object.defineProperties(h, { state: { get: () => controller.getSnapshot() }, detached: { get: () => detached } });
  harnesses.push(h); return h;
}
async function attached() { const h = harness(); h.controller.connect(h.port); await flush(); return h; }
async function ready() { const h = await attached(); h.controller.prepare(); h.respond('prepare', review()); await flush(); assert.ok(h.controller.currentConsent()); return h; }
test.afterEach(async () => {
  // Settle only these inert original Promises; never claim native cleanup.
  for (const h of harnesses.splice(0)) {
    for (const c of h.calls) if (!c.ended) c.reject({ code: 'fixture-ended' });
    await flush(); h.controller.dispose();
    for (const c of h.calls) if (!c.ended) c.reject({ code: 'fixture-ended' });
    await flush();
  }
});

test('strict redacted status keeps 404/membership as nonpermission, rejects partial or forged success and getters', () => {
  for (const s of [idle(), review(), review(3, 'public', 'organization'), pending(), observed(),
    operation('create', 'cleanup-unknown', 5, 'cleanup-unknown', 'potentially-applied')]) assert.ok(parseRepositoryCreateStatus(s));
  for (const change of [(s) => s.consent.prepared.autoInit = true, (s) => s.consent.prepared.creationPermission = 'granted',
    (s) => s.consent.prepared.confirmation += ' altered', (s) => s.consent.prepared.target.token = 'INERT PRIVATE',
    (s) => s.consent.prepared.ownerId = '22', (s) => s.operation.target.projectBinding = 'z'.repeat(64)]) {
    const s = review(); change(s); assert.equal(parseRepositoryCreateStatus(s), null);
  }
  for (const change of [(s) => s.observed = null, (s) => s.operation.phase = 'running', (s) => s.operation.reason = 'unresolved',
    (s) => s.observed.url = 'https://other.invalid', (s) => s.observed.fullName = 'other/app']) {
    const s = observed(); change(s); assert.equal(parseRepositoryCreateStatus(s), null);
  }
  const p = pending(); p.pending.push(copy(p.pending[0])); assert.equal(parseRepositoryCreateStatus(p), null);
  let reads = 0; const s = idle(); Object.defineProperty(s, 'consent', { enumerable: true, get() { reads++; return null; } });
  assert.equal(parseRepositoryCreateStatus(s), null); assert.equal(reads, 0);
  for (const v of ['https://github.com/owner/app', 'owner/app.git', 'owner/..', 'owner/app?x', 'owner/app\n', 'a--b/app', 'owner/a/b']) assert.equal(repositoryCreateCoordinate(v), false);
});

test('actual composed bridge emits exactly seven RAW closed commands; preview and absent listener do not acquire capability', async () => {
  const calls = [], events = [];
  const api = createNativeApi('native', async (command, raw) => { calls.push([command, raw]); return idle(); }, async (event) => { events.push(event); return () => {}; });
  const port = api.githubRepositoryCreate;
  assert.ok(port); const base = { sessionId: 'session-a', expectedRevision: 1 };
  await port.status(); await port.prepare({ ...base, expectedConnectionRevision: 12, ownerKind: 'user', visibility: 'private' });
  await port.create({ ...base, consentId, confirm: true }); await port.pending({ ...base, expectedConnectionRevision: 12 });
  await port.reconcile({ ...base, marker }); await port.discard({ ...base, consentId }); await port.cancel({ operationId: 'create-a' });
  await port.subscribe(() => {});
  assert.equal(new Set(calls.map(([c]) => c)).size, 7); assert.deepEqual(events, ['github-repository-create-status']);
  assert.ok(calls.every(([c, raw]) => c.startsWith('github_repository_create_') && raw instanceof Uint8Array && raw.length <= 1024));
  assert.equal(JSON.stringify(calls.map(([, raw]) => JSON.parse(new TextDecoder().decode(raw)))).includes('token'), false);
  assert.equal(createRepositoryCreatePort('preview', () => assert.fail(), null), null);
  assert.equal(createRepositoryCreatePort('native', () => assert.fail(), null), null);
  assert.equal(previewApi.githubRepositoryCreate ?? null, null);
  for (const k of ['token', 'root', 'url', 'body', 'accountId', 'force']) assert.equal(encodeRepositoryCreateRequest('github_repository_create_prepare', { ...base, expectedConnectionRevision: 12, ownerKind: 'user', visibility: 'private', [k]: 'INERT' }), null);
  assert.equal(encodeRepositoryCreateRequest('github_repository_create_create', { ...base, consentId, confirm: false }), null);
  assert.equal(encodeRepositoryCreateRequest('github_repository_create_delete', {}), null);
  assert.deepEqual(repositoryCreateError({ code: 'github_repository_create_refused_target_changed' }), { reason: 'target-changed', notAdmitted: true });
  assert.deepEqual(repositoryCreateError({ code: 'INERT PRIVATE', message: 'INERT PRIVATE', notAdmitted: true }), { reason: 'response-invalid', notAdmitted: false });
});

test('attach only observes; verified account with repository404 can explicitly review Private and never automatically creates', async () => {
  const h = await attached(); assert.equal(h.count('status'), 1); assert.equal(h.count('prepare'), 0); assert.equal(h.count('create'), 0);
  assert.equal(h.state.visibility, 'private'); assert.equal(h.state.ownerKind, 'user'); assert.equal(h.controller.prepareReason(), null);
  h.controller.prepare(); assert.deepEqual(h.last('prepare').args, { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, ownerKind: 'user', visibility: 'private' });
  h.respond('prepare', review()); await flush(); h.controller.create(); assert.equal(h.count('create'), 0);
  assert.ok(h.controller.ownerReason()); assert.equal(h.state.confirmed, false);
});

test('exact joined review, separate confirmation and one-use Create never adopt repository truth into the connection', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.create(); h.controller.create();
  assert.equal(h.count('create'), 1); assert.deepEqual(h.last('create').args, { sessionId: 'session-a', expectedRevision: 3, consentId, confirm: true });
  assert.equal(h.controller.currentConsent(), null); assert.ok(h.controller.ownerReason());
  h.respond('create', observed()); await flush(); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false);
  assert.equal(h.state.status.observed.id, '33'); assert.equal(h.currentConnection().status.repository.value, null);
  h.controller.setConfirmed(true); h.controller.create(); h.controller.prepare(); assert.equal(h.count('create'), 1); assert.equal(h.count('prepare'), 1);
});

test('Public and organization are deliberate choices; changed owner/visibility retires old consent, not native work', async () => {
  const h = await attached(), c = connection(); c.context.repository = c.status.session.targetRepository = 'example-org/new-app'; h.context(c);
  assert.match(h.controller.prepareReason(), /Organization/);
  h.controller.setOwnerKind('organization'); h.controller.setVisibility('public'); h.controller.prepare();
  assert.equal(h.last('prepare').args.visibility, 'public'); h.respond('prepare', review(3, 'public', 'organization')); await flush();
  assert.match(h.controller.currentConsent().prepared.confirmation, /Anyone can see/);
  h.controller.setConfirmed(true); h.controller.setVisibility('private'); assert.equal(h.controller.currentConsent(), null); assert.equal(h.state.confirmed, false);
  h.controller.create(); assert.equal(h.count('create'), 0); assert.ok(h.controller.canDiscard()); assert.ok(h.controller.ownerReason());
  h.controller.discardReview(); assert.equal(h.count('discard'), 1); h.respond('discard', operation('prepare', 'settled', 4, 'none', 'none', target('public', 'organization'))); await flush();
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.state.visibility, 'private');
});

test('terminal event before Start reply keeps original Promise and ignores coherent older progress without granting an early Create', async () => {
  const h = await attached(); h.controller.prepare(); h.emit(review());
  assert.equal(h.state.pending, true); assert.equal(h.controller.currentConsent(), null); assert.ok(h.controller.ownerReason());
  h.respond('prepare', operation('prepare', 'running', 2)); await flush();
  assert.equal(h.state.status.revision, 3); assert.equal(h.state.pending, false); assert.ok(h.controller.currentConsent());
  h.deferredStatus = true; h.controller.checkStatus(); h.controller.discardReview();
  assert.equal(h.count('discard'), 1); h.respond('discard', operation('prepare', 'settled', 4)); await flush();
  assert.ok(h.controller.ownerReason()); h.last('status').resolve(review()); await flush();
  assert.equal(h.state.status.revision, 4); assert.equal(h.state.uncertain, false); assert.equal(h.controller.ownerReason(), null);
});

test('synchronous project/API/ABA/choice/peer/revision changes after latch veto the one native handoff', async () => {
  for (const change of ['project', 'api', 'aba', 'choice', 'peer', 'revision', 'unknown']) {
    const h = await ready(); h.controller.setConfirmed(true); let once = false;
    const unsubscribe = h.controller.subscribe(() => {
      if (once || !h.state.pending) return; once = true;
      if (change === 'project') { const c = connection(); c.context.projectId = 'project-b'; h.context(c); }
      if (change === 'api') h.controller.connect(null);
      if (change === 'aba') { h.context({ ...connection(), context: null }); h.context(connection()); }
      if (change === 'choice') h.controller.setVisibility('public');
      if (change === 'peer') h.peer('Another original is pending.');
      if (change === 'revision') h.currentConnection().status.revision++;
      if (change === 'unknown') h.emit({ wrong: 'shape' });
    });
    h.controller.create(); unsubscribe(); assert.equal(h.count('create'), 0, change); assert.equal(h.state.pending, false, change);
  }
});

test('workspace intent before late admission requests original Stop once and never adopts stale review', async () => {
  const h = await attached(); h.controller.prepare(); h.controller.beforeWorkspaceAction();
  h.emit(operation('prepare', 'running', 2)); assert.equal(h.count('cancel'), 1); h.emit(operation('prepare', 'running', 2)); assert.equal(h.count('cancel'), 1);
  h.respond('prepare', review()); await flush(); assert.equal(h.controller.currentConsent(), null); assert.equal(h.state.pending, false);
  assert.ok(h.controller.ownerReason()); h.respond('cancel', review()); await flush();
  assert.ok(h.controller.canDiscard()); h.controller.discardReview(); h.respond('discard', operation('prepare', 'settled', 4)); await flush();
  assert.equal(h.controller.ownerReason(), null); assert.equal(h.count('create'), 0);
});

test('native clean stale refusal retires only an unmatched request; lost or synchronous failure is not no-admission', async () => {
  const clean = await attached(); clean.controller.prepare(); clean.last('prepare').reject({ code: 'github_repository_create_refused_target_changed' }); await flush();
  assert.equal(clean.state.pending, false); assert.equal(clean.state.error, 'target-changed'); assert.equal(clean.state.uncertain, false);
  assert.match(clean.controller.prepareReason(), /Check/); clean.controller.prepare(); assert.equal(clean.count('prepare'), 1);
  for (const mode of ['lost', 'throw', 'non-promise', 'matched-refusal']) {
    const h = await ready(); h.controller.setConfirmed(true);
    if (mode === 'throw') h.port.create = () => { throw { code: 'github_repository_create_refused_busy' }; };
    if (mode === 'non-promise') h.port.create = () => ({ then() { assert.fail('Do not assimilate an arbitrary thenable.'); } });
    h.controller.create();
    if (mode === 'matched-refusal') h.emit(operation('create', 'running', 4, 'none', 'potentially-applied'));
    if (mode === 'lost' || mode === 'matched-refusal') h.last('create').reject({ code: mode === 'lost' ? 'transport-lost' : 'github_repository_create_refused_busy' });
    await flush(); assert.equal(h.state.pending, true, mode); assert.equal(h.state.uncertain, true, mode);
    h.retain(idle(6)); h.controller.checkStatus(); await flush(); assert.equal(h.state.pending, true, mode); assert.ok(h.controller.createReason());
  }
});

test('lost Create is settled only by exact original joined status, then pending/reconcile never repeat POST', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.create(); h.last('create').reject({ code: 'reply-lost' }); await flush();
  h.retain(operation('create', 'settled', 5, 'network-unavailable', 'potentially-applied')); h.controller.checkStatus(); await flush();
  assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false); assert.match(h.controller.prepareReason(), /previous attempt/);
  h.controller.loadPending(); h.respond('pending', pending()); await flush(); h.controller.reconcile('f'.repeat(32)); assert.equal(h.count('reconcile'), 0);
  h.controller.reconcile(marker); assert.deepEqual(h.last('reconcile').args, { sessionId: 'session-a', expectedRevision: 7, marker });
  const found = observed(9, 'reconcile'); found.operation.effect = 'found-unattributed'; found.operation.reason = 'unattributed'; found.pending = pending().pending;
  h.respond('reconcile', found); await flush(); assert.equal(h.state.error, 'unattributed'); assert.equal(h.count('create'), 1); assert.equal(h.count('prepare'), 1);
  assert.ok(h.controller.prepareReason()); assert.equal(h.currentConnection().status.repository.value, null);
});

test('original cleanup Unknown is absorbing; late terminal/status/cancel cannot overwrite it or hide unsent Stop', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.create();
  const unknown = operation('create', 'cleanup-unknown', 5, 'cleanup-unknown', 'potentially-applied'); h.emit(unknown);
  h.emit(observed(6)); assert.equal(h.state.status.operation.phase, 'cleanup-unknown'); assert.equal(h.controller.canCancel(), true);
  h.controller.cancel(); assert.equal(h.count('cancel'), 1); h.respond('cancel', observed(7)); h.respond('create', observed(6)); await flush();
  assert.equal(h.state.pending, true); assert.equal(h.state.uncertain, true); assert.equal(h.state.status.observed, null); assert.equal(h.state.status.operation.phase, 'cleanup-unknown');
  h.controller.create(); h.controller.loadPending(); assert.equal(h.count('create'), 1); assert.equal(h.count('pending'), 0);
});

test('malformed then late original ID still forwards queued Stop without publishing a success', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.create(); h.controller.beforeWorkspaceAction();
  h.emit({ wrong: true }); assert.equal(h.count('cancel'), 0);
  h.emit(operation('create', 'running', 4, 'none', 'potentially-applied')); assert.equal(h.count('cancel'), 1);
  h.respond('create', observed()); h.respond('cancel', observed()); await flush();
  assert.equal(h.state.uncertain, true); assert.equal(h.state.status.observed, null); assert.ok(h.controller.ownerReason());
});

test('foreign target/session/marker and changed terminal result cannot become a current consent or successful completion', async () => {
  for (const change of ['project', 'session', 'target', 'account', 'marker']) {
    const h = await ready(); h.controller.setConfirmed(true); h.controller.create(); const s = observed();
    if (change === 'project') s.operation.projectId = 'project-b';
    if (change === 'session') s.sessionId = 'session-b';
    if (change === 'target') { s.operation.target.repository = 'owner/other'; s.observed.fullName = 'owner/other'; s.observed.url = 'https://github.com/owner/other'; }
    if (change === 'account') s.operation.target.accountId = '44';
    if (change === 'marker') s.operation.target.marker = 'e'.repeat(32);
    h.respond('create', s); await flush(); assert.equal(h.state.pending, true, change); assert.equal(h.state.uncertain, true, change); assert.ok(h.controller.ownerReason());
  }
  const h = await ready(); h.controller.setConfirmed(true); h.controller.create(); h.respond('create', observed()); await flush();
  const changed = observed(6); changed.observed.id = '44'; h.emit(changed);
  assert.equal(h.state.uncertain, true); assert.equal(h.state.status.observed.id, '33');
});

test('status, Start and Stop Promises retain the original port independently across service replacement', async () => {
  const h = await ready(); h.controller.setConfirmed(true); h.controller.create(); h.emit(operation('create', 'running', 4, 'none', 'potentially-applied'));
  h.deferredStatus = true; h.controller.checkStatus(); const originalRead = h.last('status'); h.controller.connect(null);
  assert.equal(h.count('cancel'), 1); assert.equal(h.detached, 0); h.respond('create', observed()); await flush(); assert.equal(h.state.pending, false);
  h.respond('cancel', observed()); await flush(); assert.equal(h.detached, 0); assert.ok(h.controller.ownerReason());
  originalRead.resolve(observed()); await flush(); assert.equal(h.detached, 1); assert.equal(h.controller.ownerReason(), null);
});

test('close remains on old port/project; review cannot be dropped by rebind, and failed unlisten retains uncertainty', async () => {
  const h = await ready(); h.controller.connect(null); h.context({ ...connection(), context: null }); assert.equal(h.detached, 0);
  assert.ok(h.controller.canDiscard()); h.controller.discardReview(); assert.deepEqual(h.last('discard').args, { sessionId: 'session-a', expectedRevision: 3, consentId });
  h.respond('discard', operation('prepare', 'settled', 4)); await flush(); assert.equal(h.detached, 1);
  const other = await attached(); other.unlistenThrows = true; other.controller.connect(null);
  assert.equal(other.state.uncertain, true); assert.equal(other.detached, 0); assert.ok(other.controller.ownerReason());
  other.controller.connect(other.port); assert.equal(other.count('status'), 1); assert.ok(other.controller.prepareReason());
});

test('parser descriptor reentrancy retires local consent and never authorizes a new Create from that reply', async () => {
  const h = await attached(); h.controller.prepare(); let once = false;
  const reply = new Proxy(review(), { getOwnPropertyDescriptor(t, k) {
    if (!once) { once = true; h.controller.beforeWorkspaceAction(); }
    return Reflect.getOwnPropertyDescriptor(t, k);
  } });
  h.rawEmit(reply); h.respond('prepare', review()); await flush();
  assert.equal(h.controller.currentConsent(), null); h.controller.setConfirmed(true); h.controller.create(); assert.equal(h.count('create'), 0);
});
