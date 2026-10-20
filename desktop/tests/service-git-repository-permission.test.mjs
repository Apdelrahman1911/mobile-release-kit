// Original UI controllers with inert DATA/promises only. No Git, filesystem,
// native consent, service grant, process, network or cleanup proof is exercised.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GIT_REPOSITORY_CONSENT, GitRepositoryPermission, copyGitRepositoryApproval, createGitRepositoryPermissionApi, parseGitRepositoryAccess } from '../src/service_git_repository_permission.ts';
import { gitRepositoryPermissionContext, gitRepositoryPermissionEffect } from '../src/gitRepositoryPermissionSelection.ts';
import { parseGitIndexAccess } from '../src/service_git_permission.ts';
import { parseGitCommitAccess } from '../src/service_git_commit_permission.ts';
import { GitReadController } from '../src/gitReadController.ts';
import { GitLocalController } from '../src/gitLocalController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';

const revision = 'a'.repeat(64), references = 'b'.repeat(64), head = 'c'.repeat(40), target = 'd'.repeat(40);
const actions = () => [{ kind: 'initialize' }, ...['branch-create', 'branch-switch', 'branch-rename'].map(kind => ({
  kind, expectedRevision: revision, expectedReferenceRevision: references, name: 'next-release',
})), { kind: 'fast-forward', expectedRevision: revision, expectedReferenceRevision: references, targetRef: 'refs/remotes/origin/main', targetOid: target }];
const approval = (action = actions()[1]) => ({ projectId: 'project-1', expectedDocumentRevision: 1, readOperationId: action.kind === 'initialize' ? null : 'read-original', action });
const empty = () => ({ enabled: false, remainingMs: 0, consumed: false, projectId: null, grantId: null, selection: null });
const allowed = (action = actions()[1]) => ({ enabled: true, remainingMs: 900000, consumed: false, projectId: '1'.repeat(32), grantId: '2'.repeat(32),
  selection: { action, selectionSha256: '3'.repeat(64) } });
const observation = (changes = []) => ({ revision, head, branch: 'refs/heads/main', unborn: false, detached: false, changes, remotes: [], restrictions: [] });
const tracking = (updates = {}) => ({ state: 'complete', remote: 'origin', mergeRef: 'refs/heads/main', localRef: 'refs/remotes/origin/main', head: target, ahead: 0, behind: 1, ...updates });
const observed = (updates = {}) => ({ observation: observation(), referenceRevision: references, basis: 'local-refs-no-fetch', tracking: tracking(), ...updates });
const branches = () => ({ revision, referenceRevision: references, head, branch: 'refs/heads/main', basis: 'local-refs-no-fetch',
  branches: [{ ref: 'refs/heads/main', oid: head }, { ref: 'refs/heads/z-other', oid: target }] });
const context = () => ({ projectId: 'project-1', generation: 1, revision: 'document-1' });
const readStatus = (operation = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, operation });
const localStatus = (operation = null) => ({ schemaVersion: 1, documentRevision: 1, available: true, review: null, operation });
function readReply(kind, result, operationId = `read-${kind}`) {
  const action = { kind, expectedRevision: kind === 'observe' ? null : revision, paths: [], staged: false };
  const value = { schemaVersion: 1, admission: 'started', request: { projectId: 'project-1', expectedDocumentRevision: 1, action }, reason: null,
    status: readStatus({ operationId, context: context(), action, phase: 'settled', outcome: 'ok', reason: null, result }) };
  assert.ok(parseGitReadStartResult(value), 'the actual read codec must accept this fixture'); return value;
}
function deferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
function rawPort(names) {
  const calls = [], queues = Object.fromEntries(names.map(name => [name, []]));
  return { calls, queue: (name, value) => queues[name].push(value), api: Object.fromEntries(names.map(name => [name, raw => {
    assert.ok(raw instanceof Uint8Array); const body = JSON.parse(new TextDecoder().decode(raw)); calls.push({ name, body });
    assert.ok(queues[name].length, `no inert ${name} reply was queued`); const next = queues[name].shift();
    return typeof next === 'function' ? next(body) : Promise.resolve(next);
  }])) };
}
function permissionPort() {
  const calls = [];
  return { calls, api: Object.fromEntries(['status', 'allow', 'revoke'].map(kind => [kind, input => {
    const call = { kind, input, ...deferred() }; calls.push(call); return call.promise;
  }])) };
}
async function fixture({ observe = true, checked = true, value = observed() } = {}) {
  const reads = rawPort(['start', 'status', 'cancel']), writes = rawPort(['prepare', 'apply', 'discard', 'status', 'cancel']), grant = permissionPort();
  let source = { api: grant.api, session: {}, projectId: 'project-1', epoch: 0, repository: null, reader: null, local: null, blocked: null };
  const reader = new GitReadController({ current: () => ({ api: reads.api, session: source.session, projectId: source.projectId, epoch: source.epoch,
    blocked: source.local?.ownerReason() ?? source.blocked }) });
  source.reader = reader; reader.syncContext();
  const repository = new GitRepositoryController('project-1', reader.port('project-1')); source.repository = repository;
  repository.editBranchName('next-release'); repository.selectSwitchBranch('z-other'); repository.editRenameName('renamed');
  const local = new GitLocalController({ current: () => ({ ...source, api: writes.api, blocked: reader.ownerReason() ?? source.blocked }),
    onMutationSubmitted: () => assert.fail('permission must never submit a Git mutation') });
  source.local = local; local.syncContext();
  if (checked) { writes.queue('status', localStatus()); await local.checkStatus(); }
  if (observe) {
    reads.queue('status', readStatus()); await reader.checkStatus(); reads.queue('start', readReply('observe', value));
    assert.equal(await repository.refresh(), true);
  }
  const controller = new GitRepositoryPermission(kind => gitRepositoryPermissionContext(kind, source));
  for (const original of [repository, reader, local]) original.subscribe(() => controller.syncContext());
  controller.syncContext();
  return { controller, grant, reads, writes, reader, repository, local,
    source: () => source,
    change(update, sync = true) { source = { ...source, ...update }; if (sync) controller.syncContext(); },
    async branches() { reads.queue('start', readReply('branches', branches())); assert.equal(await reader.readBranches('project-1', revision), true); },
  };
}

test('five existing actions use exact bounded RAW approval fields, with null read only for initialization', () => {
  for (const a of actions()) {
    assert.deepEqual(copyGitRepositoryApproval(approval(a)), approval(a));
    assert.ok(Object.isFrozen(copyGitRepositoryApproval(approval(a)).action));
    for (const field of ['paths', 'message', 'identity', 'url', 'force', 'token', 'gitAbsent', 'argv']) {
      assert.equal(copyGitRepositoryApproval(approval({ ...a, [field]: null })), null);
    }
  }
  for (const input of [{ ...approval(), readOperationId: null }, { ...approval(actions()[0]), readOperationId: 'read-original' },
    { ...approval(), readOperationId: 'x'.repeat(97) }, { ...approval(), projectId: 'project-1\n' }, { ...approval(), expectedDocumentRevision: 0xffffffff },
    approval({ kind: 'fetch' }), approval({ ...actions()[1], name: '../bad' }), approval({ ...actions()[4], targetRef: 'refs/heads/main' }),
    { ...approval(), nativeReceipt: true }]) assert.equal(copyGitRepositoryApproval(input), null);
  let touched = false; const bad = approval(); Object.defineProperty(bad, 'action', { enumerable: true, get() { touched = true; return actions()[1]; } });
  assert.equal(copyGitRepositoryApproval(bad), null); assert.equal(touched, false);
});
test('Access keeps the native action/digest pair closed and distinct from Index/Commit or completion', () => {
  assert.deepEqual(parseGitRepositoryAccess(empty()), empty());
  for (const a of actions()) {
    const v = allowed(a); assert.deepEqual(parseGitRepositoryAccess(v), v);
    assert.equal(parseGitIndexAccess(v), null); assert.equal(parseGitCommitAccess(v), null);
    assert.ok(parseGitRepositoryAccess({ ...v, enabled: false, remainingMs: 0, consumed: true }));
  }
  for (const update of [{ remainingMs: 900001 }, { remainingMs: -0 }, { remainingMs: 0 }, { consumed: true }, { grantId: null },
    { projectId: '0'.repeat(32) }, { completed: true }, { selection: { ...allowed().selection, nativeReady: true } },
    { selection: { ...allowed().selection, selectionSha256: 'F'.repeat(64) } }]) assert.equal(parseGitRepositoryAccess({ ...allowed(), ...update }), null);
  assert.equal(parseGitRepositoryAccess({ ...empty(), consumed: true }), null);
  assert.equal(parseGitRepositoryAccess({ ...allowed(), selection: { action: { kind: 'stage', paths: [] }, selectionSha256: '3'.repeat(64) } }), null);
});
test('only the agreed three native RAW calls exist, and an Allow reply must match its exact action', async () => {
  const calls = [];
  const api = createGitRepositoryPermissionApi('native', async (name, raw) => {
    assert.ok(raw instanceof Uint8Array); const body = JSON.parse(new TextDecoder().decode(raw)); calls.push({ name, body, size: raw.length });
    return name === 'allow_agent_git_repository' ? allowed(body.action) : empty();
  });
  assert.equal(createGitRepositoryPermissionApi('preview', () => assert.fail('no preview invoke')), null);
  for (const a of actions()) await api.allow(approval(a));
  await api.status(); await api.revoke();
  assert.deepEqual(calls.map(c => c.name), [...actions().map(() => 'allow_agent_git_repository'), 'agent_git_repository_access', 'revoke_agent_git_repository']);
  assert.deepEqual(calls[0].body, { ...approval(actions()[0]), consentVersion: GIT_REPOSITORY_CONSENT });
  assert.ok(calls.every(c => c.size + 96 <= (c.name === 'allow_agent_git_repository' ? 8192 : 1024)));
  const count = calls.length; await assert.rejects(api.allow({ ...approval(), root: '/not-an-input' })); assert.equal(calls.length, count);
  const mismatched = createGitRepositoryPermissionApi('native', async () => allowed(actions()[0]));
  await assert.rejects(mismatched.allow(approval()), e => e.code === 'agent_git_repository_unconfirmed' && e.retryable === false);
  const bad = createGitRepositoryPermissionApi('native', async () => { throw new Error('private untrusted diagnostic'); });
  await assert.rejects(bad.status(), e => !JSON.stringify(e).includes('private untrusted'));
});
test('initialization uses a current local-status check, not a fabricated Observe or absence receipt', async () => {
  const h = await fixture({ observe: false, checked: false });
  assert.equal(h.controller.getContext().project, null); assert.equal(h.grant.calls.length, 0);
  h.writes.queue('status', localStatus()); await h.local.checkStatus();
  assert.deepEqual(h.controller.getContext().project, approval(actions()[0]));
  assert.equal(h.reads.calls.length, 0); assert.equal(h.writes.calls.some(c => c.name === 'prepare'), false);
  assert.match(gitRepositoryPermissionEffect(actions()[0]), /only if the native review confirms/);
  await h.controller.allow(); assert.equal(h.grant.calls.length, 0);
  h.controller.acknowledge(true); const allow = h.controller.allow(); assert.equal(h.grant.calls[0].input.readOperationId, null);
  h.grant.calls[0].resolve(allowed(actions()[0])); await allow;
  assert.equal(h.controller.getState().acknowledged, false);
  const existing = await fixture(); assert.equal(existing.controller.getContext().project, null);
});
test('branch permission reuses actual Observe or Branches and the one existing per-project name draft', async () => {
  const h = await fixture(); h.controller.chooseKind('branch-create');
  assert.equal(h.controller.getContext().project.readOperationId, 'read-observe');
  assert.equal(h.controller.getContext().project.action.name, h.repository.getSnapshot().branchDraft.name);
  await h.branches(); assert.equal(h.controller.getContext().project.readOperationId, 'read-branches');
  for (const kind of ['branch-create', 'branch-switch', 'branch-rename']) {
    h.controller.chooseKind(kind); const a = h.controller.getContext().project;
    assert.ok(a); assert.equal(a.action.kind, kind); assert.equal(a.action.expectedReferenceRevision, references); assert.equal(a.readOperationId, 'read-branches');
  }
  assert.equal(h.grant.calls.length, 0); assert.equal(h.writes.calls.some(c => c.name === 'prepare' || c.name === 'apply'), false);
  h.repository.selectSwitchBranch('not-in-list'); h.controller.chooseKind('branch-switch'); assert.equal(h.controller.getContext().project, null);
  h.change({ projectId: 'project-2' }); assert.equal(h.controller.getContext().project, null);
});
test('cached fast-forward requires the exact completed Observe, not Branches, equal/diverged or incomplete tracking', async () => {
  const h = await fixture(); h.controller.chooseKind('fast-forward');
  assert.deepEqual(h.controller.getContext().project.action, actions()[4]);
  assert.match(gitRepositoryPermissionEffect(actions()[4]), /No fetch/);
  await h.branches(); assert.equal(h.controller.getContext().project, null);
  for (const t of [tracking({ ahead: 1 }), tracking({ behind: 0 }), tracking({ state: 'shallow', ahead: null, behind: null })]) {
    const changed = await fixture({ value: observed({ tracking: t }) }); changed.controller.chooseKind('fast-forward');
    assert.equal(changed.controller.getContext().project, null); assert.equal(changed.grant.calls.length, 0);
  }
});
test('actual original read remains busy after its terminal status until the Start caller returns', async () => {
  const h = await fixture(), d = deferred(); h.controller.chooseKind('fast-forward');
  const reply = readReply('observe', observed(), 'read-next'); h.reads.queue('start', () => d.promise);
  const read = h.repository.refresh(); h.reads.queue('status', reply.status); await h.reader.checkStatus();
  assert.equal(h.reader.getSnapshot().original.phase, 'settled'); assert.equal(h.reader.getSnapshot().busy, true);
  h.controller.acknowledge(true); await h.controller.allow(); assert.equal(h.grant.calls.length, 0);
  d.resolve(reply); assert.equal(await read, true); assert.equal(h.controller.getContext().project.readOperationId, 'read-next');
  assert.equal(h.controller.getState().acknowledged, false); assert.equal(h.grant.calls.length, 0);
});
test('a synchronous name ABA after Allow notification withdraws consent before the original handoff', async () => {
  const h = await fixture(); h.controller.chooseKind('branch-create'); let changed = false;
  h.controller.subscribe(s => { if (s.pending === 'allow' && !changed) {
    changed = true; h.repository.editBranchName('different'); h.repository.editBranchName('next-release');
  } });
  h.controller.acknowledge(true); await h.controller.allow();
  assert.equal(h.grant.calls.length, 0); assert.equal(h.controller.getState().pending, null);
  assert.equal(h.repository.getSnapshot().branchDraft.name, 'next-release'); assert.equal(h.controller.getState().acknowledged, false);
});
test('action changes, peers, and a new service epoch refuse stale checkbox approval without an implicit operation', async () => {
  for (const change of [{ epoch: 1 }, { session: {} }, { blocked: 'An original task needs recovery.' }]) {
    const h = await fixture(); h.controller.chooseKind('branch-create'); h.controller.acknowledge(true); h.change(change, false);
    await h.controller.allow(); assert.equal(h.grant.calls.length, 0); assert.equal(h.controller.getState().acknowledged, false);
  }
  const h = await fixture(); h.controller.chooseKind('branch-create'); let changed = false;
  h.controller.subscribe(s => { if (s.pending === 'allow' && !changed) { changed = true; h.controller.chooseKind('branch-rename'); } });
  h.controller.acknowledge(true); await h.controller.allow(); assert.equal(h.grant.calls.length, 0);
});
test('reentrant Stop runs immediately before Allow dispatch and keeps the original finite controller', async () => {
  const h = await fixture(); h.controller.chooseKind('branch-create'); let stop;
  h.controller.subscribe(s => { if (s.pending === 'allow' && !stop) stop = h.controller.revoke(); });
  h.controller.acknowledge(true); const allow = h.controller.allow(); assert.deepEqual(h.grant.calls.map(c => c.kind), ['revoke']);
  h.grant.calls[0].resolve(empty()); await stop; await allow; assert.equal(h.controller.getState().access.enabled, false);
});
test('Allow and independent Stop retain both promises across a service/project change and late acknowledgement', async () => {
  const h = await fixture(), fresh = permissionPort(); h.controller.chooseKind('branch-create'); h.controller.acknowledge(true);
  const allow = h.controller.allow(); h.change({ api: fresh.api, session: {}, projectId: 'project-2', epoch: 2 });
  const stop = h.controller.revoke(); assert.equal(h.grant.calls[1].kind, 'revoke'); assert.equal(fresh.calls.length, 0);
  h.grant.calls[1].resolve(empty()); await stop;
  assert.equal(h.controller.getState().pending, 'allow'); h.controller.acknowledge(true); await h.controller.allow(); assert.equal(fresh.calls.length, 0);
  h.grant.calls[0].resolve(allowed()); await allow;
  assert.equal(h.controller.getState().access.enabled, false); assert.equal(h.controller.getState().pending, null);
});
test('lost acknowledgement is not a no-grant receipt; consumed Access is not Git completion or Apply permission', async () => {
  const h = await fixture(); h.controller.chooseKind('branch-create'); h.controller.acknowledge(true);
  const allow = h.controller.allow(); h.grant.calls[0].reject(new Error('inert lost acknowledgement')); await allow;
  assert.equal(h.controller.getState().uncertain, true); h.controller.acknowledge(true); await h.controller.allow(); assert.equal(h.grant.calls.length, 1);
  const status = h.controller.status(); h.grant.calls[1].resolve({ ...allowed(), enabled: false, remainingMs: 0, consumed: true }); await status;
  assert.equal(h.controller.getState().uncertain, true); assert.equal(h.local.getSnapshot().original, null);
  assert.equal(h.writes.calls.some(c => c.name === 'prepare' || c.name === 'apply'), false);
  const stop = h.controller.revoke(); h.grant.calls[2].resolve({ ...allowed(), enabled: false, remainingMs: 0, consumed: true }); await stop;
  assert.equal(h.controller.getState().access.consumed, true); assert.equal(h.local.getSnapshot().original, null);
});
