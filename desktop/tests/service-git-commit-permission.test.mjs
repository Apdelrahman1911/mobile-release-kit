// Closed DATA/promises only: no native approval, Git, network or stored data.
import assert from 'node:assert/strict';
import test from 'node:test';
import { GIT_COMMIT_CONSENT, GitCommitPermission, copyGitCommitApproval, createGitCommitApi, parseGitCommitAccess } from '../src/service_git_commit_permission.ts';
import { copyGitIndexApproval, parseGitIndexAccess } from '../src/service_git_permission.ts';
const id = c => c.repeat(32);
const approval = () => ({ projectId: 'project-1', expectedDocumentRevision: 1, readOperationId: 'git-read-1', message: 'Reviewed local commit\n\nBody', authorName: 'Example Author', authorEmail: 'a@example.invalid' });
const empty = () => ({ permissionRevision: '0', enabled: false, remainingMs: 0, consumed: false, projectId: null, grantId: null, selection: null });
const enabled = () => ({ permissionRevision: '0', enabled: true, remainingMs: 900000, consumed: false, projectId: id('a'), grantId: id('b'), selection: { summary: { action: 'commit', repositoryRevision: 'c'.repeat(64), pathCount: 2, selectionSha256: 'd'.repeat(64) }, paths: ['app/a', 'other/b'] } });
function defer() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
function port() { const calls = []; return { calls, api: Object.fromEntries(['allow', 'status', 'revoke'].map(kind => [kind, (input, expectedPermissionRevision) => { const call = { kind, input, expectedPermissionRevision, ...defer() }; calls.push(call); return call.promise; }])) }; }
function controller(p = port()) { let context = { api: p.api, project: approval(), blocked: false }; const c = new GitCommitPermission(() => context); c.syncContext(); return { ...p, c, set: v => { context = v; } }; }

async function checked(c, calls, revision = '0') {
  const before = calls.length, pending = c.status();
  assert.equal(calls.length, before + 1); assert.equal(calls[before].kind, 'status');
  c.acknowledge(true); assert.equal(c.getState().acknowledged, false);
  calls[before].resolve({ ...empty(), permissionRevision: revision }); await pending;
  assert.equal(c.getState().pending, null); assert.equal(c.getState().acknowledged, false);
}

test('exact private draft uses UTF8 native limits without selecting paths or a command', () => {
  const a = approval(); assert.deepEqual(copyGitCommitApproval(a), a); assert.ok(Object.isFrozen(copyGitCommitApproval(a)));
  for (const changed of [{ message: '' }, { message: 'x\ry' }, { message: 'é'.repeat(2049) }, { authorName: 'é'.repeat(65) }, { authorName: '<A>' }, { authorEmail: 'a@b@c' }, { authorEmail: 'a\nb@c' }, { command: 'commit' }, { paths: ['a'] }, { nativeReceipt: true }]) {
    assert.equal(copyGitCommitApproval({ ...a, ...changed }), null);
  }
  let touched = false; const bad = { ...a }; Object.defineProperty(bad, 'message', { enumerable: true, get() { touched = true; return 'bad'; } });
  assert.equal(copyGitCommitApproval(bad), null); assert.equal(touched, false);
});
test('commit and index projections are distinct even with identical paths', () => {
  const c = enabled(), index = { ...c, selection: { ...c.selection, summary: { ...c.selection.summary, action: 'stage' } } };
  assert.ok(parseGitCommitAccess(c)); assert.equal(parseGitIndexAccess(c), null);
  assert.equal(parseGitCommitAccess(index), null); assert.ok(parseGitIndexAccess(index));
  assert.equal(copyGitIndexApproval(approval()), null);
  assert.ok(parseGitCommitAccess(empty()));
  for (const changed of [{ remainingMs: 900001 }, { consumed: true }, { projectId: id('0') }, { message: 'leaked' }]) assert.equal(parseGitCommitAccess({ ...c, ...changed }), null);
  assert.equal(parseGitCommitAccess({ ...c, selection: { ...c.selection, paths: ['other/b', 'app/a'] } }), null);
});
test('only native three-command private approval route is exposed and result with draft is refused', async () => {
  const calls = []; const api = createGitCommitApi('native', async (command, raw) => { calls.push({ command, input: JSON.parse(new TextDecoder().decode(raw)) }); return command === 'revoke_agent_git_commit' ? empty() : enabled(); });
  assert.equal(createGitCommitApi('preview', () => { throw Error('must not call'); }), null);
  await api.allow(approval(), '0'); await api.status(); await api.revoke();
  assert.deepEqual(calls.map(c => c.command), ['allow_agent_git_commit', 'agent_git_commit_access', 'revoke_agent_git_commit']);
  assert.deepEqual(calls[0].input, { ...approval(), expectedPermissionRevision:'0',consentVersion: GIT_COMMIT_CONSENT });
  const bad = createGitCommitApi('native', async () => ({ ...enabled(), message: 'do not forward' }));
  await assert.rejects(bad.status(), e => e.code === 'agent_git_commit_unconfirmed' && !JSON.stringify(e).includes('do not forward'));
});
test('read access or draft entry alone never invokes Allow', async () => {
  const { c, calls } = controller(); await c.allow(); assert.equal(calls.length, 0);
  await checked(c, calls); c.acknowledge(true); const p = c.allow(); assert.equal(calls[1].kind, 'allow');
  assert.deepEqual(calls[1].input, approval()); calls[1].resolve(enabled()); await p;
  assert.equal(c.getState().acknowledged, false);
});
test('same retained finite controller blocks reentrant revoke then fresh Allow', async () => {
  const { c, calls } = controller(); let stop; const unsub = c.subscribe(s => { if (s.pending === 'allow' && !stop) stop = c.revoke(); });
  await checked(c, calls); c.acknowledge(true); const pending = c.allow(); assert.deepEqual(calls.map(c => c.kind), ['status','revoke']);
  calls[1].resolve(empty()); await stop; await pending; unsub(); assert.equal(c.getState().access.enabled, false);
});
test('event-time private message or author change invalidates approval before invocation', async () => {
  for (const changed of [{ message: 'changed' }, { authorEmail: 'other@example.invalid' }]) {
    const { c, calls, set, api } = controller(); await checked(c, calls); c.acknowledge(true); set({ api, project: { ...approval(), ...changed }, blocked: false });
    await c.allow(); assert.equal(calls.length, 1); assert.equal(c.getState().acknowledged, false);
  }
});
test('late private-draft change cannot adopt acknowledged grant or silently retry', async () => {
  const { c, calls, set, api } = controller(); await checked(c, calls); c.acknowledge(true); const pending = c.allow();
  set({ api, project: { ...approval(), message: 'not approved' }, blocked: false }); c.syncContext(); calls[1].resolve(enabled()); await pending;
  assert.equal(c.getState().uncertain, true); c.acknowledge(true); await c.allow(); assert.equal(calls.length, 2);
  const stop = c.revoke(); calls[2].resolve(empty()); await stop; assert.equal(c.getState().uncertain, false);
});
test('rebind after status retains original connection for STOP and cannot grant on another host', async () => {
  const old = port(), fresh = port(), { c, set } = controller(old); const pending = c.status();
  set({ api: fresh.api, project: approval(), blocked: false }); c.syncContext(); old.calls[0].resolve(enabled()); await pending;
  c.acknowledge(true); await c.allow(); assert.equal(fresh.calls.length, 0);
  const stop = c.revoke(); assert.equal(old.calls[1].kind, 'revoke'); old.calls[1].resolve(empty()); await stop;
});
test('unknown or late Allow after acknowledged STOP never resurrects or infers native cleanup', async () => {
  const { c, calls } = controller(); await checked(c, calls); c.acknowledge(true); const allow = c.allow(); const stop = c.revoke();
  calls[2].resolve(empty()); await stop; calls[1].resolve(enabled()); await allow; assert.equal(c.getState().access.enabled, false);
  const observed = c.status(); calls[3].reject(Error('private native diagnostic')); await observed;
  assert.ok(!JSON.stringify(c.getState()).includes('private native diagnostic'));
});
