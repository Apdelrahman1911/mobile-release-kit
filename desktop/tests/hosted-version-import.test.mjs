// Passive DATA/real UI-controller fixtures only, not native or hosted proof.
import assert from 'node:assert/strict';
import test from 'node:test';
import { captureHostedImportGit, hostedImportCommitMessage, hostedImportGitUnchanged, parseHostedVersionProposal,
  sameHostedImportService } from '../src/hostedVersionImport.ts';
import { canonical, gitFixture, modifiedVersion, workflowResult } from './hosted-version-import.fixture.mjs';

test('canonical workflow line accepts both preserved two-component and three-component names; no offsets or authority survive', () => {
  for (const name of ['1.2', '1.2.3']) {
    const input = workflowResult({ name, build: 10000 });
    const parsed = parseHostedVersionProposal(canonical(input) + '\n');
    assert.ok(parsed); assert.equal(parsed.build, '10000'); assert.equal(parsed.name, name);
    assert.equal(Object.hasOwn(parsed, 'authorityVariable'), false); assert.equal(Object.hasOwn(parsed, 'replacements'), false);
    assert.equal(Object.hasOwn(parsed, 'reservationId'), false); assert.ok(Object.isFrozen(parsed));
    assert.equal(hostedImportCommitMessage(parsed), `Update version to ${name} (build 10000)\n\n${input.commitTrailer}`);
  }
});
test('raw bound, canonical duplicate refusal and exact unchanged unverified fields apply before import', () => {
  const raw = canonical(workflowResult());
  let touched = false; const object = { get sourceCommit() { touched = true; return 'a'.repeat(40); } };
  for (const input of [object, null, raw + '\n\n', raw + '\r\n', ' ' + raw, raw.replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1'),
      raw + ' '.repeat(8193), JSON.stringify(workflowResult(), null, 2), raw.replace('"schemaVersion":1', '"schemaVersion":1.0')]) {
    assert.equal(parseHostedVersionProposal(input), null);
  }
  assert.equal(touched, false);
  for (const change of [v => delete v.sourceRef, v => delete v.configSha256, v => { v.verified = true; }, v => { v.releaseEligibility = 'ready'; },
      v => { v.sourceRef = 'refs/tags/v1'; }, v => { v.sourceRef = 'refs/heads/a/../b'; }, v => { v.sourceCommit += '\n'; },
      v => { v.versionFile.path = '../outside'; }, v => { v.commitTrailer += '\nOther: yes'; }, v => { v.version.name = '01.2'; },
      v => { v.version.build = 0; }, v => { v.version.build = 2100000001; }, v => { v.version.build = '8'; },
      v => { v.versionFile.replacements[0].value = 'different'; }, v => { v.versionFile.replacements[1].value = '08'; },
      v => { v.versionFile.replacements[0].end = 3; }, v => { v.versionFile.replacements[0].start = -1; },
      v => { v.versionFile.replacements[0].end = v.versionFile.replacements[0].start; },
      v => { v.versionFile.replacements[0].end = 65537; }, v => { v.versionFile.replacements.push(v.versionFile.replacements[0]); }]) {
    const v = workflowResult(); change(v); assert.equal(parseHostedVersionProposal(canonical(v)), null);
  }
});
test('same actual successful Observe and repository view are required, not a status-shaped result or stale source', async () => {
  const git = await gitFixture(), p = parseHostedVersionProposal(canonical(workflowResult()));
  const captured = captureHostedImportGit(git.source(), p, 'before-open'); assert.ok(captured);
  assert.equal(hostedImportGitUnchanged(captured, git.source()), true);
  const calls = git.calls.length;
  assert.equal(sameHostedImportService(captured.source, { ...git.source(), session: {} }), false);
  assert.equal(captureHostedImportGit({ ...git.source(), projectId: 'foreign' }, p, 'before-open'), null);
  assert.equal(captureHostedImportGit(git.source(), { ...p, sourceCommit: 'b'.repeat(40) }, 'before-open'), null);
  assert.equal(captureHostedImportGit(git.source(), { ...p, sourceRef: 'refs/heads/other' }, 'before-open'), null);
  git.invalidate(); assert.equal(hostedImportGitUnchanged(captured, git.source()), false);
  assert.equal(captureHostedImportGit(git.source(), p, 'before-open'), null); assert.equal(git.calls.length, calls);
  await git.refresh(); assert.ok(captureHostedImportGit(git.source(), p, 'before-open'));
  // Idle status carries no new Observe payload and must not authorize reuse.
  await git.reader.checkStatus(); assert.equal(captureHostedImportGit(git.source(), p, 'before-open'), null);
});
test('post-save comparison permits only the one regular modified version path, without starting or staging anything', async () => {
  const git = await gitFixture(), p = parseHostedVersionProposal(canonical(workflowResult()));
  assert.equal(captureHostedImportGit(git.source(), p, 'after-save'), null);
  await git.refresh(modifiedVersion()); assert.ok(captureHostedImportGit(git.source(), p, 'after-save'));
  assert.equal(captureHostedImportGit(git.source(), p, 'before-open'), null);
  for (const changes of [[...modifiedVersion(), { path: 'other.txt', kind: 'file', index: 'M', worktree: ' ', conflict: false }],
      [{ ...modifiedVersion()[0], kind: 'symlink' }], [{ ...modifiedVersion()[0], path: 'another.properties' }],
      [{ ...modifiedVersion()[0], index: 'M' }]]) {
    await git.refresh(changes); assert.equal(captureHostedImportGit(git.source(), p, 'after-save'), null);
  }
  assert.ok(git.calls.every(([kind]) => kind === 'start' || kind === 'status'));
});
