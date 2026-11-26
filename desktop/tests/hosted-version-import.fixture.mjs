// Inert DATA and real UI controllers, with a closed in-memory native read port.
// No Git/process/filesystem/network/native operation or native receipt proof.
import assert from 'node:assert/strict';
import { GitReadController } from '../src/gitReadController.ts';
import { GitRepositoryController } from '../src/gitRepositoryController.ts';
import { parseGitReadStartResult } from '../src/gitReadProtocol.ts';

export const HEAD = 'a'.repeat(40), REF = 'refs/heads/main', PATH = 'public/version.properties';
export const canonical = value => value !== null && typeof value === 'object' ? Array.isArray(value) ?
  '[' + value.map(canonical).join(',') + ']' : '{' + Object.keys(value).sort().map(key => canonical(key) + ':' + canonical(value[key])).join(',') + '}' :
  JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
export function workflowResult({ name = '2.3.4', build = 8, config = 'b'.repeat(64), before = 'c'.repeat(64), after = 'd'.repeat(64), path = PATH } = {}) {
  const candidateId = '12345678-1234-4abc-8abc-123456789abc', rowSha256 = 'e'.repeat(64);
  return { schemaVersion: 1, status: 'reserved', candidateId, rowSha256, sourceCommit: HEAD, sourceRef: REF, configSha256: config,
    version: { name, build }, releaseEligibility: 'not-established', historicalUniqueness: 'not-established', sourceWrite: 'not-performed',
    authorityVariable: '{}', commitTrailer: `MRK-Version-Reservation: ${candidateId} ${rowSha256}`,
    versionFile: { path, beforeSha256: before, afterSha256: after,
      replacements: [{ start: 0, end: 1, value: name }, { start: 2, end: 3, value: String(build) }] } };
}
export async function gitFixture() {
  let documentRevision = 1, sequence = 0, next = null;
  const calls = [], source = { session: {}, projectId: 'p', epoch: 0, repository: null, reader: null };
  const status = operation => ({ schemaVersion: 1, documentRevision, available: true, operation });
  const api = {
    status: async raw => { calls.push(['status', JSON.parse(new TextDecoder().decode(raw))]); return status(null); },
    start: async raw => {
      const request = JSON.parse(new TextDecoder().decode(raw)); calls.push(['start', request]);
      assert.equal(request.action.kind, 'observe');
      const reply = { schemaVersion: 1, admission: 'started', request, reason: null,
        status: status({ operationId: `inert-read-${++sequence}`, context: { projectId: source.projectId, generation: 1, revision: `document-${documentRevision}` },
          action: request.action, phase: 'settled', outcome: 'ok', reason: null, result: next }) };
      assert.ok(parseGitReadStartResult(reply)); return reply;
    },
    cancel: async () => { assert.fail('no new read cancellation is expected'); },
  };
  const reader = new GitReadController({ current: () => ({ api, session: source.session, projectId: source.projectId, epoch: source.epoch, blocked: null }) });
  source.reader = reader; reader.syncContext();
  source.repository = new GitRepositoryController('p', reader.port('p'));
  const fixture = { source: () => source, reader, repository: source.repository, calls,
    invalidate: () => { source.epoch += 1; reader.beforeContextIntent(); reader.syncContext(); source.repository.invalidate(); },
    change: values => { Object.assign(source, values); },
    refresh: async (changes = [], overrides = {}) => {
      documentRevision += 1;
      next = { observation: { revision: String(sequence + 1).padStart(64, '0'), head: HEAD, branch: REF, unborn: false, detached: false,
          changes, remotes: [], restrictions: [], ...overrides }, referenceRevision: 'f'.repeat(64), basis: 'local-refs-no-fetch',
        tracking: { state: 'not-configured', remote: null, mergeRef: null, localRef: null, head: null, ahead: null, behind: null } };
      await reader.checkStatus(); assert.equal(await source.repository.refresh(), true);
      assert.equal(source.repository.getSnapshot().stale, false); assert.equal(reader.ownerReason(), null);
    },
  };
  await fixture.refresh(); return fixture;
}
export const modifiedVersion = () => [{ path: PATH, index: ' ', worktree: 'M', kind: 'file', conflict: false }];
