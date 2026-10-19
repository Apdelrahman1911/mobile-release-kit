// Existing reducer DATA and inert callback/landmark doubles only. No DOM,
// native save, file reads, timers, project commands or browser automation.
import assert from 'node:assert/strict';
import test from 'node:test';
import { initialWorkspace, workspaceReducer as reduce } from '../src/drafts.ts';
import { CONFIGURATION_SAVE_REVIEW_ID, beginDraftSaveFromClick, draftSaveActions, revealConfigurationSaveReview } from '../src/draftSaveActions.ts';

const reasons = (overrides = {}) => ({ save: null, discard: null, validate: null, review: null, ...overrides });
const error = { code: 'SyntheticCheckFailure', message: 'The inert check failed.', retryable: false };
function loaded() {
  let state = reduce(initialWorkspace, { type: 'select', project: { id: 'inert', name: 'Example app', path: '/inert/never-opened' } });
  state = reduce(state, { type: 'snapshot-start', projectId: 'inert', requestId: 1 });
  return reduce(state, { type: 'snapshot-done', projectId: 'inert', requestId: 1, observedAt: 1,
    snapshot: { root: '/inert/never-opened', config: { path: 'release/mobile-release.json', state: 'format-valid',
      content: null, data: { schemaVersion: 1, android: { enabled: true } }, issues: [] }, issues: [] } });
}
const session = (state) => state.projects.inert;
function start(state, kind) {
  const current = session(state);
  return kind === 'validate' ? reduce(state, { type: 'validate-start', projectId: 'inert', requestId: 2,
    revision: current.revision, baselineGeneration: current.baselineGeneration }) :
    reduce(state, { type: 'review-start', projectId: 'inert', binding: { id: 2, revision: current.revision, baselineGeneration: current.baselineGeneration } });
}

test('ordinary actions preserve the original capability gates, with no check result interpreted as save authority', () => {
  const current = session(loaded());
  assert.deepEqual(draftSaveActions(current, reasons()), { saveDisabled: false, discardDisabled: true,
    validateDisabled: false, reviewDisabled: false, checksForcedOpen: false });
  for (const save of ['Native writer unavailable.', 'Another original task is pending.', 'Browser preview.', 'Review is stale.'])
    assert.equal(draftSaveActions(current, reasons({ save })).saveDisabled, true);
  assert.equal(draftSaveActions(current, reasons({ validate: 'Unavailable.' })).validateDisabled, true);
  assert.equal(draftSaveActions(current, reasons({ review: 'Unavailable.' })).reviewDisabled, true);
  const formatOnly = { ...current, validation: { valid: true, state: 'format-valid' }, validatedRevision: current.revision,
    validatedBaselineGeneration: current.baselineGeneration };
  assert.equal(draftSaveActions(formatOnly, reasons({ save: 'Original save is unavailable.' })).saveDisabled, true);
});

test('pending validation or comparison keeps both original check controls open and disabled until settlement', () => {
  for (const kind of ['validate', 'review']) {
    const pending = session(start(loaded(), kind));
    const view = draftSaveActions(pending, reasons({ save: 'Original check pending.' }));
    assert.equal(view.checksForcedOpen, true); assert.equal(view.validateDisabled, true);
    assert.equal(view.reviewDisabled, true); assert.equal(view.saveDisabled, true);
  }
});

test('real reducer read failures force open check controls while leaving error data available outside the disclosure', () => {
  for (const kind of ['validate', 'review']) {
    const pending = start(loaded(), kind), draft = session(pending).draft;
    const failed = reduce(pending, { type: `${kind}-failed`, projectId: 'inert', requestId: 2, error });
    const current = session(failed), view = draftSaveActions(current, reasons());
    assert.equal(current.draft, draft); assert.equal(view.checksForcedOpen, true);
    assert.equal(current[kind === 'validate' ? 'validationError' : 'reviewError'], error);
    assert.equal(view.validateDisabled, false); assert.equal(view.reviewDisabled, false);
  }
});

test('discard still requires actual draft, external-change or retained-undo content and original close authority', () => {
  const state = loaded(), clean = session(state);
  assert.equal(draftSaveActions(clean, reasons()).discardDisabled, true);
  const changed = session(reduce(state, { type: 'edit', projectId: 'inert', path: 'android.enabled', value: false }));
  for (const current of [changed, { ...clean, sourceChanged: true }, { ...clean, removedFields: [{ id: 1, path: 'inert', value: 'kept', blocked: false }] }]) {
    assert.equal(draftSaveActions(current, reasons()).discardDisabled, false);
    assert.equal(draftSaveActions(current, reasons({ discard: 'Keep original draft until native settlement.' })).discardDisabled, true);
  }
});

test('computing action presentation never edits, adopts, discards or saves the actual reducer draft or baseline', () => {
  const state = reduce(loaded(), { type: 'edit', projectId: 'inert', path: 'android.enabled', value: false });
  const before = structuredClone(state), draft = session(state).draft, baseline = session(state).baseline;
  for (let i = 0; i < 3; i += 1) draftSaveActions(session(state), reasons());
  assert.deepEqual(state, before); assert.equal(session(state).draft, draft); assert.equal(session(state).baseline, baseline);
  assert.equal(session(state).lastSave, null);
});

test('a disabled save click neither invokes preparation nor searches/focuses another section', () => {
  const calls = [];
  beginDraftSaveFromClick('Original native owner is busy.', () => calls.push('prepare'), () => calls.push('reveal'));
  assert.deepEqual(calls, []);
});

test('one explicit save click invokes original Prepare exactly once then reveals only the fixed existing landmark', () => {
  const calls = [];
  beginDraftSaveFromClick(null, () => calls.push('prepare'), () => {
    const found = revealConfigurationSaveReview((id) => {
      calls.push(['find', id]);
      return { focus: (options) => calls.push(['focus', options]), scrollIntoView: (options) => calls.push(['scroll', options]) };
    });
    assert.equal(found, true, 'only a landmark lookup result, not native save success');
  });
  assert.deepEqual(calls, ['prepare', ['find', CONFIGURATION_SAVE_REVIEW_ID], ['focus', { preventScroll: true }], ['scroll', { block: 'start' }]]);
  assert.equal(CONFIGURATION_SAVE_REVIEW_ID, 'configuration-save-review');
});

test('save handoff does not await a result or focus again after unrelated asynchronous completion', async () => {
  const calls = []; let finish;
  const pending = new Promise((resolve) => { finish = resolve; });
  beginDraftSaveFromClick(null, () => { calls.push('prepare'); return pending; }, () => calls.push('reveal'));
  assert.deepEqual(calls, ['prepare', 'reveal']);
  finish(); await pending; await Promise.resolve();
  assert.deepEqual(calls, ['prepare', 'reveal']);
});

test('an absent save landmark performs no fallback navigation, extra native call or fabricated success', () => {
  const calls = [];
  const returned = beginDraftSaveFromClick(null, () => calls.push('prepare'), () => {
    assert.equal(revealConfigurationSaveReview((id) => { calls.push(['find', id]); return null; }), false);
  });
  assert.equal(returned, undefined); assert.deepEqual(calls, ['prepare', ['find', 'configuration-save-review']]);
});

test('a synchronous original callback error is not swallowed, converted to success, retried or deferred', () => {
  const original = new Error('Synthetic callback failure.'), calls = [];
  assert.throws(() => beginDraftSaveFromClick(null, () => { calls.push('prepare'); throw original; }, () => calls.push('reveal')), (value) => value === original);
  assert.deepEqual(calls, ['prepare']);
});
