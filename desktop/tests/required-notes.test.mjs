// Focused DTO/controller/bridge and App SOURCE-binding regressions. No DOM or
// installed/native picker, transaction, Store, process or native finality is
// exercised here. App text assertions are not mounted-application qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createNativeApi } from '../src/bridge.ts';
import guide from '../../src/mobile_release/api/data/required-notes-help-v1.json' with { type: 'json' };
import { RequiredNotesController } from '../src/requiredNotesController.ts';
import { parseRequiredNotesGuide, parseRequiredNotesLoaded, parseRequiredNotesPrepared,
  parseRequiredNotesRoutineStatus, parseRequiredNoteValidation, REQUIRED_NOTE_ISSUES,
  parseRequiredNotesCapabilities, parseRequiredNotesPreparedReply, parseRequiredNotesStatusReply, parseRequiredNotesRoutineEnvelope,
  parseRequiredNotesImportReply, parseRequiredNotesImportStatusReply, parseRequiredNotesImportEnvelope,
  encodeRequiredNotesRequest, requiredNotesRequestFits, requiredNotesError, requiredNotesCapabilityMessage,
  requiredNotesImportProgress, REQUIRED_NOTES_EVENT, REQUIRED_NOTES_IMPORT_EVENT } from '../src/requiredNotesProtocol.ts';

const context = { kind: 'ios-beta-review' };
const scope = { projectId: 'fixture-project', projectName: 'Synthetic project', windowGeneration: 'a'.repeat(32), configGeneration: 1, serviceGeneration: 1, context };
const originalText = 'Review the synthetic fixture screen.';
const nextText = 'Also review the second synthetic fixture screen.';
const clone = (value) => structuredClone(value);
const digest = (text) => ({ byteLength: Buffer.byteLength(text), sha256: createHash('sha256').update(text).digest('hex') });
function validation(text = originalText) {
  return { schemaVersion: 1, kind: context.kind, valid: true, state: 'format-valid', rawByteCount: Buffer.byteLength(text),
    characterCount: [...text].length, characterLimit: null, outboundCharacterCount: [...text].length, editorByteLimit: 32768, issues: [] };
}
function loaded(text = originalText) {
  return { schemaVersion: 1, type: 'required-notes-loaded', projectId: scope.projectId, windowGeneration: scope.windowGeneration,
    selection: { context: clone(context), metadataRoot: 'release/store', destination: 'release/store/review/ios-beta-notes.txt', savedBuild: null, effective: null },
    baseline: { config: digest('{}'), version: null, note: { state: 'present', ...digest(text) }, counterpart: null },
    original: { state: 'present', text }, validation: validation(text) };
}
function prepared(text = nextText) {
  const l = loaded();
  return { schemaVersion: 1, type: 'required-notes-prepared', projectId: scope.projectId, windowGeneration: scope.windowGeneration,
    ownerGeneration: 'b'.repeat(32), sessionId: 'c'.repeat(32), revision: 'd'.repeat(32), planToken: 'e'.repeat(32), draftRevision: 1,
    selection: l.selection, baseline: l.baseline, before: l.original, after: text, action: text === originalText ? 'preserve' : 'replace',
    createDirectories: [], validation: validation(text) };
}
function status(overrides = {}) {
  return { schemaVersion: 1, domain: 'required_notes', projectId: scope.projectId, windowGeneration: scope.windowGeneration,
    ownerGeneration: 'b'.repeat(32), sessionId: 'c'.repeat(32), revision: 'd'.repeat(32), planToken: 'e'.repeat(32),
    context: clone(context), draftRevision: 1, statusRevision: 2, phase: 'reviewing', applySubmitted: false,
    coreOutcome: null, nativeReason: 'none', nativeFinality: 'pending', lateSettled: false, ...overrides };
}
function finalStatus(overrides = {}) {
  return status({ phase: 'final', statusRevision: 4, applySubmitted: true, nativeFinality: 'settled',
    coreOutcome: { effect: 'committed', journal: 'clean', resources: 'settled', reason: 'none' }, ...overrides });
}
function routine(controller, value) { return { requestId: controller.originalEdit().requestId, status: value }; }
function prepareReply(request, value = prepared()) { return { requestId: request.id, prepared: value }; }
function importStatus(request, overrides = {}) {
  return { schemaVersion: 1, requestId: request.id, windowGeneration: request.scope.windowGeneration,
    projectId: request.scope.projectId, context: clone(request.scope.context), phase: 'settled', outcome: 'selected', reason: 'none', ...overrides };
}
function importReply(request, result = imported(), overrides = {}) {
  return { requestId: request.id, result, status: importStatus(request, {
    outcome: result?.state ?? 'refused', reason: result?.state === 'cancelled' ? 'cancelled' : result === null ? 'invalid_file' : 'none', ...overrides,
  }) };
}
function closeStatus(overrides = {}) {
  return finalStatus({ applySubmitted: false, nativeReason: 'discarded',
    coreOutcome: { effect: 'not_started', journal: 'not_created', resources: 'settled', reason: 'none' }, ...overrides });
}
function controllerAtDraft() {
  const controller = new RequiredNotesController();
  assert.equal(controller.setScope(scope), true);
  const request = controller.beginLoad();
  assert.equal(controller.complete(request, loaded()), true);
  assert.equal(controller.edit(nextText), true);
  return controller;
}
function controllerAtReview() {
  const controller = controllerAtDraft();
  const check = controller.beginValidate();
  assert.equal(controller.complete(check, validation(nextText)), true);
  const request = controller.beginPrepare();
  assert.equal(controller.complete(request, prepareReply(request)), true);
  return controller;
}

test('one guide covers every fixed note, its audience and practical origin/format/failure help', () => {
  assert.deepEqual(parseRequiredNotesGuide(guide), guide);
  assert.deepEqual(guide.fields.map((row) => row.id), ['android-build', 'android-default', 'ios-beta-review', 'ios-app-review', 'testflight-what-to-test']);
  assert.match(guide.fields[1].failure, /invalid exact-build/);
  assert.match(guide.fields[2].format, /not Apple acceptance/);
  assert.match(guide.actions.find((row) => row.id === 'import').where, /never moved or modified/);
});

test('private direct DTOs cannot be broadcast as routine status and field injection fails closed', () => {
  assert.deepEqual(parseRequiredNotesLoaded(loaded()), loaded());
  assert.deepEqual(parseRequiredNotesPrepared(prepared()), prepared());
  assert.equal(parseRequiredNotesRoutineStatus(loaded()), null);
  assert.equal(parseRequiredNotesRoutineStatus(prepared()), null);
  for (const field of ['text', 'sha256', 'baseline', 'before', 'after', 'prepared', 'validation', 'path']) {
    assert.equal(parseRequiredNotesRoutineStatus({ ...status(), [field]: 'synthetic-private-marker' }), null);
  }
  const s = status();
  assert.deepEqual(parseRequiredNotesRoutineStatus(s), s);
  assert.ok(!JSON.stringify(s).includes(originalText));
  assert.equal(parseRequiredNotesRoutineStatus(status({ nativeReason: originalText })), null);
});

test('closed context avoids invoking a getter and refuses arbitrary filename/version routing', () => {
  let invoked = false;
  const c = {}; Object.defineProperty(c, 'kind', { enumerable: true, get() { invoked = true; return context.kind; } });
  assert.equal(parseRequiredNotesRoutineStatus(status({ context: c })), null);
  assert.equal(invoked, false);
  for (const extra of [{ path: 'other.txt' }, { locale: 'en-US' }, { build: 42 }]) {
    assert.equal(parseRequiredNotesRoutineStatus(status({ context: { ...context, ...extra } })), null);
  }
  const other = loaded(); other.selection.destination = 'release/store/review/ios-notes.txt';
  assert.equal(parseRequiredNotesLoaded(other), null);
});

test('sensitive originals and raw parser messages are not accepted for private editing', () => {
  const l = loaded(); l.validation.valid = false; l.validation.state = 'invalid';
  l.validation.issues = [{ code: 'metadata.secret-pattern', message: REQUIRED_NOTE_ISSUES['metadata.secret-pattern'] }];
  assert.equal(parseRequiredNotesLoaded(l), null);
  const v = validation(); v.valid = false; v.state = 'invalid'; v.issues = [{ code: 'metadata.placeholder', message: originalText }];
  assert.equal(parseRequiredNoteValidation(v), null);
});

test('current explicit private review AND matching content-free owner status are needed before one-use Apply', () => {
  const controller = controllerAtReview();
  assert.equal(controller.canApply(), false);
  assert.equal(controller.acceptRoutineStatus(routine(controller, status({ sessionId: 'f'.repeat(32) }))), false);
  assert.equal(controller.acceptRoutineStatus(routine(controller, status())), true);
  assert.equal(controller.canApply(), true);
  const apply = controller.beginApply();
  assert.deepEqual(apply.input, { sessionId: 'c'.repeat(32), planToken: 'e'.repeat(32) });
  assert.equal(controller.beginApply(), null);
  assert.equal(controller.edit('late edit'), false);
  assert.equal(controller.complete(apply, routine(controller, finalStatus())), true);
  assert.equal(controller.snapshot().result, 'saved');
  assert.equal(controller.snapshot().needsReload, true);
  assert.equal(controller.beginPrepare(), null);
  assert.equal(controller.edit('edit before actual saved read'), false);
});

test('final event before direct acknowledgement retains stronger finality and never rebroadcasts private view', () => {
  const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
  const apply = controller.beginApply();
  assert.equal(controller.acceptRoutineStatus(routine(controller, finalStatus())), true);
  assert.equal(controller.snapshot().prepared, null);
  assert.equal(controller.complete(apply, routine(controller, status({ phase: 'applying', statusRevision: 3, applySubmitted: true }))), true);
  assert.equal(controller.snapshot().result, 'saved');
  assert.equal(controller.snapshot().unsettled, false);
  assert.equal(controller.snapshot().status.statusRevision, 4);
});

test('failure or cleanup uncertainty never counts as Save, never retries and keeps the draft', () => {
  const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
  const apply = controller.beginApply();
  controller.fail(apply);
  assert.equal(controller.snapshot().unsettled, true);
  assert.equal(controller.beginApply(), null);
  assert.equal(controller.snapshot().draft, nextText);
  assert.equal(controller.acceptRoutineStatus(routine(controller, status({ phase: 'unknown', statusRevision: 3, applySubmitted: true,
    nativeReason: 'cleanup_unknown', nativeFinality: 'unknown', coreOutcome: { effect: 'unknown', journal: 'unknown', resources: 'unknown', reason: 'custody_unknown' } }))), true);
  assert.equal(controller.snapshot().result, null);
  assert.equal(controller.discardDraft(true), false);
});

test('baseline or saved-build/context disagreement cannot produce a review', () => {
  for (const modify of [
    (p) => { p.baseline.config.sha256 = 'f'.repeat(64); },
    (p) => { p.draftRevision = 2; },
    (p) => { p.selection.savedBuild = 42; },
    (p) => { p.after = 'Different submitted copy'; p.validation = validation(p.after); },
  ]) {
    const controller = controllerAtDraft(); controller.complete(controller.beginValidate(), validation(nextText));
    const request = controller.beginPrepare(), p = prepared(); modify(p);
    assert.equal(controller.complete(request, prepareReply(request, p)), false);
    assert.equal(controller.snapshot().prepared, null);
    assert.equal(controller.snapshot().unsettled, true);
    assert.equal(controller.snapshot().draft, nextText);
  }
});

test('cancelled/refused native text import leaves the old draft/baseline intact', () => {
  const controller = controllerAtDraft(), before = clone(controller.snapshot().loaded);
  assert.equal(controller.beginImport(), null);
  const cancelled = controller.beginImport(true);
  assert.deepEqual(cancelled.input, { kind: context.kind });
  assert.equal(controller.complete(cancelled, importReply(cancelled, { schemaVersion: 1, type: 'required-notes-import', state: 'cancelled' })), true);
  assert.equal(controller.snapshot().draft, nextText);
  const refused = controller.beginImport(true);
  assert.equal(controller.complete(refused, importReply(refused, { schemaVersion: 1, type: 'required-notes-import', state: 'selected', kind: context.kind, path: '/not-a-native-proof' })), false);
  assert.equal(controller.snapshot().draft, nextText);
  assert.deepEqual(controller.snapshot().loaded, before);
  assert.equal(controller.snapshot().unsettled, true);
  assert.equal(controller.beginImport(true), null);
  // A malformed direct reply is not a settled refusal. Only matching original
  // content-free settlement may release that lost-call gate.
  assert.equal(controller.acceptImportStatus({ requestId: refused.id,
    status: importStatus(refused, { outcome: 'refused', reason: 'invalid_file' }) }), true);
  const imported = controller.beginImport(true), importedText = 'Reviewed imported fixture.';
  assert.equal(controller.complete(imported, importReply(imported, { schemaVersion: 1, type: 'required-notes-import', state: 'selected', kind: context.kind, text: importedText, validation: validation(importedText) })), true);
  assert.equal(controller.snapshot().draft, importedText);
  assert.equal(controller.snapshot().result, null);
});

test('external context invalidation refuses a late Load and preserves unsaved text until explicit discard', () => {
  const controller = controllerAtDraft(), request = controller.beginLoad(true);
  assert.equal(controller.setScope({ ...scope, projectId: 'other' }, true), false);
  controller.invalidateContext();
  assert.equal(controller.complete(request, loaded('Late different saved text.')), false);
  assert.equal(controller.snapshot().draft, nextText);
  assert.equal(controller.beginValidate(), null);
  assert.equal(controller.setScope({ ...scope, projectId: 'other' }), false);
  assert.equal(controller.setScope({ ...scope, projectId: 'other' }, true), true);
  assert.equal(controller.snapshot().draft, '');
  assert.equal(controller.snapshot().loaded, null);
});


function imported(text = 'Imported synthetic review notes.') {
  return { schemaVersion: 1, type: 'required-notes-import', state: 'selected', kind: context.kind, text, validation: validation(text) };
}

test('Import completion cannot overwrite a synchronous discard or newly selected project', () => {
  for (const action of ['discard', 'switch']) {
    const controller = controllerAtDraft(), request = controller.beginImport(true);
    let reacted = false;
    controller.subscribe(() => {
      if (reacted || controller.snapshot().pending !== null) return;
      reacted = true;
      if (action === 'discard') assert.equal(controller.discardDraft(true), true);
      else assert.equal(controller.setScope({ ...scope, projectId: 'new-project' }, true), true);
    });
    assert.equal(controller.complete(request, importReply(request)), true);
    assert.equal(reacted, true);
    assert.equal(controller.snapshot().scope.projectId, action === 'discard' ? scope.projectId : 'new-project');
    assert.equal(controller.snapshot().draft, '');
    assert.equal(controller.snapshot().loaded, null);
    assert.equal(controller.snapshot().validation, null);
    assert.equal(controller.snapshot().result, null);
  }
});

test('Import completion preserves a synchronous newer edit and its new validation request', () => {
  const controller = controllerAtDraft(), request = controller.beginImport(true);
  let newer = null, reacted = false;
  controller.subscribe(() => {
    if (reacted || controller.snapshot().pending !== null) return;
    reacted = true;
    assert.equal(controller.edit('Newer user-authored synthetic notes.'), true);
    newer = controller.beginValidate();
    assert.ok(newer);
  });
  assert.equal(controller.complete(request, importReply(request)), true);
  assert.equal(controller.snapshot().draft, 'Newer user-authored synthetic notes.');
  assert.equal(controller.snapshot().draftRevision, newer.draftRevision);
  assert.equal(controller.snapshot().validation, null);
  assert.equal(controller.snapshot().pending, 'validate');
  assert.equal(controller.complete(newer, validation(newer.input.text)), true);
});

test('final Apply publishes its saved result and reload gate before a synchronous listener can edit', () => {
  for (const direct of [true, false]) {
    const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
    const apply = controller.beginApply();
    if (!direct) assert.equal(controller.complete(apply, routine(controller, status({ phase: 'applying', statusRevision: 3, applySubmitted: true }))), true);
    let final = null, edited = null;
    controller.subscribe(() => {
      if (final || controller.snapshot().status?.phase !== 'final') return;
      final = clone(controller.snapshot());
      edited = controller.edit('This different draft was never saved.');
    });
    assert.equal(direct ? controller.complete(apply, routine(controller, finalStatus())) : controller.acceptRoutineStatus(routine(controller, finalStatus())), true);
    assert.equal(edited, false);
    assert.equal(final.result, 'saved');
    assert.equal(final.needsReload, true);
    assert.equal(final.prepared, null);
    assert.equal(controller.snapshot().draft, nextText);
    assert.equal(controller.dirty(), false);
  }
});

test('final Apply cannot overwrite a subscriber-selected project or its new Load', () => {
  const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
  const apply = controller.beginApply();
  let request = null, reacted = false;
  controller.subscribe(() => {
    if (reacted || controller.snapshot().status?.phase !== 'final') return;
    reacted = true;
    assert.equal(controller.setScope({ ...scope, projectId: 'new-project' }, true), true);
    request = controller.beginLoad();
    assert.ok(request);
  });
  assert.equal(controller.complete(apply, routine(controller, finalStatus())), true);
  assert.equal(controller.snapshot().scope.projectId, 'new-project');
  assert.equal(controller.snapshot().draft, '');
  assert.equal(controller.snapshot().loaded, null);
  assert.equal(controller.snapshot().result, null);
  assert.equal(controller.snapshot().error, null);
  assert.equal(controller.snapshot().needsReload, false);
  assert.equal(controller.snapshot().pending, 'load');
  const next = loaded(); next.projectId = 'new-project';
  assert.equal(controller.complete(request, next), true);
});

test('acknowledgement after the final event cannot poison a subscriber-selected project', () => {
  const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
  const apply = controller.beginApply();
  assert.equal(controller.acceptRoutineStatus(routine(controller, finalStatus())), true);
  let reacted = false;
  controller.subscribe(() => {
    if (reacted || controller.snapshot().pending !== null) return;
    reacted = true;
    assert.equal(controller.setScope({ ...scope, projectId: 'new-project' }, true), true);
  });
  assert.equal(controller.complete(apply, routine(controller, status({ phase: 'applying', statusRevision: 3, applySubmitted: true }))), true);
  assert.equal(reacted, true);
  assert.equal(controller.snapshot().scope.projectId, 'new-project');
  assert.equal(controller.snapshot().result, null);
  assert.equal(controller.snapshot().error, null);
  assert.equal(controller.snapshot().unsettled, false);
});


test('all nine required-note bridge commands send raw UTF8 JSON with exact original correlation', async () => {
  const requestId = 91, correlation = { requestId, windowGeneration: scope.windowGeneration };
  const request = { id: requestId, scope }, calls = [];
  const caps = { schemaVersion: 1, windowGeneration: scope.windowGeneration,
    read: { available: true, reason: 'none' }, edit: { available: true, reason: 'none' }, import: { available: true, reason: 'none' } };
  let expected = null;
  const api = createNativeApi('native', async (command, body) => {
    assert.ok(body instanceof Uint8Array);
    assert.equal(command, expected.command);
    const input = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(body));
    assert.deepEqual(input, expected.input);
    calls.push(command);
    return clone(expected.reply);
  });
  const observeInput = { projectId: scope.projectId, windowGeneration: scope.windowGeneration, context };
  const prepareInput = { ...observeInput, requestId, draftRevision: 1, expectedBaseline: loaded().baseline, text: nextText };
  const cases = [
    ['required_notes_capabilities', {}, caps, () => api.requiredNotesCapabilities()],
    ['required_notes_observe', observeInput, loaded(), () => api.observeRequiredNotes(observeInput)],
    ['required_notes_validate', { context, text: nextText }, validation(nextText), () => api.validateRequiredNotes({ context, text: nextText })],
    ['required_notes_import', { ...observeInput, requestId }, importReply(request), () => api.importRequiredNotes({ ...observeInput, requestId })],
    ['required_notes_edit_prepare', prepareInput, prepareReply(request), () => api.prepareRequiredNotes(prepareInput)],
    ['required_notes_edit_apply', { ...correlation, sessionId: prepared().sessionId, planToken: prepared().planToken },
      { requestId, status: finalStatus() }, () => api.applyRequiredNotes({ ...correlation, sessionId: prepared().sessionId, planToken: prepared().planToken })],
    ['required_notes_edit_close', { ...correlation, sessionId: prepared().sessionId },
      { requestId, status: closeStatus() }, () => api.closeRequiredNotes({ ...correlation, sessionId: prepared().sessionId })],
    ['required_notes_edit_status', correlation, { requestId, status: null }, () => api.requiredNotesStatus(correlation)],
    ['required_notes_import_status', correlation, { requestId, status: null }, () => api.requiredNotesImportStatus(correlation)],
  ];
  for (const [command, input, reply, call] of cases) {
    expected = { command, input, reply };
    assert.deepEqual(await call(), reply);
  }
  assert.equal(calls.length, 9);
  assert.equal(new Set(calls).size, 9);
});

test('read edit and import capabilities stay separate and validation uses only its transport ceiling', () => {
  const caps = { schemaVersion: 1, windowGeneration: scope.windowGeneration,
    read: { available: true, reason: 'none' }, edit: { available: false, reason: 'unqualified' },
    import: { available: false, reason: 'unsupported_platform' } };
  assert.deepEqual(parseRequiredNotesCapabilities(caps), caps);
  assert.equal(requiredNotesCapabilityMessage(caps.read), null);
  assert.match(requiredNotesCapabilityMessage(caps.edit), /not qualified/);
  assert.match(requiredNotesCapabilityMessage(caps.import), /not supported/);
  assert.equal(parseRequiredNotesCapabilities({ ...caps, edit: { available: true, reason: 'unqualified' } }), null);
  assert.equal(parseRequiredNotesCapabilities({ ...caps, windowGeneration: 'invented-window' }), null);
  assert.equal(parseRequiredNotesCapabilities({ ...caps, genericWriter: true }), null);
  const invalidAndroid = { context: { kind: 'android-build', locale: 'en-US' }, text: 'x'.repeat(2001) };
  assert.ok(encodeRequiredNotesRequest('required_notes_validate', invalidAndroid));
  const ceiling = { context, text: '😀'.repeat(65537) };
  assert.ok(encodeRequiredNotesRequest('required_notes_validate', ceiling));
  assert.equal(encodeRequiredNotesRequest('required_notes_validate', { ...ceiling, text: '😀'.repeat(65538) }), null);
  assert.equal(encodeRequiredNotesRequest('required_notes_validate', { context, text: '\ud800' }), null);
  assert.equal(requiredNotesRequestFits('required_notes_observe', { projectId: scope.projectId, windowGeneration: scope.windowGeneration, context, path: '/extra' }), false);
  assert.equal(requiredNotesRequestFits('required_notes_import_status', { requestId: 0x1_0000_0000, windowGeneration: scope.windowGeneration }), false);
  assert.equal(requiredNotesRequestFits('required_notes_edit_apply', { requestId: 1, windowGeneration: scope.windowGeneration, sessionId: prepared().sessionId, planToken: prepared().planToken, text: nextText }), false);
});

test('notes bridge errors use fixed safe codes without reflecting text or invoking error getters', async () => {
  let invoked = false;
  const poisoned = {};
  Object.defineProperty(poisoned, 'code', { enumerable: true, get() { invoked = true; return originalText; } });
  Object.defineProperty(poisoned, 'message', { enumerable: true, get() { invoked = true; return nextText; } });
  assert.equal(requiredNotesError(poisoned).code, 'required_notes_protocol');
  assert.equal(invoked, false);
  for (const failure of [originalText, { code: 'required_notes_invalid_file', message: originalText, cause: nextText }, poisoned]) {
    const api = createNativeApi('native', async () => { throw failure; });
    await assert.rejects(api.requiredNotesCapabilities(), (error) => {
      assert.equal(error.retryable, false);
      assert.ok(!JSON.stringify(error).includes(originalText));
      assert.ok(!JSON.stringify(error).includes(nextText));
      return true;
    });
  }
  let dispatched = false;
  const unavailable = createNativeApi('unavailable', async () => { dispatched = true; return null; });
  await assert.rejects(unavailable.requiredNotesCapabilities(), (error) => error.code === 'required_notes_unavailable');
  assert.equal(dispatched, false);
});

test('both notes event subscriptions project only content-free original envelopes', async () => {
  const handlers = new Map(), edits = [], imports = [], request = { id: 31, scope };
  const api = createNativeApi('native', async () => null, async (event, handler) => {
    handlers.set(event, handler); return () => handlers.delete(event);
  });
  const releaseEdit = await api.subscribeRequiredNotes((value) => edits.push(value));
  const releaseImport = await api.subscribeRequiredNotesImport((value) => imports.push(value));
  const editEnvelope = { requestId: request.id, status: status() };
  const importEnvelope = { requestId: request.id, status: importStatus(request) };
  handlers.get(REQUIRED_NOTES_EVENT)(editEnvelope);
  handlers.get(REQUIRED_NOTES_EVENT)({ requestId: request.id, prepared: prepared() });
  handlers.get(REQUIRED_NOTES_EVENT)({ ...editEnvelope, status: { ...status(), sha256: digest(originalText).sha256 } });
  handlers.get(REQUIRED_NOTES_IMPORT_EVENT)(importEnvelope);
  handlers.get(REQUIRED_NOTES_IMPORT_EVENT)(importReply(request));
  handlers.get(REQUIRED_NOTES_IMPORT_EVENT)({ ...importEnvelope, status: { ...importStatus(request), text: originalText } });
  assert.deepEqual(edits, [editEnvelope, null, null]);
  assert.deepEqual(imports, [importEnvelope, null, null]);
  assert.ok(!JSON.stringify([edits, imports]).includes(originalText));
  assert.ok(!JSON.stringify([edits, imports]).includes(digest(originalText).sha256));
  releaseEdit(); releaseImport(); assert.equal(handlers.size, 0);
});

test('lost Prepare retains original id and permits only original Close after a matching review event', () => {
  for (const eventFirst of [false, true]) {
    const controller = controllerAtDraft(); controller.complete(controller.beginValidate(), validation(nextText));
    const request = controller.beginPrepare();
    assert.equal(controller.claimRequest(request), true);
    const original = controller.originalEdit();
    assert.deepEqual(original, { requestId: request.id, windowGeneration: scope.windowGeneration });
    if (eventFirst) assert.equal(controller.acceptRoutineStatus(routine(controller, status())), true);
    controller.fail(request);
    assert.deepEqual(controller.originalEdit(), original);
    assert.equal(controller.nativeBusy(), true);
    const absent = parseRequiredNotesStatusReply({ requestId: request.id, status: null });
    assert.equal(controller.acceptRoutineStatus(absent), false);
    assert.equal(controller.nativeBusy(), true);
    if (!eventFirst) assert.equal(controller.acceptRoutineStatus(routine(controller, status())), true);
    assert.equal(controller.snapshot().prepared, null);
    assert.equal(controller.canApply(), false);
    assert.equal(controller.canClose(), true);
    const close = controller.beginClose();
    assert.notEqual(close.id, original.requestId);
    assert.equal(close.input.sessionId, status().sessionId);
    assert.equal(controller.claimRequest(close), true);
    assert.equal(controller.complete(close, { requestId: original.requestId, status: closeStatus() }), true);
    assert.equal(controller.nativeBusy(), false);
    assert.equal(controller.snapshot().draft, nextText);
    assert.equal(controller.complete(request, prepareReply(request)), false);
  }
});

test('original terminal or unknown status before a late private Prepare cannot restore its review', () => {
  for (const unknown of [false, true]) {
    const controller = controllerAtDraft(); controller.complete(controller.beginValidate(), validation(nextText));
    const request = controller.beginPrepare(); controller.claimRequest(request);
    const terminal = unknown ? status({ phase: 'unknown', statusRevision: 3, nativeReason: 'cleanup_unknown', nativeFinality: 'unknown',
      coreOutcome: { effect: 'unknown', journal: 'unknown', resources: 'unknown', reason: 'custody_unknown' } }) : closeStatus();
    assert.equal(controller.acceptRoutineStatus(routine(controller, terminal)), true);
    assert.equal(controller.complete(request, prepareReply(request)), true);
    assert.equal(controller.snapshot().pending, null);
    assert.equal(controller.snapshot().prepared, null);
    assert.equal(controller.canApply(), false);
    assert.equal(controller.snapshot().result, null);
    assert.equal(controller.nativeBusy(), unknown);
    if (unknown) assert.equal(controller.discardDraft(true), false);
  }
});

test('routine admission and private Prepare reject wrong original id window project context and revision', () => {
  const controller = controllerAtDraft(); controller.complete(controller.beginValidate(), validation(nextText));
  const request = controller.beginPrepare(); controller.claimRequest(request);
  for (const envelope of [
    { requestId: request.id + 1, status: status() },
    { requestId: request.id, status: status({ windowGeneration: 'f'.repeat(32) }) },
    { requestId: request.id, status: status({ projectId: 'different-project' }) },
    { requestId: request.id, status: status({ context: { kind: 'ios-app-review' } }) },
    { requestId: request.id, status: status({ draftRevision: 2 }) },
  ]) assert.equal(controller.acceptRoutineStatus(envelope), false);
  assert.equal(controller.snapshot().status, null);
  assert.equal(controller.complete(request, { requestId: request.id + 1, prepared: prepared() }), false);
  assert.equal(controller.snapshot().prepared, null);
  assert.equal(controller.snapshot().unsettled, true);
  assert.deepEqual(controller.originalEdit(), { requestId: request.id, windowGeneration: scope.windowGeneration });
});

test('one-use dispatch claims distinguish predispatch Apply refusal from an invoked original operation', () => {
  const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
  const prepareId = controller.originalEdit().requestId, apply = controller.beginApply();
  assert.notEqual(apply.id, prepareId);
  controller.unavailable(apply); // deliberately BEFORE claim/native dispatch
  assert.equal(controller.canApply(), false);
  assert.equal(controller.canClose(), true);
  const close = controller.beginClose();
  assert.notEqual(close.id, prepareId);
  assert.equal(controller.claimRequest(close), true);
  assert.equal(controller.claimRequest(close), false);
  controller.unavailable(close); // an invoked request cannot claim non-admission
  assert.equal(controller.snapshot().pending, 'close');
  assert.equal(controller.complete(close, { requestId: prepareId, status: closeStatus() }), true);
  assert.equal(controller.nativeBusy(), false);
  const lost = controllerAtDraft(); lost.complete(lost.beginValidate(), validation(nextText));
  const request = lost.beginPrepare();
  assert.equal(lost.claimRequest(request), true);
  lost.unavailable(request);
  assert.equal(lost.snapshot().pending, 'prepare');
  lost.fail(request);
  assert.equal(lost.nativeBusy(), true);
  assert.equal(lost.beginPrepare(), null);
  assert.equal(lost.canClose(), false);
});

test('lost import null query and settled status never resurrect private imported text', () => {
  for (const outcome of ['selected', 'cancelled', 'refused']) {
    const controller = controllerAtDraft(), before = clone(controller.snapshot().loaded), request = controller.beginImport(true);
    assert.equal(controller.claimRequest(request), true);
    controller.fail(request);
    assert.equal(controller.nativeBusy(), true);
    const absent = parseRequiredNotesImportStatusReply({ requestId: request.id, status: null });
    assert.equal(controller.acceptImportStatus(absent), false);
    assert.equal(controller.nativeBusy(), true);
    const settled = importStatus(request, { outcome, reason: outcome === 'selected' ? 'none' : outcome === 'cancelled' ? 'cancelled' : 'invalid_file' });
    assert.equal(controller.acceptImportStatus({ requestId: request.id + 1, status: settled }), false);
    assert.equal(controller.acceptImportStatus({ requestId: request.id, status: { ...settled, windowGeneration: 'f'.repeat(32) } }), false);
    assert.equal(controller.acceptImportStatus({ requestId: request.id, status: settled }), true);
    assert.equal(controller.nativeBusy(), false);
    assert.equal(controller.snapshot().draft, nextText);
    assert.deepEqual(controller.snapshot().loaded, before);
    assert.equal(controller.snapshot().validation, null);
    assert.equal(controller.complete(request, importReply(request)), false);
    assert.equal(controller.snapshot().draft, nextText);
  }
});

test('unknown original import cleanup is sticky and no null or replacement settlement clears its gate', () => {
  const controller = controllerAtDraft(), request = controller.beginImport(true);
  controller.claimRequest(request); controller.fail(request);
  const unknown = importStatus(request, { phase: 'unknown', outcome: null, reason: 'cleanup_unknown' });
  const settled = importStatus(request);
  assert.equal(controller.acceptImportStatus({ requestId: request.id, status: unknown }), true);
  assert.equal(requiredNotesImportProgress(unknown, settled), false);
  assert.equal(controller.acceptImportStatus({ requestId: request.id, status: settled }), false);
  assert.equal(controller.acceptImportStatus({ requestId: request.id, status: null }), false);
  assert.equal(controller.discardDraft(true), false);
  assert.equal(controller.setScope({ ...scope, serviceGeneration: 2 }, true), false);
  assert.equal(controller.beginImport(true), null);
  assert.equal(controller.snapshot().draft, nextText);
});

test('stale original import may settle but cannot publish its text into a retired context', () => {
  const controller = controllerAtDraft(), request = controller.beginImport(true);
  controller.claimRequest(request); controller.invalidateContext();
  assert.equal(controller.complete(request, importReply(request)), true);
  assert.equal(controller.snapshot().importStatus.phase, 'settled');
  assert.equal(controller.nativeBusy(), false);
  assert.equal(controller.snapshot().stale, true);
  assert.equal(controller.snapshot().draft, nextText);
  assert.equal(controller.snapshot().validation, null);
  assert.equal(controller.beginPrepare(), null);
});

test('terminal required-note journal recovery attention cannot be erased by Load discard scope or latest status', () => {
  for (const journal of ['recovery_required', 'unknown']) {
    const controller = controllerAtReview(); controller.acceptRoutineStatus(routine(controller, status()));
    const apply = controller.beginApply(); controller.claimRequest(apply);
    const terminal = finalStatus({ nativeReason: 'io_error',
      coreOutcome: { effect: 'unknown', journal, resources: 'settled', reason: 'filesystem_error' } });
    assert.equal(controller.complete(apply, routine(controller, terminal)), true);
    assert.equal(controller.snapshot().result, null);
    assert.equal(controller.nativeBusy(), true);
    assert.match(controller.ownerReason(), /unverified/);
    assert.equal(controller.beginLoad(true), null);
    assert.equal(controller.discardDraft(true), false);
    assert.equal(controller.setScope({ ...scope, serviceGeneration: 2 }, true), false);
    assert.equal(controller.acceptRoutineStatus(routine(controller, finalStatus({ statusRevision: 5 }))), false);
    controller.invalidateContext();
    assert.equal(controller.snapshot().status.coreOutcome.journal, journal);
    assert.equal(controller.nativeBusy(), true);
  }
});

test('bridge correlation rejects mismatched private and routine replies instead of adopting latest state', async () => {
  const correlation = { requestId: 17, windowGeneration: scope.windowGeneration };
  const input = { projectId: scope.projectId, windowGeneration: scope.windowGeneration, context,
    requestId: correlation.requestId, draftRevision: 1, expectedBaseline: loaded().baseline, text: nextText };
  let reply = { requestId: 18, prepared: prepared() };
  const api = createNativeApi('native', async () => reply);
  await assert.rejects(api.prepareRequiredNotes(input), (error) => error.code === 'required_notes_protocol');
  reply = { requestId: correlation.requestId, prepared: { ...prepared(), windowGeneration: 'f'.repeat(32) } };
  await assert.rejects(api.prepareRequiredNotes(input), (error) => error.code === 'required_notes_protocol');
  reply = { requestId: correlation.requestId, status: finalStatus({ sessionId: 'f'.repeat(32) }) };
  await assert.rejects(api.applyRequiredNotes({ ...correlation, sessionId: prepared().sessionId, planToken: prepared().planToken }), (error) => error.code === 'required_notes_protocol');
  reply = { requestId: 18, status: null };
  await assert.rejects(api.requiredNotesStatus(correlation), (error) => error.code === 'required_notes_protocol');
  assert.equal(parseRequiredNotesPreparedReply({ requestId: 17, prepared: prepared(), status: status() }), null);
  assert.equal(parseRequiredNotesRoutineEnvelope({ requestId: 17, status: status(), text: nextText }), null);
  const request = { id: 17, scope };
  assert.equal(parseRequiredNotesImportReply({ ...importReply(request), sourcePath: '/not-public' }), null);
  assert.equal(parseRequiredNotesImportEnvelope({ requestId: 17, status: { ...importStatus(request), sha256: digest(nextText).sha256 } }), null);
});

test('App SOURCE mounts required notes with saved context separate capability gates and original-service retention', () => {
  const app = readFileSync(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const metadata = readFileSync(new URL('../src/pages/Metadata.tsx', import.meta.url), 'utf8');
  const component = readFileSync(new URL('../src/components/RequiredNotesEditor.tsx', import.meta.url), 'utf8');
  assert.ok(app.includes('<Metadata catalog={catalog} notesEditor={notesEditor}'));
  assert.ok(metadata.includes('<div id="required-notes-editor">{notesEditor}</div>'));
  const scopeSource = app.slice(app.indexOf('const currentNotesScope ='), app.indexOf('const selectNotesContext ='));
  assert.ok(scopeSource.includes('entry.snapshot.config.data'));
  assert.ok(scopeSource.includes('configGeneration: entry.observationGeneration'));
  assert.ok(!scopeSource.includes('entry.draft'));
  const dispatchSource = app.slice(app.indexOf('const dispatch = useCallback'), app.indexOf('const [configEdit]'));
  assert.ok(dispatchSource.indexOf('notes?.ownerReason()') < dispatchSource.indexOf('retirePathPicker();'));
  assert.ok(dispatchSource.includes("setNotesConfirmation({ type: 'workspace', action })"));
  assert.ok(app.includes('savedCommandBusy(false, false, false, false, false, false, true)'));
  assert.ok(app.includes("request.kind === 'close' ? original!.api : service!.api"));
  assert.ok(app.includes('requestId: original!.requestId, windowGeneration: original!.windowGeneration'));
  assert.ok(app.includes('notesControllerRef.current?.dirty() || Object.values(workspaceRef.current.projects).some(isDirty)'));
  const bootstrap = app.slice(app.indexOf('const bootstrap = useCallback'), app.indexOf('// Synchronous original-editor'));
  assert.ok(bootstrap.indexOf('requiredNotes.ownerReason() || notesStatusPending.current') < bootstrap.indexOf('retireNotesService();'));
  const summary = app.slice(app.indexOf('const notesSummary ='), app.indexOf('const notesEditor ='));
  for (const privateField of ['.draft', '.prepared', '.baseline', '.destination', '.sha256', '.loaded']) assert.ok(!summary.includes(privateField));
  assert.ok(summary.includes('No persisted required-note recovery command'));
  assert.ok(app.includes("navigate('credentials')}>Open existing review credential forms"));
  assert.ok(component.includes('disabled={locked || state.needsReload}'));
  assert.ok(component.includes('disabled={!readAvailable || locked}'));
  assert.ok(component.includes('disabled={!importAvailable || locked || state.needsReload}'));
  assert.ok(component.includes('disabled={!writeAvailable || !controller.canApply()}'));
  assert.ok(component.includes('disabled={!controller.canClose()}'));
});
