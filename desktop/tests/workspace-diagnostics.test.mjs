import test from 'node:test';
import assert from 'node:assert/strict';
import { WorkspaceDiagnostics, WORKSPACE_DIAGNOSTICS_KEY, WORKSPACE_DIAGNOSTICS_LIMIT, WORKSPACE_DIAGNOSTICS_BYTES,
  installWorkspaceDiagnostics, workspaceFailureDescription } from '../src/workspaceDiagnostics.ts';

function memory() {
  let text = null, writes = 0;
  return { getItem: () => text, setItem(key, value) { assert.equal(key, WORKSPACE_DIAGNOSTICS_KEY); text = value; writes++; },
    get text() { return text; }, get writes() { return writes; }, replace(value) { text = value; } };
}
test('a render failure survives journal recreation with bounded component names and no raw inputs', () => {
  const storage = memory(), journal = new WorkspaceDiagnostics(() => storage, () => 1234);
  journal.setPhase('focus-return');
  const result = journal.capture(new TypeError("Cannot read properties of undefined (reading 'private-project')"), 'boundary',
    '\n at InstallationDetails (file:///private/owner/secret.tsx:1:2)\n at App (https://inert.invalid/secret?token=hidden)');
  assert.equal(result.persisted, true); assert.equal(result.failure.category, 'nullish-property');
  assert.deepEqual(result.failure.components, ['InstallationDetails', 'App']);
  assert.equal(result.failure.phase, 'focus-return');
  assert.doesNotMatch(storage.text, /private|owner|secret|token|hidden|https|undefined|reading/);
  assert.deepEqual(new WorkspaceDiagnostics(() => storage).snapshot(), journal.snapshot());
  assert.match(workspaceFailureDescription(result.failure), /unavailable/);
});
test('storage denial/quota/corruption cannot throw while reporting the original failure', () => {
  for (const storage of [null, { getItem() { throw Error('denied'); }, setItem() { throw Error('quota'); } },
    { getItem: () => '{', setItem() { throw Error('quota'); } }]) {
    const journal = new WorkspaceDiagnostics(() => storage);
    assert.doesNotThrow(() => journal.capture(Error('sensitive text'), 'boundary'));
    assert.equal(journal.snapshot().length, 1);
    assert.equal(journal.capture(Error('another'), 'boundary').persisted, false);
  }
  const journal = new WorkspaceDiagnostics(() => { throw Error('storage accessor'); });
  assert.equal(journal.capture(null, 'boundary').persisted, false);
});
test('hostile rejection values and exception accessors are never coerced or invoked', () => {
  const storage = memory(), journal = new WorkspaceDiagnostics(() => storage);
  let reads = 0;
  const hostile = Object.create(null, { name: { get() { reads++; throw Error('name'); } },
    message: { get() { reads++; throw Error('message'); } }, toString: { value() { reads++; throw Error('coerce'); } } });
  for (const value of [hostile, null, undefined, 1n, Symbol('private'), 'private raw rejection', new Proxy({}, { getOwnPropertyDescriptor() { throw Error(); }, getPrototypeOf() { throw Error(); } })]) {
    assert.doesNotThrow(() => journal.capture(value, 'unhandled-rejection'));
  }
  assert.equal(reads, 0); assert.doesNotMatch(storage.text, /private|coerce|raw rejection/);
});
test('classification keeps known framework codes while dropping arbitrary messages and object children', () => {
  const cases = [
    ['Rendered more hooks than during the previous render.', 'hook-order', null],
    ['Maximum update depth exceeded.', 'render-loop', null],
    ['Objects are not valid as a React child (found: object with keys {password}).', 'invalid-child', null],
    ['Minified React error #310; visit https://private.invalid/?token=secret', 'react-error', 310],
    ['password=not-a-diagnostic /private/owner', 'unknown', null],
  ];
  let now = 0; const storage = memory(), journal = new WorkspaceDiagnostics(() => storage, () => now += 2000);
  for (const [message, category, reactCode] of cases) {
    const failure = journal.capture(Error(message), 'boundary').failure;
    assert.equal(failure.category, category); assert.equal(failure.reactCode, reactCode);
  }
  assert.doesNotMatch(storage.text, /password|token|private|secret|https/);
});
test('a failure storm is deduplicated and the persistent journal is a bounded ring', () => {
  const storage = memory(); let now = 1000; const journal = new WorkspaceDiagnostics(() => storage, () => now);
  for (let i = 0; i < 1000; i++) journal.capture(Error('sensitive'), 'boundary');
  assert.equal(storage.writes, 1); assert.equal(journal.snapshot().length, 1);
  for (let i = 0; i < 1000; i++) {
    journal.capture(Error('sensitive'), 'window-error'); journal.capture(Error('sensitive'), 'boundary');
  }
  assert.equal(storage.writes, 2);
  for (let i = 0; i < 100; i++) { now += 1001; journal.capture(Error('sensitive'), 'boundary'); }
  assert.equal(journal.snapshot().length, WORKSPACE_DIAGNOSTICS_LIMIT);
  assert.ok(Buffer.byteLength(storage.text) <= WORKSPACE_DIAGNOSTICS_BYTES);
  assert.equal(journal.snapshot().at(-1).sequence, 102);
});
test('corrupt stored records, unknown fields and oversized storage are not replayed', () => {
  const storage = memory(), original = new WorkspaceDiagnostics(() => storage);
  original.capture(Error('x'), 'boundary'); const valid = JSON.parse(storage.text);
  for (const change of [v => v.records[0].raw = 'private', v => v.records[0].components = ['/private/owner'],
    v => v.records[0].source = 'private', v => v.records[0].atMs = -1, v => v.schemaVersion = 2,
    v => v.records.push(structuredClone(v.records[0])), v => v.records[0].reactCode = 310]) {
    const value = structuredClone(valid); change(value); storage.replace(JSON.stringify(value));
    assert.deepEqual(new WorkspaceDiagnostics(() => storage).snapshot(), []);
  }
  storage.replace(' '.repeat(WORKSPACE_DIAGNOSTICS_BYTES + 1));
  assert.deepEqual(new WorkspaceDiagnostics(() => storage).snapshot(), []);
});
test('callers cannot mutate a future persisted record through capture or snapshot results', () => {
  const storage = memory(); let now = 0; const journal = new WorkspaceDiagnostics(() => storage, () => now);
  const value = journal.capture(Error('x'), 'boundary', ' at App');
  value.failure.components.push('/private/secret'); journal.snapshot()[0].components.push('private');
  now = 2000; journal.capture(Error('x'), 'window-error');
  assert.doesNotMatch(storage.text, /private|secret/);
});
test('focus/helper-approval return and failure listeners have symmetric teardown and never submit native work', () => {
  const target = new EventTarget(), storage = memory(); let now = 0;
  const journal = new WorkspaceDiagnostics(() => storage, () => now += 2000);
  const remove = installWorkspaceDiagnostics(target, journal);
  for (const runtime of ['runtime-unavailable', 'runtime-available']) {
    journal.setPhase(runtime); target.dispatchEvent(new Event('focus'));
    const event = new Event('error'); Object.defineProperty(event, 'error', { value: new TypeError('Cannot read properties of null') });
    target.dispatchEvent(event);
    assert.equal(journal.snapshot().at(-1).phase, 'focus-return');
  }
  const rejection = new Event('unhandledrejection'); Object.defineProperty(rejection, 'reason', { value: Error('private') });
  target.dispatchEvent(rejection); assert.equal(journal.snapshot().at(-1).source, 'unhandled-rejection');
  remove(); const before = journal.snapshot(); target.dispatchEvent(rejection); assert.deepEqual(journal.snapshot(), before);
  assert.doesNotMatch(storage.text, /private/);
});
