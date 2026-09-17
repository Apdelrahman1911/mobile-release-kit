// Pure data/bridge checks only: no DOM, native picker, filesystem, or credential IO.
import assert from 'node:assert/strict';
import test from 'node:test';
import guide from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };
import github from '../../src/mobile_release/api/data/github-setup-v1.json' with { type: 'json' };
import { parseCredentialGuide, parseCatalogCredentialGuide } from '../src/credentialGuide.ts';
import { createNativeApi } from '../src/bridge.ts';

function catalog(credentialGuide) {
  return { schemaVersion: 1, schema: {}, fields: [], credentials: [], metadata: null,
    githubSetup: github.help, assurance: {}, credentialGuide };
}

test('core-owned guide is compatible, complete, and detached from its provider', () => {
  const input = structuredClone(guide);
  const result = parseCredentialGuide(input);
  assert.deepEqual(result, guide);
  assert.equal(result.availability, 'guide-only');
  input.kinds[0].fields[0].where = 'changed after delivery';
  input.controls[0].what = 'changed after delivery';
  assert.deepEqual(result, guide);
  assert.equal(result.kinds.length, 8);
});

test('future or enabled-looking guide contracts never imply collection authority', () => {
  for (const delta of [{ schemaVersion: 2 }, { policyVersion: 'unknown' }, { availability: 'available' }, { collect: true }, { credentialsRead: true }]) {
    assert.equal(parseCredentialGuide({ ...structuredClone(guide), ...delta }), null);
  }
  for (const value of [null, [], false, 1, 'guide']) assert.equal(parseCredentialGuide(value), null);
});

test('missing, repeated, and unknown roster members are refused rather than silently omitted', () => {
  for (const key of ['kinds', 'controls', 'states']) {
    for (const change of [(rows) => rows.pop(), (rows) => { rows[1] = rows[0]; }, (rows) => { rows[0].id = 'unsupported'; }]) {
      const input = structuredClone(guide);
      change(input[key]);
      assert.equal(parseCredentialGuide(input), null, key);
    }
  }
});

test('every displayed field has bounded complete help and no value or path slot', () => {
  for (const change of [
    (field) => { delete field.where; },
    (field) => { field.why = ''; },
    (field) => { field.where = 'x'.repeat(4097); },
    (field) => { field.format = 'bad\u0000text'; },
    (field) => { field.value = 'synthetic-canary-never-a-value'; },
    (field) => { field.path = '/synthetic/not-read'; },
    (field) => { field.maxBytes = NaN; },
    (field) => { field.maxBytes = 0; },
    (field) => { field.input = 'native-verified'; },
    (field) => { field.alternatives = Array(9).fill('synthetic-name'); },
  ]) {
    const input = structuredClone(guide);
    change(input.kinds.find((kind) => kind.fields[0].input === 'file').fields[0]);
    assert.equal(parseCredentialGuide(input), null);
  }
  const repeated = structuredClone(guide);
  repeated.kinds[0].fields.push(repeated.kinds[0].fields[0]);
  assert.equal(parseCredentialGuide(repeated), null);
});

test('native catalog consumer uses only the existing read-only command and validates its guide', async () => {
  const calls = [];
  const input = catalog(structuredClone(guide));
  const api = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return input; });
  const result = await api.catalog();
  assert.deepEqual(calls, [{ command: 'catalog', args: undefined }]);
  assert.deepEqual(result.credentialGuide, guide);
  input.credentialGuide.kinds[0].label = 'changed later';
  assert.equal(result.credentialGuide.kinds[0].label, guide.kinds[0].label);
});

test('missing or malformed additive guidance remains unavailable without replacing legacy guidance', async () => {
  assert.equal(parseCatalogCredentialGuide({}), null);
  const credentials = [{ name: 'synthetic requirement' }];
  for (const credentialGuide of [undefined, null, { ...guide, availability: 'stored' }]) {
    const api = createNativeApi('native', async () => ({ ...catalog(credentialGuide), credentials }));
    const result = await api.catalog();
    assert.equal(result.credentialGuide, null);
    assert.deepEqual(result.credentials, credentials);
    assert.equal(api.mode, 'native');
  }
});
