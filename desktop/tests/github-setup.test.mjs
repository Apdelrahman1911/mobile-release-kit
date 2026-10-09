// Pure wire/UI cases with inert DTOs and controlled promises only. No service,
// native GUI, file observation, credential lookup, network or template renderer.
import assert from 'node:assert/strict';
import test from 'node:test';
import resource from '../../src/mobile_release/api/data/github-setup-v1.json' with { type: 'json' };
import credentialGuide from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };
import connectionGuide from '../../src/mobile_release/api/data/github-connection-v1.json' with { type: 'json' };
import metadataGuide from '../../src/mobile_release/api/data/metadata-text-help-v1.json' with { type: 'json' };
import versionGuide from '../../src/mobile_release/api/data/release-version-help-v1.json' with { type: 'json' };
import { createNativeApi } from '../src/bridge.ts';
import { GitHubSetupController, githubSetupStartReason, githubSnapshotFromInputs } from '../src/githubSetupController.ts';
import { GITHUB_WORKFLOWS, githubSetupError, githubSetupRequestFits, githubSetupResultMatches, parseCatalogGitHubSetup, parseGitHubSetupHelp, parseGitHubSetupResult } from '../src/githubSetupProtocol.ts';
import { previewApi } from '../src/preview.ts';
import { GitHubRemoteSetupController, githubRemoteSetupOwnerReason } from '../src/GitHubRemoteSetupController.ts';
import { githubRemoteSetupConfirmation, githubRemoteSetupError, githubRemoteSetupRequestFits, parseGitHubRemoteSetupStatus } from '../src/GitHubRemoteSetupProtocol.ts';


const repository = 'inert/toolkit';
const sha = 'a'.repeat(40);
const assurance = {
  basis: 'schema-policy', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false,
  writesPerformed: false, releaseReadiness: 'unknown',
};
const draft = { source: { candidateBranch: 'candidate-policy', productionBranch: 'production-policy' }, retained: 'inert draft data' };
const guidanceIds = ['source-authority', 'protected-environments', 'runner-policy', 'credentials', 'preflight-and-releases', 'scope'];
const environments = [
  { stage: 'candidate', name: 'mobile-candidate' },
  { stage: 'external-testing', name: 'mobile-external-testing' },
  { stage: 'production', name: 'mobile-production' },
];

function request(overrides = {}) {
  return { draft: structuredClone(draft), toolingRepository: repository, toolingSha: sha, suppliedSnapshot: null, ...overrides };
}

function facts(snapshotProvided = false) {
  return {
    githubContacted: false, repositoryObserved: false, toolingRefResolved: false,
    templateCompatibility: 'unknown', comparisonBasis: 'caller-supplied-digest-summary',
    snapshotProvided, applyAvailable: false,
  };
}

function requirement(overrides = {}) {
  return {
    name: 'MOBILE_RELEASE_INERT', kind: 'secret', stage: 'candidate', platform: 'android', environment: 'mobile-candidate',
    alternatives: ['MOBILE_RELEASE_INERT_PATH'], reason: 'Inert descriptor for wire admission only.', state: 'unknown', ...overrides,
  };
}

// Deliberately not a generated real workflow or a claimed core validation.
// These short strings and hashes exercise display-assertion admission only.
function proposed() {
  return {
    schemaVersion: 1, state: 'proposed',
    validation: { valid: true, state: 'format-valid', issues: [], requirements: [requirement()], assurance: { ...assurance } },
    facts: facts(), assurance: { ...assurance },
    templateSet: { coreVersion: '0.3.0', resourceVersion: 1, resourceSha256: '0'.repeat(64) },
    tooling: { repository, sha, schemaReference: `https://raw.githubusercontent.com/${repository}/${sha}/schemas/project.schema.json`, state: 'format-only' },
    workflows: GITHUB_WORKFLOWS.map(({ id, path }, index) => {
      const content = `inert display text ${index}\n`;
      return { id, path, content, byteLength: Buffer.byteLength(content), sha256: String(index + 1).repeat(64), comparison: 'not-supplied' };
    }),
    settings: {
      configPath: 'release/mobile-release.json', sourcePolicy: { ...draft.source, basis: 'configured-policy' },
      environments: structuredClone(environments), guidanceIds: [...guidanceIds],
    },
  };
}

function invalid(snapshotProvided = false) {
  return {
    schemaVersion: 1, state: 'invalid', assurance: { ...assurance }, facts: facts(snapshotProvided),
    validation: {
      valid: false, state: 'invalid', requirements: [], assurance: { ...assurance }, issues: [{
        code: 'config.invalid', status: 'INVALID',
        message: 'Configuration does not satisfy the shared core format/policy rules; review the draft and contextual field guidance.',
        remediation: 'Correct the input and validate again; no changes were saved.',
      }],
    },
  };
}

function catalog() {
  // Match the current core's complete top-level wire shape, not the older
  // seven-key fixture. Guide bodies are the actual bundled public resources;
  // unrelated catalogue values remain inert, not a core-execution claim.
  return { schemaVersion: 1, schema: {}, fields: [], credentials: [], credentialGuide: structuredClone(credentialGuide),
    githubSetup: structuredClone(resource.help), githubConnection: structuredClone(connectionGuide), metadataText: structuredClone(metadataGuide),
    releaseVersionEdit: structuredClone(versionGuide), metadata: null, assurance: { ...assurance } };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function appInfo(available = true) {
  return {
    appName: 'Inert fixture', appVersion: '0.3.0', runtime: { state: 'available', reason: null, mode: 'development' },
    capabilities: { methods: [{ method: 'github.setup.propose', available, reason: 'Inert capability unavailable.' }], actions: [] },
  };
}

function project(id = 'project-a') {
  return { project: { id, name: id, path: 'never-forward-this-path' }, draft: structuredClone(draft), revision: 4, baselineGeneration: 2 };
}

function harness({ withHelp = true, available = true } = {}) {
  let selected = project();
  const calls = [];
  const api = { mode: 'native', proposeGitHubSetup: (input) => {
    const work = deferred();
    calls.push({ input, ...work });
    return work.promise;
  } };
  const controller = new GitHubSetupController(() => selected);
  controller.setConnection(api, appInfo(available));
  if (withHelp) assert.equal(controller.admitHelp(resource.help), true);
  controller.syncProject();
  controller.setCoordinate('toolingRepository', repository);
  controller.setCoordinate('toolingSha', sha);
  return {
    controller, api, calls, selected: () => selected,
    select: (next) => { selected = next; controller.syncProject(); },
    replaceWithoutSync: (next) => { selected = next; },
  };
}

test('setup request projection is exactly four keys and leaves pin policy to the core', () => {
  assert.equal(githubSetupRequestFits(request()), true);
  assert.equal(githubSetupRequestFits(request({ toolingRepository: 'not-a-coordinate', toolingSha: 'branch-is-not-a-pin' })), true);
  assert.equal(githubSetupRequestFits(request({ toolingRepository: ' inert/toolkit ', toolingSha: 'A'.repeat(40) })), true);
  for (const key of ['root', 'projectId', 'configPath', 'token', 'secret', 'template', 'url', 'apply', 'force', 'revision']) {
    assert.equal(githubSetupRequestFits({ ...request(), [key]: 'NEVER FORWARD' }), false, key);
  }
  for (const key of Object.keys(request())) {
    const missing = request(); delete missing[key];
    assert.equal(githubSetupRequestFits(missing), false, key);
  }
  for (const value of [null, [], false, 1, 'draft']) assert.equal(githubSetupRequestFits(request({ draft: value })), false);
  assert.equal(githubSetupRequestFits(request({ toolingRepository: 'x'.repeat(141) })), false);
  assert.equal(githubSetupRequestFits(request({ toolingRepository: 'é'.repeat(71) })), false);
  assert.equal(githubSetupRequestFits(request({ toolingSha: 'a'.repeat(41) })), false);
});

test('draft admission is bounded at UTF-8 bytes, nodes and depth without mutation', () => {
  const exactBytes = request({ draft: { x: 'x'.repeat(512 * 1024 - 8) } });
  assert.equal(Buffer.byteLength(JSON.stringify(exactBytes.draft)), 512 * 1024);
  assert.equal(githubSetupRequestFits(exactBytes), true);
  exactBytes.draft.x += 'x';
  assert.equal(githubSetupRequestFits(exactBytes), false);
  assert.equal(githubSetupRequestFits(request({ draft: { x: '🌱'.repeat(131072) } })), false);
  assert.equal(githubSetupRequestFits(request({ draft: { nodes: Array(7997).fill(0) } })), true);
  assert.equal(githubSetupRequestFits(request({ draft: { nodes: Array(7998).fill(0) } })), false);
  let nested = 'leaf';
  for (let index = 0; index < 28; index += 1) nested = { child: nested };
  assert.equal(githubSetupRequestFits(request({ draft: nested })), true);
  assert.equal(githubSetupRequestFits(request({ draft: { child: nested } })), false);
  const input = request(); const before = structuredClone(input);
  assert.equal(githubSetupRequestFits(input), true);
  assert.deepEqual(input, before);
});

test('JSON admission refuses cycles, exotic objects, accessors, hidden keys and lone surrogates', () => {
  const cycle = {}; cycle.self = cycle;
  const sparse = []; sparse.length = 1;
  const arrayExtra = [1]; arrayExtra.extra = true;
  const hidden = {}; Object.defineProperty(hidden, 'hidden', { value: true });
  const symbol = { [Symbol('not JSON')]: true };
  let getterCalls = 0;
  const accessor = { get value() { getterCalls += 1; return 'must not read'; } };
  for (const value of [cycle, { x: sparse }, { x: arrayExtra }, hidden, symbol, accessor, new Date(0), Object.create({ inherited: true }), { x: NaN }, { x: Infinity }, { x: undefined }, { x: 1n }, { x: () => null }, { x: '\ud800' }, { '\udfff': 'value' }]) {
    assert.equal(githubSetupRequestFits(request({ draft: value })), false);
  }
  assert.equal(getterCalls, 0);
  assert.equal(githubSetupRequestFits(request({ draft: { x: '🌱' } })), true);
  const nullPrototype = Object.assign(Object.create(null), { x: 'ordinary JSON' });
  assert.equal(githubSetupRequestFits(request({ draft: nullPrototype })), true);
});

test('supplied snapshot distinguishes null, empty, omitted and explicitly absent records', () => {
  for (const suppliedSnapshot of [null, { workflows: [] }, { workflows: [{ id: 'candidate', state: 'absent' }] },
    { workflows: [...GITHUB_WORKFLOWS].reverse().map(({ id }) => ({ id, state: 'present', byteLength: 0, sha256: '0'.repeat(64) })) }]) {
    assert.equal(githubSetupRequestFits(request({ suppliedSnapshot })), true);
  }
  for (const suppliedSnapshot of [undefined, {}, [], { workflows: [], observed: true }, { workflows: Array(5).fill({ id: 'candidate', state: 'absent' }) },
    { workflows: [{ id: 'candidate', state: 'absent' }, { id: 'candidate', state: 'absent' }] }]) {
    assert.equal(githubSetupRequestFits(request({ suppliedSnapshot })), false);
  }
  const validRecord = { id: 'candidate', state: 'present', byteLength: 1048576, sha256: 'a'.repeat(64) };
  for (const row of [{ id: 'elsewhere', state: 'absent' }, { id: 'candidate', state: 'unknown' }, { id: 'candidate', state: 'absent', byteLength: 0 },
    { ...validRecord, byteLength: -1 }, { ...validRecord, byteLength: true }, { ...validRecord, byteLength: 1.5 }, { ...validRecord, byteLength: 1048577 },
    { ...validRecord, sha256: 'A'.repeat(64) }, { ...validRecord, sha256: `${'a'.repeat(64)}\n` }, { ...validRecord, path: '/unrelated' }, { ...validRecord, content: 'never accept old YAML' }]) {
    assert.equal(githubSetupRequestFits(request({ suppliedSnapshot: { workflows: [row] } })), false);
  }
});

test('both result variants are admitted only with their exact discriminants and fields', () => {
  assert.deepEqual(parseGitHubSetupResult(proposed()), proposed());
  assert.deepEqual(parseGitHubSetupResult(invalid()), invalid());
  for (const property of ['templateSet', 'tooling', 'workflows', 'settings', 'help']) {
    for (const value of [null, {}, []]) assert.equal(parseGitHubSetupResult({ ...invalid(), [property]: value }), null);
  }
  for (const key of Object.keys(proposed())) {
    const value = proposed(); delete value[key];
    assert.equal(parseGitHubSetupResult(value), null, key);
  }
  for (const key of Object.keys(invalid())) {
    const value = invalid(); delete value[key];
    assert.equal(parseGitHubSetupResult(value), null, key);
  }
  for (const state of ['applied', 'ready', true, null, 'format-valid']) assert.equal(parseGitHubSetupResult({ ...proposed(), state }), null);
  assert.equal(parseGitHubSetupResult({ ...proposed(), schemaVersion: true }), null);
  assert.equal(parseGitHubSetupResult({ ...proposed(), validation: invalid().validation }), null);
  assert.equal(parseGitHubSetupResult({ ...invalid(), validation: proposed().validation }), null);
  const rawIssue = invalid(); rawIssue.validation.issues[0].message = 'PRIVATE PROJECT VALUE';
  assert.equal(parseGitHubSetupResult(rawIssue), null);
});

test('every nested proposal object rejects unknown and missing keys', () => {
  // A fail-closed decoder must not make every malformed case pass vacuously.
  const baseline = proposed();
  assert.deepEqual(parseGitHubSetupResult(baseline), baseline);
  const locations = [
    (value) => value, (value) => value.assurance, (value) => value.facts, (value) => value.validation,
    (value) => value.validation.assurance, (value) => value.validation.requirements[0], (value) => value.templateSet,
    (value) => value.tooling, (value) => value.workflows[0], (value) => value.settings,
    (value) => value.settings.sourcePolicy, (value) => value.settings.environments[0],
  ];
  for (const locate of locations) {
    const extra = proposed(); locate(extra).unknown = 'never admitted';
    assert.equal(parseGitHubSetupResult(extra), null);
    for (const key of Object.keys(locate(proposed()))) {
      const missing = proposed(); delete locate(missing)[key];
      assert.equal(parseGitHubSetupResult(missing), null, key);
    }
  }
  const issue = invalid(); issue.validation.issues[0].path = 'not permitted';
  assert.equal(parseGitHubSetupResult(issue), null);
});

test('literal no-contact and no-Apply facts cannot be strengthened or coerced', () => {
  for (const make of [proposed, invalid]) {
    for (const key of ['githubContacted', 'repositoryObserved', 'toolingRefResolved', 'applyAvailable']) {
      for (const value of [true, 0, null, 'false']) {
        const result = make(); result.facts[key] = value;
        assert.equal(parseGitHubSetupResult(result), null);
      }
    }
    for (const key of ['projectCodeExecuted', 'toolsProbed', 'credentialsRead', 'gitObserved', 'storeContacted', 'writesPerformed']) {
      const result = make(); result.assurance[key] = true;
      assert.equal(parseGitHubSetupResult(result), null);
      const nested = make(); nested.validation.assurance[key] = 0;
      assert.equal(parseGitHubSetupResult(nested), null);
    }
    for (const [group, key, value] of [['facts', 'snapshotProvided', 0], ['facts', 'templateCompatibility', 'verified'], ['facts', 'comparisonBasis', 'observed-files'],
      ['assurance', 'basis', 'static-text'], ['assurance', 'releaseReadiness', 'ready']]) {
      const result = make(); result[group][key] = value;
      assert.equal(parseGitHubSetupResult(result), null);
    }
  }
});

test('tooling and shipped resource identities are format-only closed wire assertions', () => {
  for (const [key, value] of [['repository', 'bad-owner-/repo'], ['repository', 'owner/repo_'], ['repository', 'owner/repo\n'], ['repository', 'é/repo'],
    ['repository', 'https://example.invalid/repo'], ['sha', 'A'.repeat(40)], ['sha', sha.slice(1)], ['sha', `${sha}\n`], ['state', 'resolved'],
    ['schemaReference', `https://raw.githubusercontent.com/${repository}/${sha}/schemas/project.schema.json?fetch=1`]]) {
    const result = proposed(); result.tooling[key] = value;
    assert.equal(parseGitHubSetupResult(result), null, key);
  }
  for (const [key, value] of [['resourceVersion', true], ['resourceSha256', 'A'.repeat(64)], ['resourceSha256', `${'a'.repeat(64)}\n`], ['coreVersion', '0.3.0-beta'], ['coreVersion', '0.3.0\n'], ['coreVersion', `${'1'.repeat(29)}.0.0`]]) {
    const result = proposed(); result.templateSet[key] = value;
    assert.equal(parseGitHubSetupResult(result), null, key);
  }
  const longest = proposed();
  longest.tooling.repository = `${'a'.repeat(39)}/${'b'.repeat(100)}`;
  longest.tooling.schemaReference = `https://raw.githubusercontent.com/${longest.tooling.repository}/${sha}/schemas/project.schema.json`;
  longest.templateSet.coreVersion = `${'1'.repeat(28)}.0.0`;
  assert.notEqual(parseGitHubSetupResult(longest), null);
});

test('the four complete workflow records retain fixed path/order and UTF-8 byte lengths', () => {
  for (const mutation of [
    (value) => value.workflows.pop(), (value) => value.workflows.reverse(), (value) => value.workflows.push(value.workflows[0]),
    (value) => { value.workflows[0].id = 'candidate'; }, (value) => { value.workflows[0].path = '.github/workflows/unrelated.yml'; },
    (value) => { value.workflows[0].content = ''; value.workflows[0].byteLength = 0; },
    (value) => { value.workflows[0].byteLength = true; }, (value) => { value.workflows[0].byteLength = 1.25; },
    (value) => { value.workflows[0].sha256 = 'A'.repeat(64); }, (value) => { value.workflows[0].comparison = 'repository-unchanged'; },
    (value) => { value.workflows[0].content = '\ud800'; value.workflows[0].byteLength = 3; },
  ]) {
    const result = proposed(); mutation(result);
    assert.equal(parseGitHubSetupResult(result), null);
  }
  const result = proposed();
  for (const workflow of result.workflows) { workflow.content = '🌱'.repeat(4096); workflow.byteLength = 16384; }
  assert.notEqual(parseGitHubSetupResult(result), null);
  result.workflows[0].byteLength = result.workflows[0].content.length;
  assert.equal(parseGitHubSetupResult(result), null);
  result.workflows[0].content += 'x'; result.workflows[0].byteLength = 16385;
  assert.equal(parseGitHubSetupResult(result), null);
});

test('complete encoded output has an inclusive byte ceiling and is never truncated', () => {
  const result = proposed();
  for (const workflow of result.workflows) { workflow.content = '\0'.repeat(10000); workflow.byteLength = 10000; }
  const remaining = 262144 - Buffer.byteLength(JSON.stringify(result));
  assert.ok(remaining > 0);
  result.workflows[0].content += '\0'.repeat(Math.floor(remaining / 6)) + 'x'.repeat(remaining % 6);
  result.workflows[0].byteLength = Buffer.byteLength(result.workflows[0].content);
  assert.ok(result.workflows[0].byteLength <= 16384);
  assert.equal(Buffer.byteLength(JSON.stringify(result)), 262144);
  assert.notEqual(parseGitHubSetupResult(result), null);
  result.workflows[0].content += 'x'; result.workflows[0].byteLength += 1;
  assert.equal(Buffer.byteLength(JSON.stringify(result)), 262145);
  assert.equal(parseGitHubSetupResult(result), null);
});

test('requirements are bounded unknown descriptors, not values or a second credential policy', () => {
  const maximum = proposed();
  maximum.validation.requirements = Array.from({ length: 128 }, (_, index) => requirement({ name: `MOBILE_RELEASE_INERT_${index}`, reason: '🌱'.repeat(256) }));
  assert.notEqual(parseGitHubSetupResult(maximum), null);
  maximum.validation.requirements.push(requirement({ name: 'MOBILE_RELEASE_EXTRA' }));
  assert.equal(parseGitHubSetupResult(maximum), null);
  for (const patch of [
    { name: 'FOREIGN_NAME' }, { name: `${'MOBILE_RELEASE_'}${'A'.repeat(90)}` }, { name: 'MOBILE_RELEASE_INERT\n' },
    { kind: 'credential-value' }, { stage: 'preflight' }, { platform: 'other' }, { environment: 'mobile-production' },
    { alternatives: ['MOBILE_RELEASE_ONE', 'MOBILE_RELEASE_TWO', 'MOBILE_RELEASE_THREE'] }, { alternatives: ['PRIVATE_PATH'] },
    { reason: '' }, { reason: '🌱'.repeat(257) }, { state: 'present' }, { value: 'NEVER DISPLAY' },
  ]) {
    const result = proposed(); result.validation.requirements[0] = requirement(patch);
    assert.equal(parseGitHubSetupResult(result), null);
  }
  const duplicates = proposed(); duplicates.validation.requirements.push(requirement({ reason: 'Another reason is not another identity.' }));
  assert.equal(parseGitHubSetupResult(duplicates), null);
  const separatePlatform = proposed(); separatePlatform.validation.requirements.push(requirement({ platform: 'ios' }));
  assert.notEqual(parseGitHubSetupResult(separatePlatform), null);
  const invalidWithRequirements = invalid(); invalidWithRequirements.validation.requirements.push(requirement());
  assert.equal(parseGitHubSetupResult(invalidWithRequirements), null);
});

test('settings preserve exact environment/guidance rosters and configured policy only', () => {
  for (const mutation of [
    (value) => { value.settings.configPath = '/other/config.json'; }, (value) => { value.settings.sourcePolicy.basis = 'observed-protection'; },
    (value) => { value.settings.sourcePolicy.candidateBranch = ''; }, (value) => { value.settings.sourcePolicy.productionBranch = '🌱'.repeat(257); },
    (value) => value.settings.environments.reverse(), (value) => value.settings.environments.pop(),
    (value) => { value.settings.environments[0].name = 'unprotected'; }, (value) => value.settings.guidanceIds.reverse(),
    (value) => value.settings.guidanceIds.push('other-guidance'),
  ]) {
    const result = proposed(); mutation(result);
    assert.equal(parseGitHubSetupResult(result), null);
  }
  const bytes = proposed(); bytes.settings.sourcePolicy.candidateBranch = '🌱'.repeat(256);
  assert.notEqual(parseGitHubSetupResult(bytes), null);
});

test('response correlation binds normalized input, branch echoes and all comparison states', () => {
  const output = proposed();
  const contradictory = proposed(); contradictory.workflows[0].comparison = 'reported-absent';
  assert.equal(parseGitHubSetupResult(contradictory), null);
  assert.equal(githubSetupResultMatches(output, request({ toolingSha: 'A'.repeat(40) })), true);
  assert.equal(githubSetupResultMatches(output, request({ toolingRepository: 'other/toolkit' })), false);
  assert.equal(githubSetupResultMatches(output, request({ toolingSha: 'b'.repeat(40) })), false);
  assert.equal(githubSetupResultMatches(output, request({ draft: { source: { ...draft.source, candidateBranch: 'other' } } })), false);
  assert.equal(githubSetupResultMatches(output, request({ suppliedSnapshot: { workflows: [] } })), false);
  const input = request({ suppliedSnapshot: { workflows: [
    { id: 'candidate', state: 'absent' },
    { id: 'external-testing', state: 'present', byteLength: output.workflows[2].byteLength, sha256: output.workflows[2].sha256 },
    { id: 'production-submit', state: 'present', byteLength: 0, sha256: output.workflows[3].sha256 },
  ] } });
  output.facts.snapshotProvided = true;
  output.workflows[1].comparison = 'reported-absent';
  output.workflows[2].comparison = 'supplied-digest-match';
  output.workflows[3].comparison = 'supplied-digest-differs';
  assert.equal(githubSetupResultMatches(output, input), true);
  input.suppliedSnapshot.workflows[1].byteLength += 1;
  assert.equal(githubSetupResultMatches(output, input), false);
  assert.equal(githubSetupResultMatches(invalid(true), request({ suppliedSnapshot: { workflows: [] } })), true);
  assert.equal(githubSetupResultMatches(invalid(false), request({ suppliedSnapshot: { workflows: [] } })), false);
});

test('core help is available before draft/pin validation and has exact input/guidance shapes', () => {
  assert.deepEqual(parseGitHubSetupHelp(resource.help), resource.help);
  assert.deepEqual(parseCatalogGitHubSetup(catalog()), resource.help);
  for (const mutate of [
    (value) => { value.schemaVersion = true; }, (value) => { value.extra = true; }, (value) => value.inputs.reverse(),
    (value) => value.inputs.pop(), (value) => { value.inputs[0].requiredness = 'optional'; },
    (value) => { value.inputs[2].requiredness = 'required'; }, (value) => { value.inputs[1].id = 'unknown'; },
    (value) => { value.guidance[0].requiredness = 'required'; }, (value) => value.guidance.reverse(),
    (value) => value.guidance.push(value.guidance[0]), (value) => { value.guidance[0].url = 'https://example.invalid'; },
  ]) {
    const help = structuredClone(resource.help); mutate(help);
    assert.equal(parseGitHubSetupHelp(help), null);
  }
  for (const list of ['inputs', 'guidance']) {
    for (const key of Object.keys(resource.help[list][0])) {
      const help = structuredClone(resource.help); delete help[list][0][key];
      assert.equal(parseGitHubSetupHelp(help), null, `${list}.${key}`);
    }
  }
  for (const value of [null, { ...catalog(), extra: true }, { ...catalog(), githubSetup: null }]) assert.equal(parseCatalogGitHubSetup(value), null);
  const missing = catalog(); delete missing.githubSetup;
  assert.equal(parseCatalogGitHubSetup(missing), null);
});

test('catalog envelope preserves exact admission for all known additive guide combinations', () => {
  const guides = ['credentialGuide', 'githubConnection', 'metadataText', 'releaseVersionEdit'];
  for (let mask = 0; mask < (1 << guides.length); mask += 1) {
    const input = catalog();
    guides.forEach((key, index) => { if (!(mask & (1 << index))) delete input[key]; });
    assert.deepEqual(parseCatalogGitHubSetup(input), resource.help);
    // Unavailable optional help must not hide valid mandatory Setup help.
    for (const key of guides) if (Object.hasOwn(input, key)) input[key] = null;
    assert.deepEqual(parseCatalogGitHubSetup(input), resource.help);
  }
  for (const key of ['schemaVersion', 'schema', 'fields', 'credentials', 'metadata', 'githubSetup', 'assurance']) {
    const input = catalog(); delete input[key];
    assert.equal(parseCatalogGitHubSetup(input), null, key);
  }
  assert.equal(parseCatalogGitHubSetup({ ...catalog(), schemaVersion: 2 }), null);
  assert.equal(parseCatalogGitHubSetup({ ...catalog(), futureGuide: null }), null);
  const hidden = catalog(); Object.defineProperty(hidden, 'metadataText', { enumerable: false });
  assert.equal(parseCatalogGitHubSetup(hidden), null);
  let reads = 0;
  const accessor = catalog();
  Object.defineProperty(accessor, 'metadataText', { enumerable: true, get() { reads += 1; return metadataGuide; } });
  assert.equal(parseCatalogGitHubSetup(accessor), null);
  assert.equal(reads, 0);
});

test('help uses UTF-8 byte limits and plain text without ASCII controls or lone surrogates', () => {
  for (const [key, max] of [['label', 96], ['what', 1024], ['why', 1024], ['where', 1024], ['format', 1024], ['failure', 1024]]) {
    const help = structuredClone(resource.help); help.inputs[0][key] = '🌱'.repeat(max / 4);
    assert.notEqual(parseGitHubSetupHelp(help), null, key);
    help.inputs[0][key] += 'x';
    assert.equal(parseGitHubSetupHelp(help), null, key);
    help.inputs[0][key] = '';
    assert.equal(parseGitHubSetupHelp(help), null, key);
  }
  for (const body of ['\0', '\n', '\t', '\u007f', '\ud800', '\udfff']) {
    const help = structuredClone(resource.help); help.guidance[0].what = `inert${body}text`;
    assert.equal(parseGitHubSetupHelp(help), null);
  }
  const allowed = structuredClone(resource.help); allowed.inputs[0].what = 'inert\u0085🌱text';
  assert.notEqual(parseGitHubSetupHelp(allowed), null);
  let invoked = 0;
  const accessor = structuredClone(resource.help);
  Object.defineProperty(accessor.inputs[0], 'what', { enumerable: true, get() { invoked += 1; return 'not JSON'; } });
  assert.equal(parseGitHubSetupHelp(accessor), null);
  assert.equal(invoked, 0);
});

test('native bridge sends only the fixed command/arguments and validates catalog and proposal responses', async () => {
  const calls = [];
  const native = createNativeApi('native', async (command, args) => { calls.push({ command, args }); return command === 'catalog' ? catalog() : proposed(); });
  assert.deepEqual((await native.catalog()).githubSetup, resource.help);
  assert.deepEqual(await native.proposeGitHubSetup(request()), proposed());
  assert.deepEqual(calls, [{ command: 'catalog', args: undefined }, { command: 'propose_github_setup', args: request() }]);
  await assert.rejects(native.proposeGitHubSetup({ ...request(), projectId: 'never-forward' }), (error) => error.code === 'invalid_request');
  assert.equal(calls.length, 2);
  const malformed = createNativeApi('native', async () => ({ ...proposed(), applyToken: 'NEVER ACCEPT' }));
  await assert.rejects(malformed.proposeGitHubSetup(request()), (error) => error.code === 'GitHubSetupResponseInvalid' && !JSON.stringify(error).includes('NEVER ACCEPT'));
  const missingHelp = createNativeApi('native', async () => null);
  await assert.rejects(missingHelp.catalog(), (error) => error.code === 'GitHubSetupHelpUnavailable');
  assert.equal('applyGitHubSetup' in native, false);
  assert.equal('authenticateGitHub' in native, false);
  assert.equal('dispatchGitHub' in native, false);
});

test('native catalog keeps optional guide failures independent from GitHub setup', async () => {
  const guides = ['credentialGuide', 'githubConnection', 'metadataText', 'releaseVersionEdit'];
  let reply = catalog(); let calls = 0;
  const native = createNativeApi('native', async (command, args) => {
    assert.equal(command, 'catalog'); assert.equal(args, undefined); calls += 1;
    return reply;
  });
  const current = await native.catalog();
  assert.deepEqual(current.githubSetup, resource.help);
  for (const key of guides) assert.deepEqual(current[key], reply[key]);
  for (const unavailable of guides) {
    for (const state of ['absent', 'null', 'malformed']) {
      reply = catalog();
      if (state === 'absent') delete reply[unavailable];
      else reply[unavailable] = state === 'null' ? null : { ...reply[unavailable], schemaVersion: 2 };
      const result = await native.catalog();
      assert.deepEqual(result.githubSetup, resource.help);
      for (const key of guides) assert.deepEqual(result[key], key === unavailable ? null : reply[key]);
    }
  }
  assert.equal(calls, 1 + 3 * guides.length);
});

test('native response correlation is not rebound by caller or invocation argument mutation', async () => {
  const work = deferred(); const input = request();
  const native = createNativeApi('native', async (_command, args) => {
    args.draft.source.candidateBranch = 'mutated invocation argument';
    return work.promise;
  });
  const call = native.proposeGitHubSetup(input);
  input.draft.source.candidateBranch = 'mutated caller input';
  const output = proposed(); output.settings.sourcePolicy.candidateBranch = 'mutated invocation argument';
  work.resolve(output);
  await assert.rejects(call, (error) => error.code === 'GitHubSetupResponseInvalid');
});

test('bridge failures use safe errors and never activate browser preview or a generated fallback', async () => {
  for (const code of ['invalid_params', 'resource_unavailable', 'proposal_output_limit', 'runtime_unavailable', 'cleanup_unknown', 'query_timeout', 'unknown-code']) {
    const native = createNativeApi('native', async () => { throw { code, message: 'PRIVATE REJECTION DATA' }; });
    await assert.rejects(native.proposeGitHubSetup(request()), (error) => !JSON.stringify(error).includes('PRIVATE') && error.retryable === false);
    assert.equal(native.mode, 'native');
  }
  const unavailable = createNativeApi('unavailable', async () => { throw new Error('MUST NOT INVOKE'); });
  await assert.rejects(unavailable.proposeGitHubSetup(request()), (error) => error.code === 'NativeBridgeRequired');
  for (const error of [null, 'PRIVATE', { code: '__proto__', message: 'PRIVATE' }, new Error('PRIVATE')]) assert.equal(JSON.stringify(githubSetupError(error)).includes('PRIVATE'), false);
});

test('explicit browser fixture imports only core help and refuses workflow proposals', async () => {
  assert.equal(previewApi.mode, 'preview');
  const help = (await previewApi.catalog()).githubSetup;
  assert.deepEqual(help, resource.help);
  help.inputs[0].label = 'changed copy';
  assert.equal((await previewApi.catalog()).githubSetup.inputs[0].label, resource.help.inputs[0].label);
  await assert.rejects(previewApi.proposeGitHubSetup(request()), (error) => error.code === 'PreviewOnly');
  const fixture = harness(); fixture.controller.setConnection(previewApi, appInfo());
  await fixture.controller.propose();
  assert.equal(fixture.calls.length, 0);
  assert.equal(fixture.controller.getSnapshot().result, null);
  assert.notEqual(githubSetupStartReason(fixture.controller.getSnapshot()), null);
});

test('without admitted help or method capability no proposal can start and no defaults are invented', async () => {
  const controller = new GitHubSetupController(() => null);
  assert.equal(controller.getSnapshot().inputs.toolingRepository, '');
  assert.equal(controller.getSnapshot().inputs.toolingSha, '');
  assert.equal(controller.getSnapshot().inputs.snapshotEnabled, false);
  const noHelp = harness({ withHelp: false });
  assert.notEqual(githubSetupStartReason(noHelp.controller.getSnapshot()), null);
  await noHelp.controller.propose(); assert.equal(noHelp.calls.length, 0);
  assert.equal(noHelp.controller.admitHelp({ schemaVersion: 1, inputs: [], guidance: [] }), false);
  assert.equal(noHelp.controller.getSnapshot().help, null);
  const noMethod = harness({ available: false });
  await noMethod.controller.propose(); assert.equal(noMethod.calls.length, 0);
  assert.equal(noMethod.controller.getSnapshot().help.inputs.length, 3);
});

test('snapshot input conversion never silently turns a malformed assertion into absence or null', () => {
  const fixture = harness(); const controller = fixture.controller;
  assert.equal(githubSnapshotFromInputs(controller.getSnapshot().inputs), null);
  controller.setSnapshotEnabled(true);
  assert.deepEqual(githubSnapshotFromInputs(controller.getSnapshot().inputs), { workflows: [] });
  controller.setAssertion('candidate', { state: 'present' });
  assert.equal(githubSnapshotFromInputs(controller.getSnapshot().inputs), undefined);
  assert.notEqual(githubSetupStartReason(controller.getSnapshot()), null);
  controller.setAssertion('candidate', { byteLength: '0', sha256: '0'.repeat(64) });
  assert.deepEqual(githubSnapshotFromInputs(controller.getSnapshot().inputs), { workflows: [{ id: 'candidate', state: 'present', byteLength: 0, sha256: '0'.repeat(64) }] });
  for (const byteLength of ['-1', '1.5', '1e3', ' 0 ', '1048577', '0\n']) {
    controller.setAssertion('candidate', { byteLength });
    assert.equal(githubSnapshotFromInputs(controller.getSnapshot().inputs), undefined);
  }
  controller.setAssertion('candidate', { state: 'absent' });
  assert.deepEqual(githubSnapshotFromInputs(controller.getSnapshot().inputs), { workflows: [{ id: 'candidate', state: 'absent' }] });
  controller.setSnapshotEnabled(false);
  assert.equal(githubSnapshotFromInputs(controller.getSnapshot().inputs), null);
  assert.equal(controller.getSnapshot().inputs.assertions.every((row) => row.state === 'not-supplied' && row.byteLength === '' && row.sha256 === ''), true);
});

test('proposal controller copies drafts, coalesces current clicks and preserves only immutable display results', async () => {
  const fixture = harness(); const before = structuredClone(fixture.selected());
  const first = fixture.controller.propose();
  await fixture.controller.propose();
  assert.equal(fixture.calls.length, 1);
  assert.deepEqual(fixture.calls[0].input, request());
  assert.notEqual(fixture.calls[0].input.draft, fixture.selected().draft);
  assert.throws(() => { fixture.calls[0].input.draft.source.candidateBranch = 'cannot rebind'; });
  assert.equal(Object.hasOwn(fixture.calls[0].input, 'projectId'), false);
  const output = proposed(); fixture.calls[0].resolve(output); await first;
  const retained = fixture.controller.getSnapshot().result;
  assert.deepEqual(retained, proposed());
  output.workflows[0].content = 'mutated test double';
  assert.notEqual(retained.workflows[0].content, output.workflows[0].content);
  assert.throws(() => { retained.facts.applyAvailable = true; });
  assert.deepEqual(fixture.selected(), before);
  assert.equal(fixture.controller.getSnapshot().resultBinding.projectId, before.project.id);
});

test('coordinate changes away and back invalidate pending and displayed proposals synchronously', async () => {
  const fixture = harness(); const controller = fixture.controller;
  const first = controller.propose();
  const generation = controller.getSnapshot().coordinateGeneration;
  controller.setCoordinate('toolingRepository', 'another/toolkit');
  controller.setCoordinate('toolingRepository', repository);
  assert.equal(controller.getSnapshot().pending, null);
  assert.equal(controller.getSnapshot().coordinateGeneration, generation + 2);
  fixture.calls[0].resolve(proposed()); await first;
  assert.equal(controller.getSnapshot().result, null);
  const second = controller.propose(); fixture.calls[1].resolve(proposed()); await second;
  assert.notEqual(controller.getSnapshot().result, null);
  controller.setCoordinate('toolingSha', 'A'.repeat(40));
  assert.equal(controller.getSnapshot().result, null);
  assert.equal(controller.getSnapshot().invalidated, true);
});

test('comparison generation distinguishes null, an empty summary, and changed-back digest assertions', async () => {
  const fixture = harness(); const controller = fixture.controller;
  const first = controller.propose();
  controller.setSnapshotEnabled(true); controller.setSnapshotEnabled(false);
  fixture.calls[0].resolve(proposed()); await first;
  assert.equal(controller.getSnapshot().result, null);
  controller.setSnapshotEnabled(true);
  const second = controller.propose();
  assert.deepEqual(fixture.calls[1].input.suppliedSnapshot, { workflows: [] });
  const output = proposed(); output.facts.snapshotProvided = true;
  fixture.calls[1].resolve(output); await second;
  assert.equal(controller.getSnapshot().result.facts.snapshotProvided, true);
  controller.setAssertion('candidate', { state: 'present', byteLength: '0', sha256: '0'.repeat(64) });
  const third = controller.propose();
  controller.setAssertion('candidate', { sha256: '1'.repeat(64) }); controller.setAssertion('candidate', { sha256: '0'.repeat(64) });
  output.workflows[1].comparison = 'supplied-digest-differs';
  fixture.calls[2].resolve(output); await third;
  assert.equal(controller.getSnapshot().result, null);
});

test('project switches away and back suppress replies, reset only comparisons and preserve unsaved drafts', async () => {
  const fixture = harness(); const original = fixture.selected(); const before = structuredClone(original);
  const controller = fixture.controller;
  controller.setSnapshotEnabled(true); controller.setAssertion('candidate', { state: 'absent' });
  const work = controller.propose();
  fixture.select(project('project-b')); fixture.select(original);
  const output = proposed(); output.facts.snapshotProvided = true; output.workflows[1].comparison = 'reported-absent';
  fixture.calls[0].resolve(output); await work;
  assert.equal(controller.getSnapshot().result, null);
  assert.equal(controller.getSnapshot().inputs.snapshotEnabled, false);
  assert.equal(controller.getSnapshot().inputs.toolingRepository, repository);
  assert.equal(controller.getSnapshot().inputs.toolingSha, sha);
  assert.deepEqual(fixture.selected(), before);
});

test('draft revision, baseline generation and replacement draft identity each invalidate replies', async () => {
  for (const change of [
    (session) => ({ ...session, revision: session.revision + 1 }),
    (session) => ({ ...session, baselineGeneration: session.baselineGeneration + 1 }),
    (session) => ({ ...session, draft: structuredClone(session.draft) }),
    (session) => ({ ...session, draft: null }),
  ]) {
    const fixture = harness(); const work = fixture.controller.propose();
    fixture.select(change(fixture.selected()));
    fixture.calls[0].resolve(proposed()); await work;
    assert.equal(fixture.controller.getSnapshot().result, null);
  }
  const fixture = harness(); const work = fixture.controller.propose();
  fixture.replaceWithoutSync({ ...fixture.selected(), revision: 99 });
  fixture.calls[0].resolve(proposed()); await work;
  assert.equal(fixture.controller.getSnapshot().result, null);
});

test('service generations suppress old replies and retain only labelled previously loaded help', async () => {
  const fixture = harness(); const controller = fixture.controller;
  const help = controller.getSnapshot().help;
  const first = controller.propose();
  controller.beginConnection(); controller.setConnection(fixture.api, appInfo());
  assert.equal(controller.getSnapshot().helpState, 'previous');
  fixture.calls[0].resolve(proposed()); await first;
  assert.equal(controller.getSnapshot().result, null);
  assert.equal(controller.getSnapshot().help, help);
  assert.equal(controller.admitHelp(resource.help), true);
  const second = controller.propose(); fixture.calls[1].resolve(proposed()); await second;
  controller.connectionUnavailable();
  assert.equal(controller.getSnapshot().result, null);
  assert.equal(controller.getSnapshot().helpState, 'previous');
  assert.deepEqual(controller.getSnapshot().help, resource.help);
  await controller.propose();
  assert.equal(fixture.calls.length, 2);
});

test('a superseded request success or failure cannot replace a newer accepted result', async () => {
  for (const failure of [false, true]) {
    const fixture = harness(); const controller = fixture.controller;
    const first = controller.propose();
    controller.setCoordinate('toolingRepository', 'other/toolkit'); controller.setCoordinate('toolingRepository', repository);
    const second = controller.propose();
    const newestId = controller.getSnapshot().pending.requestId;
    fixture.calls[1].resolve(proposed()); await second;
    if (failure) fixture.calls[0].reject({ code: 'runtime_unavailable', message: 'PRIVATE' });
    else fixture.calls[0].resolve(invalid());
    await first;
    assert.equal(controller.getSnapshot().result.state, 'proposed');
    assert.equal(controller.getSnapshot().resultBinding.requestId, newestId);
    assert.equal(controller.getSnapshot().error, null);
  }
});

test('invalid drafts and bridge failures retain guidance without inventing workflows or erasing input', async () => {
  const fixture = harness(); const controller = fixture.controller; const before = structuredClone(fixture.selected());
  const help = controller.getSnapshot().help;
  const first = controller.propose(); fixture.calls[0].resolve(invalid()); await first;
  assert.deepEqual(Object.keys(controller.getSnapshot().result).sort(), ['assurance', 'facts', 'schemaVersion', 'state', 'validation']);
  assert.equal(controller.getSnapshot().help, help);
  const second = controller.propose(); fixture.calls[1].reject({ code: 'resource_unavailable', message: 'PRIVATE' }); await second;
  assert.equal(controller.getSnapshot().result, null);
  assert.equal(controller.getSnapshot().help, help);
  assert.equal(controller.getSnapshot().helpState, 'previous');
  assert.equal(controller.getSnapshot().error.code, 'resource_unavailable');
  assert.equal(JSON.stringify(controller.getSnapshot().error).includes('PRIVATE'), false);
  assert.equal(controller.admitHelp({ ...resource.help, unexpected: true }), false);
  assert.equal(controller.getSnapshot().help, help);
  assert.deepEqual(fixture.selected(), before);
  assert.equal(controller.getSnapshot().inputs.toolingRepository, repository);
});

test('controller also rejects malformed or mismatched replies from a typed API test double', async () => {
  for (const output of [{ ...proposed(), planToken: 'no authority' }, { ...proposed(), facts: facts(true) },
    { ...proposed(), tooling: { ...proposed().tooling, repository: 'other/toolkit', schemaReference: `https://raw.githubusercontent.com/other/toolkit/${sha}/schemas/project.schema.json` } }]) {
    const fixture = harness(); const work = fixture.controller.propose(); fixture.calls[0].resolve(output); await work;
    assert.equal(fixture.controller.getSnapshot().result, null);
    assert.equal(fixture.controller.getSnapshot().error.code, 'GitHubSetupResponseInvalid');
    assert.deepEqual(fixture.controller.getSnapshot().help, resource.help);
  }
});

test('native unavailability and cleanup uncertainty disable further requests until an explicit reconnect', async () => {
  for (const code of ['runtime_unavailable', 'cleanup_unknown', 'shutting_down', 'unknown']) {
    const fixture = harness(); const work = fixture.controller.propose();
    fixture.calls[0].reject({ code, message: 'PRIVATE' }); await work;
    assert.notEqual(githubSetupStartReason(fixture.controller.getSnapshot()), null);
    await fixture.controller.propose(); assert.equal(fixture.calls.length, 1);
    fixture.controller.beginConnection(); fixture.controller.setConnection(fixture.api, appInfo());
    assert.equal(githubSetupStartReason(fixture.controller.getSnapshot()), null);
  }
});

test('reentrant invalidation before invocation and disposal do not publish or retry an obsolete proposal', async () => {
  const fixture = harness(); let changed = false;
  const unsubscribe = fixture.controller.subscribe(() => {
    if (!changed && fixture.controller.getSnapshot().pending) {
      changed = true; fixture.controller.setCoordinate('toolingSha', 'b'.repeat(40));
    }
  });
  await fixture.controller.propose(); assert.equal(fixture.calls.length, 0);
  unsubscribe(); fixture.controller.setCoordinate('toolingSha', sha);
  const work = fixture.controller.propose();
  let notifications = 0;
  fixture.controller.subscribe(() => { notifications += 1; });
  fixture.controller.dispose(); fixture.calls[0].resolve(proposed()); await work;
  assert.equal(notifications, 0);
  assert.equal(fixture.controller.getSnapshot().result, null);
  await fixture.controller.propose(); assert.equal(fixture.calls.length, 1);
});

// Actual remote settings parser/controller/bridge, inert fixed DATA and IPC only.
const rsTime = '2026-10-09T12:00:00Z', rsExpiry = '2026-10-09T12:02:00Z';
const rsSelection = () => ({ kind: 'actions_enabled', enabled: true });
function rsIdle(revision = 1) { return { schemaVersion: 1, revision, sessionId: 'session-a', available: true, reason: 'none', operation: null, consent: null, observed: null }; }
function rsOp(kind, phase, revision, changes = {}) {
  return { ...rsIdle(revision), available: phase === 'settled', reason: phase === 'settled' ? 'none' : phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'busy',
    operation: { id: kind + '-a', kind, phase, reason: phase === 'cleanup-unknown' ? 'cleanup-unknown' : 'none', effect: kind === 'apply' ? 'unknown' : 'not-started', writeClaimed: null, writeAcknowledged: null, ...changes } };
}
function rsReview(revision = 3, selected = rsSelection()) {
  const before = selected.kind === 'actions_enabled' ? { enabled: false, allowed_actions: 'selected', sha_pinning_required: true } : { default_workflow_permissions: 'read', can_approve_pull_request_reviews: false };
  const after = selected.kind === 'actions_enabled' ? { ...before, enabled: selected.enabled } : { default_workflow_permissions: selected.defaultWorkflowPermissions, can_approve_pull_request_reviews: selected.canApprovePullRequestReviews };
  return { ...rsOp('prepare', 'settled', revision, { writeClaimed: false, writeAcknowledged: false }), observed: structuredClone(before),
    consent: { id: 'a'.repeat(32), expiresAt: rsExpiry, prepared: { target: { projectBinding: 'b'.repeat(64), repository: 'owner/app', accountId: '11', repositoryId: '22', selection: selected }, before, after, observedAt: rsTime, confirmation: githubRemoteSetupConfirmation(selected.kind, 'owner/app') } } };
}
function rsConnection() { return { mode: 'native', context: { documentId: 'doc', projectId: 'project', projectGeneration: 1, repository: 'owner/app' }, status: { revision: 12,
  session: { id: 'session-a', projectId: 'project', targetRepository: 'owner/app', state: 'connected' }, account: { state: 'observed', value: { id: '11' } },
  repository: { state: 'observed', value: { id: '22', fullName: 'owner/app' } } }, busy: null, uncertain: false, blocked: false, retirementPending: false }; }
function rsDeferred() { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
async function rsFlush() { for (let i = 0; i < 16; i += 1) await Promise.resolve(); }
function rsHarness() {
  let current = rsIdle(), view = rsConnection(), listener = null, detached = 0, other = null; const calls = [];
  const request = (kind, args) => { const d = rsDeferred(); calls.push({ kind, args: structuredClone(args), ...d }); return d.promise; };
  const api = { mode: 'native', githubRemoteSetupStatus: async () => structuredClone(current), subscribeGitHubRemoteSetup: async (f) => { listener = f; return () => { detached += 1; listener = null; }; },
    githubRemoteSetupPrepare: (v) => request('prepare', v), githubRemoteSetupApply: (v) => request('apply', v), githubRemoteSetupDiscard: (v) => request('discard', v), githubRemoteSetupCancel: (v) => request('cancel', v) };
  const controller = new GitHubRemoteSetupController(() => view, () => other);
  return { api, controller, calls, get state() { return controller.getSnapshot(); }, get detached() { return detached; },
    last: (kind) => calls.filter((c) => c.kind === kind).at(-1), count: (kind) => calls.filter((c) => c.kind === kind).length,
    emit(s) { current = structuredClone(s); listener?.(structuredClone(s)); }, reply(kind, s) { current = structuredClone(s); this.last(kind).resolve(structuredClone(s)); },
    context(v) { view = v ?? { ...rsConnection(), context: null }; controller.syncContext(); }, block(v) { other = v; } };
}
async function rsAttached() { const h = rsHarness(); await h.controller.connect(h.api); h.controller.setSelection(rsSelection()); return h; }
async function rsReady() { const h = await rsAttached(); h.controller.prepare(); h.reply('prepare', rsReview()); await rsFlush(); assert.ok(h.controller.currentConsent()); return h; }

test('remote setup closed policy and consent preserve untouched fields and distinguish unknown writes', () => {
  for (const selected of [rsSelection(), { kind: 'workflow_token_policy', defaultWorkflowPermissions: 'write', canApprovePullRequestReviews: true }]) {
    const good = rsReview(3, selected); assert.ok(parseGitHubRemoteSetupStatus(good));
    for (const mutate of [(s) => { s.consent.prepared.after.extra = true; }, (s) => { s.consent.prepared.target.repositoryId = 22; },
      (s) => { s.consent.prepared.before = s.consent.prepared.after; }, (s) => { s.consent.prepared.confirmation += ' TRUST ME'; },
      (s) => { s.consent.prepared.target.projectBinding = 'wrong'; }, (s) => { s.consent.prepared.after = {}; },
      (s) => { s.consent.expiresAt = 'tomorrow'; }, (s) => { s.consent.prepared.target.selection.token = 'PRIVATE'; },
      (s) => { s.consent.prepared.after[Object.keys(s.consent.prepared.after).find((k) => typeof s.consent.prepared.after[k] === 'boolean')] = 1; }]) {
      const bad = structuredClone(good); mutate(bad); assert.equal(parseGitHubRemoteSetupStatus(bad), null);
    }
  }
  for (const key of ['allowed_actions', 'sha_pinning_required']) { const s = rsReview(); s.consent.prepared.after[key] = key === 'allowed_actions' ? 'all' : false; assert.equal(parseGitHubRemoteSetupStatus(s), null); }
  const unknown = rsOp('apply', 'cleanup-unknown', 6); assert.ok(parseGitHubRemoteSetupStatus(unknown));
  for (const changes of [{ effect: 'readback-confirmed' }, { writeClaimed: false, writeAcknowledged: false }, { writeAcknowledged: true }]) assert.equal(parseGitHubRemoteSetupStatus({ ...unknown, operation: { ...unknown.operation, ...changes } }), null);
  const success = { ...rsOp('apply', 'settled', 6, { effect: 'readback-confirmed', writeClaimed: true, writeAcknowledged: true }), observed: rsReview().consent.prepared.after };
  assert.ok(parseGitHubRemoteSetupStatus(success)); assert.ok(parseGitHubRemoteSetupStatus({ ...success, available: false, reason: 'expired' })); assert.ok(parseGitHubRemoteSetupStatus({ ...success, available: false, reason: 'cleanup-unknown' }));
  assert.equal(parseGitHubRemoteSetupStatus({ ...success, observed: null }), null);
  for (const field of ['writeClaimed', 'writeAcknowledged']) { const bad = structuredClone(success); bad.operation[field] = null; assert.equal(parseGitHubRemoteSetupStatus(bad), null); }
  assert.equal(parseGitHubRemoteSetupStatus({ ...rsIdle(), revision: 4294967294 }), null);
  assert.ok(parseGitHubRemoteSetupStatus({ ...rsIdle(4294967294), available: false, reason: 'cleanup-unknown' }));
  let reads = 0; const getter = rsIdle(); Object.defineProperty(getter, 'reason', { enumerable: true, get() { reads += 1; return 'none'; } });
  assert.equal(parseGitHubRemoteSetupStatus(getter), null); assert.equal(reads, 0);
  const error = githubRemoteSetupError({ code: 'github_remote_setup_refused_forbidden', message: 'PRIVATE' });
  assert.equal(error.admission, 'not-admitted'); assert.equal(error.message.includes('PRIVATE'), false);
  assert.equal(githubRemoteSetupError({ code: 'anything', admission: 'not-admitted' }).admission, 'unknown');
});

test('remote setup original controller consumes explicit review and retires stale or uncertain originals without retries', async () => {
  const h = await rsReady(); h.controller.apply(); assert.equal(h.count('apply'), 0);
  h.controller.setConfirmed(true); h.controller.apply(); h.controller.apply();
  assert.equal(h.count('apply'), 1); assert.deepEqual(h.last('apply').args, { sessionId: 'session-a', expectedRevision: 3, consentId: 'a'.repeat(32), confirm: true });
  assert.equal(h.controller.currentConsent(), null); assert.ok(githubRemoteSetupOwnerReason(h.state));
  h.emit(rsOp('apply', 'running', 4)); h.last('apply').reject(new Error('PRIVATE')); await rsFlush(); assert.equal(h.state.uncertain, true);
  h.context(null); assert.equal(h.state.originalTarget.repository, 'owner/app'); assert.equal(h.state.originalTarget.accountId, '11'); assert.equal(h.count('cancel'), 1); h.controller.cancel(); assert.equal(h.count('cancel'), 1); assert.equal(h.last('cancel').args, 'apply-a'); assert.equal(h.state.pending, true);
  const done = { ...rsOp('apply', 'settled', 6, { effect: 'readback-confirmed', writeClaimed: true, writeAcknowledged: true }), observed: rsReview().consent.prepared.after };
  h.reply('cancel', done); await rsFlush(); assert.equal(h.state.pending, false); assert.equal(h.state.uncertain, false); assert.equal(h.count('apply'), 1); assert.equal(h.controller.currentConsent(), null);
  h.emit(rsOp('apply', 'running', 4)); assert.equal(h.state.status.revision, 6); h.controller.dispose();
  // Invalidate before actual admission/reply, including an away-and-back context.
  const stale = await rsAttached(); stale.controller.prepare(); stale.context(null); stale.context(rsConnection()); stale.controller.setSelection(rsSelection());
  stale.reply('prepare', rsReview()); await rsFlush(); assert.equal(stale.controller.currentConsent(), null); assert.equal(stale.count('discard'), 1);
  assert.deepEqual(stale.last('discard').args, { sessionId: 'session-a', expectedRevision: 3, consentId: 'a'.repeat(32) });
  stale.last('discard').reject(new Error('unknown discard')); await rsFlush(); assert.equal(stale.state.uncertain, true);
  stale.emit({ ...rsReview(4), consent: null }); await rsFlush(); assert.equal(stale.state.uncertain, false); assert.equal(stale.count('prepare'), 1); stale.controller.dispose();
  const deferredStop = await rsAttached(); deferredStop.controller.prepare(); deferredStop.controller.beforeWorkspaceAction();
  assert.equal(deferredStop.count('cancel'), 0); deferredStop.emit(rsOp('prepare', 'running', 2)); assert.equal(deferredStop.count('cancel'), 1);
  deferredStop.controller.beforeWorkspaceAction(); deferredStop.emit(rsOp('prepare', 'running', 2)); assert.equal(deferredStop.count('cancel'), 1);
  const cancelled = rsOp('prepare', 'settled', 3, { reason: 'cancelled', writeClaimed: false, writeAcknowledged: false });
  deferredStop.reply('prepare', cancelled); deferredStop.reply('cancel', cancelled); await rsFlush(); assert.equal(deferredStop.state.pending, false); deferredStop.controller.dispose();
  const edit = await rsReady(); edit.controller.beforeWorkspaceAction(); assert.equal(edit.controller.currentConsent(), null); assert.equal(edit.count('discard'), 1);
  edit.reply('discard', { ...rsReview(4), consent: null }); await rsFlush(); assert.equal(edit.state.discarding, false); edit.controller.dispose();
  const stopped = await rsAttached(); stopped.controller.prepare(); stopped.emit(rsOp('prepare', 'running', 2)); stopped.controller.cancel();
  stopped.reply('prepare', rsReview()); await rsFlush(); assert.equal(stopped.controller.currentConsent(), null); assert.equal(stopped.count('discard'), 1);
  stopped.reply('cancel', rsReview()); stopped.reply('discard', { ...rsReview(4), consent: null }); await rsFlush(); stopped.controller.dispose();
  const unknown = await rsReady(); unknown.controller.setConfirmed(true); unknown.controller.apply(); unknown.emit(rsOp('apply', 'cleanup-unknown', 4));
  assert.equal(unknown.state.uncertain, true); assert.equal(unknown.controller.canCancel(), true); unknown.reply('apply', done); await rsFlush();
  assert.equal(unknown.state.uncertain, true); assert.notEqual(unknown.state.status.operation.effect, 'readback-confirmed'); assert.equal(unknown.count('apply'), 1); unknown.controller.dispose();
  const replaced = await rsAttached(); replaced.controller.prepare(); replaced.emit(rsOp('prepare', 'running', 2));
  await replaced.controller.connect({ ...replaced.api, mode: 'preview' }); assert.equal(replaced.detached, 0); assert.equal(replaced.count('cancel'), 1); assert.equal(replaced.last('cancel').args, 'prepare-a');
  replaced.reply('prepare', { ...rsOp('prepare', 'settled', 3, { reason: 'cancelled', writeClaimed: false, writeAcknowledged: false }) }); await rsFlush(); assert.equal(replaced.detached, 0); replaced.reply('cancel', { ...rsOp('prepare', 'settled', 3, { reason: 'cancelled', writeClaimed: false, writeAcknowledged: false }) }); await rsFlush(); assert.equal(replaced.detached, 1); replaced.controller.dispose();
  const unavailable = await rsAttached(); unavailable.block('another original'); unavailable.controller.prepare(); assert.equal(unavailable.count('prepare'), 0); unavailable.controller.dispose();
  const reentrant = await rsAttached(); let retired = false;
  reentrant.controller.subscribe(() => { if (reentrant.state.pending && !retired) { retired = true; reentrant.controller.beforeWorkspaceAction(); } });
  reentrant.controller.prepare(); assert.equal(reentrant.count('prepare'), 0); assert.equal(reentrant.state.pending, false); reentrant.controller.dispose();
  const denied = await rsAttached(); denied.controller.prepare(); denied.last('prepare').reject({ code: 'github_remote_setup_refused_forbidden' }); await rsFlush();
  assert.equal(denied.state.pending, false); assert.equal(denied.state.uncertain, false); assert.equal(denied.count('prepare'), 1); denied.controller.dispose();
  // Same revision data changes are never a new authoritative Status.
  const contradictory = await rsAttached(); contradictory.emit({ ...rsIdle(), reason: 'busy' }); assert.equal(contradictory.state.uncertain, true); contradictory.controller.dispose();
});

test('remote setup bridge admits only five fixed commands and preview never synthesizes remote results', async () => {
  const calls = []; let event = null; const api = createNativeApi('native', async (name, args) => { calls.push([name, structuredClone(args)]); return rsIdle(); }, async (name, handler) => { assert.equal(name, 'github-remote-setup-status'); event = handler; return () => {}; });
  const prepareArgs = { sessionId: 'session-a', expectedRevision: 1, expectedConnectionRevision: 12, selection: rsSelection() };
  const applyArgs = { sessionId: 'session-a', expectedRevision: 1, consentId: 'a'.repeat(32), confirm: true };
  const discardArgs = { sessionId: 'session-a', expectedRevision: 1, consentId: 'a'.repeat(32) };
  await api.githubRemoteSetupStatus(); await api.githubRemoteSetupPrepare(prepareArgs); await api.githubRemoteSetupApply(applyArgs); await api.githubRemoteSetupDiscard(discardArgs); await api.githubRemoteSetupCancel('operation-a');
  assert.deepEqual(calls, [['github_remote_setup_status', {}], ['github_remote_setup_prepare', prepareArgs], ['github_remote_setup_apply', applyArgs], ['github_remote_setup_discard', discardArgs], ['github_remote_setup_cancel', { operationId: 'operation-a' }]]);
  for (const bad of [{ ...prepareArgs, token: 'PRIVATE' }, { ...prepareArgs, expectedRevision: true }, { ...prepareArgs, expectedConnectionRevision: 0 }, { ...prepareArgs, selection: { kind: 'secret', enabled: true } }]) await assert.rejects(api.githubRemoteSetupPrepare(bad), (e) => e.admission === 'not-admitted');
  assert.equal(calls.length, 5); assert.equal(githubRemoteSetupRequestFits('github_remote_setup_apply', { ...applyArgs, prepared: rsReview().consent.prepared }), false);
  assert.equal(githubRemoteSetupRequestFits('github_remote_setup_apply', { ...applyArgs, confirm: 1 }), false);
  let received = 'untouched'; await api.subscribeGitHubRemoteSetup((s) => { received = s; }); event({ ...rsIdle(), url: 'PRIVATE' }); assert.equal(received, null);
  for (const method of ['githubRemoteSetupStatus', 'githubRemoteSetupPrepare', 'githubRemoteSetupApply', 'githubRemoteSetupDiscard', 'githubRemoteSetupCancel', 'subscribeGitHubRemoteSetup']) await assert.rejects(previewApi[method]({}), (e) => e.reason === 'runtime-unavailable');
  const unavailable = createNativeApi('unavailable', async () => { throw new Error('must not invoke'); }); await assert.rejects(unavailable.githubRemoteSetupStatus(), (e) => e.admission === 'not-admitted');
});
