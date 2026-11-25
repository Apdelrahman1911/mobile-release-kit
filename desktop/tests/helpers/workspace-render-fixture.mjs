import assert from 'node:assert/strict';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { AndroidToolService } from '../../src/components/AndroidBuild.tsx';
import { WorkspaceBoundary } from '../../src/workspaceBoundary.tsx';
import { WorkspaceDiagnostics } from '../../src/workspaceDiagnostics.ts';
import { parseAndroidToolServiceStatus } from '../../src/androidToolRegistration.ts';

const context = { projectId: 'fixture', draftRevision: 1, baselineGeneration: 1,
  savedConfig: { bytes: 1, sha256: 'a'.repeat(64) },
  savedVersion: { source: 'VERSION', bytes: 12, sha256: 'b'.repeat(64), name: '1.0.0', build: 1 },
  artifactValidation: { mode: 'structure-and-version', uploadCertificateSha256: null } };
let calls = 0;
const controller = new Proxy({ serviceActionReason: () => null, serviceRegistrationReason: () => 'Explicit approval required' }, {
  get(target, key) { if (key in target) return target[key]; return () => { calls++; throw Error('Native work must not execute during rendering'); }; },
});
const results = [];
for (const [generation, service, prerequisite] of [[1, 'requires-approval', 'approval-required'], [2, 'enabled', 'ready'],
  [3, 'not-registered', 'service-unavailable'], [4, 'unavailable', 'service-unavailable']]) {
  const status = parseAndroidToolServiceStatus({ schemaVersion: 1, statusRevision: generation, setupGeneration: generation,
    availability: 'available', prerequisite, phase: 'complete', reason: 'none',
    operation: { operationId: generation.toString(16).padStart(32, '0'), setupGeneration: generation, sourceGeneration: 0, action: 'check', context },
    observation: { state: service, outcome: 'observed', mutationEntered: false, mutationReturned: false, mutationUncertain: false, nativeSettled: true } });
  assert.ok(status, service);
  const state = { toolService: status, serviceListening: true, serviceConsent: null, serviceUnconfirmed: false, serviceError: null };
  const html = renderToStaticMarkup(React.createElement(AndroidToolService, { state, controller }));
  assert.match(html, /Check installed service/);
  if (service === 'enabled') assert.match(html, /Enabled in macOS/);
  if (service === 'requires-approval') assert.match(html, /Approval required in System Settings/);
  results.push(service);
}
assert.equal(calls, 0);
// The boundary's actual reporting/rendering path must survive a thrown value
// whose accessors would have thrown a second exception in the old handler.
let stored = '';
const diagnostics = new WorkspaceDiagnostics(() => ({ getItem: () => stored, setItem: (_key, value) => { stored = value; } }));
const boundary = new WorkspaceBoundary({ children: null, diagnostics });
boundary.setState = update => { boundary.state = { ...boundary.state, ...update }; };
boundary.state.failed = true;
const bad = Object.create(null, { message: { get() { throw Error('secondary exception'); } }, name: { get() { throw Error('secondary exception'); } } });
assert.doesNotThrow(() => boundary.componentDidCatch(bad, { componentStack: '\n at AndroidToolService (file:///private/fixture.tsx)' }));
const fallback = renderToStaticMarkup(boundary.render());
assert.match(fallback, /bounded diagnostic record was saved locally/);
assert.doesNotMatch(fallback, /private|secondary exception/);
assert.equal(JSON.parse(stored).records[0].components[0], 'AndroidToolService');
console.log(JSON.stringify({ helperStatesRendered: results, nativeCalls: calls, persistentBoundaryFallback: 'PASS' }));
