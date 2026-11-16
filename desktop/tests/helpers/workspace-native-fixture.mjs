// Test-only native DATA. No native command, project, credential or helper is accessed.
import {previewApi} from '../../src/preview.ts';
import snapshot from './workspace-native-data/snapshot.json' with {type:'json'};
import version from './workspace-native-data/version.json' with {type:'json'};
import capabilities from './workspace-native-data/capabilities.json' with {type:'json'};
import images from '../../../src/mobile_release/api/data/metadata-images-v1.json' with {type:'json'};
import imageHelp from '../../../src/mobile_release/api/data/metadata-image-help-v1.json' with {type:'json'};
const base='mrktest://app/desktop/src/';
const data={'snapshot.json':snapshot,'version.json':version,'capabilities.json':capabilities,
 'metadata-images-v1.json':images,'metadata-image-help-v1.json':imageHelp};
const readFileSync=url=>JSON.stringify(data[url.pathname.split('/').at(-1)]);
const methods = ['catalog', 'project.snapshot', 'release.version.observe', 'environment', 'metadata.plan', 'config.validate', 'config.review'];
let connected = true, service = { schemaVersion: 1, statusRevision: 0, setupGeneration: 0,
  availability: 'available', prerequisite: 'service-unavailable', phase: 'idle', reason: 'service-unavailable', operation: null, observation: null };
const subscriptions = new Map(), calls = [], inflight = [];
let projectSelections = 0;
globalThis.fixtureListen = async (event, fn) => {
  const set = subscriptions.get(event) ?? new Set(); subscriptions.set(event, set); set.add(fn);
  return () => set.delete(fn);
};
const emit = value => { service = structuredClone(value); for (const fn of subscriptions.get('android-tool-service-state-changed') ?? []) fn(structuredClone(value)); };
const pending = (command, input) => ({ ...service, statusRevision: service.statusRevision + 1, setupGeneration: input.setupGeneration + 1,
  availability: 'busy', phase: command === 'check_android_tool_service' ? 'checking' : command === 'request_android_tool_service_registration' ? 'requesting' : 'opening-settings', reason: 'none', observation: null,
  operation: { operationId: (input.setupGeneration + 1).toString(16).padStart(32, '0'), setupGeneration: input.setupGeneration + 1,
    sourceGeneration: 0, action: command === 'check_android_tool_service' ? 'check' : command === 'request_android_tool_service_registration' ? 'request-registration' : 'open-approval-settings', context: structuredClone(input.context) } });
const finished = (row, state) => ({ ...row, statusRevision: row.statusRevision + 1, availability: 'available', phase: 'complete',
  prerequisite: state === 'enabled' ? 'ready' : state === 'requires-approval' ? 'approval-required' : 'service-unavailable',
  observation: { state, outcome: row.operation.action === 'check' ? 'observed' : row.operation.action === 'request-registration' ? 'registration-requested' : 'settings-requested',
    mutationEntered: row.operation.action !== 'check', mutationReturned: row.operation.action !== 'check', mutationUncertain: false, nativeSettled: true } });
globalThis.fixtureInvoke = async (command, args) => {
  calls.push(command); if (calls.length > 600) throw Error('unexpected invocation loop');
  if (command === 'app_info') return { ...await previewApi.appInfo(), appVersion: '0.1.4',
    projectSelection: { available: true, reason: null },
    runtime: connected ? { state: 'available', mode: 'bundled', reason: null } : { state: 'unavailable', mode: 'unavailable', reason: 'Installed Mac runtime native or data inspection could not finish.' },
    capabilities: connected ? JSON.parse(readFileSync(new URL('./capabilities.json', import.meta.url))) : null };
  if (command === 'catalog') return previewApi.catalog();
  if (['release_evidence_status','evidence_status'].includes(command)) return { schemaVersion: 1, revision: '0', availability: 'available',
    phase: 'idle', selection: null, operation: null, result: null, problem: null };
  if (command === 'metadata_images_catalog') {
    const resource = JSON.parse(readFileSync(new URL('../../src/mobile_release/api/data/metadata-images-v1.json', base)));
    const help = JSON.parse(readFileSync(new URL('../../src/mobile_release/api/data/metadata-image-help-v1.json', base)));
    return { schemaVersion: resource.schemaVersion, policy: resource.policy,
      platforms: [{ id: 'android', label: 'Android' }, { id: 'ios', label: 'iOS' }], types: resource.types, help: help.fields,
      limits: { maxFiles: 10, maxFileBytes: 10485760, maxBatchBytes: 25165824, maxTransactionBytes: 67108864,
        maxDimension: 16384, maxPixels: 67108864, formats: ['png','jpeg'] } };
  }
  if (command === 'vault_status') return { schemaVersion: 3, statusRevision: 0, mode: 'closed', persistence: null,
    capability: { available: true, reason: 'none' }, modes: { session: { available: true, reason: 'none' }, encrypted: { available: false, reason: 'unqualified' } },
    context: null, records: [], assignments: [], operation: null };
  if (['config_edit_status','project_initialization_status','github_workflow_edit_status','metadata_text_edit_status','release_version_edit_status','metadata_images_selection_status','metadata_images_edit_status'].includes(command)) {
    const row = { schemaVersion: 1, windowGeneration: 'a'.repeat(32), statusRevision: 0,
      capability: { available: true, reason: 'available' }, active: null, lastTerminal: null };
    const domain = { project_initialization_status: 'project_initialization', github_workflow_edit_status: 'github_workflows',
      metadata_text_edit_status: 'metadata_text', release_version_edit_status: 'release_version',
      metadata_images_selection_status: 'metadata_images_selection', metadata_images_edit_status: 'metadata_images' }[command];
    if (domain) row.domain = domain;
    return row;
  }
  if (['github_preflight_status','github_release_status'].includes(command)) return { schemaVersion: 1, revision: 1, sessionId: null,
    available: false, reason: 'unqualified', operation: null, prepared: null, consentExpiresAt: null, pending: [], run: null };
  if (command === 'github_history_status') return { schemaVersion: 1, revision: 1, sessionId: null, available: false, reason: 'unqualified', operation: null, result: null };
  if (command === 'github_setup_publication_status') return { schemaVersion: 1, revision: 1, sessionId: null, available: false,
    reason: 'unqualified', operation: null, consent: null, pending: [], pull: null };
  if (command === 'github_remote_setup_status') return { schemaVersion: 1, revision: 1, sessionId: null, available: false,
    reason: 'unqualified', operation: null, consent: null, observed: null };
  if (['github_repository_create_status', 'github_pull_request_status', 'github_actions_retry_status', 'github_play_cleanup_status'].includes(command)) {
    const row = { schemaVersion: 1, revision: 1, sessionId: null, available: false, reason: 'runtime-unavailable',
      operation: null, consent: null, pending: [], observed: null };
    if (command !== 'github_repository_create_status') row.acknowledged = command === 'github_pull_request_status' ? null : false;
    if (command === 'github_play_cleanup_status') row.agentAccess = null;
    return row;
  }
  if (command === 'github_activity_status') return { schemaVersion: 1, revision: 1, sessionId: null, available: false, reason: 'runtime-unavailable', operation: null, result: null };
  if (command === 'github_connection_status') {
    const fact = () => ({ state: 'not-observed', value: null, observedAt: null, reason: 'not-connected' });
    return { schemaVersion: 1, revision: 1,
      capability: { readOnlySessionAvailable: false, reason: 'unqualified', deviceLogin: 'publisher-unconfigured', storage: 'session-only' },
      session: null, operation: null, account: fact(), repository: fact(), automation: fact(),
      facts: { remoteMutationAvailable: false, dispatchAvailable: false, repositoryActionsSettingsObservation: 'not-run',
        environmentObservation: 'not-run', secretObservation: 'not-run', variableObservation: 'not-run', protectionObservation: 'not-run',
        runnerObservation: 'not-run', templateCompatibility: 'unknown', releaseReadiness: 'unknown' } };
  }
  if (command === 'artifact_inspection_status') return { schemaVersion: 1, statusRevision: 0, availability: 'available',
    selection: { generation: 0, projectId: null, format: null, phase: 'idle', reason: 'none', operation: null, items: [] }, operation: null };
  if (command === 'agent_version_reserve_review_status') return null;
  if (command.startsWith('agent_')) throw { code: 'cli_access_unavailable' };
  if (command === 'ios_archive_status') return { schemaVersion: 2, statusRevision: 0, availability: 'available',
    modeCapabilities: { unsigned: true, signed: true, recovery: true }, operation: null };
  if (command === 'environment_diagnostics_status') return { schemaVersion: 1, statusRevision: 0,
    capability: { available: true, reason: 'available' }, active: null, lastTerminal: null };
  if (command === 'tool_acquisition_status') return { schemaVersion: 1, statusRevision: 0, availability: 'available', operation: null };
  if (command === 'project_identity_status') return { schemaVersion: 1, domain: 'project_identity', windowGeneration: 'a'.repeat(32),
    statusRevision: 0, capability: { available: true, reason: 'available' }, active: null, lastTerminal: null };
  if (command === 'choose_project') {projectSelections++;return {id:'fixture-project-'+projectSelections,name:'Fixture '+projectSelections,path:'/inert/approval-fixture'};}
  if (command === 'project_snapshot') return JSON.parse(readFileSync(new URL('./snapshot.json', import.meta.url)));
  if (command === 'release_version_observe') return JSON.parse(readFileSync(new URL('./version.json', import.meta.url)));
  if (command === 'android_toolchain_catalog_status') return { schemaVersion: 1, statusRevision: 0, catalogGeneration: 0, operationId: null,
    availability: 'available', phase: 'idle', reason: 'not-inspected', entries: [], selected: null };
  if (command === 'android_build_status') return { schemaVersion: 1, statusRevision: 0, availability: 'available', operation: null };
  if (command === 'android_tool_service_status') return structuredClone(service);
  if (command === 'android_tool_sources_status') return { schemaVersion: 1, statusRevision: 0, sourceGeneration: 0, projectId: null,
    availability: 'available', phase: 'idle', reason: 'not-inspected', operation: null, selections: [], inspection: 'not-run', protectedCopy: 'not-created' };
  if (command === 'android_tool_registration_status') return { schemaVersion: 1, statusRevision: 0, registrationGeneration: 0,
    availability: 'available', prerequisite: 'ready', phase: 'idle', reason: 'not-inspected', operation: null, review: null, report: null };
  if (['check_android_tool_service', 'request_android_tool_service_registration', 'open_android_tool_service_approval_settings'].includes(command)) {
    const input = args instanceof Uint8Array ? JSON.parse(new TextDecoder().decode(args)) : args.request ?? args;
    const row = pending(command, input); emit(row);
    return await new Promise(resolve => inflight.push({ command, row, resolve }));
  }
  if (command.endsWith('_status')) return { schemaVersion: 1, statusRevision: 0, availability: 'available', operation: null };
  throw { code: 'fixture_unavailable', message: 'Closed inert fixture: operation unavailable', retryable: false };
};

export {calls,inflight,emit,pending,finished};
export async function statusRows() {
 const rows=[];
 for(const [event,command] of [['config-edit-state','config_edit_status'],
  ['github-workflow-edit-status','github_workflow_edit_status'],['asset-session-state','vault_status'],
  ['github-connection-status','github_connection_status']])rows.push([event,await globalThis.fixtureInvoke(command)]);
 return rows;
}
export function nativeTick(rows) {
 let count=0;
 for(const [event,row] of rows)for(const fn of subscriptions.get(event)??[]){fn(structuredClone(row));count++;}
 return count;
}
export const subscriptionCounts=()=>Object.fromEntries([...subscriptions].map(([name,set])=>[name,set.size]));
