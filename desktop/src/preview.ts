import { offlinePreflightError } from './offlinePreflightProtocol.ts';
import { androidBuildError } from './androidBuildProtocol.ts';
import fieldHelp from '../../src/mobile_release/api/data/field-help.json' with { type: 'json' };
import projectSchema from '../../src/mobile_release/api/data/project.schema.json' with { type: 'json' };
import githubSetupResource from '../../src/mobile_release/api/data/github-setup-v1.json' with { type: 'json' };
import credentialGuideResource from '../../src/mobile_release/api/data/credential-guide-v1.json' with { type: 'json' };
import githubConnectionResource from '../../src/mobile_release/api/data/github-connection-v1.json' with { type: 'json' };
import metadataTextResource from '../../src/mobile_release/api/data/metadata-text-help-v1.json' with { type: 'json' };
import versionEditResource from '../../src/mobile_release/api/data/release-version-help-v1.json' with { type: 'json' };
import { parseVersionEditGuide, versionEditError } from './releaseVersionEdit.ts';
import { githubSetupError, parseGitHubSetupHelp } from './githubSetupProtocol.ts';
import { parseCredentialGuide } from './credentialGuide.ts';
import { assetError } from './assetSessionProtocol.ts';
import { workflowEditError } from './githubWorkflowEditProtocol.ts';
import { githubConnectionError, parseGitHubConnectionHelp } from './githubConnectionProtocol.ts';
import { metadataTextError, parseMetadataTextGuide } from './metadataTextProtocol.ts';
import { environmentError, environmentRequestFits } from './environment.ts';
import { environmentDiagnosticsError } from './environmentDiagnosticsProtocol.ts';
import { releaseVersionError } from './releaseVersion.ts';
import { evidenceError } from './candidateEvidence.ts';
import { projectPathError } from './projectPaths.ts';
import type { EnvironmentRequest, EnvironmentResult, EnvironmentRole, EnvironmentRequirement } from './environment.ts';
import type { ApiError, Assurance, Catalog, DesktopApi, FieldHelp, JsonObject, ProjectSnapshot } from './types.ts';

// Inert, explicit browser-design fixture. Nothing here is a project observation.
const assurance: Assurance = {
  basis: 'static-text', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false,
  writesPerformed: false, releaseReadiness: 'unknown',
};

// Only shipped core guidance is displayed in explicit browser design mode.
// No JS template renderer or successful proposal fixture exists here.
const githubSetup = parseGitHubSetupHelp(githubSetupResource.help);
if (!githubSetup) throw githubSetupError({ code: 'GitHubSetupHelpUnavailable' });

const catalog: Catalog = {
  credentialGuide: parseCredentialGuide(credentialGuideResource),
  githubConnection: parseGitHubConnectionHelp(githubConnectionResource),
  metadataText: parseMetadataTextGuide(metadataTextResource),
  releaseVersionEdit: parseVersionEditGuide(versionEditResource),
  // TypeScript adds optional `undefined` properties when inferring heterogeneous
  // JSON arrays. The exact core-owned JSON resource cannot contain undefined.
  schemaVersion: 1, schema: projectSchema as unknown as JsonObject, fields: fieldHelp as FieldHelp[],
  credentials: [], metadata: null, githubSetup, assurance: { ...assurance, basis: 'schema-policy' },
};

const example: ProjectSnapshot = {
  root: 'Example workspace · no folder has been read',
  observedAt: '', observationScope: 'single-request-non-atomic',
  config: {
    path: 'mobile-release.json (illustration only)', state: 'unavailable', content: null, issues: [],
    data: {
      schemaVersion: 1,
      version: { source: 'release/version.properties', nameKey: 'VERSION_NAME', buildKey: 'BUILD_NUMBER' },
      source: { candidateBranch: 'main', productionBranch: 'main' },
      android: { enabled: true, applicationId: 'com.example.northstar', identityStatus: 'unverified' },
      ios: { enabled: true, bundleId: 'com.example.northstar', identityStatus: 'unverified' },
      metadata: { root: 'release/store', androidLocales: ['en-US'], iosLocales: ['en-US'] },
      services: { androidFirebase: 'disabled', iosFirebase: 'disabled' },
      projectChecks: { preflight: [], androidArtifact: [], iosArtifact: [] },
    },
  },
  discovery: {
    state: 'unverified', partial: false, hints: {},
    scan: { entries: 0, sourceFiles: 0, sourceBytes: 0, excludedEntries: 0 }, limits: {},
  },
  assurance,
  issues: [],
};

const editUnavailable = async (): Promise<never> => {
  throw { code: 'PreviewOnly', message: 'Browser preview has no native edit owner, save plan or finality. No save operation was performed.', retryable: false } satisfies ApiError;
};
const assetUnavailable = async (): Promise<never> => { throw assetError({ code: 'AssetSessionUnavailable' }); };
const workflowUnavailable = async (): Promise<never> => { throw workflowEditError({ code: 'PreviewOnly' }); };
const connectionUnavailable = (): Promise<never> => Promise.reject(githubConnectionError({ code: 'github_connection_refused_unqualified' }));
const versionEditUnavailable = (): Promise<never> => Promise.reject(versionEditError(null));
const metadataUnavailable = (): Promise<never> => Promise.reject(metadataTextError(null));
const offlineUnavailable = (): Promise<never> => Promise.reject(offlinePreflightError({ code: 'offline_preflight_unavailable' }));
const androidUnavailable = (): Promise<never> => Promise.reject(androidBuildError({ code: 'android_build_unavailable' }));
const diagnosticsUnavailable = (): Promise<never> => Promise.reject(environmentDiagnosticsError({ code: 'environment_diagnostics_unavailable' }));

// Deliberate design fixture, not a core assessment or a source of version policy.
// The page labels every returned row as illustrative and hides the fixture host.
function exampleEnvironment(request: EnvironmentRequest): EnvironmentResult {
  const ids: EnvironmentRole[] = request.platform === 'android' ? request.operation === 'build'
    ? ['android-jdk', 'android-gradle-wrapper', 'android-sdk'] : ['android-jdk', 'android-bundletool']
    : request.operation === 'build' ? ['apple-macos', 'apple-xcode', 'apple-signing-tools']
      : ['apple-macos', 'apple-codesign', 'apple-openssl', 'apple-security-framework'];
  const labels: Record<EnvironmentRole, string> = {
    'android-jdk': 'Java Development Kit', 'android-gradle-wrapper': 'Project Gradle wrapper', 'android-sdk': 'Android SDK',
    'android-bundletool': 'Bundletool helper', 'apple-macos': 'macOS host', 'apple-xcode': 'Xcode',
    'apple-signing-tools': 'Signing tools', 'apple-codesign': 'Code signature tools', 'apple-openssl': 'OpenSSL',
    'apple-security-framework': 'Apple Security and CoreFoundation',
  };
  const exampleHelp = (label: string) => ({ label, requiredness: 'required' as const, requiredWhen: 'Illustration only.',
    what: 'Example of contextual guidance, not a core environment assessment.',
    why: 'The native app will explain the purpose of this exact prerequisite.',
    where: 'The connected core provides practical instructions for finding this item.',
    format: 'Illustrative placeholder only; no actual tool or expected version is supplied by this preview.',
    failure: 'No installation, project, account or release readiness has been checked.' });
  const requirements: EnvironmentRequirement[] = ids.map((id) => {
    const kind: EnvironmentRequirement['kind'] = id === 'android-gradle-wrapper' ? 'project-file' :
      id === 'android-bundletool' ? 'bundled-helper' : id === 'android-jdk' || id === 'android-sdk' || id === 'apple-xcode' ? 'external-toolchain' : 'native-os';
    const baseline: EnvironmentRequirement['baseline'] = { kind: 'platform-defined', version: null, build: null, sha256: null, maxBytes: null };
    if (id === 'android-jdk') { baseline.kind = 'workflow-reference'; baseline.version = 'Example only'; }
    else if (id === 'android-sdk' || id === 'android-gradle-wrapper') baseline.kind = 'project-defined';
    else if (id === 'apple-xcode') { baseline.kind = 'exact-pin'; baseline.version = 'Example only'; baseline.build = 'Example only'; }
    else if (id === 'android-bundletool') { baseline.kind = 'exact-pin'; baseline.version = 'Example only'; baseline.sha256 = '0'.repeat(64); baseline.maxBytes = 1; }
    return { id, kind, presence: 'unknown', versionState: 'unknown', inspection: 'not-run', baseline, help: exampleHelp(labels[id]) };
  });
  return { schemaVersion: 1, policyVersion: 'environment-requirements-v1', hostPlatform: 'other',
    context: { platform: request.platform, operation: request.operation }, platformEnabled: true, state: 'requirements-only',
    coverage: 'toolchain-prerequisites-only', nativeInspection: 'unavailable', dependencyCompleteness: 'unknown', requirements,
    help: { platform: exampleHelp('Release platform'), operation: exampleHelp('Activity') },
    limitations: ['Browser design fixture only. Baseline text is illustrative and is not loaded from the core.',
      'No configuration was validated and no host or tool was inspected. This fixture cannot enable native operations.'],
    assurance: { ...assurance, basis: 'schema-policy' } };
}

export const previewApi: DesktopApi = {
  mode: 'preview',
  appInfo: async () => ({
    appName: 'Mobile Release Kit', appVersion: 'Example only',
    runtime: { state: 'unavailable', mode: 'unavailable', reason: 'Browser preview has no native runtime or core validation.' },
    capabilities: null,
    projectPathSelection: { available: false, reason: 'Browser preview has no native project-path picker.' },
  }),
  chooseProject: async () => ({ id: 'preview-example', name: 'Northstar Notes', path: example.root }),
  // No invented relative path or successful native selection in design mode.
  chooseProjectPath: async () => { throw projectPathError({ code: 'project_path_unavailable' }); },
  // No fabricated folder, documents, lifecycle or successful result in preview.
  chooseEvidenceFolder: async () => { throw evidenceError({ code: 'artifact_evidence_unavailable' }); },
  evidenceStatus: async () => { throw evidenceError({ code: 'artifact_evidence_unavailable' }); },
  observeEvidence: async () => { throw evidenceError({ code: 'artifact_evidence_unavailable' }); },
  cancelEvidence: async () => { throw evidenceError({ code: 'artifact_evidence_unavailable' }); },
  snapshot: async () => structuredClone(example),
  observeReleaseVersion: async () => {
    // No successful saved-file fixture, including after native bridge failure.
    throw { ...releaseVersionError({ code: 'release_version_unavailable' }),
      message: 'Browser preview cannot read saved project files or fabricate a version observation.' };
  },
  catalog: async () => structuredClone(catalog),
  validate: async () => {
    throw { code: 'PreviewOnly', message: 'Core validation is unavailable in browser preview. Open the native application to validate a draft.', retryable: false } satisfies ApiError;
  },
  suggestConfig: async () => {
    throw { code: 'PreviewOnly', message: 'Core configuration suggestions are unavailable in browser preview. No suggestion was prepared.', retryable: false } satisfies ApiError;
  },
  configPreview: async () => {
    throw { code: 'PreviewOnly', message: 'Core draft review is unavailable in browser preview. No configuration was reviewed.', retryable: false } satisfies ApiError;
  },
  proposeGitHubSetup: async () => { throw githubSetupError({ code: 'PreviewOnly' }); },
  environmentRequirements: async (request) => {
    if (!environmentRequestFits(request)) throw environmentError({ code: 'environment_request_invalid' });
    return exampleEnvironment(request);
  },
  // Browser requirements are explicit design examples. There is no successful
  // diagnostics fixture, native status, owner or fallback after a bridge error.
  prepareAndroidBuild: androidUnavailable,
  startAndroidBuild: androidUnavailable,
  androidBuildStatus: androidUnavailable,
  cancelAndroidBuild: androidUnavailable,
  subscribeAndroidBuild: androidUnavailable,
  prepareOfflinePreflight: offlineUnavailable,
  startOfflinePreflight: offlineUnavailable,
  offlinePreflightStatus: offlineUnavailable,
  cancelOfflinePreflight: offlineUnavailable,
  subscribeOfflinePreflight: offlineUnavailable,
  startEnvironmentDiagnostics: diagnosticsUnavailable,
  cancelEnvironmentDiagnostics: diagnosticsUnavailable,
  environmentDiagnosticsStatus: diagnosticsUnavailable,
  subscribeEnvironmentDiagnostics: diagnosticsUnavailable,
  openConfigEdit: editUnavailable,
  prepareConfigEdit: editUnavailable,
  applyConfigEdit: editUnavailable,
  closeConfigEdit: editUnavailable,
  configEditStatus: editUnavailable,
  subscribeConfigEdit: editUnavailable,
  openGitHubWorkflowEdit: workflowUnavailable,
  prepareGitHubWorkflowEdit: workflowUnavailable,
  applyGitHubWorkflowEdit: workflowUnavailable,
  closeGitHubWorkflowEdit: workflowUnavailable,
  githubWorkflowEditStatus: workflowUnavailable,
  subscribeGitHubWorkflowEdit: workflowUnavailable,
  openReleaseVersionEdit: versionEditUnavailable,
  prepareReleaseVersionEdit: versionEditUnavailable,
  applyReleaseVersionEdit: versionEditUnavailable,
  closeReleaseVersionEdit: versionEditUnavailable,
  releaseVersionEditStatus: versionEditUnavailable,
  subscribeReleaseVersionEdit: versionEditUnavailable,
  observeMetadataText: metadataUnavailable,
  validateMetadataText: metadataUnavailable,
  openMetadataTextEdit: metadataUnavailable,
  prepareMetadataTextEdit: metadataUnavailable,
  applyMetadataTextEdit: metadataUnavailable,
  closeMetadataTextEdit: metadataUnavailable,
  metadataTextEditStatus: metadataUnavailable,
  subscribeMetadataTextEdit: metadataUnavailable,
  githubConnectionStatus: connectionUnavailable,
  connectGitHubToken: connectionUnavailable,
  refreshGitHubConnection: connectionUnavailable,
  disconnectGitHubConnection: connectionUnavailable,
  subscribeGitHubConnection: connectionUnavailable,
  assetStatus: assetUnavailable,
  openAssetSession: assetUnavailable,
  setAssetContext: assetUnavailable,
  chooseAsset: assetUnavailable,
  prepareCredential: assetUnavailable,
  prepareAssetDelete: assetUnavailable,
  commitAsset: assetUnavailable,
  bindAsset: assetUnavailable,
  discardAsset: assetUnavailable,
  lockAssetSession: assetUnavailable,
  subscribeAssets: assetUnavailable,
};
