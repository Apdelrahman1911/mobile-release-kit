import type { AssetSessionApi } from './assetSessionTypes.ts';
import type { GitHubWorkflowEditApi } from './githubWorkflowEditTypes.ts';
import type { GitHubConnectionApi, GitHubConnectionHelp } from './githubConnectionTypes.ts';
import type { MetadataTextApi, MetadataTextGuide } from './metadataText.ts';
import type { EnvironmentRequest, EnvironmentResult } from './environment.ts';
import type { EnvironmentDiagnosticsApi } from './environmentDiagnosticsTypes.ts';
import type { ReleaseVersionApi } from './releaseVersion.ts';

// Closed passive service contracts. Python owns field policy and assurance.
export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject { [key: string]: JsonValue }

export interface Issue {
  code: string;
  status: 'INVALID' | 'SKIP';
  message: string;
  remediation: string;
}

export interface Assurance {
  basis: 'static-text' | 'schema-policy';
  projectCodeExecuted: false;
  toolsProbed: false;
  credentialsRead: false;
  gitObserved: false;
  storeContacted: false;
  writesPerformed: false;
  releaseReadiness: 'unknown';
}

export interface HelpContent {
  label: string;
  requiredness: 'required' | 'optional' | 'conditional';
  requiredWhen: string;
  what: string;
  why: string;
  where: string;
  format: string;
  failure: string;
}

export interface FieldHelp extends HelpContent {
  path: string;
  section: string;
  input: 'text' | 'boolean' | 'number' | 'enum' | 'string-list' | 'argv' | 'commands';
  options?: string[];
  example?: JsonValue;
}

export interface CredentialHelp extends Omit<HelpContent, 'label'> {
  name: string;
  kind: string;
  platform: string;
  stages: string[];
  alternatives: string[];
}

export type CredentialKindId = 'android-keystore' | 'android-firebase' | 'apple-p12' | 'apple-profile' | 'asc-p8' | 'ios-firebase' | 'google-wif' | 'project-read-token';
export interface CredentialGuideField extends HelpContent {
  id: string;
  requirement: string;
  alternatives: string[];
  input: 'file' | 'secret' | 'text';
  maxBytes: number | null;
  suffixes: string[];
  requiredness: 'conditional';
}
export interface CredentialKind {
  id: CredentialKindId;
  label: string;
  platform: 'android' | 'ios' | 'project';
  defaultLabel: string;
  fields: CredentialGuideField[];
  plannedChecks: string[];
  notVerified: string[];
}
export interface CredentialGuide {
  schemaVersion: 1;
  policyVersion: 'credential-policy-v1';
  availability: 'guide-only';
  kinds: CredentialKind[];
  controls: (HelpContent & { id: string })[];
  states: { id: string; label: string; meaning: string }[];
}

export interface RequirementDescriptor {
  name: string;
  kind: string;
  stage: string;
  platform: string;
  environment: string;
  alternatives: string[];
  reason: string;
  state: 'unknown';
}

export interface Capabilities {
  coreVersion: string;
  apiVersion: 1;
  hostPlatform: 'linux' | 'macos' | 'windows' | 'other';
  mode: 'read-only-foundation';
  methods: { method: string; available: boolean; reason: string }[];
  actions: { id: string; available: false; reason: string }[];
  limitations: string[];
}

export interface Catalog {
  schemaVersion: 1;
  schema: JsonObject;
  fields: FieldHelp[];
  credentials: CredentialHelp[];
  credentialGuide: CredentialGuide | null;
  metadata: MetadataRules | null;
  metadataText: MetadataTextGuide | null;
  githubSetup: GitHubSetupHelp;
  githubConnection: GitHubConnectionHelp | null;
  assurance: Assurance;
}

// Passive GitHub setup DTOs. Pins and digests are assertions, not authority.
export type GitHubWorkflowId = 'preflight' | 'candidate' | 'external-testing' | 'production-submit';
export type GitHubWorkflowPath = '.github/workflows/mobile-preflight.yml' | '.github/workflows/mobile-candidate.yml' | '.github/workflows/mobile-external-testing.yml' | '.github/workflows/mobile-production-submit.yml';
export type GitHubSetupStage = 'candidate' | 'external-testing' | 'production';
export type GitHubGuidanceId = 'source-authority' | 'protected-environments' | 'runner-policy' | 'credentials' | 'preflight-and-releases' | 'scope';
export interface GitHubHelpText {
  label: string;
  what: string;
  why: string;
  where: string;
  format: string;
  failure: string;
}
export interface GitHubSetupHelp {
  schemaVersion: 1;
  inputs: (GitHubHelpText & (
    { id: 'toolingRepository' | 'toolingSha'; requiredness: 'required' } |
    { id: 'suppliedSnapshot'; requiredness: 'optional' }
  ))[];
  guidance: (GitHubHelpText & { id: GitHubGuidanceId })[];
}
export type GitHubWorkflowAssertion =
  | { id: GitHubWorkflowId; state: 'absent' }
  | { id: GitHubWorkflowId; state: 'present'; byteLength: number; sha256: string };
export interface GitHubSuppliedSnapshot { workflows: GitHubWorkflowAssertion[] }
export interface GitHubSetupRequest {
  draft: JsonObject;
  toolingRepository: string;
  toolingSha: string;
  suppliedSnapshot: GitHubSuppliedSnapshot | null;
}
export interface GitHubProposalFacts {
  githubContacted: false;
  repositoryObserved: false;
  toolingRefResolved: false;
  templateCompatibility: 'unknown';
  comparisonBasis: 'caller-supplied-digest-summary';
  snapshotProvided: boolean;
  applyAvailable: false;
}
export interface GitHubRequirement extends RequirementDescriptor {
  kind: 'secret' | 'variable' | 'file' | 'manual';
  stage: GitHubSetupStage;
  platform: 'android' | 'ios' | 'project';
  environment: 'mobile-candidate' | 'mobile-external-testing' | 'mobile-production';
}
export type GitHubComparison = 'not-supplied' | 'reported-absent' | 'supplied-digest-match' | 'supplied-digest-differs';
export interface GitHubWorkflowProposal {
  id: GitHubWorkflowId;
  path: GitHubWorkflowPath;
  content: string;
  byteLength: number;
  sha256: string;
  comparison: GitHubComparison;
}
type GitHubAssurance = Assurance & { basis: 'schema-policy' };
interface GitHubInvalidIssue extends Issue {
  code: 'config.invalid';
  status: 'INVALID';
  message: 'Configuration does not satisfy the shared core format/policy rules; review the draft and contextual field guidance.';
  remediation: 'Correct the input and validate again; no changes were saved.';
}
interface GitHubResultBase {
  schemaVersion: 1;
  facts: GitHubProposalFacts;
  assurance: GitHubAssurance;
}
export interface GitHubSetupInvalid extends GitHubResultBase {
  state: 'invalid';
  validation: { valid: false; state: 'invalid'; issues: [GitHubInvalidIssue]; requirements: []; assurance: GitHubAssurance };
}
export interface GitHubSetupProposed extends GitHubResultBase {
  state: 'proposed';
  validation: { valid: true; state: 'format-valid'; issues: []; requirements: GitHubRequirement[]; assurance: GitHubAssurance };
  templateSet: { coreVersion: string; resourceVersion: 1; resourceSha256: string };
  tooling: { repository: string; sha: string; schemaReference: string; state: 'format-only' };
  workflows: GitHubWorkflowProposal[];
  settings: {
    configPath: 'release/mobile-release.json';
    sourcePolicy: { candidateBranch: string; productionBranch: string; basis: 'configured-policy' };
    environments: { stage: GitHubSetupStage; name: GitHubRequirement['environment'] }[];
    guidanceIds: GitHubGuidanceId[];
  };
}
export type GitHubSetupResult = GitHubSetupInvalid | GitHubSetupProposed;

export interface MetadataRules {
  requiredLocaleText: { android: string[]; ios: string[] };
  textLimits: Record<string, number>;
  androidReleaseNoteLimit: number;
  maxFileBytes: number;
  maxFiles: number;
  maxArchiveBytes: number;
  supportedSuffixes: string[];
  assurance: 'format-rules-only';
}

export interface ValidationResult {
  valid: boolean;
  state: 'invalid' | 'format-valid';
  issues: Issue[];
  requirements: RequirementDescriptor[];
  assurance: Assurance;
}

// Pure preparation only: no roots, file authority, mutation revision or tokens.
export interface SuggestionHints {
  platforms?: ('android' | 'ios')[];
  androidApplicationId?: string;
  iosBundleId?: string;
  versionSource?: string;
  versionNameKey?: string;
  versionBuildKey?: string;
}

export interface ConfigSuggestion {
  schemaVersion: 1;
  draft: JsonObject;
  platformSelectionRequired: boolean;
  provenance: { path: string; source: 'hint' | 'default' | 'example'; reason: string }[];
  validation: ValidationResult;
  assurance: Assurance;
}

export interface FieldContext {
  path: string;
  state: 'required' | 'optional' | 'forbidden' | 'unknown';
  present: boolean;
  reason: string;
}

export interface ValueSummary {
  present: boolean;
  type?: 'null' | 'boolean' | 'number' | 'string' | 'array' | 'object';
  // Immediate items for arrays or own keys for objects; never string length.
  count?: number;
}

export interface ConfigPreview {
  schemaVersion: 1;
  validation: ValidationResult;
  comparison: {
    baseProvided: boolean;
    kind: 'proposed-create' | 'compare';
    state: 'complete' | 'partial';
    semanticallyChanged: boolean;
    counts: { added: number; changed: number; removed: number };
    changes: { path: string; operation: 'add' | 'change' | 'remove'; before: ValueSummary; after: ValueSummary }[];
    unreviewedCount: number;
  };
  fields: FieldContext[];
  assurance: Assurance;
}

export interface ProjectSnapshot {
  root: string;
  observedAt: string;
  observationScope: 'single-request-non-atomic';
  config: {
    path: string;
    state: 'missing' | 'invalid' | 'format-valid' | 'unavailable';
    data: JsonObject | null;
    issues: Issue[];
  };
  discovery: {
    state: 'unverified';
    partial: boolean;
    hints: JsonObject;
    scan: { entries: number; sourceFiles: number; sourceBytes: number; excludedEntries: number };
    limits: { [key: string]: number };
  };
  assurance: Assurance;
  issues: Issue[];
}

export interface ProjectReference { id: string; name: string; path: string }
export interface ApiError { code: string; message: string; retryable: false }

export interface AppInfo {
  appName: string;
  appVersion: string;
  runtime: {
    state: 'available' | 'unavailable' | 'disabled';
    reason: string | null;
    mode: 'bundled' | 'development' | 'unavailable';
  };
  capabilities: Capabilities | null;
}

export type BridgeMode = 'native' | 'preview' | 'unavailable';

// Dedicated native edit owner, not methods on the passive query service.
// Tokens are opaque 32-lowercase-hex strings; all counters are bounded u32.
export type EditAvailability = 'available' | 'unsupported_platform' | 'runtime_unqualified' | 'cleanup_unknown' | 'shutdown' | 'other_edit_active';
export type NativeEditReason = 'none' | 'discarded' | 'cancelled' | 'active_timeout' | 'review_expired' | 'caller_lost' | 'window_lost' | 'shutdown' | 'runtime_unavailable' | 'spawn_failed' | 'protocol_error' | 'io_error' | 'output_limit' | 'cleanup_unknown';
export type CoreEditReason = 'none' | 'invalid_params' | 'invalid_config' | 'ignore_conflict' | 'stale_revision' | 'pending_state' | 'busy' | 'cancelled' | 'filesystem_error' | 'custody_unknown' | 'unsupported_platform';
export interface CoreEditOutcome {
  effect: 'not_started' | 'unchanged' | 'rolled_back' | 'committed' | 'unknown';
  journal: 'not_created' | 'clean' | 'recovery_required' | 'unknown';
  resources: 'settled' | 'unknown';
  reason: CoreEditReason;
}
export type FixedIgnoreLine = '.mobile-release/' | '.mobile-release-init-prepare/' | '.mobile-release-init/' | '.mobile-release-init-cleanup/' |
  '.mobile-release-metadata-text-prepare/' | '.mobile-release-metadata-text/' | '.mobile-release-metadata-text-cleanup/';
export interface PreparedConfigView {
  schemaVersion: 1;
  files: [
    { path: 'release/mobile-release.json'; action: 'create' | 'replace' | 'preserve'; beforeBytes: number | null; afterBytes: number },
    { path: '.gitignore'; action: 'create' | 'append' | 'preserve'; beforeBytes: number | null; afterBytes: number },
  ];
  createReleaseDirectory: boolean;
  rewritesConfigFormatting: boolean;
  ignoreAdditions: FixedIgnoreLine[];
  preview: ConfigPreview;
}
export interface ConfigEditProjection {
  projectId: string;
  sessionId: string;
  ownerGeneration: string;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  reviewRemainingMs: number;
  checkout: { revision: string; base: JsonObject | null } | null;
  prepared: { revision: string; planToken: string; draftRevision: number; baselineGeneration: number; view: PreparedConfigView } | null;
  applySubmitted: boolean;
  coreOutcome: CoreEditOutcome | null;
  nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown';
  lateSettled: boolean;
}
export interface ConfigEditStatus {
  schemaVersion: 1;
  windowGeneration: string;
  statusRevision: number;
  capability: { available: boolean; reason: EditAvailability };
  active: ConfigEditProjection | null;
  lastTerminal: ConfigEditProjection | null;
}
export interface PrepareConfigEditRequest {
  sessionId: string;
  revision: string;
  expectedBase: JsonObject | null;
  draft: JsonObject;
  draftRevision: number;
  baselineGeneration: number;
}

export interface DesktopApi extends AssetSessionApi, GitHubWorkflowEditApi, GitHubConnectionApi, MetadataTextApi, EnvironmentDiagnosticsApi, ReleaseVersionApi {
  mode: BridgeMode;
  appInfo(): Promise<AppInfo>;
  chooseProject(): Promise<ProjectReference | null>;
  snapshot(projectId: string): Promise<ProjectSnapshot>;
  catalog(): Promise<Catalog>;
  validate(draft: JsonObject): Promise<ValidationResult>;
  suggestConfig(hints: SuggestionHints): Promise<ConfigSuggestion>;
  configPreview(base: JsonObject | null, draft: JsonObject): Promise<ConfigPreview>;
  proposeGitHubSetup(request: GitHubSetupRequest): Promise<GitHubSetupResult>;
  environmentRequirements(request: EnvironmentRequest): Promise<EnvironmentResult>;
  openConfigEdit(projectId: string): Promise<ConfigEditStatus>;
  prepareConfigEdit(request: PrepareConfigEditRequest): Promise<ConfigEditStatus>;
  applyConfigEdit(sessionId: string, planToken: string): Promise<ConfigEditStatus>;
  closeConfigEdit(sessionId: string): Promise<ConfigEditStatus>;
  configEditStatus(): Promise<ConfigEditStatus>;
  // Payloads are validated before any renderer state/authority is advanced.
  subscribeConfigEdit(onStatus: (status: unknown) => void): Promise<() => void>;
}

export type Page = 'dashboard' | 'settings' | 'environment' | 'credentials' | 'metadata' | 'github' | 'releases' | 'artifacts' | 'recovery';
