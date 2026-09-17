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
  metadata: MetadataRules | null;
  assurance: Assurance;
}

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
export interface DesktopApi {
  mode: BridgeMode;
  appInfo(): Promise<AppInfo>;
  chooseProject(): Promise<ProjectReference | null>;
  snapshot(projectId: string): Promise<ProjectSnapshot>;
  catalog(): Promise<Catalog>;
  validate(draft: JsonObject): Promise<ValidationResult>;
  suggestConfig(hints: SuggestionHints): Promise<ConfigSuggestion>;
  configPreview(base: JsonObject | null, draft: JsonObject): Promise<ConfigPreview>;
}

export type Page = 'dashboard' | 'settings' | 'environment' | 'credentials' | 'metadata' | 'github' | 'releases' | 'artifacts' | 'recovery';
