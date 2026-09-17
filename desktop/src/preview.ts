import fieldHelp from '../../src/mobile_release/api/data/field-help.json';
import projectSchema from '../../src/mobile_release/api/data/project.schema.json';
import type { ApiError, Assurance, Catalog, DesktopApi, FieldHelp, JsonObject, ProjectSnapshot } from './types.ts';

// Inert, explicit browser-design fixture. Nothing here is a project observation.
const assurance: Assurance = {
  basis: 'static-text', projectCodeExecuted: false, toolsProbed: false,
  credentialsRead: false, gitObserved: false, storeContacted: false,
  writesPerformed: false, releaseReadiness: 'unknown',
};

const catalog: Catalog = {
  // TypeScript adds optional `undefined` properties when inferring heterogeneous
  // JSON arrays. The exact core-owned JSON resource cannot contain undefined.
  schemaVersion: 1, schema: projectSchema as unknown as JsonObject, fields: fieldHelp as FieldHelp[],
  credentials: [], metadata: null, assurance: { ...assurance, basis: 'schema-policy' },
};

const example: ProjectSnapshot = {
  root: 'Example workspace · no folder has been read',
  observedAt: '', observationScope: 'single-request-non-atomic',
  config: {
    path: 'mobile-release.json (illustration only)', state: 'unavailable', issues: [],
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

export const previewApi: DesktopApi = {
  mode: 'preview',
  appInfo: async () => ({
    appName: 'Mobile Release Kit', appVersion: 'Example only',
    runtime: { state: 'unavailable', mode: 'unavailable', reason: 'Browser preview has no native runtime or core validation.' },
    capabilities: null,
  }),
  chooseProject: async () => ({ id: 'preview-example', name: 'Northstar Notes', path: example.root }),
  snapshot: async () => structuredClone(example),
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
  openConfigEdit: editUnavailable,
  prepareConfigEdit: editUnavailable,
  applyConfigEdit: editUnavailable,
  closeConfigEdit: editUnavailable,
  configEditStatus: editUnavailable,
  subscribeConfigEdit: editUnavailable,
};
