// Closed comparison DATA for one original native Config session, not authority
// to read arbitrary fields or to write a document without Desktop approval.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import type { ConfigEditStatus, JsonObject } from './types.ts';
export const CONFIGURATION_CONSENT = 'agent-exact-configuration-preview-v1';
export interface ConfigurationOrigin { serviceInstance: string; projectId: string; requestId: string }
export interface ConfigurationOriginal { sessionId: string; ownerGeneration: string; revision: string }
export type ConfigurationContainer = { kind: 'project' | 'workspace'; path: string };
export interface ConfigurationMetadata { root: string; androidLocales: string[]; iosLocales: string[] }
export interface ConfigurationSettings {
  source: { candidateBranch: string; productionBranch: string };
  android: { module: string | null; variant: string | null } | null;
  ios: { container: ConfigurationContainer | null; scheme: string | null; archiveConfiguration: string | null } | null;
  // Omitted means outside the bounded projection, never missing/default data.
  metadata?: ConfigurationMetadata;
}
export type ConfigurationChange = { kind: 'source'; candidateBranch: string; productionBranch: string } |
  { kind: 'android'; module: string; variant: string } |
  { kind: 'ios'; container: ConfigurationContainer; scheme: string; archiveConfiguration: string } |
  ({ kind: 'metadata' } & ConfigurationMetadata);
export interface ConfigurationFile { path: 'release/mobile-release.json' | '.gitignore'; action: 'create' | 'preserve' | 'replace' | 'append'; beforeBytes: number | null; afterBytes: number }
export interface ConfigurationReview {
  planToken: string; nativeStatusRevision: number; before: ConfigurationSettings; after: ConfigurationSettings;
  files: ConfigurationFile[]; createReleaseDirectory: boolean; rewritesConfigFormatting: boolean; ignoreAdditions: string[];
}
export type ConfigurationPhase = 'queued-read' | 'opening' | 'opened' | 'queued-prepare' | 'preparing' | 'reviewing' | 'queued-apply' | 'applying' | 'stopping' | 'final' | 'refused' | 'unknown';
export interface ConfigurationResult {
  effect: 'not_started' | 'unchanged' | 'rolled_back' | 'committed'; journal: 'not_created' | 'clean' | 'recovery_required'; cancelled: boolean; applySubmitted: boolean;
}
export interface ConfigurationRequest {
  schemaVersion: 1; origin: ConfigurationOrigin; revision: number; runtimeProjectId: string; phase: ConfigurationPhase;
  operationId: string | null; ownerGeneration: string | null; original: ConfigurationOriginal | null;
  settings: ConfigurationSettings | null; change: ConfigurationChange | null; review: ConfigurationReview | null;
  permissionLive: boolean; remainingMs: number; applyConsumed: boolean; cancelRequested: boolean; result: ConfigurationResult | null; doNotReplay: true;
}
export interface ConfigurationStatus { serviceInstance: string; revision: number; request: ConfigurationRequest | null }
export interface ConfigurationAllow { origin: ConfigurationOrigin; original: ConfigurationOriginal; planToken: string; expectedNativeStatusRevision: number; consentVersion: typeof CONFIGURATION_CONSENT }
export type ConfigurationStep = 'read' | 'prepare' | 'apply';
export interface ConfigurationApi {
  status(origin?: ConfigurationOrigin): Promise<ConfigurationStatus>;
  allow(input: ConfigurationAllow): Promise<ConfigurationStatus>;
  revoke(origin: ConfigurationOrigin): Promise<ConfigurationStatus>;
  continue(origin: ConfigurationOrigin, step: ConfigurationStep): Promise<ConfigEditStatus>;
  subscribe(listener: (status: unknown) => void): Promise<() => void>;
}
const keys = (v: unknown, fields: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && !/^0+$/.test(v);
const u32 = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 1 && v <= 0xffffffff;
const text = (v: unknown, n: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= n && /^[\x20-\x7e]+$/.test(v) && /[^ ]/.test(v);
const branch = (v: unknown): v is string => text(v, 255) && !v.startsWith('/') && !/[./]$/.test(v) && !['..', '//', '@{'].some(s => v.includes(s)) && !/[ ~^:?*\[\\]/.test(v);
const moduleName = (v: unknown): v is string => typeof v === 'string' && v.length <= 512 && (v === ':' || /^:(?:[A-Za-z0-9_.-]+)(?::[A-Za-z0-9_.-]+)*$/.test(v));
const variant = (v: unknown): v is string => typeof v === 'string' && /^[A-Za-z][A-Za-z0-9_-]{0,127}$/.test(v);
const relative = (v: unknown): v is string => text(v, 512) && !v.startsWith('/') && !/[\\:]/.test(v) && v.split('/').length <= 16 && v.split('/').every(p => p !== '' && p !== '.' && p !== '..');
const container = (v: unknown): v is ConfigurationContainer => keys(v, ['kind', 'path']) && ['project', 'workspace'].includes(String(v.kind)) && relative(v.path) &&
  v.path.endsWith(v.kind === 'project' ? '.xcodeproj' : '.xcworkspace');
const nullable = <T>(v: unknown, check: (x: unknown) => x is T): v is T | null => v === null || check(v);
// Match core config.py metadata policy, including Unicode relative paths and
// Python's whitespace-only refusal. No path is resolved or asset moved here.
const metadataRoot = (v: unknown): v is string => typeof v === 'string' && v.length <= 1024 &&
  Array.from(v).length <= 512 && /[^\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u.test(v) &&
  !/[\0\n\r\\\ud800-\udfff]/u.test(v) && !v.startsWith('/') && !/^[A-Za-z]:/.test(v) &&
  v.split('/').every(p=>p!=='' && p!=='.' && p!=='..');
const locales = (v: unknown): v is string[] => Array.isArray(v) && v.length <= 32 && v.every((s,n)=>
  typeof s === 'string' && /^[a-z]{2,3}(?:-[A-Z][a-z]{3})?(?:-[A-Z]{2}|-[0-9]{3})?$(?![\s\S])/.test(s) && v.indexOf(s)===n);
function metadata(v: unknown): v is ConfigurationMetadata {
  return keys(v,['root','androidLocales','iosLocales']) && metadataRoot(v.root) && locales(v.androidLocales) && locales(v.iosLocales) &&
    v.androidLocales.length + v.iosLocales.length <= 32 &&
    new TextEncoder().encode(JSON.stringify(v)).length <= 2048 - '"kind":"metadata",'.length;
}
const metadataFor = (m: ConfigurationMetadata, a: boolean, i: boolean) => (!a || m.androidLocales.length > 0) && (!i || m.iosLocales.length > 0);
const sameMetadata = (a: ConfigurationMetadata | undefined, b: ConfigurationMetadata) => !!a && a.root === b.root &&
  a.androidLocales.length===b.androidLocales.length && a.androidLocales.every((s,n)=>s===b.androidLocales[n]) &&
  a.iosLocales.length===b.iosLocales.length && a.iosLocales.every((s,n)=>s===b.iosLocales[n]);
const unchangedSelections = (a: ConfigurationSettings, b: ConfigurationSettings) =>
  a.source.candidateBranch===b.source.candidateBranch && a.source.productionBranch===b.source.productionBranch &&
  (a.android===null ? b.android===null : b.android!==null && a.android.module===b.android.module && a.android.variant===b.android.variant) &&
  (a.ios===null ? b.ios===null : b.ios!==null && a.ios.scheme===b.ios.scheme && a.ios.archiveConfiguration===b.ios.archiveConfiguration &&
    (a.ios.container===null ? b.ios.container===null : b.ios.container!==null && a.ios.container.kind===b.ios.container.kind && a.ios.container.path===b.ios.container.path));
export function configurationSettings(value: unknown): value is ConfigurationSettings {
  if ((!keys(value, ['source', 'android', 'ios']) && !keys(value, ['source', 'android', 'ios', 'metadata'])) || !keys(value.source, ['candidateBranch', 'productionBranch']) || !branch(value.source.candidateBranch) || !branch(value.source.productionBranch)) return false;
  if (value.android !== null && (!keys(value.android, ['module', 'variant']) || !nullable(value.android.module, moduleName) || !nullable(value.android.variant, variant))) return false;
  if (value.ios !== null && (!keys(value.ios, ['container', 'scheme', 'archiveConfiguration']) || !nullable(value.ios.container, container) ||
      !nullable(value.ios.scheme, (s): s is string => text(s, 255)) || !nullable(value.ios.archiveConfiguration, (s): s is string => text(s, 255)))) return false;
  if (Object.hasOwn(value,'metadata') && (!metadata(value.metadata) || !metadataFor(value.metadata,value.android!==null,value.ios!==null))) return false;
  return new TextEncoder().encode(JSON.stringify(value)).length <= 4096;
}
export function configurationChange(value: unknown): value is ConfigurationChange {
  if (!value || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  const valid = v.kind === 'source' ? keys(v, ['kind', 'candidateBranch', 'productionBranch']) && branch(v.candidateBranch) && branch(v.productionBranch) :
    v.kind === 'android' ? keys(v, ['kind', 'module', 'variant']) && moduleName(v.module) && variant(v.variant) :
    v.kind === 'ios' ? keys(v, ['kind', 'container', 'scheme', 'archiveConfiguration']) && container(v.container) && text(v.scheme, 255) && text(v.archiveConfiguration, 255) :
    v.kind === 'metadata' ? keys(v,['kind','root','androidLocales','iosLocales']) && metadata({root:v.root,androidLocales:v.androidLocales,iosLocales:v.iosLocales}) : false;
  return valid && new TextEncoder().encode(JSON.stringify(v)).length <= 2048;
}
function origin(v: unknown): v is ConfigurationOrigin { return keys(v, ['serviceInstance', 'projectId', 'requestId']) && id(v.serviceInstance) && id(v.projectId) && id(v.requestId); }
function original(v: unknown): v is ConfigurationOriginal { return keys(v, ['sessionId', 'ownerGeneration', 'revision']) && id(v.sessionId) && id(v.ownerGeneration) && id(v.revision); }
function review(v: unknown): v is ConfigurationReview {
  if (!keys(v, ['planToken', 'nativeStatusRevision', 'before', 'after', 'files', 'createReleaseDirectory', 'rewritesConfigFormatting', 'ignoreAdditions']) ||
    !id(v.planToken) || !u32(v.nativeStatusRevision) || !configurationSettings(v.before) || !configurationSettings(v.after) ||
    typeof v.createReleaseDirectory !== 'boolean' || typeof v.rewritesConfigFormatting !== 'boolean' || !Array.isArray(v.files) || v.files.length !== 2 ||
    !Array.isArray(v.ignoreAdditions) || v.ignoreAdditions.length > 16 || !v.ignoreAdditions.every(s => text(s, 128))) return false;
  for (const [i, f] of v.files.entries()) {
    const max = i === 0 ? 512 * 1024 : 1024 * 1024;
    const size = (n: unknown) => typeof n === 'number' && Number.isInteger(n) && n >= 0 && n <= max;
    if (!keys(f, ['path', 'action', 'beforeBytes', 'afterBytes']) || f.path !== (i === 0 ? 'release/mobile-release.json' : '.gitignore') ||
      !['create', 'preserve', 'replace', 'append'].includes(String(f.action)) || !size(f.afterBytes) || f.beforeBytes !== null && !size(f.beforeBytes)) return false;
  }
  return new TextEncoder().encode(JSON.stringify(v)).length <= 12 * 1024;
}
export const configurationSaved = (v: ConfigurationResult | null): boolean => !!v && v.applySubmitted && !v.cancelled &&
  (v.effect === 'committed' && v.journal === 'clean' || v.effect === 'unchanged' && v.journal === 'not_created');
function request(v: unknown): v is ConfigurationRequest {
  if (!keys(v, ['schemaVersion', 'origin', 'revision', 'runtimeProjectId', 'phase', 'operationId', 'ownerGeneration', 'original', 'settings', 'change', 'review', 'permissionLive', 'remainingMs', 'applyConsumed', 'cancelRequested', 'result', 'doNotReplay']) ||
    v.schemaVersion !== 1 || !origin(v.origin) || !u32(v.revision) || typeof v.runtimeProjectId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(v.runtimeProjectId) ||
    !['queued-read', 'opening', 'opened', 'queued-prepare', 'preparing', 'reviewing', 'queued-apply', 'applying', 'stopping', 'final', 'refused', 'unknown'].includes(String(v.phase)) ||
    !nullable(v.operationId, id) || !nullable(v.ownerGeneration, id) || (v.operationId === null) !== (v.ownerGeneration === null) ||
    !nullable(v.original, original) || !nullable(v.settings, configurationSettings) || !nullable(v.change, configurationChange) || !nullable(v.review, review) ||
    typeof v.permissionLive !== 'boolean' || typeof v.applyConsumed !== 'boolean' || typeof v.cancelRequested !== 'boolean' || v.doNotReplay !== true ||
    typeof v.remainingMs !== 'number' || !Number.isInteger(v.remainingMs) || v.remainingMs < 0 || v.remainingMs > 900000 || v.permissionLive !== (v.remainingMs > 0) ||
    v.permissionLive && (v.cancelRequested || v.applyConsumed || v.phase !== 'reviewing') || (v.result !== null) !== (v.phase === 'final')) return false;
  if (v.original && (v.original.sessionId !== v.operationId || v.original.ownerGeneration !== v.ownerGeneration) ||
    v.settings && !v.original || v.review && (!v.change || !v.original) || ['queued-apply', 'applying'].includes(String(v.phase)) && (!v.applyConsumed || !v.review)) return false;
  if (v.change?.kind === 'metadata' && v.review && (!v.review.before.metadata || !sameMetadata(v.review.after.metadata,v.change) ||
      !unchangedSelections(v.review.before,v.review.after))) return false;
  if (v.result !== null && (!keys(v.result, ['effect', 'journal', 'cancelled', 'applySubmitted']) || !['not_started', 'unchanged', 'rolled_back', 'committed'].includes(String(v.result.effect)) ||
    !['not_created', 'clean', 'recovery_required'].includes(String(v.result.journal)) || typeof v.result.cancelled !== 'boolean' || typeof v.result.applySubmitted !== 'boolean')) return false;
  return true;
}
export function parseConfigurationStatus(value: unknown): ConfigurationStatus | null {
  try {
    const v = copyBoundedComparisonData(value, 16 * 1024 + 256, 1600);
    if (!keys(v, ['serviceInstance', 'revision', 'request']) || !id(v.serviceInstance) || !u32(v.revision) || !nullable(v.request, request) ||
      v.request && (v.request.origin.serviceInstance !== v.serviceInstance || new TextEncoder().encode(JSON.stringify(v.request)).length > 16 * 1024)) return null;
    return deepFreeze(v as unknown as ConfigurationStatus);
  } catch { return null; }
}
export function deepFreeze<T>(v: T): T { if (v && typeof v === 'object' && !Object.isFrozen(v)) { for (const child of Object.values(v)) deepFreeze(child); Object.freeze(v); } return v; }
export function settingsFromConfig(base: JsonObject): ConfigurationSettings | null {
  if (base.schemaVersion !== 1) return null;
  const s = base.source, a = base.android, i = base.ios;
  if (!s || typeof s !== 'object' || Array.isArray(s) || !a || typeof a !== 'object' || Array.isArray(a) || !i || typeof i !== 'object' || Array.isArray(i)) return null;
  if (typeof a.enabled !== 'boolean' || typeof i.enabled !== 'boolean') return null;
  const c = i.project !== undefined && i.workspace !== undefined ? false : i.project !== undefined ? {kind: 'project', path: i.project} : i.workspace !== undefined ? {kind: 'workspace', path: i.workspace} : null;
  const v = {source: {candidateBranch: s.candidateBranch, productionBranch: s.productionBranch}, android: a.enabled ? {module: a.module ?? null, variant: a.variant ?? null} : null,
    ios: i.enabled ? {container: c, scheme: i.scheme ?? null, archiveConfiguration: i.archiveConfiguration ?? null} : null};
  if (!configurationSettings(v)) return null;
  const m=base.metadata;
  if (metadata(m) && metadataFor(m,a.enabled,i.enabled)) {
    const withMetadata={...v,metadata:{root:m.root,androidLocales:m.androidLocales.slice(),iosLocales:m.iosLocales.slice()}};
    if (configurationSettings(withMetadata)) return withMetadata;
  }
  return v;
}
// Local display/adoption only. The native original derives independently and
// checks expectedBase against actual source. This is never sent as a full draft.
export function changedConfiguration(base: JsonObject, change: ConfigurationChange): JsonObject | null {
  const prior = settingsFromConfig(base); if (!prior || !configurationChange(change)) return null;
  if (change.kind === 'android' && !prior.android || change.kind === 'ios' && !prior.ios) return null;
  if (change.kind === 'metadata' && (!prior.metadata || !metadataFor(change,prior.android!==null,prior.ios!==null))) return null;
  const next = structuredClone(base);
  if (change.kind === 'source') next.source = {...next.source as JsonObject, candidateBranch: change.candidateBranch, productionBranch: change.productionBranch};
  if (change.kind === 'android') next.android = {...next.android as JsonObject, module: change.module, variant: change.variant};
  if (change.kind === 'ios') { const ios = {...next.ios as JsonObject}; delete ios.project; delete ios.workspace;
    ios[change.container.kind] = change.container.path; ios.scheme = change.scheme; ios.archiveConfiguration = change.archiveConfiguration; next.ios = ios; }
  if (change.kind === 'metadata') {
    next.metadata={root:change.root,androidLocales:change.androidLocales.slice(),iosLocales:change.iosLocales.slice()};
    if (!sameMetadata(settingsFromConfig(next)?.metadata,change)) return null;
  }
  return next;
}
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
type Listen = (event: 'mrk:agent-configuration', callback: (payload: unknown) => void) => Promise<() => void>;
export function createConfigurationApi(mode: string, invoke: Invoke, listen?: Listen): ConfigurationApi | null {
  if (mode !== 'native' || !listen) return null;
  const failure = () => ({code: 'agent_configuration_unconfirmed', message: 'Inspect or stop the same original configuration request. Do not repeat Apply.', retryable: false});
  const raw = (value: unknown) => { const b = new TextEncoder().encode(JSON.stringify(value)); if (b.length + 96 > 4096) throw failure(); return b; };
  const status = async (command: string, value: unknown) => { try { const parsed = parseConfigurationStatus(await invoke(command, raw(value))); if (!parsed) throw failure(); return parsed; } catch { throw failure(); } };
  return Object.freeze({status: (q?: ConfigurationOrigin) => status('agent_configuration_status', q ?? {}), allow: (a: ConfigurationAllow) => status('allow_agent_configuration_apply', a),
    revoke: (q: ConfigurationOrigin) => status('revoke_agent_configuration', q),
    continue: (q: ConfigurationOrigin, step: ConfigurationStep) => invoke<ConfigEditStatus>(({read:'open_config_edit', prepare:'prepare_config_edit', apply:'apply_config_edit'})[step], raw({intent: 'agent-configuration', origin: q})),
    subscribe: (fn: (value: unknown) => void) => listen('mrk:agent-configuration', fn)});
}
