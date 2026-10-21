// Fixed public-text comparison DATA. No filename/root/Store or write authority.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { deepFreeze, configurationSaved } from './serviceConfigurationProtocol.ts';
import type { ConfigurationOrigin, ConfigurationOriginal, ConfigurationResult } from './serviceConfigurationProtocol.ts';
import { METADATA_TEXT_IDS } from './metadataText.ts';
import type { MetadataPlatform, MetadataTextEditStatus, MetadataTextObservation, NormalMetadataTextEditProjection } from './metadataText.ts';
import { parseMetadataTextObservation } from './metadataTextProtocol.ts';
export const METADATA_TEXT_CONSENT = 'agent-exact-metadata-text-preview-v1';
export const metadataTextSaved = configurationSaved;
export type MetadataOrigin = ConfigurationOrigin;
export type MetadataOriginal = ConfigurationOriginal;
export type MetadataStep = 'read' | 'open' | 'prepare' | 'apply';
export type MetadataPhase = 'queued-read' | 'reading' | 'loaded' | 'queued-prepare' | 'opening' | 'opened' | 'preparing' | 'reviewing' | 'queued-apply' | 'applying' | 'stopping' | 'final' | 'refused' | 'unknown';
export interface MetadataServiceReview { planToken: string; nativeStatusRevision: number; proposalSha256: string; files: {id: string; action: 'create' | 'replace' | 'preserve'; beforeBytes: number | null; afterBytes: number; afterSha256: string}[] }
export interface MetadataServiceRequest {
  schemaVersion: 1; origin: MetadataOrigin; revision: number; runtimeProjectId: string; platform: MetadataPlatform; locale: string; phase: MetadataPhase;
  observation: MetadataTextObservation | null; original: MetadataOriginal | null; proposalSha256: string | null; review: MetadataServiceReview | null;
  permissionLive: boolean; remainingMs: number; applyConsumed: boolean; cancelRequested: boolean; result: ConfigurationResult | null; doNotReplay: true;
}
export interface MetadataServiceStatus { serviceInstance: string; revision: number; request: MetadataServiceRequest | null }
export interface MetadataServiceAllow { origin: MetadataOrigin; original: MetadataOriginal; planToken: string; expectedNativeStatusRevision: number; consentVersion: typeof METADATA_TEXT_CONSENT }
export interface MetadataServiceApi {
  status(origin?: MetadataOrigin): Promise<MetadataServiceStatus>;
  allow(input: MetadataServiceAllow): Promise<MetadataServiceStatus>;
  revoke(origin: MetadataOrigin): Promise<MetadataServiceStatus>;
  load(origin: MetadataOrigin): Promise<MetadataTextObservation>;
  continue(origin: MetadataOrigin, step: Exclude<MetadataStep, 'read'>): Promise<MetadataTextEditStatus>;
  subscribe(listener: (value: unknown) => void): Promise<() => void>;
}
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && !/^0+$/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v);
const integer = (v: unknown, min: number, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const nullable = <T>(v: unknown, check: (v: unknown) => v is T): v is T | null => v === null || check(v);
const origin = (v: unknown): v is MetadataOrigin => keys(v, ['serviceInstance', 'projectId', 'requestId']) && id(v.serviceInstance) && id(v.projectId) && id(v.requestId);
const original = (v: unknown): v is MetadataOriginal => keys(v, ['sessionId', 'ownerGeneration', 'revision']) && id(v.sessionId) && id(v.ownerGeneration) && id(v.revision);
function review(v: unknown, platform: MetadataPlatform): v is MetadataServiceReview {
  return keys(v, ['planToken', 'nativeStatusRevision', 'proposalSha256', 'files']) && id(v.planToken) && integer(v.nativeStatusRevision, 1, 0xffffffff) && hash(v.proposalSha256) && Array.isArray(v.files) &&
    v.files.length === METADATA_TEXT_IDS[platform].length && v.files.every((f, i) => keys(f, ['id', 'action', 'beforeBytes', 'afterBytes', 'afterSha256']) && f.id === METADATA_TEXT_IDS[platform][i] &&
      ['create', 'replace', 'preserve'].includes(String(f.action)) && (f.beforeBytes === null || integer(f.beforeBytes, 0, 32768)) && integer(f.afterBytes, 0, 32768) && hash(f.afterSha256));
}
function request(v: unknown): v is MetadataServiceRequest {
  if (!keys(v, ['schemaVersion', 'origin', 'revision', 'runtimeProjectId', 'platform', 'locale', 'phase', 'observation', 'original', 'proposalSha256', 'review', 'permissionLive', 'remainingMs', 'applyConsumed', 'cancelRequested', 'result', 'doNotReplay']) ||
      v.schemaVersion !== 1 || !origin(v.origin) || !integer(v.revision, 1, 0xffffffff) || typeof v.runtimeProjectId !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(v.runtimeProjectId) ||
      (v.platform !== 'android' && v.platform !== 'ios') || typeof v.locale !== 'string' || !/^[A-Za-z0-9-]{2,12}$/.test(v.locale) ||
      !['queued-read', 'reading', 'loaded', 'queued-prepare', 'opening', 'opened', 'preparing', 'reviewing', 'queued-apply', 'applying', 'stopping', 'final', 'refused', 'unknown'].includes(String(v.phase)) ||
      !nullable(v.original, original) || !nullable(v.proposalSha256, hash) || v.review !== null && !review(v.review, v.platform) ||
      typeof v.permissionLive !== 'boolean' || typeof v.applyConsumed !== 'boolean' || typeof v.cancelRequested !== 'boolean' || !integer(v.remainingMs, 0, 900000) || v.doNotReplay !== true ||
      v.permissionLive !== (v.remainingMs > 0) || v.permissionLive && (v.phase !== 'reviewing' || v.applyConsumed || v.cancelRequested) ||
      v.review !== null && (!v.original || v.proposalSha256 !== v.review.proposalSha256) || ['queued-apply', 'applying'].includes(String(v.phase)) && (!v.applyConsumed || !v.review) ||
      (v.result !== null) !== (v.phase === 'final')) return false;
  if (v.result !== null && (!keys(v.result, ['effect', 'journal', 'cancelled', 'applySubmitted']) ||
      !['not_started', 'unchanged', 'rolled_back', 'committed'].includes(String(v.result.effect)) || !['not_created', 'clean', 'recovery_required'].includes(String(v.result.journal)) ||
      typeof v.result.cancelled !== 'boolean' || typeof v.result.applySubmitted !== 'boolean')) return false;
  if (v.observation !== null) {
    const o = parseMetadataTextObservation(v.observation);
    if (!o || v.phase !== 'loaded' || o.platform !== v.platform || o.locale !== v.locale || new TextEncoder().encode(JSON.stringify(o)).length > 256 * 1024 - 4096) return false;
  }
  return new TextEncoder().encode(JSON.stringify(v)).length <= (v.observation === null ? 8192 - 1024 : 256 * 1024 - 1024);
}
export function parseMetadataServiceStatus(value: unknown): MetadataServiceStatus | null {
  try {
    const v = copyBoundedComparisonData(value, 256 * 1024, 1024);
    if (!keys(v, ['serviceInstance', 'revision', 'request']) || !id(v.serviceInstance) || !integer(v.revision, 1, 0xffffffff) || !nullable(v.request, request) || v.request && v.request.origin.serviceInstance !== v.serviceInstance) return null;
    return deepFreeze(v as unknown as MetadataServiceStatus);
  } catch { return null; }
}
// Compact service digest/size DATA must agree with the actual native full view.
// This does not grant Apply; native current source, publisher, READ and token do.
export function metadataServicePreviewMatches(r: MetadataServiceRequest, owner: NormalMetadataTextEditProjection): boolean {
  const v = owner.prepared, review = r.review, o = r.original;
  return !!o && !!review && !!v && owner.projectId === r.runtimeProjectId && owner.sessionId === o.sessionId && owner.ownerGeneration === o.ownerGeneration &&
    owner.platform === r.platform && owner.locale === r.locale && owner.checkout?.revision === o.revision && v.revision === o.revision && v.planToken === review.planToken &&
    v.draftRevision === 0 && v.baselineGeneration === 0 && v.view.files.length === review.files.length && v.view.files.every((f, i) => {
      const row = review.files[i]; return !!row && f.id === row.id && f.action === row.action && (f.before.state === 'present' ? f.before.byteLength : null) === row.beforeBytes && f.after.byteLength === row.afterBytes && f.after.sha256 === row.afterSha256;
    });
}
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
type Listen = (event: 'mrk:agent-metadata-text', callback: (payload: unknown) => void) => Promise<() => void>;
export function createMetadataServiceApi(mode: string, invoke: Invoke, listen?: Listen): MetadataServiceApi | null {
  if (mode !== 'native' || !listen) return null;
  const failure = () => ({code: 'agent_metadata_text_unconfirmed', message: 'Check or stop this original text request; never repeat a missing Apply.', retryable: false});
  const raw = (v: unknown) => {const b = new TextEncoder().encode(JSON.stringify(v)); if (b.length + 96 > 4096) throw failure(); return b;};
  const status = async (command: string, v: unknown) => {try {const s = parseMetadataServiceStatus(await invoke(command, raw(v))); if (!s) throw failure(); return s;} catch {throw failure();}};
  return Object.freeze({status: (q?: MetadataOrigin) => status('agent_metadata_text_status', q ?? {}), allow: (a: MetadataServiceAllow) => status('allow_agent_metadata_text_apply', a),
    revoke: (q: MetadataOrigin) => status('revoke_agent_metadata_text', q),
    load: (q: MetadataOrigin) => invoke<MetadataTextObservation>('metadata_text_observe', raw({intent: 'agent-metadata-text', origin: q})),
    continue: (q: MetadataOrigin, step: Exclude<MetadataStep, 'read'>) => invoke<MetadataTextEditStatus>(({open: 'metadata_text_edit_open', prepare: 'metadata_text_edit_prepare', apply: 'metadata_text_edit_apply'})[step], raw({intent: 'agent-metadata-text', origin: q})),
    subscribe: (fn: (value: unknown) => void) => listen('mrk:agent-metadata-text', fn)});
}
