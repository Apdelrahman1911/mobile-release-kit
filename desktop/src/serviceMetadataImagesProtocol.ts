// Closed comparison DATA for one already reviewed local image copy. The
// native EditOwner, not this summary/hash, owns the original plan and images.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseMetadataImagesEditStatus } from './metadataImagesProtocol.ts';
import type { MetadataImagesEditStatus } from './metadataImages.ts';

export const METADATA_IMAGES_AGENT_EVENT = 'mrk:agent-metadata-images';
export const METADATA_IMAGES_AGENT_CONSENT = 'agent-exact-metadata-images-preview-v1';
export interface ImagesAgentOrigin { projectId: string; serviceInstance: string; requestId: string }
export interface ImagesAgentOriginal {
  sessionId: string; ownerGeneration: string; revision: string; planToken: string;
  draftRevision: number; baselineGeneration: number;
}
export interface ImagesAgentSummary {
  original: ImagesAgentOriginal; nativeStatusRevision: number;
  platform: 'android' | 'ios'; locale: string; assetType: string;
  fileCount: number; createCount: number; replaceCount: number; preserveCount: number; selectedBytes: number;
}
export interface ImagesAgentReview extends ImagesAgentSummary { preparedSha256: string }
export interface ImagesAgentFinal {
  effect: 'not_started' | 'unchanged' | 'committed' | 'rolled_back';
  journal: 'not_created' | 'clean' | 'recovery_required';
  cancelled: boolean; applySubmitted: boolean; completed: boolean;
}
export interface ImagesAgentRequest {
  schemaVersion: 1; origin: ImagesAgentOrigin; grantId: string; revision: number;
  phase: 'queued' | 'admitting' | 'applying' | 'stopping' | 'final' | 'unknown';
  settlement: 'pending' | 'settled' | 'unknown'; review: ImagesAgentReview;
  cancelRequested: boolean; result: ImagesAgentFinal | null; doNotReplay: true;
}
export interface ImagesAgentAccess {
  schemaVersion: 1; serviceInstance: string; projectId: string | null; grantId: string | null;
  nonce: string | null; review: ImagesAgentReview | null; live: boolean; remainingMs: number;
  request: ImagesAgentRequest | null;
}
export interface ImagesAgentRevoked { nonce: string; access: ImagesAgentAccess }
export interface ImagesAgentAllow {
  projectId: string; original: ImagesAgentOriginal; statusRevision: number; nonce: string;
  consent: typeof METADATA_IMAGES_AGENT_CONSENT;
}
export interface MetadataImagesAgentApi {
  status(origin?: ImagesAgentOrigin): Promise<ImagesAgentAccess>;
  allow(input: ImagesAgentAllow): Promise<ImagesAgentAccess>;
  revoke(nonce: string): Promise<ImagesAgentRevoked>;
  apply(origin: ImagesAgentOrigin): Promise<MetadataImagesEditStatus>;
  subscribe(listener: (value: unknown) => void): Promise<() => void>;
}
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v, k));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}(?![\s\S])/.test(v) && !/^0+$/.test(v);
const uint = (v: unknown, max = 0xfffffffe, min = 0): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const hash = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}(?![\s\S])/.test(v);
const nullable = <T>(v: unknown, f: (v: unknown) => v is T): v is T | null => v === null || f(v);
const origin = (v: unknown): v is ImagesAgentOrigin => keys(v, ['projectId','serviceInstance','requestId']) && Object.values(v).every(id);
export const sameImagesAgentOrigin = (a: ImagesAgentOrigin, b: ImagesAgentOrigin): boolean =>
  a.projectId === b.projectId && a.serviceInstance === b.serviceInstance && a.requestId === b.requestId;
export function sameImagesAgentSummary(a: ImagesAgentSummary, b: ImagesAgentSummary): boolean {
  return a.original.sessionId === b.original.sessionId && a.original.ownerGeneration === b.original.ownerGeneration &&
    a.original.revision === b.original.revision && a.original.planToken === b.original.planToken &&
    a.original.draftRevision === b.original.draftRevision && a.original.baselineGeneration === b.original.baselineGeneration &&
    a.nativeStatusRevision === b.nativeStatusRevision && a.platform === b.platform && a.locale === b.locale && a.assetType === b.assetType &&
    a.fileCount === b.fileCount && a.createCount === b.createCount && a.replaceCount === b.replaceCount &&
    a.preserveCount === b.preserveCount && a.selectedBytes === b.selectedBytes;
}
export const sameImagesAgentReview = (a: ImagesAgentReview, b: ImagesAgentReview): boolean =>
  sameImagesAgentSummary(a, b) && a.preparedSha256 === b.preparedSha256;
function original(v: unknown): v is ImagesAgentOriginal {
  return keys(v, ['sessionId','ownerGeneration','revision','planToken','draftRevision','baselineGeneration']) &&
    [v.sessionId,v.ownerGeneration,v.revision,v.planToken].every(id) && v.revision !== v.planToken &&
    uint(v.draftRevision) && uint(v.baselineGeneration);
}
export function isImagesAgentReview(v: unknown): v is ImagesAgentReview {
  return keys(v, ['original','nativeStatusRevision','platform','locale','assetType','fileCount','createCount','replaceCount','preserveCount','selectedBytes','preparedSha256']) &&
    original(v.original) && uint(v.nativeStatusRevision) && (v.platform === 'android' || v.platform === 'ios') &&
    typeof v.locale === 'string' && /^[A-Za-z0-9-]{2,12}(?![\s\S])/.test(v.locale) &&
    typeof v.assetType === 'string' && /^[A-Za-z0-9_]{1,64}(?![\s\S])/.test(v.assetType) && uint(v.fileCount,10,1) &&
    uint(v.createCount,10) && uint(v.replaceCount,10) && uint(v.preserveCount,10) &&
    v.fileCount === v.createCount + v.replaceCount + v.preserveCount && uint(v.selectedBytes,25165824,1) && hash(v.preparedSha256);
}
function request(v: unknown): v is ImagesAgentRequest {
  if (!keys(v, ['schemaVersion','origin','grantId','revision','phase','settlement','review','cancelRequested','result','doNotReplay']) ||
    v.schemaVersion !== 1 || !origin(v.origin) || !id(v.grantId) || !uint(v.revision,0xfffffffe,1) || !isImagesAgentReview(v.review) ||
    !['queued','admitting','applying','stopping','final','unknown'].includes(String(v.phase)) ||
    !['pending','settled','unknown'].includes(String(v.settlement)) || (v.phase === 'unknown') !== (v.settlement === 'unknown') ||
    (v.phase === 'final') !== (v.settlement === 'settled') || (v.phase === 'final') !== (v.result !== null) ||
    typeof v.cancelRequested !== 'boolean' || v.doNotReplay !== true) return false;
  const f = v.result;
  if (f === null) return true;
  if (!keys(f, ['effect','journal','cancelled','applySubmitted','completed']) ||
    !['not_started','unchanged','committed','rolled_back'].includes(String(f.effect)) ||
    !['not_created','clean','recovery_required'].includes(String(f.journal)) ||
    typeof f.cancelled !== 'boolean' || typeof f.applySubmitted !== 'boolean' || typeof f.completed !== 'boolean') return false;
  if (f.completed && (!f.applySubmitted || f.cancelled || !(f.effect === 'committed' && f.journal === 'clean' || f.effect === 'unchanged' && f.journal === 'not_created')) ||
    !f.applySubmitted && (f.effect !== 'not_started' || f.journal !== 'not_created') ||
    f.effect === 'unchanged' && (v.review.createCount !== 0 || v.review.replaceCount !== 0 || f.journal !== 'not_created') ||
    (f.effect === 'committed' || f.effect === 'rolled_back') && v.review.createCount + v.review.replaceCount === 0) return false;
  return true;
}
function access(v: unknown): v is ImagesAgentAccess {
  if (!keys(v, ['schemaVersion','serviceInstance','projectId','grantId','nonce','review','live','remainingMs','request']) ||
    v.schemaVersion !== 1 || !id(v.serviceInstance) || !nullable(v.projectId,id) || !nullable(v.grantId,id) || !nullable(v.nonce,id) ||
    !nullable(v.review,isImagesAgentReview) || !nullable(v.request,request) || typeof v.live !== 'boolean' || !uint(v.remainingMs,900000) ||
    v.live !== (v.remainingMs > 0)) return false;
  const group = [v.projectId,v.grantId,v.nonce,v.review];
  if (!group.every(x => x === null) && !group.every(x => x !== null) || v.live && (!v.review || v.request) || !v.review && v.request) return false;
  return !v.request || v.request.origin.serviceInstance === v.serviceInstance && v.request.origin.projectId === v.projectId &&
    v.request.grantId === v.grantId && !!v.review && sameImagesAgentReview(v.request.review,v.review);
}
function freeze<T>(v: T): T {
  if (v && typeof v === 'object') { for (const x of Object.values(v)) freeze(x); Object.freeze(v); } return v;
}
export function parseImagesAgentAccess(raw: unknown): ImagesAgentAccess | null {
  try { const v = copyBoundedComparisonData(raw,8192,192); return access(v) ? freeze(v) : null; } catch { return null; }
}
export function parseImagesAgentRevoked(raw: unknown): ImagesAgentRevoked | null {
  try { const v = copyBoundedComparisonData(raw,8192,200); return keys(v,['nonce','access']) && id(v.nonce) && access(v.access) ? freeze(v as unknown as ImagesAgentRevoked) : null; }
  catch { return null; }
}
type Invoke = <T>(command: string, args?: Record<string, unknown> | Uint8Array) => Promise<T>;
type Listen = (event: typeof METADATA_IMAGES_AGENT_EVENT, fn: (v: unknown) => void) => Promise<() => void>;
export function createMetadataImagesAgentApi(mode: string, invoke: Invoke, listen?: Listen): MetadataImagesAgentApi | undefined {
  if (mode !== 'native' || !listen) return undefined;
  const error = () => ({code:'agent_metadata_images_unconfirmed',message:'Keep the original image review and request. Do not resend Apply.',retryable:false});
  const raw = (v: unknown) => { const b = new TextEncoder().encode(JSON.stringify(v)); if (b.length + 96 > 4096) throw error(); return b; };
  const call = async <T>(command: string, v: unknown, parse: (v: unknown) => T | null): Promise<T> => {
    const result = parse(await invoke(command,raw(v))); if (!result) throw error(); return result;
  };
  return Object.freeze({status:(q?: ImagesAgentOrigin) => call('agent_metadata_images_status',q ?? {},parseImagesAgentAccess),
    allow:(v: ImagesAgentAllow) => call('allow_agent_metadata_images_apply',v,parseImagesAgentAccess),
    revoke:(nonce: string) => call('revoke_agent_metadata_images',{nonce},parseImagesAgentRevoked),
    apply:(q: ImagesAgentOrigin) => call('metadata_images_edit_apply',{intent:'agent-metadata-images',origin:q},parseMetadataImagesEditStatus),
    subscribe:(fn: (v: unknown) => void) => listen(METADATA_IMAGES_AGENT_EVENT,fn)});
}
