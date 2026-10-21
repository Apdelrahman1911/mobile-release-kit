// Bounded comparison DATA only. The original native Prepared/lease owns Apply.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { parseVersionEditStatus } from './releaseVersionEdit.ts';
import type { VersionEditStatus } from './releaseVersionEdit.ts';
export const VERSION_EDIT_CONSENT = 'agent-exact-prepared-version-apply-v1';
export interface VersionEditOrigin { projectId: string; serviceInstance: string; requestId: string }
export interface VersionEditOriginal { sessionId: string; ownerGeneration: string; revision: string; planToken: string }
export interface VersionEditReview {
  original: VersionEditOriginal; nativeStatusRevision: number; name: string; build: string; source: string;
  beforeBytes: number; beforeSha256: string; afterBytes: number; afterSha256: string; candidateId: string | null;
}
export interface VersionEditRequest {
  schemaVersion: 1; origin: VersionEditOrigin; grantId: string; revision: number;
  phase: 'queued' | 'admitting' | 'applying' | 'stopping' | 'final' | 'unknown'; settlement: 'pending' | 'settled' | 'unknown';
  review: VersionEditReview; cancelRequested: boolean; result: {effect: 'not-started' | 'unchanged' | 'rolled-back' | 'committed';
    journal: 'not-created' | 'clean' | 'recovery-required'; cancelled: boolean; applySubmitted: boolean} | null; doNotReplay: true;
}
export interface VersionEditAccess {
  schemaVersion: 1; serviceInstance: string | null; projectId: string | null; grantId: string | null; nonce: string | null;
  review: VersionEditReview | null; live: boolean; remainingMs: number; request: VersionEditRequest | null;
}
export interface VersionEditAllow { projectId: string; original: VersionEditOriginal; statusRevision: number; nonce: string; consent: typeof VERSION_EDIT_CONSENT }
export interface VersionEditAgentApi {
  status(origin?: VersionEditOrigin): Promise<VersionEditAccess>;
  allow(input: VersionEditAllow): Promise<VersionEditAccess>;
  revoke(nonce: string): Promise<VersionEditAccess>;
  apply(origin: VersionEditOrigin): Promise<VersionEditStatus>;
  subscribe(listener: (value: unknown) => void): Promise<() => void>;
}
const keys = (v: unknown, fields: string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === fields.length && fields.every(k => Object.hasOwn(v, k));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}(?![\s\S])/.test(v) && !/^0+$/.test(v);
const hash = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{64}(?![\s\S])/.test(v);
const uint = (v: unknown, max = 0xfffffffe, min = 0): v is number => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max;
const text = (v: unknown, n: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= n && /^[\x20-\x7e]+(?![\s\S])/.test(v);
const nullable = <T>(v: unknown, check: (v: unknown) => v is T): v is T | null => v === null || check(v);
export function sameVersionEditReview(a: VersionEditReview, b: VersionEditReview): boolean {
  return a.original.sessionId === b.original.sessionId && a.original.ownerGeneration === b.original.ownerGeneration && a.original.revision === b.original.revision &&
    a.original.planToken === b.original.planToken && a.nativeStatusRevision === b.nativeStatusRevision && a.name === b.name && a.build === b.build && a.source === b.source &&
    a.beforeBytes === b.beforeBytes && a.beforeSha256 === b.beforeSha256 && a.afterBytes === b.afterBytes && a.afterSha256 === b.afterSha256 && a.candidateId === b.candidateId;
}
function review(v: unknown): v is VersionEditReview {
  return keys(v, ['original','nativeStatusRevision','name','build','source','beforeBytes','beforeSha256','afterBytes','afterSha256','candidateId']) &&
    keys(v.original, ['sessionId','ownerGeneration','revision','planToken']) && Object.values(v.original).every(id) && uint(v.nativeStatusRevision) && text(v.name,64) &&
    typeof v.build === 'string' && /^[0-9]{1,10}(?![\s\S])/.test(v.build) && text(v.source,512) && !v.source.startsWith('/') && !/[\\:]/.test(v.source) && v.source.split('/').every(p => p !== '' && p !== '.' && p !== '..') &&
    uint(v.beforeBytes,65536,1) && uint(v.afterBytes,65536,1) && hash(v.beforeSha256) && hash(v.afterSha256) &&
    (v.candidateId === null || typeof v.candidateId === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/.test(v.candidateId));
}
function request(v: unknown): v is VersionEditRequest {
  if (!keys(v,['schemaVersion','origin','grantId','revision','phase','settlement','review','cancelRequested','result','doNotReplay']) ||
    v.schemaVersion !== 1 || !keys(v.origin,['projectId','serviceInstance','requestId']) || !Object.values(v.origin).every(id) || !id(v.grantId) || !uint(v.revision,0xfffffffe,1) ||
    !['queued','admitting','applying','stopping','final','unknown'].includes(String(v.phase)) || !['pending','settled','unknown'].includes(String(v.settlement)) ||
    (v.phase === 'final') !== (v.settlement === 'settled') || (v.phase === 'unknown') !== (v.settlement === 'unknown') || (v.phase === 'final') !== (v.result !== null) ||
    !review(v.review) || typeof v.cancelRequested !== 'boolean' || v.doNotReplay !== true) return false;
  return v.result === null || keys(v.result,['effect','journal','cancelled','applySubmitted']) && ['not-started','unchanged','rolled-back','committed'].includes(String(v.result.effect)) &&
    ['not-created','clean','recovery-required'].includes(String(v.result.journal)) && typeof v.result.cancelled === 'boolean' && typeof v.result.applySubmitted === 'boolean';
}
export function parseVersionEditAccess(raw: unknown): VersionEditAccess | null {
  try {
    const v = copyBoundedComparisonData(raw,16384,256);
    if (!keys(v,['schemaVersion','serviceInstance','projectId','grantId','nonce','review','live','remainingMs','request']) || v.schemaVersion !== 1 ||
      !nullable(v.serviceInstance,id) || !nullable(v.projectId,id) || !nullable(v.grantId,id) || !nullable(v.nonce,id) || !nullable(v.review,review) || !nullable(v.request,request) ||
      typeof v.live !== 'boolean' || !uint(v.remainingMs,900000) || v.live !== (v.remainingMs > 0) || v.live && (!v.serviceInstance || !v.projectId || !v.grantId || !v.nonce || !v.review || v.request !== null)) return null;
    const all = [v.serviceInstance,v.projectId,v.grantId,v.nonce,v.review];
    if (!(all.every(x=>x === null) || all.every(x=>x !== null)) || v.request && (v.request.origin.serviceInstance !== v.serviceInstance ||
        v.request.origin.projectId !== v.projectId || v.request.grantId !== v.grantId || !v.review || !sameVersionEditReview(v.request.review,v.review))) return null;
    const freeze = (x: unknown): void => { if (x && typeof x === 'object') { for (const child of Object.values(x)) freeze(child); Object.freeze(x); } };
    freeze(v); return v as unknown as VersionEditAccess;
  } catch { return null; }
}
type Invoke = <T>(command: string, args?: Record<string, unknown> | Uint8Array) => Promise<T>;
type Listen = (event: 'mrk:agent-version-edit', listener: (raw: unknown) => void) => Promise<() => void>;
export function createVersionEditAgentApi(mode: string, invoke: Invoke, listen?: Listen): VersionEditAgentApi | null {
  if (mode !== 'native' || !listen) return null;
  const error = () => ({code:'agent_version_edit_unconfirmed',message:'Keep and inspect the same version edit request. Do not resend Apply.',retryable:false});
  const raw = (v: unknown) => { const bytes = new TextEncoder().encode(JSON.stringify(v)); if (bytes.length > 1024) throw error(); return bytes; };
  const status = async (command: string, v: unknown) => { const parsed = parseVersionEditAccess(await invoke(command,raw(v))); if (!parsed) throw error(); return parsed; };
  return Object.freeze({status:(q?: VersionEditOrigin) => status('agent_version_edit_status',q ?? {}), allow:(v: VersionEditAllow) => status('allow_agent_version_edit_apply',v),
    revoke:(nonce: string) => status('revoke_agent_version_edit',{nonce}), apply:async (q: VersionEditOrigin) => {
      const v = parseVersionEditStatus(await invoke('release_version_edit_apply',raw({intent:'agent-version-edit',origin:q}))); if (!v) throw error(); return v;
    }, subscribe:(fn: (v: unknown) => void) => listen('mrk:agent-version-edit',fn)});
}
