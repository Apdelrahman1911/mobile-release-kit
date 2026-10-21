// Comparison/presentation only. Original native Context, material and explicit
// one-use approval remain with the existing Store permission/operation owners.
import type { StoreKind, StorePlatform, StoreReview } from './agentStoreAccess.ts';

export type StoreReleaseMode = 'candidate-upload' | 'external-testing' | 'production-submit' |
  'current-internal' | 'recovery-settlement' | 'external-readiness';
export interface StoreReleaseReview {
  readonly mode: StoreReleaseMode; readonly intentSha256: string;
  readonly stageOperationId: string | null;
  readonly basis: { readonly operationId: string; readonly receiptSha256: string } | null;
}
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every(n => Object.hasOwn(v, n));
const sha = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const uuid = (v: unknown) => typeof v === 'string' && /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v) && v !== '00000000-0000-0000-0000-000000000000';
const one = (v: unknown, names: readonly string[]) => typeof v === 'string' && names.includes(v);
const integer = (v: unknown, min: number, max: number) => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= min && v <= max;

export function validStoreReleaseReview(v: unknown, kind: StoreKind, platform: StorePlatform, candidate: StoreReview['candidate']): v is StoreReleaseReview {
  if (!keys(v, ['mode','intentSha256','stageOperationId','basis']) || !candidate || !uuid(candidate.operationId) || !sha(candidate.sha256) || !sha(v.intentSha256)) return false;
  if (!(kind === 'execute' && one(v.mode, ['candidate-upload','external-testing','production-submit']) || kind === 'reconcile' &&
    (v.mode === 'current-internal' || v.mode === 'recovery-settlement' && platform === 'android' || v.mode === 'external-readiness' && platform === 'ios'))) return false;
  if (one(v.mode, ['candidate-upload','current-internal','recovery-settlement'])) return v.stageOperationId === null && v.basis === null;
  if (!uuid(v.stageOperationId) || v.stageOperationId === candidate.operationId || !keys(v.basis, ['operationId','receiptSha256']) || !uuid(v.basis.operationId) || !sha(v.basis.receiptSha256)) return false;
  return v.mode === 'external-testing' ? v.basis.operationId === candidate.operationId : v.mode === 'external-readiness' ? v.basis.operationId === v.stageOperationId :
    v.basis.operationId !== candidate.operationId && v.basis.operationId !== v.stageOperationId;
}

// Input is only an already-bounded, current original controller Context. The
// outer exact Review parser checks all resulting fields and mode/platform ties.
export function storeReleaseFromContext(c: Record<string, unknown>, kind: StoreKind): StoreReleaseReview | null {
  let mode: StoreReleaseMode;
  let stage: unknown = null, basis: unknown = null;
  if (kind === 'execute' && c.operation === 'local-store-execute' && c.action === undefined && c.settlement === undefined) {
    if (c.stage === undefined) { mode = 'candidate-upload'; stage = c.stageOperationId ?? null; }
    else if (c.stage === 'external-testing' || c.stage === 'production-submit') {
      mode = c.stage; stage = c.stageOperationId;
      basis = { operationId: c.predecessorOperationId, receiptSha256: c.predecessorReceiptSha256 };
    } else return null;
  } else if (kind === 'reconcile' && c.stage === undefined) {
    if (c.action === 'external-readiness' && c.operation === 'local-store-reconcile' && c.settlement === undefined) {
      mode = 'external-readiness'; stage = c.stageOperationId;
      basis = { operationId: c.stageOperationId, receiptSha256: c.executionReceiptSha256 };
    } else if (c.action === undefined && c.settlement === 'record-current-target' && c.operation === 'local-store-recovery-settle') mode = 'recovery-settlement';
    else if (c.action === undefined && c.settlement === undefined && c.operation === 'local-store-reconcile') mode = 'current-internal';
    else return null;
  } else return null;
  const v = { mode, intentSha256: c.intentSha256, stageOperationId: stage, basis };
  const candidate = { operationId: c.candidateOperationId, sha256: c.candidateSha256 };
  if (!one(c.platform, ['android','ios']) || typeof candidate.operationId !== 'string' || typeof candidate.sha256 !== 'string') return null;
  return validStoreReleaseReview(v, kind, c.platform as StorePlatform, { operationId: candidate.operationId, sha256: candidate.sha256 }) ? v : null;
}

export function storeReleaseTarget(mode: StoreReleaseMode, platform: StorePlatform): string {
  if (mode === 'external-testing' || mode === 'external-readiness') return platform === 'ios' ? 'testflight-external' : 'configured-play-external';
  if (mode === 'production-submit') return platform === 'ios' ? 'app-store-submission' : 'play-production-draft';
  return platform === 'ios' ? 'testflight-internal' : 'play-internal';
}
export const storeReleaseLimitations = (mode: StoreReleaseMode): readonly string[] => {
  const base = ['no-automatic-retry','saved-inputs-not-atomic'];
  return one(mode, ['candidate-upload','external-testing','production-submit']) ? [...base,'receipt-not-public-availability','no-build-or-signing'] :
    [...base,'target-match-not-prior-finality','no-upload-or-promotion',...(mode === 'current-internal' ? [] : ['local-checkpoint-not-prior-finality'])];
};
export function validStoreReleaseResult(v: unknown, r: StoreReview): boolean {
  const d = r.release, c = r.candidate;
  if (!d || !c || !validStoreReleaseReview(d, r.kind, r.platform, c) || !keys(v, ['kind','release']) || v.kind !== r.kind ||
    !keys(v.release, ['mode','headSequence','operationId','candidateOperationId','candidateSha256','intentSha256','receiptSha256','basis','target','result','state','limitations'])) return false;
  const p = v.release, min = d.mode === 'external-readiness' ? 12 : d.mode === 'production-submit' ? 15 : d.mode === 'external-testing' ? 11 : d.mode === 'current-internal' ? 6 : 7;
  if (p.mode !== d.mode || !integer(p.headSequence, min, d.mode === 'external-readiness' ? 509 : 513) || p.operationId !== (d.stageOperationId ?? c.operationId) ||
    p.candidateOperationId !== c.operationId || p.candidateSha256 !== c.sha256 || p.intentSha256 !== d.intentSha256 || !sha(p.receiptSha256) ||
    JSON.stringify(p.basis) !== JSON.stringify(d.basis) || p.target !== storeReleaseTarget(d.mode, r.platform) || JSON.stringify(p.limitations) !== JSON.stringify(storeReleaseLimitations(d.mode))) return false;
  switch (d.mode) {
    case 'candidate-upload': return one(p.result, ['accepted','reconciled']) && p.state === null;
    case 'current-internal': case 'recovery-settlement': return p.result === 'reconciled' && p.state === null;
    case 'external-readiness': return p.result === 'ready' && p.state === 'available-to-testers';
    case 'external-testing': return p.result === 'accepted' && one(p.state, r.platform === 'android' ? ['available-to-testers'] : ['available-to-testers','submitted-for-review','in-review','approved']);
    case 'production-submit': return p.result === 'accepted' && one(p.state, r.platform === 'android' ? ['draft'] : ['submitted-for-review','in-review','approved','pending-developer-release']);
  }
}

export function storeStepLabel(kind: StoreKind): string {
  return ({ 'access-check':'Basic access check', 'candidate-prepare':'Prepare candidate intent', execute:'Execute reviewed Store intent', reconcile:'Reconcile / recovery / readiness' })[kind];
}
export function storeEffectText(r: StoreReview): string {
  if (r.kind === 'access-check') return r.platform === 'android' ? 'Basic Play access only: creates and attempts to delete a temporary uncommitted edit. No upload or release.' : 'Basic App Store Connect access only. No upload or release.';
  if (r.kind === 'candidate-prepare') return 'Prepare the candidate intent and local journal only. This grant does not authorize Execute, upload, promotion or Reconcile.';
  switch (r.release?.mode) {
    case 'candidate-upload': return r.platform === 'android' ? 'Upload the reviewed signed AAB and commit its Play internal-testing release. No rebuild, signing or public release.' : 'Upload the reviewed signed IPA for internal TestFlight processing. No rebuild, signing or public release.';
    case 'external-testing': return r.platform === 'android' ? 'Promote the original uploaded binary to the configured external-testing track shown in the native review. The track name is not replaced or chosen by the CLI.' : 'Use the original uploaded build for the reviewed external TestFlight target. Review/submission/approval is not necessarily availability to testers.';
    case 'production-submit': return r.platform === 'android' ? 'Create the reviewed Play production draft from the original uploaded binary. A draft is not served to production users.' : 'Submit the reviewed App Store version for review with manual release. Submitted, approved or pending release is not public availability.';
    case 'current-internal': return r.platform === 'android' ? 'Check the exact current internal target using a temporary uncommitted Play edit and its cleanup. No upload, commit, repair or retry; matching is not earlier finality.' : 'Check the exact current internal TestFlight build. No upload, repair or retry; matching is not earlier execution finality.';
    case 'recovery-settlement': return 'Check the current Play internal target and write one explicitly reviewed local recovery checkpoint. Preserve old evidence; this cannot clear a live unknown owner or authorize retry.';
    case 'external-readiness': return 'Check the reviewed external TestFlight target and save one separate local readiness record. No upload, notification or resubmission; this is not earlier execution finality.';
    default: return 'No complete original Store review is selected.';
  }
}

// Called only with early App controller refs. A matching DATA review alone is
// insufficient: the controller must still retain that exact returned Attempt.
export function storeSelectedPeerReason(r: StoreReview | null, kind: StoreKind,
  original: { agentPreparedMatches(id: { operationId: string; ownerGeneration: string }, revision: number): boolean } | null,
  reason: string | null): string | null {
  return r?.kind === kind && original?.agentPreparedMatches(r, r.statusRevision) ? null : reason;
}
