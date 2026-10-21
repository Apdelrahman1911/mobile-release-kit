// Public certificate comparison DATA -> one ordinary Settings draft edit.
// This is neither credential assignment nor a save/review/native permission.
import type { AppleProvisioningController } from './appleProvisioningController.ts';
import type { AppleProvisioningStatus } from './appleProvisioningTypes.ts';
import { parseAppleP12Result, parseAppleP12SavedReference } from './appleP12SetupProtocol.ts';
import { blockingAncestor, getValue, sameJson } from './catalog.ts';
import { isDirty, reviewFresh } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import { parseSavedConfigContent, sameOfflineData, sameSavedConfig, savedConfigFromSnapshot } from './offlinePreflightProtocol.ts';
import type { Catalog } from './types.ts';

const field = 'ios.distributionCertificateSha256';
export interface AppleP12FingerprintContext {
  controller: AppleProvisioningController; session: ProjectSession | null; catalog: Catalog | null;
  service: object | null; epoch: number; preview: boolean; reason: string | null;
}
export interface AppleP12FingerprintEdit {
  readonly context: AppleP12FingerprintContext;
  readonly status: AppleProvisioningStatus;
  readonly certificateSha256: string;
}
export interface AppleP12FingerprintView {
  certificateSha256: string | null; edit: AppleP12FingerprintEdit | null; reason: string | null;
}

// Match the exact supported syntax for comparison only. Never trim, repair or
// rewrite an existing value (including an already-equal colon/uppercase value).
function normalizedFingerprint(value: unknown): string | null {
  return typeof value === 'string' && /^(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{2}(?::[a-fA-F0-9]{2}){31})$/.test(value) ?
    value.replaceAll(':', '').toLowerCase() : null;
}

// Pure, provisional render. The explicit click below synchronizes the actual
// controller before comparing these facts; a displayed snapshot is not enough.
export function appleP12FingerprintView(context: AppleP12FingerprintContext): AppleP12FingerprintView {
  const state = context.controller.getSnapshot(), status = state.status, op = status?.operation;
  const absent = { certificateSha256: null, edit: null, reason: null };
  if (!state.p12TerminalRead || !status || !op || op.context.mode !== 'p12-save' || op.phase !== 'terminal' ||
      op.outcome !== 'complete' || op.reason !== 'none' || op.intentUsable) return absent;
  const result = parseAppleP12Result(state.p12Result, op.context), saved = parseAppleP12SavedReference(state.savedP12);
  if (!result || result.decision !== 'assembled' || !result.certificateSha256 || !saved ||
      !sameOfflineData(result, op.result) || !sameOfflineData(saved, op.savedP12)) return absent;
  const certificateSha256 = result.certificateSha256;
  const refuse = (reason: string): AppleP12FingerprintView => ({ certificateSha256, edit: null, reason });
  if (context.preview || !context.service || !state.native || !state.initialized || !state.listening) {
    return refuse('Use the original connected project to add this fingerprint. Earlier results remain display-only.');
  }
  if (context.reason !== null) return refuse(context.reason);
  if (!Number.isSafeInteger(context.epoch) || context.epoch < 0 || context.epoch >= Number.MAX_SAFE_INTEGER ||
      state.historical || state.retained || state.issue || state.pending || state.requestPending || state.cancelPending || state.reading || state.cancelRequested) {
    return refuse('The project or original P12 task changed or is still pending. Keep the draft; this result cannot update it.');
  }
  const { session, catalog } = context;
  if (!session?.draft || !session.snapshot || !catalog || session.observedAt === null ||
      session.project.id !== op.context.projectId || session.project.id !== state.projectId ||
      session.revision !== op.context.draftRevision || session.baselineGeneration !== op.context.baselineGeneration) {
    return refuse('Open the same project and its current Settings draft first.');
  }
  if (session.snapshot.root !== session.project.path || session.snapshotRequest !== null || session.snapshotError ||
      session.snapshotPredatesSave || session.sourceChanged || session.saveRecoveryRequired || session.saveRecoveryNeedsReload ||
      session.recoveryReloadRequest !== null || session.reviewRequest !== null || session.validationRequest !== null || session.suggestionRequest !== null ||
      isDirty(session) || !sameJson(session.baseline, session.snapshot.config.data)) {
    return refuse('Finish or review the current draft and project read first. Nothing was replaced.');
  }
  const observed = savedConfigFromSnapshot(session.snapshot), retained = parseSavedConfigContent(session.savedConfigContent);
  if (!observed || !retained || !sameSavedConfig(observed, retained) || !sameSavedConfig(retained, op.context.savedConfig)) {
    return refuse('The saved project comparison changed. Keep the draft and review Settings manually.');
  }
  if (!catalog.fields.some(row => row.path === field && row.input === 'text') ||
      reviewFresh(session) && session.review?.result.fields.some(row => row.path === field && row.state === 'forbidden') ||
      blockingAncestor(session.draft, field) !== null) {
    return refuse('This setting or its parent needs attention in Settings. No value was replaced.');
  }
  const existing = getValue(session.draft, field);
  if (existing !== undefined && existing !== '') {
    return refuse(normalizedFingerprint(existing) === certificateSha256 ?
      'This fingerprint is already in Settings. Its existing formatting was kept.' :
      'Settings already has a value for this fingerprint. Review it there; this action never replaces it.');
  }
  return { certificateSha256, reason: null, edit: { context: { ...context }, status, certificateSha256 } };
}

function sameContext(a: AppleP12FingerprintContext, b: AppleP12FingerprintContext): boolean {
  return a.controller === b.controller && a.session === b.session && a.service === b.service && a.catalog === b.catalog && a.epoch === b.epoch;
}
export interface AppleP12FingerprintDraftAction {
  type: 'edit'; projectId: string; path: 'ios.distributionCertificateSha256'; value: string; expectedSession: ProjectSession;
}
export function applyAppleP12Fingerprint(edit: AppleP12FingerprintEdit, current: () => AppleP12FingerprintContext,
  commit: (action: AppleP12FingerprintDraftAction) => boolean): boolean {
  const before = current();
  if (!sameContext(before, edit.context) || before.controller.getSnapshot().status !== edit.status) return false;
  // Re-read the current selected sources without invoking native work. Its
  // synchronous listeners can retire context or edit the draft: rematch AFTER.
  before.controller.syncProject();
  const after = current();
  if (!sameContext(after, edit.context)) return false;
  const fresh = appleP12FingerprintView(after).edit;
  if (!fresh || fresh.status !== edit.status || fresh.certificateSha256 !== edit.certificateSha256 || !after.session) return false;
  // App retirement listeners run before the reducer. expectedSession is the
  // existing final guard against overwriting a reentrant, newer draft.
  return commit({ type: 'edit', projectId: after.session.project.id, path: field,
    value: fresh.certificateSha256, expectedSession: after.session });
}
