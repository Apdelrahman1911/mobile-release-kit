// The existing AssetSessionController owns ALL invokes, original-operation
// correlation, cancellation and context updates. This child holds only the
// bounded, nonsecret generation view and one explicit declaration.
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { NEW_UPLOAD_KEY_DECLARATION, parseUploadKeyStatus, uploadKeyBaseReason, uploadKeyContext,
  type UploadKeyContextRequest, type UploadKeyCreateRequest, type UploadKeyStatus, type UploadKeyRecoverRequest, type UploadKeyRecoveryAction, type UploadKeyReference } from './credentialUploadKey.ts';

export interface UploadKeyView {
  status: UploadKeyStatus | null;
  checking: boolean;
  uncertain: boolean;
  attempted: boolean;
  confirmed: boolean;
  error: string | null;
}
function frozen(value: UploadKeyView): UploadKeyView {
  // This book contains only the closed, already-parsed public DTO. Keep its
  // nested asset comparison just as immutable as the outer controller view.
  const freezeData = (data: unknown): void => {
    if (data && typeof data === 'object' && !Object.isFrozen(data)) {
      Object.values(data).forEach(freezeData); Object.freeze(data);
    }
  };
  freezeData(value); return value;
}
export class CredentialUploadKeyController {
  private state: UploadKeyView = frozen({ status: null, checking: false, uncertain: false, attempted: false, confirmed: false, error: null });
  private context: string | null = null;
  private confirmationRevision: number | null = null;
  private pending: 'prepare' | 'create' | 'recover' | null = null;
  private recoveryOriginal: number | null = null;
  private recoveryFailed = false;
  private recoverySettled = false;
  private recoveryAttempt: { request: UploadKeyRecoverRequest; context: string; record: UploadKeyReference | null } | null = null;
  private original: number | null = null;
  getSnapshot = (): UploadKeyView => this.state;
  private update(value: Partial<UploadKeyView>): void { this.state = frozen({ ...this.state, ...value }); }
  sync(assets: AssetDisplayState): void {
    const context = uploadKeyContext(assets);
    if (context !== this.context) {
      this.context = context;
      this.confirmationRevision = null;
      if (this.recoverySettled) {
        this.recoveryAttempt = null; this.recoveryOriginal = null; this.recoverySettled = false;
      }
      // A view change never loses an in-flight or uncertain original.
      const unresolved = this.pending || this.state.uncertain || this.state.status?.operation && this.state.status.operation.phase !== 'saved';
      if (!unresolved) this.original = null;
      this.update({ confirmed: false, status: null,
        ...(unresolved ? {} : { attempted: false, error: null }) });
    } else if (this.confirmationRevision !== null && assets.status?.statusRevision !== this.confirmationRevision) {
      this.confirmationRevision = null; this.update({ confirmed: false });
    }
    if ((this.state.attempted || this.original !== null) && (assets.blocked || assets.observationFailed)) {
      this.update({ uncertain: true, confirmed: false });
    }
  }
  prepareRequest(assets: AssetDisplayState, recovery = false): UploadKeyContextRequest | null {
    this.sync(assets);
    if (uploadKeyBaseReason(assets) || this.pending ||
        (recovery ? this.recoveryFailed || !this.state.status?.recovery : this.state.uncertain || this.state.attempted) ||
        this.state.status?.capability.available !== true) return null;
    this.pending = 'prepare'; this.confirmationRevision = null;
    this.update({ checking: true, confirmed: false, error: null });
    return { contextRevision: assets.status!.context!.revision };
  }
  confirm(assets: AssetDisplayState, checked: boolean): boolean {
    this.sync(assets);
    if (!this.canCreate(assets, false)) { this.confirmationRevision = null; this.update({ confirmed: false }); return false; }
    this.confirmationRevision = checked ? assets.status!.statusRevision : null;
    this.update({ confirmed: checked }); return true;
  }
  canCreate(assets: AssetDisplayState, requireDeclaration = true): boolean {
    const status = this.state.status;
    return !uploadKeyBaseReason(assets) && !this.pending && !this.state.uncertain && !this.state.attempted &&
      !!status?.capability.available && status.setup === 'ready' && status.plan === 'confirm-application-history' &&
      uploadKeyContext(assets) === this.context && status.assets.context?.revision === assets.status?.context?.revision &&
      status.assets.statusRevision === assets.status?.statusRevision &&
      (!requireDeclaration || this.state.confirmed && this.confirmationRevision === assets.status?.statusRevision);
  }
  createRequest(assets: AssetDisplayState): UploadKeyCreateRequest | null {
    this.sync(assets);
    if (!this.canCreate(assets)) return null;
    const request = { contextRevision: assets.status!.context!.revision, expectedStatusRevision: assets.status!.statusRevision,
      declaration: NEW_UPLOAD_KEY_DECLARATION };
    // Spent BEFORE the actual invoke. A delayed/rejected response, refresh,
    // navigation or remounted component cannot rearm key generation.
    this.pending = 'create'; this.confirmationRevision = null;
    this.update({ attempted: true, confirmed: false, error: null });
    return request;
  }
  canRecover(assets: AssetDisplayState, action: UploadKeyRecoveryAction): boolean {
    const status = this.state.status, recovery = status?.recovery;
    return !uploadKeyBaseReason(assets) && !this.pending && !this.recoveryFailed &&
      (!this.recoveryAttempt || this.recoveryCompleted(assets) !== null) &&
      status?.capability.available === true && status.setup !== 'required' && status.setup !== 'checking' && status.setup !== 'failed' &&
      !!recovery && recovery.state === action && recovery.preferenceRevision !== null &&
      uploadKeyContext(assets) === this.context && status.assets.statusRevision === assets.status?.statusRevision;
  }
  recoverRequest(assets: AssetDisplayState, action: UploadKeyRecoveryAction): UploadKeyRecoverRequest | null {
    this.sync(assets);
    if (!this.canRecover(assets, action)) return null;
    const request = { contextRevision: assets.status!.context!.revision, expectedStatusRevision: assets.status!.statusRevision,
      expectedPreferenceRevision: this.state.status!.recovery!.preferenceRevision!, action };
    this.recoveryAttempt = { request, context: this.context!, record: this.state.status!.recovery!.record };
    this.recoveryOriginal = null; this.recoverySettled = false; this.pending = 'recover'; this.confirmationRevision = null;
    this.update({ confirmed: false, error: null });
    return { ...request };
  }
  recoveryCompleted(assets: AssetDisplayState): UploadKeyRecoveryAction | null {
    const attempt = this.recoveryAttempt, status = this.state.status, operation = status?.recovery?.operation;
    if (!attempt || !status || this.pending || this.recoveryFailed || assets.blocked || assets.observationFailed || assets.originPending ||
        uploadKeyContext(assets) !== attempt.context || attempt.context !== this.context ||
        status.assets.statusRevision !== assets.status?.statusRevision || operation?.phase !== 'completed' ||
        operation.operationId !== this.recoveryOriginal || operation.action !== attempt.request.action ||
        operation.preferenceRevision === null || BigInt(operation.preferenceRevision) !== BigInt(attempt.request.expectedPreferenceRevision) + 1n)
      return null;
    if (operation.action === 'remember-bound') {
      const now = status.recovery!.record, before = attempt.record;
      if (!now || !before || now.vaultId !== before.vaultId || now.generationId !== before.generationId || now.recordId !== before.recordId ||
          now.revisionId !== before.revisionId || now.revisionCounter !== before.revisionCounter) return null;
    }
    return operation.action;
  }
  private acceptRecoveryCompletion(assets: AssetDisplayState): void {
    const completed = this.recoveryCompleted(assets);
    if (completed !== null) this.recoverySettled = true;
    if (completed === 'acknowledge-unstarted') {
      // Only this explicit command's SAME completed original can clear the old
      // no-GO attempt. No new declaration, setup, generation or Bind is sent.
      this.original = null; this.confirmationRevision = null;
      this.update({ attempted: false, uncertain: false, confirmed: false });
    }
  }
  accept(value: unknown, assets: AssetDisplayState, action: 'prepare' | 'create' | 'recover' | null): UploadKeyStatus | null {
    const result = parseUploadKeyStatus(value);
    const current = uploadKeyContext(assets);
    const observed = `${result.assets.context!.projectId}:${result.assets.context!.revision}`;
    if (!current || observed !== current || current !== this.context) {
      if (action) this.failed(action);
      return null;
    }
    if (action && this.pending !== action) return null;
    if (action === 'create') {
      if (!result.operation) { this.failed(action); return null; }
      this.original = result.operation.operationId;
    }
    if (action === 'recover') {
      if (!this.recoveryAttempt || !result.recovery?.operation || result.recovery.operation.action !== this.recoveryAttempt.request.action) {
        this.failed(action); return null;
      }
      this.recoveryOriginal = result.recovery.operation.operationId;
    }
    if (this.recoveryOriginal !== null && result.recovery?.operation && result.recovery.operation.operationId !== this.recoveryOriginal) {
      this.failed(action); return null;
    }
    if (this.original !== null && result.operation && result.operation.operationId !== this.original) {
      this.failed(action); return null;
    }
    if (result.assets.statusRevision < (assets.status?.statusRevision ?? 0)) {
      // The SAME outer controller already checked/bound this command's own
      // original acknowledgement. An overtaking event cannot make it foreign,
      // but this older response must not replace the current displayed result.
      if (action !== 'create' && action !== 'recover') { if (action) this.failed(action); return null; }
      this.pending = null; this.confirmationRevision = null;
      this.update({ checking: false, confirmed: false });
      this.acceptRecoveryCompletion(assets);
      return result;
    }
    if (action) this.pending = null;
    this.confirmationRevision = null;
    this.update({ status: result, checking: false, confirmed: false, error: null,
      attempted: this.state.attempted || result.setup === 'attempted' || result.operation !== null,
      // Read-only refresh may explain the original outcome but cannot erase a
      // lost original create acknowledgement or grant another attempt.
      uncertain: this.state.uncertain || result.operation?.phase === 'recovery-required' || result.recovery?.operation?.phase === 'recovery-required' || result.setup === 'failed' });
    if (this.recoveryAttempt && result.recovery?.operation?.phase === 'recovery-required') this.recoveryFailed = true;
    this.acceptRecoveryCompletion(assets);
    return result;
  }
  saved(assets: AssetDisplayState): boolean {
    const status = this.state.status;
    return !this.pending && !this.state.uncertain && !assets.blocked && !assets.observationFailed && !assets.originPending &&
      !!uploadKeyContext(assets) && uploadKeyContext(assets) === this.context &&
      status?.assets.statusRevision === assets.status?.statusRevision && status?.operation?.phase === 'saved' &&
      status.operation.operationId === this.original && status.saved !== null;
  }
  unavailable(): void {
    this.update({ checking: false, confirmed: false,
      error: 'Creating an upload key is unavailable in this version. Use the existing import and assessment controls when available.' });
  }
  failed(action: 'prepare' | 'create' | 'recover' | null): void {
    if (action === 'recover' || this.pending === 'recover' || this.recoveryAttempt && !this.recoverySettled) this.recoveryFailed = true;
    this.pending = null; this.confirmationRevision = null;
    this.update({ checking: false, uncertain: true, confirmed: false,
      error: 'The original action could not be confirmed. Check status and keep existing keys unchanged; do not create another key.' });
  }
  refreshRequest(assets: AssetDisplayState): UploadKeyContextRequest | null {
    this.sync(assets);
    const context = assets.status?.context;
    // Checking never authorizes work; allow the original read after STOP too.
    if (assets.mode !== 'native' || !context || context.platform !== 'android') return null;
    return { contextRevision: context.revision };
  }
}
