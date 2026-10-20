// The existing AssetSessionController owns ALL invokes, original-operation
// correlation, cancellation and context updates. This child holds only the
// bounded, nonsecret generation view and one explicit declaration.
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { NEW_UPLOAD_KEY_DECLARATION, parseUploadKeyStatus, uploadKeyBaseReason, uploadKeyContext,
  type UploadKeyContextRequest, type UploadKeyCreateRequest, type UploadKeyStatus } from './credentialUploadKey.ts';

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
  private pending: 'prepare' | 'create' | null = null;
  private original: number | null = null;
  getSnapshot = (): UploadKeyView => this.state;
  private update(value: Partial<UploadKeyView>): void { this.state = frozen({ ...this.state, ...value }); }
  sync(assets: AssetDisplayState): void {
    const context = uploadKeyContext(assets);
    if (context !== this.context) {
      this.context = context;
      this.confirmationRevision = null;
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
  prepareRequest(assets: AssetDisplayState): UploadKeyContextRequest | null {
    this.sync(assets);
    if (uploadKeyBaseReason(assets) || this.pending || this.state.uncertain || this.state.attempted ||
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
  accept(value: unknown, assets: AssetDisplayState, action: 'prepare' | 'create' | null): UploadKeyStatus | null {
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
    if (this.original !== null && result.operation && result.operation.operationId !== this.original) {
      this.failed(action); return null;
    }
    if (result.assets.statusRevision < (assets.status?.statusRevision ?? 0)) {
      // The SAME outer controller already checked/bound this command's own
      // original acknowledgement. An overtaking event cannot make it foreign,
      // but this older response must not replace the current displayed result.
      if (action !== 'create') { if (action) this.failed(action); return null; }
      this.pending = null; this.confirmationRevision = null;
      this.update({ checking: false, confirmed: false });
      return result;
    }
    if (action) this.pending = null;
    this.confirmationRevision = null;
    this.update({ status: result, checking: false, confirmed: false, error: null,
      attempted: this.state.attempted || result.setup === 'attempted' || result.operation !== null,
      // Read-only refresh may explain the original outcome but cannot erase a
      // lost original create acknowledgement or grant another attempt.
      uncertain: this.state.uncertain || result.operation?.phase === 'recovery-required' || result.setup === 'failed' });
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
  failed(_action: 'prepare' | 'create' | null): void {
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
