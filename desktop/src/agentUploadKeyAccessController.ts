import { AGENT_UPLOAD_KEY_MAX_MS, agentUploadKeySelection, parseAgentUploadKeyAccess } from './agentUploadKeyAccess.ts';
import type { AgentUploadKeyAccess, AgentUploadKeyAccessPort, AgentUploadKeyKind, AgentUploadKeySelection } from './agentUploadKeyAccess.ts';
import type { AssetDisplayState, AssetRecordRef } from './assetSessionTypes.ts';
import { agentUploadKeyBackupOptions, agentUploadKeyBackupReason } from './agentUploadKeyBackup.ts';
import type { AgentUploadKeyBackupOption } from './agentUploadKeyBackup.ts';
import { agentUploadKeyReuseOptions, agentUploadKeyReuseReason, sameAgentUploadKeyPrepared } from './agentUploadKeyReuse.ts';
import type { AgentUploadKeyPreparation, AgentUploadKeyReuseOption } from './agentUploadKeyReuse.ts';
import { reserveId, reserveProject } from './versionReserve.ts';

export interface AgentUploadKeyContext {
  port: AgentUploadKeyAccessPort | null; nativeSession: object | null; projectId: string | null;
  project: object | null; assets: AssetDisplayState | null; generateReady: boolean; blockedReason: string | null;
}
export interface AgentUploadKeyAccessView {
  readonly kind: AgentUploadKeyKind; readonly access: AgentUploadKeyAccess | null;
  readonly acknowledged: boolean; readonly newApplication: boolean;
  readonly backupRecord: Readonly<AssetRecordRef> | null;
  readonly prepareRecord: Readonly<AssetRecordRef> | null;
  readonly stale: boolean; readonly unknown: boolean; readonly issue: string | null;
  readonly pending: 'status' | 'allow' | null; readonly revoking: boolean;
}
interface Witness { context: AgentUploadKeyContext; revision: number; contextRevision: number; entry: number;
  selection: AgentUploadKeySelection; end: number; version: object; key: string }
interface Address { context: AgentUploadKeyContext; id: string; kind: AgentUploadKeyKind }
interface Work { kind: 'status' | 'allow' | 'revoke'; context: AgentUploadKeyContext; generation: object;
  address: Address | null; witness: Witness | null; sent: boolean; startedAt: number | null;
  original: Promise<unknown> | null; completion: Promise<void>; finish(): void }
interface Source { current(): AgentUploadKeyContext; now?(): number; nonce?(): string;
  prepareExisting?(record: Readonly<AssetRecordRef>): AgentUploadKeyPreparation | null }
const absent = (): AgentUploadKeyContext => ({ port: null, nativeSession: null, projectId: null, project: null,
  assets: null, generateReady: false, blockedReason: 'Open the native app and select your Android project.' });
const uncertain = 'CLI permission is unconfirmed. Keep the original request; check it or withdraw this exact permission. Do not repeat generation, assignment, backup or restore.';
const hostReason = (c: AgentUploadKeyContext): string | null => !c.port || !c.nativeSession ? 'CLI signing-key permission requires the running native Desktop app.' : null;
const sameHost = (a: AgentUploadKeyContext, b: AgentUploadKeyContext) => a.port === b.port && a.nativeSession === b.nativeSession;
const sameContext = (a: AgentUploadKeyContext, b: AgentUploadKeyContext) => sameHost(a, b) && a.project === b.project && a.projectId === b.projectId &&
  a.assets?.entryGeneration === b.assets?.entryGeneration && a.assets?.status?.context === b.assets?.status?.context &&
  a.assets?.status?.statusRevision === b.assets?.status?.statusRevision && a.assets?.contextCurrent === b.assets?.contextCurrent;
const sameGrant = (a: AgentUploadKeyAccess, b: AgentUploadKeyAccess) => a.grantId === b.grantId && a.kind === b.kind &&
  a.projectId === b.projectId && a.serviceInstance === b.serviceInstance;

// Permission only. Native keeps the actual PreparedSetup/Bind preview and all
// original caller/Asset retirement facts; Access never establishes completion.
export class AgentUploadKeyAccessController {
  private readonly source: Source;
  private context = absent();
  private version: object = {};
  private generation: object = {};
  private normal: Work | null = null;
  private revocation: Work | null = null;
  private consent: Witness | null = null;
  private address: Address | null = null;
  private withdrawn: Address | null = null;
  private attempted = new Set<string>();
  private nonces = new Set<string>();
  private permissionEnd: number | null = null;
  private preparation: { address: Address; attempt: AgentUploadKeyPreparation; allowJoined: boolean } | null = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  private state: AgentUploadKeyAccessView = Object.freeze({ kind: 'bind-reviewed', access: null, acknowledged: false,
    newApplication: false, backupRecord: null, prepareRecord: null, stale: true, unknown: false, issue: null, pending: null, revoking: false });
  constructor(source: Source) { this.source = source; this.syncContext(); }
  getSnapshot = (): AgentUploadKeyAccessView => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  whenSettled = (): Promise<void> => Promise.all([this.normal?.completion, this.revocation?.completion]).then(() => undefined);
  ownerReason = (): string | null => this.state.unknown ? uncertain : this.normal || this.revocation ?
    'Wait for the original CLI permission call. Withdrawal of that same permission stays available.' : this.state.access?.enabled ?
      'A CLI signing-key permission was allowed. Check it or withdraw it before starting a different action.' :
      this.state.access?.consumed && this.address !== null && this.withdrawn !== this.address ?
        'The previous CLI permission was used. Withdraw that exact permission before allowing another review; withdrawal does not prove its request completed.' : null;
  private read(): AgentUploadKeyContext {
    try {
      const c = this.source.current(), p = c.port;
      if (typeof c.generateReady !== 'boolean' || c.blockedReason !== null && typeof c.blockedReason !== 'string') return absent();
      return { ...c, projectId: reserveProject(c.projectId) ? c.projectId : null,
        project: c.project && typeof c.project === 'object' ? c.project : null,
        nativeSession: c.nativeSession && typeof c.nativeSession === 'object' ? c.nativeSession : null,
        assets: c.assets && typeof c.assets === 'object' ? c.assets : null,
        port: p && ['status', 'allow', 'revoke'].every((k) => typeof p[k as keyof AgentUploadKeyAccessPort] === 'function') ? p : null };
    } catch { return absent(); }
  }
  private now(): number | null {
    try { const n = this.source.now ? this.source.now() : performance.now(); return Number.isFinite(n) && n >= 0 ? n : null; } catch { return null; }
  }
  private patch(change: Partial<AgentUploadKeyAccessView> = {}): void {
    this.state = Object.freeze({ ...this.state, ...change, pending: this.normal?.kind === 'allow' ? 'allow' : this.normal ? 'status' : null, revoking: this.revocation !== null });
    if (!this.disposed) for (const fn of [...this.listeners]) { try { fn(); } catch { /* An observer cannot retire an original. */ } }
  }
  syncContext(): void {
    if (this.disposed) return;
    const c = this.read(), changed = !sameContext(c, this.context), display = c.blockedReason !== this.context.blockedReason || c.generateReady !== this.context.generateReady;
    this.context = c;
    const preparation = this.preparation, origin = preparation?.address.context;
    // Native Load progress may change the displayed status revision without
    // replacing this original. Host/project/entry or peer drift must instead
    // invalidate it immediately, including a later return to the old values.
    if (preparation && origin && (!sameHost(c, origin) || c.project !== origin.project || c.projectId !== origin.projectId ||
        c.assets?.entryGeneration !== origin.assets?.entryGeneration || c.blockedReason)) preparation.attempt.invalidate();
    if (changed || display) {
      this.version = {}; this.consent = null;
      this.patch({ acknowledged: false, newApplication: false, ...(changed ? { stale: true, backupRecord: null, prepareRecord: null } : {}) });
    }
  }
  private witness(c: AgentUploadKeyContext): Witness | null {
    const now = this.now(), a = c.assets;
    if (!a || !c.projectId || !c.project || hostReason(c) || c.blockedReason || now === null || a.status?.context?.projectId !== c.projectId) return null;
    const selection = agentUploadKeySelection(a, this.state.kind, c.generateReady, now,
      this.state.kind === 'prepare-existing' ? this.state.prepareRecord : this.state.backupRecord), status = a.status;
    if (!selection || !status?.context) return null;
    const key = selection.kind === 'bind-reviewed' ? `bind:${c.projectId}:${status.context.revision}:${selection.previewOperationId}:${selection.previewToken}` :
      selection.kind === 'backup-encrypted' || selection.kind === 'prepare-existing' ? `${selection.kind === 'backup-encrypted' ? 'backup' : 'prepare'}:${c.projectId}:${status.context.revision}:${status.statusRevision}:${a.entryGeneration}:${selection.recordId}:${selection.expectedRevision}` :
      `${selection.kind === 'generate-new' ? 'generate' : 'restore'}:${c.projectId}:${status.context.revision}:${status.statusRevision}:${a.entryGeneration}`;
    return { context: c, revision: status.statusRevision, contextRevision: status.context.revision, entry: a.entryGeneration, selection,
      end: selection.kind === 'bind-reviewed' ? Math.min(now + AGENT_UPLOAD_KEY_MAX_MS, a.previewDeadline!) : now + AGENT_UPLOAD_KEY_MAX_MS,
      version: this.version, key };
  }
  private current(w: Witness): boolean {
    const c = this.read(), next = this.witness(c), now = this.now();
    return !this.disposed && w.version === this.version && sameContext(w.context, c) && next?.key === w.key && now !== null && now < w.end;
  }
  selectionReason(): string | null {
    const c = this.read(), w = this.witness(c);
    return this.disposed ? 'This permission controller is retired.' : this.ownerReason() ?? hostReason(c) ?? c.blockedReason ??
      (this.state.kind === 'prepare-existing' && !this.source.prepareExisting ? 'Use the original Desktop credential controller to prepare an existing key.' : null) ??
      (!w ? this.state.kind === 'generate-new' ? 'Finish the ordinary new-app signing setup and tool checks in Desktop first. Any existing or uncertain key prevents generation.' :
        this.state.kind === 'prepare-existing' ? agentUploadKeyReuseReason(c.assets) ?? 'Explicitly select the encrypted Android key to load and assess; assignment is a separate review.' :
        this.state.kind === 'backup-encrypted' || this.state.kind === 'restore-encrypted' ? agentUploadKeyBackupReason(c.assets) ?? 'Explicitly select the encrypted Android key to back up.' :
        'Select and assess an existing encrypted Android key in Desktop first, leaving its current Assign review open.' :
        this.attempted.has(w.key) ? 'This exact review was already delegated. Check its original request; it is not renewed by a refresh.' :
          this.nonces.size >= 32 ? 'This session has reached its finite permission limit. Preserve any original request before closing Desktop.' : null);
  }
  allowReason(): string | null {
    return this.selectionReason() ?? (!this.consent || !this.current(this.consent) || !this.state.acknowledged ||
      this.state.kind === 'generate-new' && !this.state.newApplication ? 'Confirm the separate permission for this exact action.' : null);
  }
  setKind(value: AgentUploadKeyKind): boolean {
    if (this.disposed || !['prepare-existing', 'generate-new', 'bind-reviewed', 'backup-encrypted', 'restore-encrypted'].includes(value) || this.ownerReason()) return false;
    if (value !== this.state.kind) { this.version = {}; this.consent = null; this.patch({ kind: value, acknowledged: false, newApplication: false, backupRecord: null, prepareRecord: null, stale: true }); }
    return true;
  }
  prepareOptions(): readonly AgentUploadKeyReuseOption[] { return agentUploadKeyReuseOptions(this.read().assets); }
  setPrepareRecord(value: Readonly<AssetRecordRef> | null): boolean {
    this.syncContext();
    if (this.disposed || this.ownerReason() || this.state.kind !== 'prepare-existing') return false;
    const exact = value === null ? null : this.prepareOptions().find(r => r.recordId === value.recordId && r.expectedRevision === value.expectedRevision);
    if (value !== null && !exact) return false;
    this.version = {}; this.consent = null;
    this.patch({ prepareRecord: exact ? Object.freeze({ recordId: exact.recordId, expectedRevision: exact.expectedRevision }) : null,
      acknowledged: false, newApplication: false, stale: true });
    return true;
  }
  backupOptions(): readonly AgentUploadKeyBackupOption[] { return agentUploadKeyBackupOptions(this.read().assets); }
  setBackupRecord(value: Readonly<AssetRecordRef> | null): boolean {
    this.syncContext();
    if (this.disposed || this.ownerReason() || this.state.kind !== 'backup-encrypted') return false;
    const exact = value === null ? null : this.backupOptions().find((r) => r.recordId === value.recordId && r.expectedRevision === value.expectedRevision);
    if (value !== null && !exact) return false;
    this.version = {}; this.consent = null;
    this.patch({ backupRecord: exact ? Object.freeze({ recordId: exact.recordId, expectedRevision: exact.expectedRevision }) : null,
      acknowledged: false, newApplication: false, stale: true });
    return true;
  }
  setNewApplication(value: boolean): boolean {
    this.syncContext();
    if (typeof value !== 'boolean' || this.disposed || this.normal || this.revocation || this.state.kind !== 'generate-new' || value && this.selectionReason()) return false;
    this.consent = null; this.patch({ newApplication: value, acknowledged: false }); return true;
  }
  setAcknowledged(value: boolean): boolean {
    this.syncContext();
    if (typeof value !== 'boolean' || this.disposed || this.normal || this.revocation || value && (this.selectionReason() || this.state.kind === 'generate-new' && !this.state.newApplication)) return false;
    this.consent = value ? this.witness(this.read()) : null;
    this.patch({ acknowledged: this.consent !== null }); return true;
  }
  private controls(): AgentUploadKeyContext { return this.address?.context ?? this.normal?.context ?? this.read(); }
  statusReason(): string | null { return this.disposed ? 'This permission controller is retired.' : hostReason(this.controls()) ??
    (this.normal || this.revocation ? 'Wait for the original permission reply. Exact withdrawal remains available.' : null); }
  revokeReason(): string | null { return this.disposed ? 'This permission controller is retired.' : !this.address ? 'No original permission address has been observed.' :
    hostReason(this.address.context) ?? (this.revocation ? 'Withdrawing this exact permission…' : null); }
  remainingSeconds(): number | null {
    const now = this.now();
    return this.state.stale || !this.state.access?.enabled || this.permissionEnd === null || now === null ? null : Math.max(0, Math.ceil((this.permissionEnd - now) / 1000));
  }
  private unknown(): void { this.consent = null; this.preparation?.attempt.invalidate(); this.patch({ unknown: true, stale: true, acknowledged: false, newApplication: false, issue: uncertain }); }
  private begin(kind: Work['kind'], c: AgentUploadKeyContext, address: Address | null, witness: Witness | null): Work {
    if (kind === 'revoke') { this.generation = {}; this.preparation?.attempt.invalidate(); } // Fence Allow BEFORE notifying a subscriber.
    this.consent = null;
    let finish!: () => void; const completion = new Promise<void>((resolve) => { finish = resolve; });
    const w: Work = { kind, context: c, address, witness, generation: this.generation, sent: false, startedAt: this.now(), original: null, completion, finish };
    if (kind === 'revoke') this.revocation = w; else this.normal = w;
    this.patch({ acknowledged: false, newApplication: false, stale: true }); return w;
  }
  private delivered(w: Work): boolean { return !this.disposed && w.generation === this.generation &&
    (w.address === null || this.address === w.address); }
  private finish(w: Work): void {
    if (this.normal === w) this.normal = null; if (this.revocation === w) this.revocation = null;
    this.patch(); w.finish();
  }
  private accept(w: Work, raw: unknown): AgentUploadKeyAccess | null {
    if (!this.delivered(w)) return null;
    let a = parseAgentUploadKeyAccess(raw);
    if (!this.delivered(w)) return null;
    if (!a || w.kind === 'allow' && (!w.address || a.grantId !== w.address.id || a.kind !== w.address.kind) ||
        w.address && a.grantId !== null && (a.grantId !== w.address.id || a.kind !== w.address.kind) ||
        w.kind === 'revoke' && a.enabled || w.kind === 'status' && w.address && a.grantId === null) { this.unknown(); return null; }
    const old = this.state.access;
    if (old?.grantId && old.grantId === a.grantId && (!sameGrant(old, a) || old.consumed && (!a.consumed || old.requestId !== a.requestId) ||
        !old.enabled && a.enabled)) { this.unknown(); return null; }
    if (old?.prepared && a.prepared && old.grantId === a.grantId) {
      if (!sameAgentUploadKeyPrepared(old.prepared, a.prepared)) { this.unknown(); return null; }
      a = Object.freeze({ ...a, prepared: Object.freeze({ ...a.prepared, remainingMs: Math.min(old.prepared.remainingMs, a.prepared.remainingMs) }) });
    }
    if (a.grantId && !this.address && a.kind) this.address = { context: w.context, id: a.grantId, kind: a.kind }; // Stop address only, never consent.
    // Consumed Access and a zero countdown cannot retire the current native
    // lease. Only this original exact Revoke's actual returned acknowledgment
    // removes the next-Allow UI gate; it never settles the request or Unknown.
    if (w.kind === 'revoke' && w.address === this.address) this.withdrawn = w.address;
    if (a.enabled) {
      const deadline = w.startedAt === null ? null : w.startedAt + a.remainingMs;
      this.permissionEnd = old?.grantId === a.grantId && this.permissionEnd !== null && deadline !== null ? Math.min(this.permissionEnd, deadline) : deadline;
    } else this.permissionEnd = null;
    const current = sameContext(w.context, this.read()) && (w.witness === null || this.current(w.witness));
    this.patch({ access: a, stale: !current || this.state.unknown, ...(this.state.unknown ? {} : { issue: null }) });
    return a;
  }
  private async correlate(w: Work, a: AgentUploadKeyAccess | null): Promise<void> {
    const original = this.preparation;
    if (!original || !original.allowJoined || !a?.prepared || a.kind !== 'prepare-existing') return;
    const current = () => {
      const c = this.read(), latest = this.state.access;
      return this.preparation === original && this.delivered(w) && !this.revocation && !this.state.unknown &&
        this.address === original.address && this.withdrawn !== original.address && sameHost(c, original.address.context) &&
        c.project === original.address.context.project && c.projectId === original.address.context.projectId && !c.blockedReason &&
        latest?.grantId === original.address.id && latest.requestId === a.requestId && !!latest.prepared &&
        sameAgentUploadKeyPrepared(latest.prepared, a.prepared!);
    };
    // Anchor this returned countdown to its SAME Allow/Check call, not its
    // receipt or a later Asset callback. This is comparison only, not a lease.
    const reviewEnd = w.startedAt === null ? null : w.startedAt + a.prepared.remainingMs;
    if (current()) await original.attempt.observe(a.prepared, current, reviewEnd);
  }
  private nonce(): string | null {
    try {
      const id = this.source.nonce ? this.source.nonce() : Array.from(crypto.getRandomValues(new Uint8Array(16)), (v) => v.toString(16).padStart(2, '0')).join('');
      return reserveId(id) && !this.nonces.has(id) ? id : null;
    } catch { return null; }
  }
  async allow(): Promise<boolean> {
    this.syncContext(); if (this.allowReason()) return false;
    const witness = this.consent!, id = this.nonce();
    if (!id || !this.current(witness)) return false;
    const c = witness.context, address: Address = { context: c, id, kind: witness.selection.kind };
    let attempt: AgentUploadKeyPreparation | null = null;
    if (witness.selection.kind === 'prepare-existing') {
      try { attempt = this.source.prepareExisting?.({ recordId: witness.selection.recordId, expectedRevision: witness.selection.expectedRevision }) ?? null; }
      catch { return false; }
      if (!attempt || !attempt.current() || !this.current(witness)) { attempt?.invalidate(); return false; }
    }
    this.preparation?.attempt.invalidate();
    this.preparation = attempt ? { address, attempt, allowJoined: false } : null;
    this.address = address; this.withdrawn = null; this.nonces.add(id); // Retain before any notification/native handoff, including lost Allow.
    const w = this.begin('allow', c, address, witness);
    try {
      if (!this.delivered(w) || this.revocation || !this.current(witness) || attempt && !attempt.current() || !c.port || !c.projectId) return false;
      w.sent = true; this.attempted.add(witness.key);
      w.original = c.port.allow({ projectId: c.projectId, consentId: id, contextRevision: witness.contextRevision,
        expectedStatusRevision: witness.revision, selection: witness.selection });
      if (!w.original || typeof w.original.then !== 'function') { this.unknown(); return true; }
      const raw = await w.original; // Actual original Allow return, not an event/Access bit.
      const a = this.accept(w, raw);
      if (a && this.delivered(w) && !this.state.unknown && this.preparation?.address === address) this.preparation.allowJoined = true;
      await this.correlate(w, a);
    } catch { if (this.delivered(w)) this.unknown(); }
    finally { if (!w.sent) attempt?.invalidate(); this.finish(w); }
    return w.sent;
  }
  async check(): Promise<boolean> {
    this.syncContext(); if (this.statusReason()) return false;
    const c = this.controls(), w = this.begin('status', c, this.address, null);
    try {
      if (!this.delivered(w) || this.revocation || !c.port) return false;
      w.sent = true; w.original = c.port.status();
      if (!w.original || typeof w.original.then !== 'function') { this.unknown(); return true; }
      await this.correlate(w, this.accept(w, await w.original));
    } catch { if (this.delivered(w)) this.unknown(); }
    finally { this.finish(w); }
    return w.sent;
  }
  async revoke(): Promise<boolean> {
    this.syncContext(); if (this.revokeReason()) return false;
    const address = this.address!, c = address.context, w = this.begin('revoke', c, address, null);
    try {
      if (!this.delivered(w) || !c.port) return false;
      w.sent = true; w.original = c.port.revoke(address.id);
      if (!w.original || typeof w.original.then !== 'function') { this.unknown(); return true; }
      this.accept(w, await w.original);
    } catch { if (this.delivered(w)) this.unknown(); }
    finally { this.finish(w); }
    return w.sent;
  }
  dispose(): void { this.disposed = true; this.generation = {}; this.consent = null; this.preparation?.attempt.invalidate(); this.listeners.clear(); }
}
