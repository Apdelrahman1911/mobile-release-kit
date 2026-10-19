import { cliReadAccessProjectIdFits, cliReadAccessSummary, parseCliReadAccessStatus } from './cliReadAccess.ts';
import type { CliReadAccessStatus, CliReadAccessSummary } from './cliReadAccess.ts';

// Root supplies an ORIGINAL host-bound port. No renderer token, service/path
// override, generic IPC method, command or CLI mutation belongs in this port.
// revoke() must return the original HOST's fresh status after native revocation.
// Its native admission epoch, not JS reply suppression, defeats an older Allow.
export interface CliReadAccessPort {
  status(): Promise<unknown>;
  allow(projectId: string): Promise<unknown>;
  revoke(): Promise<unknown>;
}
export interface CliReadAccessContext {
  port: CliReadAccessPort | null;
  nativeSession: object | null; // Stable Root-owned identity, never serialized.
  selectedProject: { readonly id: string; readonly name: string } | null;
  preview: boolean;
  busy: boolean; // OTHER owners only; not this controller's own pending calls.
}
export interface CliReadAccessOptions { current(): CliReadAccessContext; now?(): number }
export interface CliReadAccessView {
  readonly selectedProject: { readonly id: string; readonly name: string } | null;
  readonly observation: { readonly status: CliReadAccessStatus; readonly startedAt: number | null } | null;
  readonly stale: boolean;
  readonly pending: 'status' | 'allow' | null;
  readonly pendingRetired: boolean;
  readonly revoking: boolean;
  readonly pendingCount: number;
  readonly issue: 'unavailable' | 'response-invalid' | 'revoke-unconfirmed' | null;
}
interface Scope {
  kind: 'status' | 'allow' | 'revoke';
  context: CliReadAccessContext;
  epoch: object;
  startedAt: number | null;
  completion: Promise<void>;
  finish(): void;
}
const absent = (): CliReadAccessContext => ({ port: null, nativeSession: null, selectedProject: null, preview: false, busy: true });
const nativeReason = (context: CliReadAccessContext): string | null => context.preview ? 'CLI access is unavailable in the browser preview.' :
  !context.port || !context.nativeSession ? 'Open the native app’s current connection to manage CLI access.' : null;
const pendingReason = 'An earlier CLI access request is still finishing. You can still turn off access.';
export const CLI_READ_ACCESS_ISSUE_HELP = Object.freeze({
  unavailable: 'Access could not be checked. It may still be allowed. Check access or turn it off; no request is repeated automatically.',
  'response-invalid': 'The app returned an unusable access status. Access is unknown, not confirmed off. Check access or turn it off.',
  'revoke-unconfirmed': 'Turning off access could not be confirmed. Access may still be allowed. Check access or explicitly turn it off again.',
});

export class CliReadAccessController {
  private readonly options: CliReadAccessOptions;
  private context: CliReadAccessContext = absent();
  private epoch: object = {};
  private normal: Scope | null = null;
  private revocation: Scope | null = null;
  private disposed = false;
  private readonly listeners = new Set<() => void>();
  private state: CliReadAccessView = Object.freeze({ selectedProject: null, observation: null, stale: true,
    pending: null, pendingRetired: false, revoking: false, pendingCount: 0, issue: null });

  constructor(options: CliReadAccessOptions) { this.options = options; this.syncContext(); }
  getSnapshot = (): CliReadAccessView => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  pendingReason = (): string | null => this.normal || this.revocation ? pendingReason : null;
  whenSettled = (): Promise<void> => Promise.all([this.normal?.completion, this.revocation?.completion]).then(() => undefined);

  private readContext(): CliReadAccessContext {
    try {
      const context = this.options.current(), project = context.selectedProject;
      if (typeof context.preview !== 'boolean' || typeof context.busy !== 'boolean' ||
          context.nativeSession !== null && typeof context.nativeSession !== 'object') return absent();
      const port = context.port && typeof context.port.status === 'function' && typeof context.port.allow === 'function' &&
        typeof context.port.revoke === 'function' ? context.port : null;
      return { ...context, port, selectedProject: project && cliReadAccessProjectIdFits(project.id) && typeof project.name === 'string' ?
        Object.freeze({ id: project.id, name: project.name }) : null };
    } catch { return absent(); }
  }
  private sameContext(left: CliReadAccessContext, right: CliReadAccessContext): boolean {
    return left.port === right.port && left.nativeSession === right.nativeSession && left.preview === right.preview &&
      left.selectedProject?.id === right.selectedProject?.id;
  }
  private patch(change: Partial<CliReadAccessView> = {}): void {
    this.state = Object.freeze({ ...this.state, ...change, pending: this.normal?.kind === 'allow' ? 'allow' : this.normal ? 'status' : null,
      pendingRetired: this.normal !== null && this.normal.epoch !== this.epoch, revoking: this.revocation !== null,
      pendingCount: Number(this.normal !== null) + Number(this.revocation !== null) });
    if (!this.disposed) for (const listener of [...this.listeners]) { try { listener(); } catch { /* Keep original promises owned. */ } }
  }
  // Root calls synchronously BEFORE selection/service changes (including ABA),
  // then syncContext afterwards. Never dispose/recreate to clear a pending call.
  invalidateContext(): void { this.epoch = {}; this.patch({ stale: true, issue: null }); }
  syncContext(): void {
    if (this.disposed) return;
    const next = this.readContext(), changed = !this.sameContext(this.context, next);
    const displayChanged = this.context.selectedProject?.name !== next.selectedProject?.name || this.context.busy !== next.busy;
    this.context = next;
    if (changed) this.epoch = {};
    if (changed || displayChanged) this.patch({ selectedProject: next.selectedProject, ...(changed ? { stale: true, issue: null } : {}) });
  }
  private now(): number | null {
    try { const value = this.options.now ? this.options.now() : performance.now(); return Number.isFinite(value) && value >= 0 ? value : null; }
    catch { return null; }
  }
  summary(): CliReadAccessSummary {
    const observation = !this.state.stale && this.sameContext(this.context, this.readContext()) ? this.state.observation : null;
    const now = this.now();
    return cliReadAccessSummary(observation?.status ?? null, observation?.startedAt !== null && observation?.startedAt !== undefined && now !== null ?
      now - observation.startedAt : Number.NaN);
  }
  statusReason(): string | null { return this.disposed ? 'This desktop connection has been retired.' : nativeReason(this.readContext()) ?? this.pendingReason(); }
  allowReason(): string | null {
    const context = this.readContext();
    return this.statusReason() ?? (!context.selectedProject ? 'Select a project through the native app before allowing access.' :
      context.busy ? 'Finish the current task before allowing CLI access.' : null);
  }
  revokeReason(): string | null {
    return this.disposed ? 'This desktop connection has been retired.' : nativeReason(this.readContext()) ??
      (this.revocation ? 'Turning off access…' : null);
  }
  private current(scope: Scope): boolean {
    return !this.disposed && scope.epoch === this.epoch && this.sameContext(scope.context, this.readContext()) && nativeReason(scope.context) === null;
  }
  private begin(kind: Scope['kind'], context: CliReadAccessContext): Scope {
    if (kind === 'revoke') this.epoch = {}; // Fence older replies BEFORE any handoff/listener.
    let finish!: () => void;
    const completion = new Promise<void>((resolve) => { finish = resolve; });
    const scope = { kind, context, epoch: this.epoch, startedAt: this.now(), completion, finish };
    if (kind === 'revoke') this.revocation = scope;
    else this.normal = scope;
    this.patch({ stale: true, issue: null });
    return scope;
  }
  private end(scope: Scope): void {
    if (this.normal === scope) this.normal = null;
    if (this.revocation === scope) this.revocation = null;
    this.patch();
    scope.finish();
  }
  private accept(scope: Scope, raw: unknown): void {
    if (!this.current(scope)) return;
    const status = parseCliReadAccessStatus(raw);
    if (!this.current(scope)) return; // Descriptor inspection is not native/context authority.
    if (!status || scope.kind === 'allow' && status.enabled && status.projectIds.length !== 1) {
      this.patch({ stale: true, issue: scope.kind === 'revoke' ? 'revoke-unconfirmed' : 'response-invalid' }); return;
    }
    if (scope.kind === 'revoke' && status.enabled) { this.patch({ stale: true, issue: 'revoke-unconfirmed' }); return; }
    this.patch({ observation: Object.freeze({ status, startedAt: scope.startedAt }), stale: false, issue: null });
  }
  private failed(scope: Scope): void {
    if (this.current(scope)) this.patch({ stale: true, issue: scope.kind === 'revoke' ? 'revoke-unconfirmed' : 'unavailable' });
  }
  private async ordinary(kind: 'status' | 'allow'): Promise<boolean> {
    if (this.disposed) return false;
    this.syncContext();
    if ((kind === 'allow' ? this.allowReason() : this.statusReason()) !== null) return false;
    const scope = this.begin(kind, this.readContext());
    try {
      // A listener can change selection, acquire another owner, or explicitly
      // Revoke before this handoff. Never send an Allow behind that Revoke.
      if (!this.current(scope) || this.revocation || kind === 'allow' && (this.readContext().busy || !scope.context.selectedProject)) return false;
      const raw = kind === 'allow' ? await scope.context.port!.allow(scope.context.selectedProject!.id) : await scope.context.port!.status();
      this.accept(scope, raw);
    } catch { this.failed(scope); }
    finally { this.end(scope); }
    return true; // Dispatched, NOT a permission or successful action receipt.
  }
  check = (): Promise<boolean> => this.ordinary('status');
  allowSelected = (): Promise<boolean> => this.ordinary('allow');
  async revoke(): Promise<boolean> {
    if (this.disposed) return false;
    this.syncContext();
    if (this.revokeReason() !== null) return false;
    const scope = this.begin('revoke', this.readContext());
    try {
      const current = this.readContext();
      // Revocation is host-wide. A project switch or other busy owner must not
      // delay it, but a preview/disconnected/replaced host is not a new target.
      if (this.disposed || nativeReason(current) !== null || current.port !== scope.context.port || current.nativeSession !== scope.context.nativeSession) return false;
      this.accept(scope, await scope.context.port!.revoke());
    } catch { this.failed(scope); }
    finally { this.end(scope); }
    return true;
  }
  // Panel unmount only unsubscribes. Root/native still owns shutdown, revocation
  // and original-host joins; this merely prevents future UI delivery/admission.
  dispose(): void { this.disposed = true; this.epoch = {}; this.patch({ stale: true }); this.listeners.clear(); }
}
