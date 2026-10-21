// Shared finite UI promise bookkeeping, not native permission/execution.
// Only the two fixed family wrappers supply descriptor-safe comparison copying;
// native codecs/Inbox independently enforce the exact family at each boundary.
import { parseBuildPermissionAccess, nextBuildPermissionRevision } from './agentBuildPermissionProtocol.ts';
import type { BuildPermissionAccess } from './agentBuildPermissionProtocol.ts';
export { parseBuildPermissionAccess } from './agentBuildPermissionProtocol.ts';
export type { BuildPermissionAccess } from './agentBuildPermissionProtocol.ts';
export interface PermissionApi<A> {status():Promise<BuildPermissionAccess>;allow(input:A,expectedPermissionRevision:string):Promise<BuildPermissionAccess>;revoke():Promise<BuildPermissionAccess>}
export interface PermissionState { access: BuildPermissionAccess | null; acknowledged: boolean; pending: 'allow' | 'status' | null; revokePending: boolean; uncertain: boolean; message: string | null }
export interface PermissionContext<A> { api: PermissionApi<A> | null; project: A | null; blocked: boolean }
interface Work<A> { api: PermissionApi<A>; epoch: number; context: A | null; superseded: boolean }
/** App-owned finite UI requests: one read/allow and one independent revoke.
 * Native consent/epoch and original native owner remain authoritative. */
export class BuildPermission<A> {
  private readonly copy:(value:unknown)=>A|null;
  private readonly parseAccess:(value:unknown)=>BuildPermissionAccess|null;
  private returnedAccess:Readonly<{api:PermissionApi<A>;context:A|null;epoch:number;value:BuildPermissionAccess}>|null=null;
  private api: PermissionApi<A> | null = null;
  private original: PermissionApi<A> | null = null;
  private observed: Readonly<{api: PermissionApi<A>; revision: string}> | null = null;
  private context: A | null = null;
  private epoch = 0;
  private blocked = false;
  private readonly current: (() => PermissionContext<A>) | null;
  private work: Work<A> | null = null;
  private revokeWork: Work<A> | null = null;
  private listeners = new Set<(state: PermissionState) => void>();
  private state: PermissionState = { access: null, acknowledged: false, pending: null, revokePending: false, uncertain: false, message: null };
  constructor(copy: (value:unknown)=>A|null,current?:()=>PermissionContext<A>,parseAccess=(value:unknown)=>parseBuildPermissionAccess(value)) {this.copy=copy;this.current=current??null;this.parseAccess=parseAccess;}
  // Comparison-only original returned value. The fixed iOS recovery wrapper
  // permits an explicit action change on the SAME inspected project; its
  // native controller separately rematches the exact inspection/context.
  protected currentReturnedAccess(sameContext:(a:A|null,b:A|null)=>boolean=(a,b)=>a===b):BuildPermissionAccess|null {
    const r=this.returnedAccess;
    // The current original caller may retain its already-returned comparison
    // while its own pre-send recheck/refresh is pending. That is not a new
    // response or permission: canAllow still forbids all pending callers, and
    // a foreign context/epoch or any lost reply removes this comparison.
    return r&&r.api===this.api&&r.epoch===this.epoch&&
      (!this.work||this.work.api===r.api&&this.work.epoch===r.epoch&&this.work.context===this.context)&&
      !this.revokeWork&&!this.blocked&&!this.state.uncertain&&
      sameContext(r.context,this.context)?r.value:null;
  }
  getState(): PermissionState { return this.state; }
  protected comparison(): A | null { return this.context; }
  subscribe(listener: (state: PermissionState) => void): () => void { this.listeners.add(listener); listener(this.state); return () => { this.listeners.delete(listener); }; }
  private update(value: Partial<PermissionState>): void { this.state = Object.freeze({ ...this.state, ...value }); for (const fn of this.listeners) fn(this.state); }
  bind(api: PermissionApi<A> | null, input: A | null): void {
    const context = input ? this.copy(input) : null;
    if (this.api === api && JSON.stringify(this.context) === JSON.stringify(context)) return;
    this.api = api; this.context = context;
    // Do not lose an in-flight original on service/selection change. It can
    // still be explicitly revoked, never adopted as a new permission.
    this.update({ acknowledged: false, message: this.original && this.original !== api ? 'Revoke the original Desktop permission before using a different connection.' : null });
  }
  syncContext(): void {
    if (!this.current) return;
    const current = this.current();
    this.blocked = current.blocked;
    this.bind(current.api, current.project);
  }
  acknowledge(value: boolean): void { this.update({ acknowledged: value === true }); }
  canAllow(): boolean { return !this.blocked && !!this.api && !!this.context && (!this.original || this.original === this.api) && !this.work && !this.revokeWork &&
    !this.state.uncertain && this.observed?.api === this.api && nextBuildPermissionRevision(this.observed.revision) !== null && this.state.acknowledged && this.epoch < Number.MAX_SAFE_INTEGER; }
  async allow(): Promise<void> {
    this.syncContext(); // Native invocation uses current event-time selection, not an earlier render/effect.
    if (!this.canAllow()) return;
    const api = this.api!, context = this.context!, observed = this.observed!, expected = observed.revision;
    const work: Work<A> = { api, context, epoch: this.epoch, superseded: false };
    this.original = api; this.work = work; this.update({ pending: 'allow', acknowledged: false, message: null });
    try {
      // Notification is synchronous: a subscriber can revoke or change the
      // current selection before invocation. Do not send a fresh Allow after
      // that original Revoke merely because its eventual ACK would be ignored.
      this.syncContext();
      if (this.work !== work || work.superseded || work.epoch !== this.epoch || this.revokeWork ||
          this.api !== api || this.context !== context || this.blocked || this.observed !== observed) return;
      const result = this.parseAccess(await api.allow(context, expected));
      if (!result || result.permissionRevision !== nextBuildPermissionRevision(expected)) throw new Error('Unconfirmed permission');
      if (this.work === work && !work.superseded && work.epoch === this.epoch && this.api === api && this.context === context) {
        this.observed = Object.freeze({ api, revision: result.permissionRevision });
        this.returnedAccess=Object.freeze({api,context:work.context,epoch:work.epoch,value:result});
        this.update({ access: result, acknowledged: false, uncertain: false });
      }
      else if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: 'Selection changed while permission was pending. Revoke the original permission before allowing again.' });
    } catch { if (!work.superseded && work.epoch === this.epoch) { this.returnedAccess=null; this.update({ uncertain: true, message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the build.' }); } }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async status(): Promise<void> {
    this.syncContext();
    const api = this.original ?? this.api; if (!api || this.work || this.revokeWork) return;
    // A status-only reconnect can observe a previously enabled permission.
    // Keep that exact connection until original Revoke, even after rebinding.
    this.original = api;
    const work: Work<A> = { api, context: this.context, epoch: this.epoch, superseded: false }; this.work = work; this.update({ pending: 'status' });
    try { const result = this.parseAccess(await api.status());
      if (!result) throw new Error('Unconfirmed permission');
      if (this.work === work && !work.superseded && work.epoch === this.epoch) {
        this.observed = Object.freeze({ api, revision: result.permissionRevision });
        this.returnedAccess=Object.freeze({api,context:work.context,epoch:work.epoch,value:result});
        // An earlier acknowledgement (including one made while this read
        // was pending) cannot authorize a newly returned permission origin.
        this.update({ access: result, acknowledged: false, message: null });
      }
    }
    catch { if (!work.superseded && work.epoch === this.epoch) { this.returnedAccess=null; this.update({ message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the build.' }); } }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async revoke(): Promise<void> {
    this.syncContext();
    const api = this.work?.api ?? this.original ?? this.api; if (!api || this.revokeWork) return;
    // Even counter saturation still invokes original Revoke. There is no
    // late Allow display after it and never a new action on an old ACK.
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    if (this.work) this.work.superseded = true;
    const work: Work<A> = { api, context: null, epoch: this.epoch, superseded: false }; this.revokeWork = work; this.returnedAccess=null;
    this.update({ revokePending: true, access: null, acknowledged: false });
    try {
      const result = this.parseAccess(await api.revoke());
      if (!result || result.enabled) throw new Error("Permission remains enabled");
      if (this.revokeWork === work) { this.original = null;
        this.observed = Object.freeze({ api, revision: result.permissionRevision });
        this.returnedAccess=Object.freeze({api,context:work.context,epoch:work.epoch,value:result});
        this.update({ access: result, acknowledged: false, uncertain: false, message: 'Permission stopped. Wait for any running build to finish stopping.' }); }
    } catch { this.original = api; this.update({ uncertain: true, message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the build.' }); }
    finally { if (this.revokeWork === work) { this.revokeWork = null; this.update({ revokePending: false }); } }
  }
}
