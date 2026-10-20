// Shared finite UI promise bookkeeping, not native permission/execution.
// Only the two fixed family wrappers supply descriptor-safe comparison copying;
// native codecs/Inbox independently enforce the exact family at each boundary.
import type { LocalCheckAccess } from './agentLocalChecks.ts';
export interface PermissionApi<A> {status():Promise<LocalCheckAccess>;allow(input:A):Promise<LocalCheckAccess>;revoke():Promise<LocalCheckAccess>}
export interface PermissionState { access: LocalCheckAccess | null; acknowledged: boolean; pending: 'allow' | 'status' | null; revokePending: boolean; uncertain: boolean; message: string | null }
export interface PermissionContext<A> { api: PermissionApi<A> | null; project: A | null; blocked: boolean }
interface Work<A> { api: PermissionApi<A>; epoch: number; context: A | null; superseded: boolean }
/** App-owned finite UI requests: one read/allow and one independent revoke.
 * Native consent/epoch and original native owner remain authoritative. */
export class BuildPermission<A> {
  private readonly copy:(value:unknown)=>A|null;
  private api: PermissionApi<A> | null = null;
  private original: PermissionApi<A> | null = null;
  private context: A | null = null;
  private epoch = 0;
  private blocked = false;
  private readonly current: (() => PermissionContext<A>) | null;
  private work: Work<A> | null = null;
  private revokeWork: Work<A> | null = null;
  private listeners = new Set<(state: PermissionState) => void>();
  private state: PermissionState = { access: null, acknowledged: false, pending: null, revokePending: false, uncertain: false, message: null };
  constructor(copy: (value:unknown)=>A|null,current?:()=>PermissionContext<A>) {this.copy=copy;this.current=current??null;}
  getState(): PermissionState { return this.state; }
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
    !this.state.uncertain && this.state.acknowledged && this.epoch < Number.MAX_SAFE_INTEGER; }
  async allow(): Promise<void> {
    this.syncContext(); // Native invocation uses current event-time selection, not an earlier render/effect.
    if (!this.canAllow()) return;
    const api = this.api!, context = this.context!, work: Work<A> = { api, context, epoch: this.epoch, superseded: false };
    this.original = api; this.work = work; this.update({ pending: 'allow', acknowledged: false, message: null });
    try {
      // Notification is synchronous: a subscriber can revoke or change the
      // current selection before invocation. Do not send a fresh Allow after
      // that original Revoke merely because its eventual ACK would be ignored.
      this.syncContext();
      if (this.work !== work || work.superseded || work.epoch !== this.epoch || this.revokeWork ||
          this.api !== api || this.context !== context || this.blocked) return;
      const result = await api.allow(context);
      if (this.work === work && !work.superseded && work.epoch === this.epoch && this.api === api && this.context === context) this.update({ access: result, uncertain: false });
      else if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: 'Selection changed while permission was pending. Revoke the original permission before allowing again.' });
    } catch { if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the build.' }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async status(): Promise<void> {
    this.syncContext();
    const api = this.original ?? this.api; if (!api || this.work || this.revokeWork) return;
    // A status-only reconnect can observe a previously enabled permission.
    // Keep that exact connection until original Revoke, even after rebinding.
    this.original = api;
    const work: Work<A> = { api, context: this.context, epoch: this.epoch, superseded: false }; this.work = work; this.update({ pending: 'status' });
    try { const result = await api.status(); if (!work.superseded && work.epoch === this.epoch) this.update({ access: result, message: null }); }
    catch { if (!work.superseded && work.epoch === this.epoch) this.update({ message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the build.' }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async revoke(): Promise<void> {
    this.syncContext();
    const api = this.work?.api ?? this.original ?? this.api; if (!api || this.revokeWork) return;
    // Even counter saturation still invokes original Revoke. There is no
    // late Allow display after it and never a new action on an old ACK.
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    if (this.work) this.work.superseded = true;
    const work: Work<A> = { api, context: null, epoch: this.epoch, superseded: false }; this.revokeWork = work;
    this.update({ revokePending: true, access: null, acknowledged: false });
    try {
      const result = await api.revoke();
      if (result.enabled) throw new Error("Permission remains enabled");
      if (this.revokeWork === work) { this.original = null; this.update({ access: result, uncertain: false, message: 'Permission stopped. Wait for any running build to finish stopping.' }); }
    } catch { this.original = api; this.update({ uncertain: true, message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the build.' }); }
    finally { if (this.revokeWork === work) { this.revokeWork = null; this.update({ revokePending: false }); } }
  }
}
