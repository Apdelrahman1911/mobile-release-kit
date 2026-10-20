// A single exact-input START permission, separate from reading and local checks.
// The existing Android controller owns display/STOP; this creates no executor.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { copyAndroidBuildRequest } from './androidBuildProtocol.ts';
import { parseAndroidMacToolchainSelection } from './androidToolchainCatalogProtocol.ts';
import { parseLocalCheckAccess } from './agentLocalChecks.ts';
import type { LocalCheckAccess } from './agentLocalChecks.ts';
import type { PrepareAndroidBuild, AndroidMacToolchainSelection } from './androidBuildTypes.ts';
export const AGENT_ANDROID_BUILD_CONSENT = 'agent-saved-android-build-inspect-v1';
const REQUEST_LIMIT = 4096; // Same whole RAW GUI body / service frame limit, not stdin alone.
export interface AndroidBuildApproval { input: PrepareAndroidBuild; toolchainSelection: AndroidMacToolchainSelection }
export type AndroidBuildAccess = LocalCheckAccess; // Same closed DATA shape, not a reusable grant.
export const parseAndroidBuildAccess = parseLocalCheckAccess;
export interface AgentAndroidBuildApi {
  status(): Promise<AndroidBuildAccess>; allow(input: AndroidBuildApproval): Promise<AndroidBuildAccess>; revoke(): Promise<AndroidBuildAccess>;
}
type Command = 'agent_android_build_access' | 'allow_agent_android_build' | 'revoke_agent_android_build';
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every((n) => Object.hasOwn(v, n));
export function copyAndroidBuildApproval(value: unknown): AndroidBuildApproval | null {
  try {
    const v = copyBoundedComparisonData(value, REQUEST_LIMIT, 160);
    if (!keys(v, ['input', 'toolchainSelection'])) return null;
    const input = copyAndroidBuildRequest('prepare_android_build', v.input) as PrepareAndroidBuild | null;
    const selected = parseAndroidMacToolchainSelection(v.toolchainSelection);
    if (!input || input.signing !== undefined || input.operation !== undefined || input.action !== undefined ||
      input.artifactValidation.mode !== 'structure-and-version' || input.artifactValidation.uploadCertificateSha256 !== null || !selected) return null;
    Object.freeze(input.savedConfig); Object.freeze(input.savedVersion); Object.freeze(input.artifactValidation);
    return Object.freeze({ input: Object.freeze(input), toolchainSelection: Object.freeze(selected) });
  } catch { return null; }
}
export function encodeAndroidBuildAccessRequest(command: Command, value: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(value, REQUEST_LIMIT, 160);
    if (command === 'allow_agent_android_build') {
      if (!keys(v, ['input', 'toolchainSelection', 'consentVersion']) || v.consentVersion !== AGENT_ANDROID_BUILD_CONSENT ||
          !copyAndroidBuildApproval({ input: v.input, toolchainSelection: v.toolchainSelection })) return null;
    } else if ((command !== 'agent_android_build_access' && command !== 'revoke_agent_android_build') || !keys(v, [])) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length <= REQUEST_LIMIT ? bytes : null;
  } catch { return null; }
}
const refusal = () => ({ code: 'agent_android_build_unavailable', message: 'Permission was not confirmed. Inspect or revoke it in the original Desktop. This response proves neither build admission nor cleanup.', retryable: false });
export function createAgentAndroidBuildApi(mode: string, invoke: Invoke): AgentAndroidBuildApi | null {
  if (mode !== 'native') return null;
  const call = (command: Command, value: unknown): Promise<AndroidBuildAccess> => {
    const bytes = encodeAndroidBuildAccessRequest(command, value); if (!bytes) return Promise.reject(refusal());
    try { return invoke<unknown>(command, bytes).then((v) => { const parsed = parseAndroidBuildAccess(v); if (!parsed) throw refusal(); return parsed; }, () => { throw refusal(); }); }
    catch { return Promise.reject(refusal()); }
  };
  return Object.freeze({ status: () => call('agent_android_build_access', {}),
    allow: (input: AndroidBuildApproval) => { const safe = copyAndroidBuildApproval(input); return safe ? call('allow_agent_android_build', { ...safe, consentVersion: AGENT_ANDROID_BUILD_CONSENT }) : Promise.reject(refusal()); },
    revoke: () => call('revoke_agent_android_build', {}) });
}
export interface PermissionState { access: AndroidBuildAccess | null; acknowledged: boolean; pending: 'allow' | 'status' | null; revokePending: boolean; uncertain: boolean; message: string | null }
export interface PermissionContext { api: AgentAndroidBuildApi | null; project: AndroidBuildApproval | null; blocked: boolean }
interface Work { api: AgentAndroidBuildApi; epoch: number; context: AndroidBuildApproval | null; superseded: boolean }
/** App-owned finite UI requests: one read/allow and one independent revoke.
 * Native consent/epoch and original Android owner remain authoritative. */
export class AgentAndroidBuildPermission {
  private api: AgentAndroidBuildApi | null = null;
  private original: AgentAndroidBuildApi | null = null;
  private context: AndroidBuildApproval | null = null;
  private epoch = 0;
  private blocked = false;
  private readonly current: (() => PermissionContext) | null;
  private work: Work | null = null;
  private revokeWork: Work | null = null;
  private listeners = new Set<(state: PermissionState) => void>();
  private state: PermissionState = { access: null, acknowledged: false, pending: null, revokePending: false, uncertain: false, message: null };
  constructor(current?: () => PermissionContext) { this.current = current ?? null; }
  getState(): PermissionState { return this.state; }
  subscribe(listener: (state: PermissionState) => void): () => void { this.listeners.add(listener); listener(this.state); return () => { this.listeners.delete(listener); }; }
  private update(value: Partial<PermissionState>): void { this.state = Object.freeze({ ...this.state, ...value }); for (const fn of this.listeners) fn(this.state); }
  bind(api: AgentAndroidBuildApi | null, input: AndroidBuildApproval | null): void {
    const context = input ? copyAndroidBuildApproval(input) : null;
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
    const api = this.api!, context = this.context!, work: Work = { api, context, epoch: this.epoch, superseded: false };
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
    } catch { if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: refusal().message }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async status(): Promise<void> {
    this.syncContext();
    const api = this.original ?? this.api; if (!api || this.work || this.revokeWork) return;
    // A status-only reconnect can observe a previously enabled permission.
    // Keep that exact connection until original Revoke, even after rebinding.
    this.original = api;
    const work: Work = { api, context: this.context, epoch: this.epoch, superseded: false }; this.work = work; this.update({ pending: 'status' });
    try { const result = await api.status(); if (!work.superseded && work.epoch === this.epoch) this.update({ access: result, message: null }); }
    catch { if (!work.superseded && work.epoch === this.epoch) this.update({ message: refusal().message }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async revoke(): Promise<void> {
    this.syncContext();
    const api = this.work?.api ?? this.original ?? this.api; if (!api || this.revokeWork) return;
    // Even counter saturation still invokes original Revoke. There is no
    // late Allow display after it and never a new action on an old ACK.
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    if (this.work) this.work.superseded = true;
    const work: Work = { api, context: null, epoch: this.epoch, superseded: false }; this.revokeWork = work;
    this.update({ revokePending: true, access: null, acknowledged: false });
    try {
      const result = await api.revoke();
      if (result.enabled) throw refusal();
      if (this.revokeWork === work) { this.original = null; this.update({ access: result, uncertain: false, message: 'Permission revoked; any active build still needs its original cleanup.' }); }
    } catch { this.original = api; this.update({ uncertain: true, message: refusal().message }); }
    finally { if (this.revokeWork === work) { this.revokeWork = null; this.update({ revokePending: false }); } }
  }
}
