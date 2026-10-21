// One named permission, not an execution owner. The ordinary offline-check
// controller displays the same native operation and keeps its original STOP.
import { copyBoundedComparisonData, offlineCounter } from './offlinePreflightProtocol.ts';
export const AGENT_LOCAL_CHECK_CONSENT = 'agent-saved-local-android-checks-v1';
export interface LocalCheckProject { projectId: string; draftRevision: number; baselineGeneration: number }
export interface LocalCheckAccess { enabled: boolean; remainingMs: number; projectId: string | null; observationRevision: number | null; consumed: boolean }
export interface MainLocalCheckAccess extends LocalCheckAccess { readonly permissionRevision: string }
export interface AgentLocalCheckApi {
  status(): Promise<MainLocalCheckAccess>;
  allow(input: LocalCheckProject, expectedPermissionRevision: string): Promise<MainLocalCheckAccess>;
  revoke(): Promise<MainLocalCheckAccess>;
}
type Command = 'agent_local_check_access' | 'allow_agent_local_check' | 'revoke_agent_local_check';
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}$/.test(v) && v !== '0'.repeat(32);
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every((n) => Object.hasOwn(v, n));
const permissionRevision = (v: unknown): v is string => typeof v === 'string' && /^(0|[1-9][0-9]{0,19})$(?![\s\S])/.test(v) &&
  (v.length < 20 || v <= '18446744073709551615');
function project(v: unknown): v is LocalCheckProject {
  return keys(v, ['projectId', 'draftRevision', 'baselineGeneration']) && typeof v.projectId === 'string' &&
    /^[A-Za-z0-9_-]{1,64}$/.test(v.projectId) && offlineCounter(v.draftRevision) && offlineCounter(v.baselineGeneration);
}
function copyProject(value: unknown): LocalCheckProject | null {
  try {
    const safe = copyBoundedComparisonData(value, 1024, 32);
    return project(safe) ? Object.freeze({ projectId: safe.projectId, draftRevision: safe.draftRevision,
      baselineGeneration: safe.baselineGeneration }) : null;
  } catch { return null; }
}
export function parseLocalCheckAccess(value: unknown): LocalCheckAccess | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 32);
    if (!keys(v, ['enabled', 'remainingMs', 'projectId', 'observationRevision', 'consumed']) || typeof v.enabled !== 'boolean' ||
        typeof v.consumed !== 'boolean' || typeof v.remainingMs !== 'number' || !Number.isSafeInteger(v.remainingMs) ||
        v.remainingMs < 0 || v.remainingMs > 900_000 || Object.is(v.remainingMs, -0) ||
        !(v.projectId === null && v.observationRevision === null || id(v.projectId) && typeof v.observationRevision === 'number' &&
          Number.isSafeInteger(v.observationRevision) && v.observationRevision > 0) ||
        v.enabled && (v.remainingMs === 0 || v.consumed || v.projectId === null) || !v.enabled && v.remainingMs !== 0 ||
        v.projectId === null && v.consumed) return null;
    const projectId = typeof v.projectId === 'string' ? v.projectId : null;
    const observationRevision = typeof v.observationRevision === 'number' ? v.observationRevision : null;
    return Object.freeze({ enabled: v.enabled, remainingMs: v.remainingMs, projectId,
      observationRevision, consumed: v.consumed });
  } catch { return null; }
}
// Preserve the five-field service/CLI parser also used by the two Build facades.
export function parseMainLocalCheckAccess(value: unknown): MainLocalCheckAccess | null {
  try {
    const v = copyBoundedComparisonData(value, 1024, 32);
    if (!keys(v, ['enabled', 'remainingMs', 'projectId', 'observationRevision', 'consumed', 'permissionRevision']) || !permissionRevision(v.permissionRevision)) return null;
    const base = parseLocalCheckAccess({ enabled: v.enabled, remainingMs: v.remainingMs, projectId: v.projectId,
      observationRevision: v.observationRevision, consumed: v.consumed });
    return base ? Object.freeze({ ...base, permissionRevision: v.permissionRevision }) : null;
  } catch { return null; }
}
export function encodeLocalCheckAccessRequest(command: Command, value: unknown): Uint8Array | null {
  try {
    const safe = copyBoundedComparisonData(value, 1024, 32);
    if (command === 'allow_agent_local_check') {
      if (!keys(safe, ['projectId', 'draftRevision', 'baselineGeneration', 'consentVersion', 'expectedPermissionRevision']) || !permissionRevision(safe.expectedPermissionRevision) || safe.consentVersion !== AGENT_LOCAL_CHECK_CONSENT ||
          !project({ projectId: safe.projectId, draftRevision: safe.draftRevision, baselineGeneration: safe.baselineGeneration })) return null;
    } else if ((command !== 'agent_local_check_access' && command !== 'revoke_agent_local_check') || !keys(safe, [])) return null;
    return new TextEncoder().encode(JSON.stringify(safe));
  } catch { return null; }
}
const refusal = () => ({ code: 'agent_local_check_unavailable', message: 'Permission was not confirmed. Inspect or revoke it in the original Desktop. No check is proven started or settled by this response.', retryable: false });
export function createAgentLocalCheckApi(mode: string, invoke: Invoke): AgentLocalCheckApi | null {
  if (mode !== 'native') return null;
  const call = (command: Command, value: unknown): Promise<MainLocalCheckAccess> => {
    const bytes = encodeLocalCheckAccessRequest(command, value); if (!bytes) return Promise.reject(refusal());
    try { return invoke<unknown>(command, bytes).then((v) => { const parsed = parseMainLocalCheckAccess(v); if (!parsed) throw refusal(); return parsed; }, () => { throw refusal(); }); }
    catch { return Promise.reject(refusal()); }
  };
  return Object.freeze({ status: () => call('agent_local_check_access', {}),
    allow: (input: LocalCheckProject, expectedPermissionRevision: string) => {
      const safe = copyProject(input); // No spread/getter evaluation before the existing safe copier.
      return safe && permissionRevision(expectedPermissionRevision) ? call('allow_agent_local_check', { ...safe, consentVersion: AGENT_LOCAL_CHECK_CONSENT, expectedPermissionRevision }) : Promise.reject(refusal());
    },
    revoke: () => call('revoke_agent_local_check', {}) });
}
export interface PermissionState { access: MainLocalCheckAccess | null; acknowledged: boolean; pending: 'allow' | 'status' | null; revokePending: boolean; uncertain: boolean; message: string | null }
export interface PermissionContext { api: AgentLocalCheckApi | null; project: LocalCheckProject | null; blocked: boolean }
interface Work { api: AgentLocalCheckApi; epoch: number; context: LocalCheckProject | null; superseded: boolean }
/** App-owned finite UI requests: one read/allow and one independent revoke.
 * Native consent/epoch and original preflight remain authoritative. */
export class AgentLocalCheckPermission {
  private api: AgentLocalCheckApi | null = null;
  private original: AgentLocalCheckApi | null = null;
  private context: LocalCheckProject | null = null;
  private epoch = 0;
  private blocked = false;
  private readonly current: (() => PermissionContext) | null;
  private work: Work | null = null;
  private revokeWork: Work | null = null;
  private listeners = new Set<(state: PermissionState) => void>();
  private observed: { api: AgentLocalCheckApi; context: LocalCheckProject | null; revision: string } | null = null;
  private consent: { api: AgentLocalCheckApi; context: LocalCheckProject; revision: string } | null = null;
  private state: PermissionState = { access: null, acknowledged: false, pending: null, revokePending: false, uncertain: false, message: null };
  constructor(current?: () => PermissionContext) { this.current = current ?? null; }
  getState(): PermissionState { return this.state; }
  subscribe(listener: (state: PermissionState) => void): () => void { this.listeners.add(listener); listener(this.state); return () => { this.listeners.delete(listener); }; }
  private update(value: Partial<PermissionState>): void { this.state = Object.freeze({ ...this.state, ...value }); for (const fn of this.listeners) fn(this.state); }
  bind(api: AgentLocalCheckApi | null, input: LocalCheckProject | null): void {
    const context = input ? copyProject(input) : null;
    if (this.api === api && JSON.stringify(this.context) === JSON.stringify(context)) return;
    this.api = api; this.context = context;
    this.observed = null; this.consent = null;
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
  acknowledge(value: boolean): void {
    this.syncContext();
    const o = this.observed;
    this.consent = value === true && !this.work && !this.revokeWork && !this.blocked && !this.state.uncertain &&
      !!this.api && !!this.context && o?.api === this.api && o.context === this.context && permissionRevision(o.revision)
      ? { api: this.api, context: this.context, revision: o.revision } : null;
    this.update({ acknowledged: !!this.consent, message: value && !this.consent ? 'Check permission first, then confirm one local check for this project.' : null });
  }
  canAllow(): boolean { return !this.blocked && !!this.api && !!this.context && (!this.original || this.original === this.api) && !this.work && !this.revokeWork &&
    !this.state.uncertain && this.state.acknowledged && this.consent?.api === this.api && this.consent?.context === this.context && this.epoch < Number.MAX_SAFE_INTEGER; }
  async allow(): Promise<void> {
    this.syncContext(); // Native invocation uses current event-time selection, not an earlier render/effect.
    if (!this.canAllow()) return;
    const expectedPermissionRevision = this.consent!.revision;
    const api = this.api!, context = this.context!, work: Work = { api, context, epoch: this.epoch, superseded: false };
    this.original = api; this.work = work; this.observed = null; this.consent = null;
    this.update({ pending: 'allow', acknowledged: false, message: null });
    try {
      // Notification is synchronous: a subscriber can revoke or change the
      // current selection before invocation. Do not send a fresh Allow after
      // that original Revoke merely because its eventual ACK would be ignored.
      this.syncContext();
      if (this.work !== work || work.superseded || work.epoch !== this.epoch || this.revokeWork ||
          this.api !== api || this.context !== context || this.blocked) return;
      const result = await api.allow(context, expectedPermissionRevision);
      this.syncContext();
      if (this.work === work && !work.superseded && work.epoch === this.epoch && this.api === api && this.context === context) this.update({ access: result, uncertain: false });
      else if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: 'Selection changed while permission was pending. Revoke the original permission before allowing again.' });
    } catch { if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: refusal().message }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async status(): Promise<void> {
    this.syncContext();
    const api = this.original ?? this.api; if (!api || this.work || this.revokeWork) return;
    this.observed = null; this.consent = null;
    // A status-only reconnect can observe a previously enabled permission.
    // Keep that exact connection until original Revoke, even after rebinding.
    this.original = api;
    const work: Work = { api, context: this.context, epoch: this.epoch, superseded: false }; this.work = work; this.update({ pending: 'status', acknowledged: false });
    try {
      if (this.work !== work || work.superseded || work.epoch !== this.epoch || this.revokeWork) return;
      const result = await api.status();
      if (this.work === work && !work.superseded && work.epoch === this.epoch) {
        this.syncContext();
        // Context synchronization publishes synchronously; a subscriber can
        // revoke right there. Recheck before retaining this Check's stamp.
        if (this.work !== work || work.superseded || work.epoch !== this.epoch || this.revokeWork) return;
        if (!permissionRevision(result.permissionRevision)) throw refusal();
        if (this.api === api && this.context === work.context) this.observed = { api, context: work.context, revision: result.permissionRevision };
        this.update({ access: result, message: null });
      }
    }
    catch { if (!work.superseded && work.epoch === this.epoch) this.update({ message: refusal().message }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async revoke(): Promise<void> {
    this.syncContext();
    const api = this.work?.api ?? this.original ?? this.api; if (!api || this.revokeWork) return;
    // Even counter saturation still invokes original Revoke. There is no
    // late Allow display after it and never a new action on an old ACK.
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    this.observed = null; this.consent = null;
    if (this.work) this.work.superseded = true;
    const work: Work = { api, context: null, epoch: this.epoch, superseded: false }; this.revokeWork = work;
    this.update({ revokePending: true, access: null, acknowledged: false });
    try {
      const result = await api.revoke();
      if (result.enabled) throw refusal();
      if (this.revokeWork === work) { this.original = null; this.update({ access: result, uncertain: false, message: 'Permission revoked; any active check still needs its original cleanup.' }); }
    } catch { this.original = api; this.update({ uncertain: true, message: refusal().message }); }
    finally { if (this.revokeWork === work) { this.revokeWork = null; this.update({ revokePending: false }); } }
  }
}
