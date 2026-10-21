// Bounded public session-only OAuth DATA. Private device codes/tokens never
// cross this interface. Only existing Connection observations verify an account.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionOpaqueId as id, connectionRepository as repository,
  connectionRevision, parseGitHubConnectionStatus } from './githubConnectionProtocol.ts';
import type { GitHubConnectionObservationPort, GitHubConnectionReason, GitHubConnectionStatus } from './githubConnectionTypes.ts';
export const DEVICE_CONSENT = 'github-device-session-repo-v1';
export const DEVICE_URI = 'https://github.com/login/device';
export type DevicePhase = 'idle' | 'starting' | 'pending' | 'checking' | 'connecting' | 'stopping' | 'settled' | 'failed' | 'cleanup-unknown';
export type DeviceReason = 'none' | 'publisher-unconfigured' | 'runtime-unavailable' | 'busy' | 'target-changed' | 'waiting' | 'slow-down' |
  'denied' | 'expired' | 'client-refused' | 'response-invalid' | 'cancelled' | 'cleanup-unknown';
export interface DeviceStatus {
  schemaVersion: 1; documentRevision: number; connectionRevision: number; available: boolean;
  operationId: string | null; projectId: string | null; repository: string | null; revision: number; phase: DevicePhase; reason: DeviceReason;
  code: { userCode: string; verificationUri: typeof DEVICE_URI; remainingSeconds: number; checkAfterSeconds: number } | null;
  http: { sessionId: string; operationId: string } | null;
}
export interface DeviceStart { projectId: string; repository: string; expectedDocumentRevision: number; expectedConnectionRevision: number; consentVersion: typeof DEVICE_CONSENT }
export interface DeviceSelected { operationId: string; revision: number }
export type DeviceCommand = 'github_device_status' | 'github_device_start' | 'github_device_check' | 'github_device_open' | 'github_device_cancel';
export interface GitHubDeviceApi { readonly mode: 'native'; status(): Promise<unknown>; start(value: DeviceStart): Promise<unknown>;
  check(value: DeviceSelected): Promise<unknown>; open(value: DeviceSelected): Promise<unknown>; cancel(value: { operationId: string }): Promise<unknown> }
export interface DeviceCompletion { device: DeviceStatus; connection: GitHubConnectionStatus | null }
export interface DeviceHandoff { port: GitHubConnectionObservationPort; submit(request: DeviceStart): Promise<unknown> }
const phases: readonly string[] = ['idle','starting','pending','checking','connecting','stopping','settled','failed','cleanup-unknown'];
const reasons: readonly string[] = ['none','publisher-unconfigured','runtime-unavailable','busy','target-changed','waiting','slow-down','denied','expired','client-refused','response-invalid','cancelled','cleanup-unknown'];
const revision = (v: unknown): v is number => connectionRevision(v) && v < 0xffff_ffff;
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= max;
export const deviceTerminal = (s: DeviceStatus): boolean => ['settled','failed','cleanup-unknown'].includes(s.phase);
export function parseDeviceStart(value: unknown): DeviceStart | null {
  try { const v = copyBoundedComparisonData(value,1024,16); return keys(v,['projectId','repository','expectedDocumentRevision','expectedConnectionRevision','consentVersion']) &&
    id(v.projectId) && repository(v.repository) && revision(v.expectedDocumentRevision) && revision(v.expectedConnectionRevision) && v.consentVersion === DEVICE_CONSENT ? v as unknown as DeviceStart : null;
  } catch { return null; }
}
export function parseDeviceStatus(value: unknown): DeviceStatus | null {
  try {
    const v = copyBoundedComparisonData(value,8192,64);
    if (!keys(v,['schemaVersion','documentRevision','connectionRevision','available','operationId','projectId','repository','revision','phase','reason','code','http']) ||
      v.schemaVersion !== 1 || !connectionRevision(v.documentRevision) || !connectionRevision(v.connectionRevision) || !revision(v.revision) ||
      typeof v.available !== 'boolean' || typeof v.phase !== 'string' || !phases.includes(v.phase) || typeof v.reason !== 'string' || !reasons.includes(v.reason)) return null;
    if (v.phase === 'idle') return [v.operationId,v.projectId,v.repository,v.code,v.http].every((x) => x === null) &&
      (v.available ? v.reason === 'none' : ['publisher-unconfigured','runtime-unavailable'].includes(v.reason)) ? v as unknown as DeviceStatus : null;
    if (!id(v.operationId) || !id(v.projectId) || !repository(v.repository)) return null;
    if (v.http !== null && (!keys(v.http,['sessionId','operationId']) || !id(v.http.sessionId) || !id(v.http.operationId))) return null;
    if (v.code !== null && (!keys(v.code,['userCode','verificationUri','remainingSeconds','checkAfterSeconds']) ||
      typeof v.code.userCode !== 'string' || !/^[A-Z0-9]{4}-[A-Z0-9]{4}$(?![\s\S])/.test(v.code.userCode) || v.code.verificationUri !== DEVICE_URI ||
      !integer(v.code.remainingSeconds,600) || !integer(v.code.checkAfterSeconds,1500) || !['pending','checking'].includes(v.phase) || v.http !== null)) return null;
    if (v.phase === 'cleanup-unknown' ? v.reason !== 'cleanup-unknown' || v.code !== null : v.reason === 'cleanup-unknown') return null;
    if (v.phase === 'pending' && (!v.code || !['waiting','slow-down'].includes(v.reason))) return null;
    if (v.phase === 'stopping' && (['none','waiting','slow-down'].includes(v.reason) || v.code !== null)) return null;
    if (['starting','checking','connecting'].includes(v.phase) && ['waiting','slow-down'].includes(v.reason)) return null;
    if (v.phase === 'starting' && v.http !== null || ['settled','failed','connecting'].includes(v.phase) && v.code !== null) return null;
    if (v.phase === 'settled' && (v.reason !== 'none' || !v.http) || v.phase === 'failed' && v.reason === 'none') return null;
    return v as unknown as DeviceStatus;
  } catch { return null; }
}
export function encodeDeviceRequest(command: DeviceCommand,value: unknown): Uint8Array | null {
  try { const v = command === 'github_device_start' ? parseDeviceStart(value) : copyBoundedComparisonData(value,1024,12);
    if (!(command === 'github_device_start' ? v !== null : command === 'github_device_status' ? keys(v,[]) :
      command === 'github_device_cancel' ? keys(v,['operationId']) && id(v.operationId) :
      ['github_device_check','github_device_open'].includes(command) && keys(v,['operationId','revision']) && id(v.operationId) && revision(v.revision))) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length + command.length + 32 <= 1024 ? bytes : null;
  } catch { return null; }
}
export function createGitHubDeviceApi(mode: string,invoke: (name: DeviceCommand,bytes: Uint8Array) => Promise<unknown>): GitHubDeviceApi | null {
  if (mode !== 'native') return null;
  const call = (name: DeviceCommand,value: unknown) => { const bytes = encodeDeviceRequest(name,value);
    if (!bytes) throw {code:'invalid_request'}; return invoke(name,bytes); };
  return Object.freeze({mode:'native' as const,status:()=>call('github_device_status',{}),start:(v:DeviceStart)=>call('github_device_start',v),
    check:(v:DeviceSelected)=>call('github_device_check',v),open:(v:DeviceSelected)=>call('github_device_open',v),cancel:(v:{operationId:string})=>call('github_device_cancel',v)});
}
// These Start errors occur BEFORE installing OriginalWork. Never applied to a
// Check/Cancel or to lost/generic invoke errors; no renderer admission Boolean.
export function deviceStartFailure(error: unknown): {notAdmitted:boolean;reason:GitHubConnectionReason;code:string|null} {
  const closed: Record<string,GitHubConnectionReason> = {device_unconfigured:'publisher-unconfigured',runtime_unavailable:'runtime-unavailable',invalid_request:'invalid-input',
    device_stale:'target-changed',busy:'busy',github_connection_refused_unqualified:'unqualified',github_connection_refused_busy:'busy',
    github_connection_refused_runtime_unavailable:'runtime-unavailable',github_connection_refused_cancelled:'cancelled'};
  try { const p = error && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error,'code') : null;
    if (p && Object.hasOwn(p,'value') && typeof p.value === 'string' && Object.hasOwn(closed,p.value)) return {notAdmitted:true,reason:closed[p.value]!,code:p.value};
  } catch { /* No private error text. */ }
  return {notAdmitted:false,reason:'response-invalid',code:null};
}
export function deviceConnectionReason(reason: DeviceReason): GitHubConnectionReason {
  return reason === 'denied' ? 'unauthorized' : reason === 'client-refused' ? 'publisher-unconfigured' :
    reason === 'waiting' || reason === 'slow-down' ? 'busy' : reason;
}
export function parseDeviceCompletion(value: unknown): DeviceCompletion | null {
  try { const v = copyBoundedComparisonData(value,73728,4096); if (!keys(v,['device','connection'])) return null;
    const d = parseDeviceStatus(v.device); if (!d || !['failed','settled'].includes(d.phase)) return null;
    if (!d.http) return d.phase === 'failed' && v.connection === null ? {device:d,connection:null} : null;
    const c = parseGitHubConnectionStatus(v.connection);
    return c?.session?.id === d.http.sessionId && c.operation?.id === d.http.operationId && c.operation.kind === 'connect' &&
      c.operation.phase === 'settled' && c.session.projectId === d.projectId && c.session.targetRepository === d.repository && c.session.state !== 'cleanup-unknown'
      ? {device:d,connection:c} : null;
  } catch { return null; }
}
