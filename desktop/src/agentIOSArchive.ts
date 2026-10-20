import { BuildPermission } from './agentBuildPermission.ts';
// A single exact-input START permission, separate from reading and local checks.
// The existing iOS controller owns display/STOP; this creates no executor.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { copyIOSArchiveRequest } from './iosArchiveProtocol.ts';
import { parseLocalCheckAccess } from './agentLocalChecks.ts';
import type { LocalCheckAccess } from './agentLocalChecks.ts';
import type { PrepareIOSBuild } from './iosArchiveTypes.ts';
export const AGENT_IOS_ARCHIVE_CONSENT = 'agent-saved-ios-unsigned-archive-v1';
const REQUEST_LIMIT = 4096; // Same whole RAW GUI body / service frame limit, not stdin alone.
export interface IOSArchiveApproval { input: PrepareIOSBuild }
export type IOSArchiveAccess = LocalCheckAccess; // Same closed DATA shape, not a reusable grant.
export const parseIOSArchiveAccess = parseLocalCheckAccess;
export interface AgentIOSArchiveApi {
  status(): Promise<IOSArchiveAccess>; allow(input: IOSArchiveApproval): Promise<IOSArchiveAccess>; revoke(): Promise<IOSArchiveAccess>;
}
type Command = 'agent_ios_archive_access' | 'allow_agent_ios_archive' | 'revoke_agent_ios_archive';
type Invoke = <T>(command: string, input?: Record<string, unknown> | Uint8Array) => Promise<T>;
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: string[]): v is Record<string, unknown> => record(v) && Object.keys(v).length === names.length && names.every((n) => Object.hasOwn(v, n));
export function copyIOSArchiveApproval(value: unknown): IOSArchiveApproval | null {
  try {
    const v = copyBoundedComparisonData(value, REQUEST_LIMIT, 160);
    if (!keys(v, ['input'])) return null;
    const input = copyIOSArchiveRequest('prepare_ios_archive', v.input) as PrepareIOSBuild | null;
    if (!input || 'recovery' in input || input.signing !== undefined || input.action !== undefined) return null;
    Object.freeze(input.savedConfig); Object.freeze(input.savedVersion);
    return Object.freeze({input:Object.freeze(input)});
  } catch { return null; }
}
export function encodeIOSArchiveAccessRequest(command: Command, value: unknown): Uint8Array | null {
  try {
    const v = copyBoundedComparisonData(value, REQUEST_LIMIT, 160);
    if (command === 'allow_agent_ios_archive') {
      if (!keys(v, ['input', 'consentVersion']) || v.consentVersion !== AGENT_IOS_ARCHIVE_CONSENT ||
          !copyIOSArchiveApproval({ input: v.input })) return null;
    } else if ((command !== 'agent_ios_archive_access' && command !== 'revoke_agent_ios_archive') || !keys(v, [])) return null;
    const bytes = new TextEncoder().encode(JSON.stringify(v)); return bytes.length <= REQUEST_LIMIT ? bytes : null;
  } catch { return null; }
}
const refusal = () => ({ code: 'agent_ios_archive_unavailable', message: 'Permission was not confirmed. Inspect or revoke it in the original Desktop. This response proves neither build admission nor cleanup.', retryable: false });
export function createAgentIOSArchiveApi(mode: string, invoke: Invoke): AgentIOSArchiveApi | null {
  if (mode !== 'native') return null;
  const call = (command: Command, value: unknown): Promise<IOSArchiveAccess> => {
    const bytes = encodeIOSArchiveAccessRequest(command, value); if (!bytes) return Promise.reject(refusal());
    try { return invoke<unknown>(command, bytes).then((v) => { const parsed = parseIOSArchiveAccess(v); if (!parsed) throw refusal(); return parsed; }, () => { throw refusal(); }); }
    catch { return Promise.reject(refusal()); }
  };
  return Object.freeze({ status: () => call('agent_ios_archive_access', {}),
    allow: (input: IOSArchiveApproval) => { const safe = copyIOSArchiveApproval(input); return safe ? call('allow_agent_ios_archive', { ...safe, consentVersion: AGENT_IOS_ARCHIVE_CONSENT }) : Promise.reject(refusal()); },
    revoke: () => call('revoke_agent_ios_archive', {}) });
}
export type PermissionContext=import('./agentBuildPermission.ts').PermissionContext<IOSArchiveApproval>;
export type {PermissionState} from './agentBuildPermission.ts';
export class AgentIOSArchivePermission extends BuildPermission<IOSArchiveApproval>{
  constructor(current?:()=>PermissionContext){super(copyIOSArchiveApproval,current);}
}
