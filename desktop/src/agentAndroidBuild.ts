import { BuildPermission } from './agentBuildPermission.ts';
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
export type PermissionContext = import('./agentBuildPermission.ts').PermissionContext<AndroidBuildApproval>;
export type { PermissionState } from './agentBuildPermission.ts';
export class AgentAndroidBuildPermission extends BuildPermission<AndroidBuildApproval> {
  constructor(current?:()=>PermissionContext){super(copyAndroidBuildApproval,current);}
}
