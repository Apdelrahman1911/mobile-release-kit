import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { reserveId, reserveProject } from './versionReserve.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';

// Permission and comparison DATA only. No private input or native credential
// capability is transported by this panel or by the installed CLI.
export type AgentUploadKeyKind = 'generate-new' | 'bind-reviewed';
export type AgentUploadKeySelection =
  | { readonly kind: 'generate-new'; readonly declaration: 'new-application-no-existing-upload-key' }
  | { readonly kind: 'bind-reviewed'; readonly previewOperationId: number; readonly previewToken: string };
export interface AgentUploadKeyAccess {
  readonly schemaVersion: 1;
  readonly serviceInstance: string | null;
  readonly projectId: string | null; // Service ID, not the runtime project ID.
  readonly grantId: string | null;
  readonly kind: AgentUploadKeyKind | null;
  readonly requestId: string | null;
  readonly enabled: boolean;
  readonly remainingMs: number;
  readonly consumed: boolean;
}
export interface AgentUploadKeyAllow {
  readonly projectId: string;
  readonly consentId: string;
  readonly contextRevision: number;
  readonly expectedStatusRevision: number;
  readonly selection: AgentUploadKeySelection;
}
export interface AgentUploadKeyAccessPort {
  status(): Promise<unknown>;
  allow(input: AgentUploadKeyAllow): Promise<unknown>;
  revoke(consentId: string): Promise<unknown>;
}
export const AGENT_UPLOAD_KEY_MAX_MS = 300_000;
export const AGENT_UPLOAD_KEY_DECLARATION = 'new-application-no-existing-upload-key' as const;
export const agentUploadKeyConsent = (kind: AgentUploadKeyKind): string => kind === 'generate-new'
  ? 'agent-android-upload-key-generate-once-v1' : 'agent-android-upload-key-bind-once-v1';
const fields = ['schemaVersion', 'serviceInstance', 'projectId', 'grantId', 'kind', 'requestId', 'enabled', 'remainingMs', 'consumed'];
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
export const uploadKeyRevision = (v: unknown): v is number => integer(v, 0xffff_fffe) && v > 0;
const kind = (v: unknown): v is AgentUploadKeyKind => v === 'generate-new' || v === 'bind-reviewed';

export function parseAgentUploadKeyAccess(raw: unknown): AgentUploadKeyAccess | null {
  try {
    const v = copyBoundedComparisonData(raw, 4096, 32);
    if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== fields.length || !fields.every((k) => Object.hasOwn(v, k))) return null;
    const d = v as Record<string, unknown>;
    if (d.schemaVersion !== 1 || typeof d.enabled !== 'boolean' || typeof d.consumed !== 'boolean' ||
        !integer(d.remainingMs, AGENT_UPLOAD_KEY_MAX_MS) || !(d.requestId === null || reserveId(d.requestId)) ||
        d.consumed !== (d.requestId !== null) || d.enabled && (d.consumed || d.remainingMs === 0) || !d.enabled && d.remainingMs !== 0) return null;
    if (d.grantId === null) {
      if (d.serviceInstance !== null || d.projectId !== null || d.kind !== null || d.enabled || d.consumed || d.requestId !== null) return null;
      return Object.freeze({ schemaVersion: 1, serviceInstance: null, projectId: null, grantId: null, kind: null,
        requestId: null, enabled: false, remainingMs: 0, consumed: false });
    }
    if (!reserveId(d.serviceInstance) || !reserveId(d.projectId) || !reserveId(d.grantId) || !kind(d.kind)) return null;
    return Object.freeze({ schemaVersion: 1, serviceInstance: d.serviceInstance, projectId: d.projectId, grantId: d.grantId,
      kind: d.kind, requestId: d.requestId, enabled: d.enabled, remainingMs: d.remainingMs, consumed: d.consumed });
  } catch { return null; }
}
export function parseAgentUploadKeySelection(raw: unknown): AgentUploadKeySelection | null {
  try {
    const v = copyBoundedComparisonData(raw, 256, 8);
    if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
    const d = v as Record<string, unknown>, keys = Object.keys(d);
    if (keys.length === 2 && d.kind === 'generate-new' && d.declaration === AGENT_UPLOAD_KEY_DECLARATION)
      return Object.freeze({ kind: 'generate-new', declaration: AGENT_UPLOAD_KEY_DECLARATION });
    if (keys.length === 3 && d.kind === 'bind-reviewed' && uploadKeyRevision(d.previewOperationId) && reserveId(d.previewToken))
      return Object.freeze({ kind: 'bind-reviewed', previewOperationId: d.previewOperationId, previewToken: d.previewToken });
    return null;
  } catch { return null; }
}
export function createAgentUploadKeyAccessPort(invoke: (command: string, body: Uint8Array) => Promise<unknown>): AgentUploadKeyAccessPort {
  const invalid = () => Promise.reject({ code: 'cli_access_invalid_request' });
  const send = (command: string, body: object): Promise<unknown> => {
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    return bytes.length + 96 <= 1024 ? invoke(command, bytes) : invalid();
  };
  return Object.freeze({
    status: () => send('agent_upload_key_access', {}),
    allow: (input: AgentUploadKeyAllow) => {
      const selection = parseAgentUploadKeySelection(input.selection);
      return reserveProject(input.projectId) && reserveId(input.consentId) && uploadKeyRevision(input.contextRevision) &&
        uploadKeyRevision(input.expectedStatusRevision) && selection ? send('allow_agent_upload_key', {
          projectId: input.projectId, consentId: input.consentId, contextRevision: input.contextRevision,
          expectedStatusRevision: input.expectedStatusRevision, selection, consentVersion: agentUploadKeyConsent(selection.kind),
        }) : invalid();
    },
    revoke: (consentId: string) => reserveId(consentId) ? send('revoke_agent_upload_key', { consentId }) : invalid(),
  });
}

// This helper is a UI admission hint over the SAME Asset controller's actual
// joined preview. Native Allow/consume still capture/recheck the private full
// StoredRef, OriginalWork, source and assessment; this is not a Bind factory.
export function agentUploadKeySelection(assets: AssetDisplayState, selected: AgentUploadKeyKind, generateReady: boolean, now: number): AgentUploadKeySelection | null {
  const s = assets.status, c = s?.context;
  if (!Number.isFinite(now) || now < 0 || assets.mode !== 'native' || assets.blocked || assets.observationFailed || !assets.contextCurrent ||
      assets.busy || assets.updatingContext || assets.originPending || !s || s.mode !== 'encrypted' ||
      s.persistence?.state !== 'unlocked' || s.persistence.keyAccess !== 'read-write' || c?.platform !== 'android' || c.executionMode !== 'local' ||
      !uploadKeyRevision(c.revision) || !uploadKeyRevision(s.statusRevision)) return null;
  const o = s.operation;
  if (selected === 'generate-new') return generateReady && (!o || o.phase === 'idle' && o.settlement === 'known') &&
    !s.records.some((r) => r.kind === 'android-keystore') ? Object.freeze({ kind: selected, declaration: AGENT_UPLOAD_KEY_DECLARATION }) : null;
  const p = o?.preview, subject = p?.subject, i = assets.intent;
  if (!o || o.phase !== 'preview' || o.reason !== 'none' || o.settlement !== 'known' || !assets.reviewReady ||
      assets.previewDeadline === null || now >= assets.previewDeadline || p?.action !== 'bind' ||
      subject?.type !== 'record' || subject.kind !== 'android-keystore' || subject.change !== 'assign' ||
      !reserveId(subject.recordId) || !uploadKeyRevision(subject.recordRevision) ||
      i?.type !== 'record' || i.kind !== 'android-keystore' || i.change !== 'assign' ||
      i.record?.recordId !== subject.recordId || i.record.expectedRevision !== subject.recordRevision ||
      !reserveId(p.token) || !uploadKeyRevision(o.operationId)) return null;
  const rows = s.records.filter((r) => r.recordId === subject.recordId && r.revision === subject.recordRevision && r.kind === 'android-keystore' &&
    r.storage === 'encrypted' && r.availability !== 'mutation-pending' && r.payloadState === 'assessed');
  return rows.length === 1 ? Object.freeze({ kind: selected, previewOperationId: o.operationId, previewToken: p.token }) : null;
}
export function agentUploadKeyCommands(access: AgentUploadKeyAccess): readonly string[] {
  const a = parseAgentUploadKeyAccess(access);
  if (!a?.grantId) return [];
  const origin = `${a.projectId} ${a.serviceInstance}`;
  return a.requestId ? [`mrk upload-key-status ${origin} ${a.requestId} --json`, `mrk upload-key-cancel ${origin} ${a.requestId} --json`] :
    a.enabled ? [`mrk upload-key-submit ${origin} ${a.grantId} --reviewed --json`] : [];
}
