import type { ApiError, BridgeMode, HelpContent } from './types.ts';
import type { LifecycleEvidenceStatus, EvidenceStage } from './lifecycleEvidence.ts';

export const EVIDENCE_ASSURANCE = 'Local document consistency; provenance and artifact bytes unverified.';
const roles = ['android-aab', 'android-mapping', 'android-native-symbols', 'ios-ipa', 'ios-archive', 'ios-dsyms', 'store-metadata', 'validation-report'] as const;
export type EvidenceProblem = 'unavailable' | 'busy' | 'cancelled' | 'stale_selection' | 'unsafe_selection' | 'observation_failed' | 'limit' | 'deadline' | 'cleanup_unknown';
export type EvidencePhase = 'idle' | 'choosing' | 'selected' | 'observing' | 'observed' | 'stopping' | 'cancelled' | 'refused' | 'unknown';
export interface CandidateEvidence {
  schemaVersion: 1; outcome: 'consistent' | 'incomplete' | 'invalid' | 'inconsistent';
  documents: { kind: 'manifest' | 'receipt' | 'intent'; state: 'missing' | 'invalid' | 'valid' }[];
  summary: null | {
    platform: 'android' | 'ios'; applicationId: string; version: { marketing: string; build: number };
    source: { commit: string; tree: string };
    artifacts: { logicalName: typeof roles[number]; declaredBytes: string; sha256: string }[];
    recordedRuns: { authorizedBy: RecordedRun; executedBy: RecordedRun; producedBy: RecordedRun };
    documentPayloadSha256: { manifest: string; receipt: string; intent: string };
  };
  assurance: {
    level: 'local-document-consistency'; documentsOnly: true; artifactBytesVerified: false; workflowAuthenticated: false;
    storeStateObserved: false; comparedWithSourceProject: false; releaseReady: false; recoveryAuthorized: false;
  };
}
interface RecordedRun { runId: string; attempt: string }
export interface EvidenceSelection { selectionId: string; displayName: string }
export interface EvidenceOperation { operationId: string; kind: 'choose' | 'observe'; selectionId: string | null }
export interface EvidenceStatus {
  schemaVersion: 1; revision: string; availability: 'available' | 'unavailable'; phase: EvidencePhase;
  selection: EvidenceSelection | null; operation: EvidenceOperation | null; result: CandidateEvidence | null; problem: EvidenceProblem | null;
}
export interface CandidateEvidenceApi {
  chooseEvidenceFolder(): Promise<EvidenceStatus>;
  evidenceStatus(): Promise<EvidenceStatus>;
  observeEvidence(selectionId: string): Promise<EvidenceStatus>;
  cancelEvidence(operationId: string, selectionId: string | null): Promise<EvidenceStatus>;
}
export type EvidenceCommand = 'artifact_evidence_choose' | 'artifact_evidence_status' | 'artifact_evidence_observe' | 'artifact_evidence_cancel';
type ObjectValue = Record<string, unknown>;
const encoder = new TextEncoder();

// Bounded, own-data-only copy BEFORE serialization, getters or validators. No
// raw DTO/rejection object survives in the application model.
function clean(value: unknown): unknown {
  let nodes = 0;
  function visit(item: unknown, depth: number): unknown {
    if (++nodes > 2048 || depth > 8) throw 0;
    if (item === null || typeof item === 'boolean') return item;
    if (typeof item === 'string') { if (item.length > 65536) throw 0; return item; }
    if (typeof item === 'number') { if (!Number.isSafeInteger(item)) throw 0; return item; }
    if (typeof item !== 'object') throw 0;
    const array = Array.isArray(item); const prototype: unknown = Object.getPrototypeOf(item);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) throw 0;
    const keys = Reflect.ownKeys(item);
    if (keys.length > 2048 - nodes) throw 0;
    const copy: ObjectValue | unknown[] = array ? [] : Object.create(null) as ObjectValue;
    if (array) {
      const length = Object.getOwnPropertyDescriptor(item, 'length');
      if (!length || !Object.hasOwn(length, 'value') || !Number.isSafeInteger(length.value) || length.value < 0 || keys.length !== length.value + 1) throw 0;
      for (let i = 0; i < length.value; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(item, String(i));
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw 0;
        (copy as unknown[]).push(visit(descriptor.value, depth + 1));
      }
    } else {
      for (const key of keys) {
        if (typeof key !== 'string' || ++nodes > 2048 || key.length > 65536) throw 0;
        const descriptor = Object.getOwnPropertyDescriptor(item, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw 0;
        (copy as ObjectValue)[key] = visit(descriptor.value, depth + 1);
      }
    }
    return copy;
  }
  const result = visit(value, 1);
  if (encoder.encode(JSON.stringify(result)).byteLength > 65536) throw 0;
  return result;
}
function fields(value: unknown, names: readonly string[]): value is ObjectValue {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}
function one<T extends string>(value: unknown, values: readonly T[]): value is T { return typeof value === 'string' && values.includes(value as T); }
function text(value: unknown, scalars: number, bytes: number): value is string {
  return typeof value === 'string' && value.length > 0 && [...value].length <= scalars && encoder.encode(value).byteLength <= bytes
    && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value);
}
function decimal(value: unknown, positive: boolean, digits: number): value is string {
  // `$` alone also matches before a final line terminator in JavaScript.
  // These protocol fields require the entire string to be canonical ASCII.
  return typeof value === 'string' && value.length <= digits && (positive ? /^[1-9][0-9]*(?![\s\S])/ : /^(?:0|[1-9][0-9]*)(?![\s\S])/).test(value);
}
function counter(value: unknown): value is string { return decimal(value, false, 20) && compareDecimal(value, '18446744073709551615') <= 0; }
function operationId(value: unknown): value is string { return decimal(value, true, 10) && compareDecimal(value, '4294967294') <= 0; }
function selectionId(value: unknown): value is string { return typeof value === 'string' && /^evidence-[A-Za-z0-9_-]{1,55}(?![\s\S])/.test(value); }
function sha(value: unknown): value is string { return typeof value === 'string' && /^[a-f0-9]{64}(?![\s\S])/.test(value); }
function gitHash(value: unknown): value is string { return typeof value === 'string' && /^[a-fA-F0-9]{40}(?![\s\S])/.test(value); }
export function compareDecimal(left: string, right: string): number { return left.length === right.length ? left < right ? -1 : left > right ? 1 : 0 : left.length < right.length ? -1 : 1; }
function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
export function evidenceRequestFits(command: EvidenceCommand, value: unknown): value is Record<string, unknown> {
  try {
    const input = clean(value);
    if (command === 'artifact_evidence_choose' || command === 'artifact_evidence_status') return fields(input, []);
    if (command === 'artifact_evidence_observe') return fields(input, ['selectionId']) && selectionId(input.selectionId);
    return command === 'artifact_evidence_cancel' && fields(input, ['operationId', 'selectionId']) && operationId(input.operationId)
      && (input.selectionId === null || selectionId(input.selectionId));
  } catch { return false; }
}
function resultShape(input: unknown): input is CandidateEvidence {
  if (!fields(input, ['schemaVersion', 'outcome', 'documents', 'summary', 'assurance']) || input.schemaVersion !== 1
      || !one(input.outcome, ['consistent', 'incomplete', 'invalid', 'inconsistent']) || !Array.isArray(input.documents) || input.documents.length !== 3) return false;
  const kinds = ['manifest', 'receipt', 'intent'];
  if (!input.documents.every((row: unknown, i) => fields(row, ['kind', 'state']) && row.kind === kinds[i] && one(row.state, ['missing', 'invalid', 'valid']))) return false;
  if (!assuranceShape(input.assurance)) return false;
  const invalid = input.documents.some((row: ObjectValue) => row.state === 'invalid');
  const missing = input.documents.some((row: ObjectValue) => row.state === 'missing');
  if (input.outcome !== 'consistent') return input.summary === null && (input.outcome === 'invalid' ? invalid : input.outcome === 'incomplete' ? !invalid && missing : !invalid && !missing);
  return !invalid && !missing && summaryShape(input.summary);
}
function assuranceShape(a: unknown): a is CandidateEvidence['assurance'] {
  if (!fields(a, ['level', 'documentsOnly', 'artifactBytesVerified', 'workflowAuthenticated', 'storeStateObserved', 'comparedWithSourceProject', 'releaseReady', 'recoveryAuthorized'])
      || a.level !== 'local-document-consistency' || a.documentsOnly !== true
      || !['artifactBytesVerified', 'workflowAuthenticated', 'storeStateObserved', 'comparedWithSourceProject', 'releaseReady', 'recoveryAuthorized'].every((key) => a[key] === false)) return false;
  return true;
}
function runsShape(value: unknown): value is NonNullable<CandidateEvidence['summary']>['recordedRuns'] {
  return fields(value, ['authorizedBy', 'executedBy', 'producedBy']) && Object.values(value).every((run) => fields(run, ['runId', 'attempt']) && decimal(run.runId, true, 64) && decimal(run.attempt, true, 64));
}
function summaryShape(s: unknown): s is NonNullable<CandidateEvidence['summary']> {
  if (!fields(s, ['platform', 'applicationId', 'version', 'source', 'artifacts', 'recordedRuns', 'documentPayloadSha256'])
      || !one(s.platform, ['android', 'ios']) || !text(s.applicationId, 255, 1024) || [...s.applicationId].length < 3 || !fields(s.version, ['marketing', 'build'])
      || !text(s.version.marketing, 64, 256) || !/^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?(?![\s\S])/.test(s.version.marketing)
      || typeof s.version.build !== 'number' || !Number.isSafeInteger(s.version.build) || s.version.build < 1 || s.version.build > 2100000000
      || !fields(s.source, ['commit', 'tree']) || !gitHash(s.source.commit) || !gitHash(s.source.tree)
      || !Array.isArray(s.artifacts) || s.artifacts.length < 3 || s.artifacts.length > 5) return false;
  let previous = -1;
  if (!s.artifacts.every((artifact: unknown) => {
    if (!fields(artifact, ['logicalName', 'declaredBytes', 'sha256']) || !one(artifact.logicalName, roles) || !decimal(artifact.declaredBytes, true, 64) || !sha(artifact.sha256)) return false;
    const index = roles.indexOf(artifact.logicalName); if (index <= previous) return false; previous = index; return true;
  })) return false;
  const present = (name: string) => (s.artifacts as ObjectValue[]).some((a) => a.logicalName === name);
  if (!present('store-metadata') || !present('validation-report')) return false;
  if (s.platform === 'android' ? !present('android-aab') || (s.artifacts as ObjectValue[]).some((a) => String(a.logicalName).startsWith('ios-'))
    : !present('ios-ipa') || !present('ios-archive') || (s.artifacts as ObjectValue[]).some((a) => String(a.logicalName).startsWith('android-'))) return false;
  if (!runsShape(s.recordedRuns)) return false;
  return fields(s.documentPayloadSha256, ['manifest', 'receipt', 'intent']) && Object.values(s.documentPayloadSha256).every(sha);
}
export function parseCandidateEvidence(value: unknown): CandidateEvidence | null {
  try { const input = clean(value); return resultShape(input) ? freeze(input) : null; } catch { return null; }
}
const problems = ['unavailable', 'busy', 'cancelled', 'stale_selection', 'unsafe_selection', 'observation_failed', 'limit', 'deadline', 'cleanup_unknown'] as const;
export function parseEvidenceStatus(value: unknown): EvidenceStatus | null {
  try {
    const input = clean(value);
    if (!fields(input, ['schemaVersion', 'revision', 'availability', 'phase', 'selection', 'operation', 'result', 'problem']) || input.schemaVersion !== 1 || !counter(input.revision)
        || !one(input.availability, ['available', 'unavailable']) || !one(input.phase, ['idle', 'choosing', 'selected', 'observing', 'observed', 'stopping', 'cancelled', 'refused', 'unknown'])
        || input.problem !== null && !one(input.problem, problems)) return null;
    const selection = input.selection; const op = input.operation;
    if (selection !== null && (!fields(selection, ['selectionId', 'displayName']) || !selectionId(selection.selectionId) || !text(selection.displayName, 128, 512) || /[/\\]/.test(selection.displayName))) return null;
    if (op !== null && (!fields(op, ['operationId', 'kind', 'selectionId']) || !operationId(op.operationId) || !one(op.kind, ['choose', 'observe'])
        || (op.kind === 'choose' ? op.selectionId !== null : !selectionId(op.selectionId)))) return null;
    if (input.availability === 'unavailable') {
      if (input.phase !== 'idle' || selection !== null || op !== null || input.result !== null || input.problem !== 'unavailable') return null;
    } else {
      if (input.phase === 'idle' && (selection !== null || op !== null || input.result !== null || input.problem !== null)) return null;
      if (['choosing', 'selected', 'observing', 'observed'].includes(input.phase) && (!op || input.problem !== null)) return null;
      if (input.phase === 'choosing' && (op?.kind !== 'choose' || selection !== null)) return null;
      if (input.phase === 'selected' && (op?.kind !== 'choose' || !selection)) return null;
      if (['observing', 'observed'].includes(input.phase) && (op?.kind !== 'observe' || !selection || selection.selectionId !== op.selectionId)) return null;
      if (['stopping', 'cancelled', 'refused', 'unknown'].includes(input.phase) && input.problem === null) return null;
      if ((input.phase === 'unknown') !== (input.problem === 'cleanup_unknown')) return null;
      if (input.phase === 'stopping' && !op || input.phase === 'cancelled' && (!op || input.problem !== 'cancelled')) return null;
      if (input.phase === 'observed' ? !resultShape(input.result) : input.result !== null) return null;
    }
    return freeze(input as unknown as EvidenceStatus);
  } catch { return null; }
}

const messages: Record<string, string> = {
  artifact_evidence_invalid: 'The evidence request has an unsupported shape or identity.',
  artifact_evidence_unavailable: 'Evidence-folder inspection is unavailable in this build. It requires a qualified native Linux adapter and admitted bundled runtime; macOS and Windows support are not yet implemented.',
  artifact_evidence_busy: 'Another original native operation is still active. Wait for it to settle before trying this action.',
  artifact_evidence_cancelled: 'The original evidence operation was cancelled. No new document observation was accepted.',
  artifact_evidence_stale_selection: 'The evidence selection or original operation changed. Check its current status; do not reuse an earlier selection.',
  artifact_evidence_unsafe_selection: 'The folder or one of its fixed document paths could not be read safely. Originals were not modified.',
  artifact_evidence_observation_failed: 'The documents could not be observed. No current result was accepted. Check the original operation status before another action.',
  artifact_evidence_limit: 'The documents exceeded a supported input, structure or display limit. No current result was accepted.',
  artifact_evidence_deadline: 'The observation reached its deadline. Wait for the original operation to settle; another status check does not extend its deadline.',
  artifact_evidence_cleanup_unknown: 'Original-operation cleanup is unconfirmed. The owner is retained and new work is disabled; a late response cannot turn this into success.',
  artifact_evidence_protocol: 'The service returned an invalid or conflicting evidence status. No current result was accepted.',
};
export function evidenceError(error: unknown): ApiError {
  let code = 'artifact_evidence_protocol';
  try {
    const d = error !== null && typeof error === 'object' ? Object.getOwnPropertyDescriptor(error, 'code') : null;
    const value: unknown = d && Object.hasOwn(d, 'value') ? d.value : null;
    if (typeof value === 'string' && Object.hasOwn(messages, value)) code = value;
  } catch { /* Exception properties/messages are never UI data. */ }
  return { code, message: messages[code]!, retryable: false };
}
export function evidenceProblemText(problem: EvidenceProblem): string { return messages[`artifact_evidence_${problem}`]!; }

type EvidenceWireStatus = EvidenceStatus | LifecycleEvidenceStatus;
export interface EvidenceView<S extends EvidenceWireStatus = EvidenceStatus> {
  mode: BridgeMode; status: S | null; stage: EvidenceStage | null; error: ApiError | null; pending: 'choose' | 'observe' | null;
  cancelling: boolean; checking: boolean; uncertain: boolean; integrityFailed: boolean;
  stale: { selection: NonNullable<S['selection']>; result: NonNullable<S['result']> } | null;
}
type Port = CandidateEvidenceApi & { mode: BridgeMode };
export interface EvidencePort<S extends EvidenceWireStatus> {
  mode: BridgeMode; evidenceStatus(): Promise<S>; chooseEvidenceFolder(stage: EvidenceStage | null): Promise<S>;
  observeEvidence(selectionId: string): Promise<S>; cancelEvidence(operationId: string, selectionId: string | null): Promise<S>;
}

interface RequestBinding { purpose: 'candidate' | 'lifecycle'; stage: EvidenceStage | null; generation: number; kind: 'choose' | 'observe'; selectionId: string | null; after: string; priorOperation: string; originalId: string | null }
interface CancellationBinding { purpose: 'candidate' | 'lifecycle'; stage: EvidenceStage | null; generation: number; operation: EvidenceWireStatus['operation']; after: string }
const active = (status: EvidenceWireStatus | null) => status !== null && ['choosing', 'observing', 'stopping'].includes(status.phase);
function same(left: unknown, right: unknown): boolean {
  if (left === right) return true;
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object' || Array.isArray(left) !== Array.isArray(right)) return false;
  const a = left as ObjectValue; const b = right as ObjectValue; const keys = Object.keys(a);
  return keys.length === Object.keys(b).length && keys.every((key) => Object.hasOwn(b, key) && same(a[key], b[key]));
}

/** No project/draft callback exists here: selecting evidence cannot select a project. */
export class EvidenceController<S extends EvidenceWireStatus> {
  private state: EvidenceView<S> = freeze({ stage: null, mode: 'unavailable', status: null, error: null, pending: null, cancelling: false, checking: false, uncertain: true, integrityFailed: false, stale: null });
  private api: EvidencePort<S> | null = null;
  private generation = 0;
  private request: RequestBinding | null = null;
  private cancellation: CancellationBinding | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private disposed = false;
  private listeners = new Set<() => void>();
  private otherOperationReason: () => string | null;
  private purpose: 'candidate' | 'lifecycle';
  private parseStatus: (value: unknown) => S | null;
  private stageChosen = false;
  protected constructor(otherOperationReason: () => string | null, purpose: 'candidate' | 'lifecycle', parseStatus: (value: unknown) => S | null) {
    this.otherOperationReason = otherOperationReason; this.purpose = purpose; this.parseStatus = parseStatus;
    if (purpose === 'lifecycle') this.state = freeze({ ...this.state, stage: 'candidate' });
  }
  getSnapshot = (): EvidenceView<S> => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private update(patch: Partial<EvidenceView<S>>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch }); for (const listener of this.listeners) listener();
  }
  private prior(): EvidenceView<S>['stale'] { const s = this.state.status; return s?.selection && s.result ? { selection: s.selection, result: s.result } : this.state.stale; }
  private clearTimer(): void { if (this.timer !== null) clearTimeout(this.timer); this.timer = null; }
  private schedule(): void {
    this.clearTimer();
    if (this.disposed || this.state.integrityFailed || this.state.mode !== 'native' || this.state.checking || this.state.status?.phase === 'unknown') return;
    if (active(this.state.status) || this.request && this.request.originalId === null) this.timer = setTimeout(() => { this.timer = null; void this.check(); }, 300);
  }
  beginConnection(): void {
    this.clearTimer(); this.api = null; this.request = null; this.cancellation = null; this.stageChosen = false;
    if (this.generation === Number.MAX_SAFE_INTEGER) { this.update({ integrityFailed: true, status: null }); return; }
    this.generation++;
    this.update({ mode: 'unavailable', status: null, error: null, pending: null, cancelling: false, checking: false, uncertain: true, stale: this.prior() });
  }
  protected async connectEvidence(api: EvidencePort<S>): Promise<void> {
    if (this.disposed || this.state.integrityFailed) return;
    this.api = api; this.update({ mode: api.mode, error: null });
    if (api.mode === 'native') await this.check();
    else this.update({ status: null, uncertain: false, error: evidenceError({ code: 'artifact_evidence_unavailable' }) });
  }
  startReason(): string | null {
    const other = this.otherOperationReason(); if (other) return other;
    if (this.state.mode !== 'native' || this.state.status?.availability === 'unavailable') return messages.artifact_evidence_unavailable!;
    if (this.state.integrityFailed) return messages.artifact_evidence_protocol!;
    if (this.state.status?.phase === 'unknown') return messages.artifact_evidence_cleanup_unknown!;
    if (this.state.pending || this.state.cancelling) return 'Waiting for the original command acknowledgment. Status and exact original cancellation remain available.';
    if (this.state.uncertain || !this.state.status) return 'Check the native operation status before starting an evidence action.';
    return active(this.state.status) ? 'Wait for this original evidence operation to settle, or request its cancellation.' : null;
  }
  protected changeStage(stage: EvidenceStage): void {
    if (this.purpose !== 'lifecycle' || this.startReason() || !['candidate', 'external-testing', 'production-submit'].includes(stage)) return;
    this.stageChosen = true; this.update({ stage });
  }
  private stageOf(value: EvidenceWireStatus['operation'] | EvidenceWireStatus['selection']): EvidenceStage | null {
    return value && 'stage' in value ? value.stage : null;
  }
  observeReason(): string | null {
    const reason = this.startReason(); if (reason) return reason;
    const selection = this.state.status?.selection;
    if (!selection) return 'Choose an evidence folder first.';
    return this.stageOf(selection) !== this.state.stage ? 'Choose a new folder for this stage. An earlier selection cannot be reclassified.' : null;
  }
  private receive(value: unknown): S | null {
    const status = this.parseStatus(value);
    if (!status) { this.update({ status: null, stale: this.prior(), uncertain: true, integrityFailed: true, error: evidenceError(null) }); this.clearTimer(); return null; }
    const current = this.state.status;
    if (current && compareDecimal(status.revision, current.revision) < 0) return current;
    if (current && status.revision === current.revision && !same(current, status)) {
      this.update({ status: null, stale: this.prior(), uncertain: true, integrityFailed: true, error: evidenceError(null) }); this.clearTimer(); return null;
    }
    if (current?.phase === 'unknown' && status.phase !== 'unknown') {
      this.update({ uncertain: true, integrityFailed: true, error: evidenceError(null) }); this.clearTimer(); return null;
    }
    if (current?.selection && status.selection && current.selection.selectionId === status.selection.selectionId && !same(current.selection, status.selection)
        || current?.operation && status.operation && current.operation.operationId === status.operation.operationId && !same(current.operation, status.operation)) {
      this.receive(null); return null;
    }
    let pending = this.state.pending; let cancelling = this.state.cancelling;
    if (this.request && status.operation && compareDecimal(status.revision, this.request.after) > 0
        && compareDecimal(status.operation.operationId, this.request.priorOperation) > 0
        && status.operation.kind === this.request.kind && status.operation.selectionId === this.request.selectionId) {
      if (this.request.purpose !== this.purpose || this.request.stage !== this.stageOf(status.operation)) { this.receive(null); return null; }
      if (this.request.originalId !== null && this.request.originalId !== status.operation.operationId) {
        this.update({ status: null, stale: this.prior(), uncertain: true, integrityFailed: true, error: evidenceError(null) }); return null;
      }
      this.request.originalId = status.operation.operationId;
      if (!active(status)) {
        // A matching native terminal Status is the original acknowledgment
        // even when the first invoke Promise is lost forever. Retire only the
        // local request token; never repeat the native operation or its wait.
        this.request = null; pending = null;
      }
    }
    if (this.cancellation && compareDecimal(status.revision, this.cancellation.after) > 0
        && this.cancellation.purpose === this.purpose && this.cancellation.stage === this.stageOf(status.operation)
        && same(status.operation, this.cancellation.operation) && !['choosing', 'observing'].includes(status.phase)) {
      this.cancellation = null; cancelling = false;
    }
    const stale = status.result ? null : this.prior();
    const stage = this.purpose === 'lifecycle' && !this.stageChosen ? this.stageOf(status.operation) ?? this.state.stage : this.state.stage;
    this.update({ status, stale, pending, cancelling, stage, uncertain: false, error: null }); return status;
  }
  async check(): Promise<void> {
    if (!this.api || this.api.mode !== 'native' || this.disposed || this.state.checking || this.state.integrityFailed) return;
    const generation = this.generation; this.update({ checking: true }); let okay = false;
    try { const value = await this.api.evidenceStatus(); if (generation === this.generation && !this.disposed) okay = this.receive(value) !== null; }
    catch (error) { if (generation === this.generation) this.update({ uncertain: true, stale: this.prior(), error: evidenceError(error) }); }
    finally { if (generation === this.generation) { this.update({ checking: false }); if (okay) this.schedule(); } }
  }
  async choose(): Promise<void> { await this.start('choose'); }
  async observe(): Promise<void> { await this.start('observe'); }
  private async start(kind: 'choose' | 'observe'): Promise<void> {
    if (!this.api || this.disposed || this.startReason()) return;
    const selection = this.state.status?.selection;
    if (kind === 'observe' && this.observeReason()) return;
    this.stageChosen = true;
    const request: RequestBinding = { purpose: this.purpose, stage: this.state.stage, generation: this.generation, kind, selectionId: kind === 'observe' ? selection!.selectionId : null,
      after: this.state.status?.revision ?? '0', priorOperation: this.state.status?.operation?.operationId ?? '0', originalId: null };
    this.request = request; this.update({ pending: kind, stale: this.prior(), error: null }); this.schedule();
    try {
      const raw = await (kind === 'choose' ? this.api.chooseEvidenceFolder(request.stage) : this.api.observeEvidence(request.selectionId!));
      if (request.generation !== this.generation || this.disposed || this.request !== request) return;
      const value = this.parseStatus(raw); const op = value?.operation;
      if (!value || !op || request.purpose !== this.purpose || request.stage !== this.stageOf(op) || op.kind !== kind || op.selectionId !== request.selectionId || compareDecimal(value.revision, request.after) <= 0
          || compareDecimal(op.operationId, request.priorOperation) <= 0 || request.originalId !== null && request.originalId !== op.operationId) {
        this.receive(null); return;
      }
      request.originalId = op.operationId; this.receive(value);
    } catch (error) {
      if (request.generation === this.generation && this.request === request) this.update({ uncertain: true, stale: this.prior(), error: evidenceError(error) });
    } finally {
      if (request.generation === this.generation && this.request === request) {
        this.request = null; this.update({ pending: null });
        // Reconcile a lost/rejected initial reply without automatically
        // repeating the choose/read operation or guessing an operation ID.
        if (this.state.uncertain && !this.state.integrityFailed) void this.check(); else this.schedule();
      }
    }
  }
  async cancel(): Promise<void> {
    const op = this.state.status?.operation;
    if (!this.api || this.api.mode !== 'native' || !op || this.disposed || this.state.cancelling || this.state.integrityFailed
        || !active(this.state.status) && this.state.status?.phase !== 'unknown') return;
    const request: CancellationBinding = { purpose: this.purpose, stage: this.stageOf(op), generation: this.generation, operation: { ...op }, after: this.state.status!.revision };
    this.cancellation = request; this.update({ cancelling: true });
    try {
      const value = this.parseStatus(await this.api.cancelEvidence(op.operationId, op.selectionId));
      if (request.generation !== this.generation || this.disposed || this.cancellation !== request) return;
      if (!value || request.purpose !== this.purpose || request.stage !== this.stageOf(value.operation) || !same(value.operation, request.operation)) { this.receive(null); return; }
      this.receive(value);
    } catch (error) { if (request.generation === this.generation && this.cancellation === request) this.update({ uncertain: true, error: evidenceError(error) }); }
    finally { if (request.generation === this.generation && this.cancellation === request) { this.cancellation = null; this.update({ cancelling: false }); this.schedule(); } }
  }
  dispose(): void { this.clearTimer(); this.disposed = true; this.api = null; this.request = null; this.cancellation = null; this.listeners.clear(); }
}

/** The v1 facade keeps its exact routes, requests and DTO parser. */
export class CandidateEvidenceController extends EvidenceController<EvidenceStatus> {
  constructor(otherOperationReason: () => string | null = () => null) { super(otherOperationReason, 'candidate', parseEvidenceStatus); }
  connect(api: Port): Promise<void> { return this.connectEvidence(api); }
}
// Narrow reuse of the existing bounded own-DATA admission, never legacy-result
// coercion. Callers clean before any of these shape validators.
export { clean as cleanEvidenceData, fields, one, text, decimal, counter, operationId, selectionId, sha, freeze, same, summaryShape, assuranceShape, runsShape };

const help = (label: string, what: string, why: string, where: string, format: string, failure: string): HelpContent => ({
  label, requiredness: 'optional', requiredWhen: 'Only when you want to inspect saved candidate evidence; not required for editing a project draft.', what, why, where, format, failure,
});
export const evidenceHelp = {
  folder: help('Evidence folder', 'A folder containing a saved candidate manifest, receipt and operation intent.', 'Checks whether those three documents have valid formats, self-digests and consistent candidate bindings.',
    'Choose the final candidate evidence output you already retained from Mobile Release Kit. The native folder picker registers it; do not rename or move files into the application.',
    'candidate-manifest.json, candidate-receipt.json and operation/candidate-operation-intent.json; at most 2 MiB each. Original files stay in place and are read only.',
    'Missing or unsafe files produce no complete summary. This folder is separate from your source project; choosing it never saves or discards a draft.'),
  summary: help('Declared candidate identity', 'The platform, application ID, version, build and source commit/tree written in a consistent manifest.', 'Helps you recognize which saved candidate the documents describe.',
    'These values are read from the manifest, not from your selected project or the Stores.', 'Read-only declared values; the app does not compare them with your source, signed package, or GitHub.',
    'Even a self-consistent forged manifest can supply these values. Do not use this display alone to authorize a release.'),
  artifacts: help('Declared artifacts', 'Artifact roles, declared byte sizes and SHA-256 digests recorded in the manifest.', 'Shows which packages and supporting records the candidate claims to include.',
    'Mobile Release Kit writes these records when preparing candidate evidence. Keep the original artifact files separately.', 'Decimal byte counts and 64-character SHA-256 digests. The inspector never opens or hashes artifact payloads.',
    'Matching document declarations do not establish that the artifact exists, is signed correctly, or matches those bytes.'),
  runs: help('Manifest-recorded runs', 'Separate authorizing, executing and producing GitHub run IDs and attempt numbers.', 'Preserves the three recorded roles without treating them as the same execution.',
    'They come from the manifest; authenticated GitHub run/attempt acquisition is not performed here.', 'Exact decimal text, including large IDs; these are not clickable service identities or proof of a successful workflow.',
    'The documents may be self-consistent without authentic workflow history. No GitHub or Store status is inferred.'),
  digests: help('Document payload digests', 'The validated canonical payload digest from each of the three documents.', 'Detects inconsistent self-integrity using the existing core rules.',
    'Mobile Release Kit writes each document’s integrity section.', 'SHA-256 of the canonical payload with its integrity field excluded, not the SHA-256 of the raw JSON file.',
    'A recomputed digest does not authenticate the author. Whitespace changes can preserve the canonical digest; a forged set can still be locally consistent.'),
};
