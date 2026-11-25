// Optional policy INPUT DATA and a single-use UI intent hook. No HTTP, native
// job owner, clock, Store observation, version calculation or writer lives here.
import { localStoreProjectObservation } from './localStorePreflight.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import type { ProjectSession } from './drafts.ts';
import { releaseVersionRequestFits } from './releaseVersion.ts';
import type { ReleaseVersionBinding, ReleaseVersionInputContent, ReleaseVersionState } from './releaseVersion.ts';

export type VersionIncrement = 'build' | 'patch' | 'minor' | 'major';
export interface VersionRefRule { ref: string; increment: VersionIncrement }
export interface VersionPolicy {
  schemaVersion: 1; mode: 'manual' | 'automatic'; rules: readonly VersionRefRule[];
  buildCeiling: number; storeMaxAgeSeconds: number;
}
export interface VersionPolicyDraft {
  mode: 'manual' | 'automatic'; rules: readonly VersionRefRule[];
  buildCeiling: string; storeMaxAgeSeconds: string;
}
export const versionAutomationUnavailable = 'Automatic version reservations are unavailable here. Use the manual version editor if it is enabled.';
const invalidPolicy = 'Enter unique exact refs/heads/… or refs/tags/… rules, a build ceiling from 1 to 2100000000, and Store observation age from 1 to 3600 seconds.';
const staleSaved = 'Refresh the saved configuration and explicitly read its current saved version. Drafts, stale observations and earlier editor baselines are not reservation inputs.';
const unknownSubmission = 'Reservation submission could not be confirmed. Keep the original native operation; do not retry or replace its owner.';

function freeze<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function record(value: unknown, names: readonly string[]): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}
function integer(value: unknown, maximum: number, minimum = 1): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}
function exactRef(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 220) return false;
  const prefix = ['refs/heads/', 'refs/tags/'].find((item) => value.startsWith(item));
  if (!prefix) return false;
  const name = value.slice(prefix.length), parts = name.split('/');
  return /^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}(?![\s\S])/.test(name) && !name.startsWith('refs/') && !name.includes('..') &&
    parts.length <= 16 && parts.every((part) => part !== '' && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
}
export function parseVersionPolicy(input: unknown): VersionPolicy | null {
  try {
    const value = copyBoundedComparisonData(input, 16 * 1024, 512);
    if (!record(value, ['schemaVersion', 'mode', 'rules', 'buildCeiling', 'storeMaxAgeSeconds']) || value.schemaVersion !== 1 ||
        !['manual', 'automatic'].includes(value.mode as string) || !Array.isArray(value.rules) || value.rules.length > 32 ||
        !integer(value.buildCeiling, 2_100_000_000) || !integer(value.storeMaxAgeSeconds, 3600)) return null;
    const rules: VersionRefRule[] = [];
    for (const rule of value.rules) {
      if (!record(rule, ['ref', 'increment']) || !exactRef(rule.ref) ||
          !['build', 'patch', 'minor', 'major'].includes(rule.increment as string) || rules.some((item) => item.ref === rule.ref)) return null;
      rules.push({ ref: rule.ref, increment: rule.increment as VersionIncrement });
    }
    if (value.mode === 'manual' ? rules.length !== 0 : rules.length === 0) return null;
    return freeze({ schemaVersion: 1, mode: value.mode as VersionPolicy['mode'], rules,
      buildCeiling: value.buildCeiling, storeMaxAgeSeconds: value.storeMaxAgeSeconds });
  } catch { return null; }
}
export function manualVersionPolicy(): VersionPolicy {
  return freeze({ schemaVersion: 1, mode: 'manual', rules: [], buildCeiling: 2_100_000_000, storeMaxAgeSeconds: 900 });
}
export function versionPolicyDraft(policy: VersionPolicy = manualVersionPolicy()): VersionPolicyDraft {
  return freeze({ mode: policy.mode, rules: policy.rules.map((rule) => ({ ...rule })),
    buildCeiling: String(policy.buildCeiling), storeMaxAgeSeconds: String(policy.storeMaxAgeSeconds) });
}
export function versionPolicyFromDraft(input: unknown): VersionPolicy | null {
  try {
    const value = copyBoundedComparisonData(input, 16 * 1024, 512);
    if (!record(value, ['mode', 'rules', 'buildCeiling', 'storeMaxAgeSeconds']) ||
        !Array.isArray(value.rules) || value.rules.length > 32 || value.rules.some((rule) =>
          !record(rule, ['ref', 'increment']) || typeof rule.ref !== 'string' || rule.ref.length > 220 ||
          !['build', 'patch', 'minor', 'major'].includes(rule.increment as string)) ||
        typeof value.buildCeiling !== 'string' || !/^[1-9][0-9]{0,9}(?![\s\S])/.test(value.buildCeiling) ||
        typeof value.storeMaxAgeSeconds !== 'string' || !/^[1-9][0-9]{0,3}(?![\s\S])/.test(value.storeMaxAgeSeconds)) return null;
    // Toggling Manual explicitly disables rules, but the controlled in-memory
    // draft may retain them for a later toggle. It never recycles reservations.
    return parseVersionPolicy({ schemaVersion: 1, mode: value.mode, rules: value.mode === 'manual' ? [] : value.rules,
      buildCeiling: Number(value.buildCeiling), storeMaxAgeSeconds: Number(value.storeMaxAgeSeconds) });
  } catch { return null; }
}

// Root derives this display/admission gate from its original native registry.
// It is not a new wire schema or proof that a renderer can create authority.
export interface VersionAllocationNativeGate {
  projectId: string; generation: number;
  state: 'available' | 'unqualified' | 'disconnected' | 'busy' | 'recovery-required';
}
export interface VersionAutomationContext {
  session: ProjectSession | null; version: ReleaseVersionState | null; draft: VersionPolicyDraft;
  contextEpoch: number; nativeGate?: VersionAllocationNativeGate | null;
  otherOwnerBusy: boolean;
}
export interface VersionReservationIntent {
  kind: 'version-reserve-intent'; projectId: string; contextEpoch: number; nativeGeneration: number; intentEpoch: number;
  binding: ReleaseVersionBinding; policy: VersionPolicy;
  savedConfig: ReleaseVersionInputContent; savedVersion: ReleaseVersionInputContent;
  version: { name: string; build: number };
}
function reason(context: VersionAutomationContext): string | null {
  if (context.otherOwnerBusy !== false || context.nativeGate?.state === 'busy') return 'Finish the original active operation before requesting a version reservation.';
  if (context.nativeGate?.state === 'recovery-required') return 'Reconcile the original pending allocation. A new request cannot replace or recycle that reservation.';
  const policy = versionPolicyFromDraft(context.draft);
  if (!policy) return invalidPolicy;
  if (policy.mode === 'manual') return 'Manual versioning is selected. Use the separate saved-version editor; no automatic reservation is requested.';
  const gate = context.nativeGate;
  if (!gate || gate.state === 'unqualified') return versionAutomationUnavailable;
  if (gate.state === 'disconnected') return 'Connect the enrolled shared repository authority. Disconnected automatic allocation is refused, not replaced with a local counter.';
  if (gate.state !== 'available' || !context.session || gate.projectId !== context.session.project.id ||
      !releaseVersionRequestFits({ projectId: gate.projectId }) || !integer(gate.generation, Number.MAX_SAFE_INTEGER - 1, 0) ||
      !integer(context.contextEpoch, Number.MAX_SAFE_INTEGER - 1, 0)) return versionAutomationUnavailable;
  if (context.session.sourceChanged || context.session.saveRecoveryRequired || context.session.saveRecoveryNeedsReload) return staleSaved;
  const observed = localStoreProjectObservation(context.session, context.version);
  return observed.inputIssue === null && observed.savedConfig && observed.savedVersion ? null : staleSaved;
}
function buildIntent(context: VersionAutomationContext, epoch: number): VersionReservationIntent | null {
  if (reason(context) !== null || !context.session || !context.version?.resultBinding || !context.nativeGate) return null;
  const policy = versionPolicyFromDraft(context.draft), observed = localStoreProjectObservation(context.session, context.version);
  const saved = observed.savedVersion;
  if (!policy || !observed.savedConfig || !saved) return null;
  const copied = copyBoundedComparisonData(context.version.resultBinding, 2048, 64);
  if (!record(copied, ['projectId', 'draftRevision', 'baselineGeneration', 'observationGeneration', 'dirtyDraft',
    'snapshotRequest', 'saveRecoveryRequired', 'requestId', 'readEpoch', 'connectionGeneration', 'selectionGeneration'])) return null;
  const binding = copied as unknown as ReleaseVersionBinding;
  return freeze({ kind: 'version-reserve-intent', projectId: context.session.project.id, contextEpoch: context.contextEpoch,
    nativeGeneration: context.nativeGate.generation, intentEpoch: epoch, binding, policy,
    savedConfig: { ...observed.savedConfig }, savedVersion: { bytes: saved.bytes, sha256: saved.sha256 },
    version: { name: saved.name, build: saved.build } });
}

export class VersionReservationIntentController {
  private epoch = 0;
  private issued = new WeakSet<VersionReservationIntent>();
  private claimed = new WeakSet<VersionReservationIntent>();
  private delivering = false;
  private failed = false;
  private listeners = new Set<() => void>();
  private readonly context: () => VersionAutomationContext;
  private readonly begin: ((intent: VersionReservationIntent) => boolean) | undefined;
  constructor(context: () => VersionAutomationContext,
              // Synchronous ORIGINAL-owner admission only. True means accepted,
              // NOT reserved/settled; false must mean no submission. Never pass
              // a raw asynchronous bridge, HTTP port or Promise-returning call.
              begin?: (intent: VersionReservationIntent) => boolean) { this.context = context; this.begin = begin; }
  getSnapshot = (): number => this.epoch;
  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener); return () => { this.listeners.delete(listener); };
  };
  startReason(): string | null {
    if (this.failed) return unknownSubmission;
    if (this.delivering) return 'The original native controller is accepting this reservation intent.';
    if (!this.begin || this.epoch >= Number.MAX_SAFE_INTEGER - 1) return versionAutomationUnavailable;
    try { return reason(this.context()); } catch { return staleSaved; }
  }
  // Root calls on every API/project/workspace intent (including away/back and
  // reducer no-ops). The controlled form also calls BEFORE any policy change.
  retire(): void {
    this.epoch = Math.min(Number.MAX_SAFE_INTEGER - 1, this.epoch + 1); this.issued = new WeakSet();
    for (const listener of this.listeners) listener();
  }
  prepare(): VersionReservationIntent | null {
    if (this.startReason() !== null) return null;
    try {
      const intent = buildIntent(this.context(), this.epoch);
      if (intent) this.issued.add(intent);
      return intent;
    } catch { return null; }
  }
  submit(intent: VersionReservationIntent): boolean {
    if (!this.issued.has(intent) || this.claimed.has(intent) || this.startReason() !== null) return false;
    try {
      const current = buildIntent(this.context(), this.epoch);
      if (!current || JSON.stringify(current) !== JSON.stringify(intent)) return false;
    } catch { return false; }
    this.claimed.add(intent); this.delivering = true;
    try {
      const accepted = this.begin!(intent);
      if (typeof accepted !== 'boolean') { this.failed = true; return false; }
      return accepted;
    } catch { this.failed = true; return false; }
    finally { this.delivering = false; this.retire(); }
  }
}

// A reserved-version edit MUST use Root's original native reservation/request
// and authentic checkout via prepare_reserved_version_edit. Do not turn this
// intent into two unbound manual editField calls, or claim upload eligibility.
