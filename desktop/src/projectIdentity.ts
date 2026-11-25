// Display DATA from project_identity*.py, not a source parser or native lease.
// The optional UI adapter below must wrap the ORIGINAL identity EditOwner.
// It does not install a bridge command, qualify a runtime, or share another
// domain's checkout/token. Root owns that native integration and finality.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import type { CoreEditOutcome } from './types.ts';
import type { ProjectInitializationProjection, ProjectInitializationStatus } from './projectInitializationTypes.ts';

export interface IdentitySelection {
  platform: 'android' | 'ios'; target: string; project: string | null; continuity: 'existing' | 'unknown';
}
export type IdentityIntent = 'preserve' | 'new-application';
export type IdentityRole = 'android-application-id' | 'ios-bundle-id' | 'saved-identity';
export interface IdentityLocation { path: string; line: number; column: number; role: IdentityRole }
export interface IdentityDiagnostic { code: string; path: string; line: number; column: number; help: string }
export interface IdentityAnalysis {
  schemaVersion: 1; kind: 'project-identity'; revision: string; selection: IdentitySelection;
  state: 'supported' | 'unsupported'; identity: string | null; configuredIdentity: string | null;
  identityStatus: 'unverified' | 'approved' | 'blocked' | null; configurations: string[];
  locations: IdentityLocation[]; diagnostics: IdentityDiagnostic[]; nextStep: string;
  scope: 'recognized-literal-source-only'; buildVerificationRequired: true;
}
export interface IdentityPreview {
  schemaVersion: 1; kind: 'project-identity-preview'; revision: string; selection: IdentitySelection;
  intent: IdentityIntent; state: 'change' | 'unchanged';
  changes: (IdentityLocation & { beforeId: string; afterId: string })[];
  warnings: string[]; invalidations: string[]; retainVersionReservations: true; buildVerificationRequired: true;
}
export interface IdentityRecovery {
  schemaVersion: 1; kind: 'project-identity-recovery'; state: 'idle' | 'recoverable' | 'conflict';
  reason: string; action: 'rollback' | 'preparing_cleanup' | 'committed_cleanup' | 'rolled_back_cleanup' | null;
  transactionId: string | null; desiredIdentity: string | null;
  files: { path: string; action: 'restore_original' | 'preserve'; beforeBytes: number; afterBytes: number | null }[];
  help: string; privateCleanup: { fileCount: number; directoryCount: number; scope: 'inspected-owned-journal-only' };
  retainVersionReservations: true;
}
export interface IdentityCheckout { revision: string; view: IdentityAnalysis | IdentityRecovery }
export interface IdentityPrepared { revision: string; planToken: string; view: IdentityPreview | IdentityRecovery }

// UI-only projection of the SAME native lifecycle fields. No initialization
// API/controller/profile is used. Native retains the original checkout/plan.
export interface IdentityProjection extends Pick<ProjectInitializationProjection,
  'projectId' | 'sessionId' | 'ownerGeneration' | 'phase' | 'reviewRemainingMs' |
  'applySubmitted' | 'coreOutcome' | 'nativeReason' | 'nativeFinality' | 'lateSettled'> {
  domain: 'project_identity'; intent: 'edit' | 'recover'; checkout: IdentityCheckout | null;
  prepared: IdentityPrepared | null; diagnostic: IdentityDiagnostic | null;
}
export interface IdentityOwnerStatus extends Pick<ProjectInitializationStatus,
  'schemaVersion' | 'windowGeneration' | 'statusRevision' | 'capability'> {
  domain: 'project_identity'; active: IdentityProjection | null; lastTerminal: IdentityProjection | null;
}
export interface IdentityOwnerSnapshot {
  // busy comes from the original controller's retained command admission, not
  // an inferred phase or a renderer-created Promise. getSnapshot is local.
  busy: boolean; status: IdentityOwnerStatus | null;
}
export interface IdentityUiContext {
  projectId: string | null; selection: IdentitySelection | null;
  // Root increments/retire()s BEFORE every project, saved-input, API or selection
  // intent, including no-op/ABA intents; this is not a native revision/token.
  contextEpoch: number; preview: boolean; blocked: boolean;
}
export interface IdentitySessionRequest { sessionId: string; revision: string }
export interface IdentityApplyRequest extends IdentitySessionRequest { planToken: string }
export interface IdentityNativePort {
  readonly mode: 'native';
  getSnapshot(): unknown;
  subscribe(listener: () => void): () => void;
  // These MUST synchronously enter the original native controller's gate and
  // retain its original work. true = admitted, NEVER completed. false guarantees
  // nothing submitted. Do not wrap an async bridge with `void ...; return true`.
  analyze(request: { projectId: string; selection: IdentitySelection }): boolean;
  prepare(request: IdentitySessionRequest & { desiredIdentity: string; intent: IdentityIntent }): boolean;
  apply(request: IdentityApplyRequest): boolean;
  inspectRecovery(request: { projectId: string }): boolean;
  prepareRecovery(request: IdentitySessionRequest): boolean;
  recover(request: IdentityApplyRequest): boolean;
  discard(request: { sessionId: string }): boolean;
  checkStatus(): boolean;
}

const CONFIG = 'release/mobile-release.json';
export const IDENTITY_NEW_WARNING = 'A different identity is a different app. This cannot update your existing app. Availability in the stores has not been checked.';
const invalidations = ['credential-assessments-and-assignments', 'prepared-release-plans', 'candidate-identity-revision'];
const diagnosticCodes = ['invalid-input', 'unsafe-path', 'missing-control', 'invalid-config', 'identity-mismatch', 'target-mismatch',
  'ambiguous-target', 'unsupported-syntax', 'dynamic-identity', 'unsupported-plugin', 'imported-control', 'generated-project',
  'variant-identity', 'ambiguous-identity', 'conditional-config', 'include-cycle', 'shared-control', 'unsupported-plist',
  'plist-override', 'scheme-selection', 'scheme-required', 'existing-application', 'new-intent-required', 'dependent-service', 'stale-revision'];
const recoveryReasons = ['none', 'incomplete_journal', 'foreign_journal', 'legacy_journal', 'invalid_journal', 'unsupported_descriptor',
  'target_changed', 'control_changed', 'namespace_changed', 'inventory_changed'];
const nativeReasons = ['none', 'discarded', 'cancelled', 'active_timeout', 'review_expired', 'caller_lost', 'window_lost', 'shutdown',
  'runtime_unavailable', 'spawn_failed', 'protocol_error', 'io_error', 'output_limit', 'cleanup_unknown'];
const coreReasons = ['none', 'invalid_params', 'invalid_config', 'ignore_conflict', 'stale_revision', 'pending_state', 'busy',
  'cancelled', 'filesystem_error', 'custody_unknown', 'unsupported_platform'];
const availability = ['available', 'unsupported_platform', 'runtime_unqualified', 'cleanup_unknown', 'shutdown', 'other_edit_active'];
const phases = ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing', 'final', 'unknown'];
const encoder = new TextEncoder();
const record = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => record(v) &&
  Object.keys(v).length === names.length && names.every((key) => Object.hasOwn(v, key));
const oneOf = (v: unknown, names: readonly string[]): boolean => typeof v === 'string' && names.includes(v);
const integer = (v: unknown, max: number): v is number => typeof v === 'number' && Number.isSafeInteger(v) && !Object.is(v, -0) && v >= 0 && v <= max;
const text = (v: unknown, max: number): v is string => typeof v === 'string' && v.length > 0 && v.length <= max &&
  !/[\u0000-\u001f\u007f]/u.test(v) && encoder.encode(v).byteLength <= max;
const token = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{32}$/.test(v);
const projectId = (v: unknown): v is string => text(v, 128) && /^[A-Za-z0-9_-]+$/.test(v);

// Mirror only the core's display vocabulary, not source discovery or write grants.
function path(v: unknown): v is string {
  if (!text(v, 512)) return false;
  const parts = v.split('/');
  return parts.length <= 16 && parts.every((p) => /^[A-Za-z0-9_.+ @()-]+$/.test(p) && p !== '.' && p !== '..' &&
    !['.git', '.gradle', '.idea', '.mobile-release', 'build', 'deriveddata', 'pods', 'node_modules', 'private', 'secrets', 'credentials', 'xcuserdata'].includes(p.toLowerCase()) &&
    !/^\.(?:mobile-release-|private-|codex-private-)/i.test(p));
}
export function identityValueFits(value: unknown, platform: IdentitySelection['platform']): value is string {
  return typeof value === 'string' && value.length <= 255 && (platform === 'android'
    ? /^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$/
    : /^[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*)+$/).test(value);
}
function selection(v: unknown): v is IdentitySelection {
  return keys(v, ['platform', 'target', 'project', 'continuity']) && oneOf(v.continuity, ['existing', 'unknown']) &&
    text(v.target, 255) && /^[A-Za-z0-9_. :()-]+$/.test(v.target) &&
    (v.platform === 'android' ? v.project === null && /^:([A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)*)?$/.test(v.target) &&
      (v.target === ':' || path(`${v.target.slice(1).replaceAll(':', '/')}/build.gradle.kts`))
      : v.platform === 'ios' && path(v.project) && v.project.endsWith('.xcodeproj'));
}
function diagnostic(v: unknown): v is IdentityDiagnostic {
  return keys(v, ['code', 'path', 'line', 'column', 'help']) && oneOf(v.code, diagnosticCodes) && path(v.path) &&
    integer(v.line, 2 * 1024 * 1024) && v.line > 0 && integer(v.column, 2 * 1024 * 1024) && v.column > 0 && text(v.help, 1024);
}
function location(v: unknown, platform: IdentitySelection['platform'], change = false): v is IdentityLocation & { beforeId: string; afterId: string } {
  return keys(v, ['path', 'line', 'column', 'role', ...(change ? ['beforeId', 'afterId'] : [])]) && path(v.path) &&
    integer(v.line, 2 * 1024 * 1024) && v.line > 0 && integer(v.column, 2 * 1024 * 1024) && v.column > 0 &&
    (v.role === 'saved-identity' ? v.path === CONFIG : v.path !== CONFIG && v.role === (platform === 'android' ? 'android-application-id' : 'ios-bundle-id')) &&
    (!change || identityValueFits(v.beforeId, platform) && identityValueFits(v.afterId, platform) && v.beforeId !== v.afterId);
}
function uniqueLocations(rows: IdentityLocation[]): boolean {
  return new Set(rows.map((r) => JSON.stringify([r.path, r.line, r.column, r.role]))).size === rows.length;
}
function analysis(v: unknown): v is IdentityAnalysis {
  if (!keys(v, ['schemaVersion', 'kind', 'revision', 'selection', 'state', 'identity', 'configuredIdentity', 'identityStatus',
    'configurations', 'locations', 'diagnostics', 'nextStep', 'scope', 'buildVerificationRequired']) || v.schemaVersion !== 1 ||
    v.kind !== 'project-identity' || !token(v.revision) || !selection(v.selection) || !oneOf(v.state, ['supported', 'unsupported']) ||
    v.scope !== 'recognized-literal-source-only' || v.buildVerificationRequired !== true || !text(v.nextStep, 1024) ||
    !(v.identity === null || identityValueFits(v.identity, v.selection.platform)) ||
    !(v.configuredIdentity === null || identityValueFits(v.configuredIdentity, v.selection.platform)) ||
    !(v.identityStatus === null || oneOf(v.identityStatus, ['unverified', 'approved', 'blocked'])) ||
    !Array.isArray(v.configurations) || v.configurations.length > 32 || !v.configurations.every((r) => text(r, 80)) ||
    new Set(v.configurations).size !== v.configurations.length || !Array.isArray(v.locations) || v.locations.length > 65 ||
    !Array.isArray(v.diagnostics) || v.diagnostics.length > 1 || !v.diagnostics.every(diagnostic)) return false;
  const platform = v.selection.platform;
  if (!v.locations.every((r) => location(r, platform)) || !uniqueLocations(v.locations)) return false;
  if (v.state === 'unsupported') return v.diagnostics.length === 1;
  return v.diagnostics.length === 0 && v.identity !== null && v.identity === v.configuredIdentity && v.identityStatus !== null &&
    v.configurations.length > 0 && v.locations.length >= 2 && v.locations.filter((r) => r.role === 'saved-identity').length === 1;
}
function preview(v: unknown): v is IdentityPreview {
  if (!keys(v, ['schemaVersion', 'kind', 'revision', 'selection', 'intent', 'state', 'changes', 'warnings', 'invalidations',
    'retainVersionReservations', 'buildVerificationRequired']) || v.schemaVersion !== 1 || v.kind !== 'project-identity-preview' ||
    !token(v.revision) || !selection(v.selection) || !oneOf(v.intent, ['preserve', 'new-application']) ||
    !oneOf(v.state, ['change', 'unchanged']) || v.retainVersionReservations !== true || v.buildVerificationRequired !== true ||
    !Array.isArray(v.changes) || v.changes.length > 65 || !Array.isArray(v.warnings) || !Array.isArray(v.invalidations)) return false;
  if (v.state === 'unchanged') return v.changes.length === 0 && v.warnings.length === 0 && v.invalidations.length === 0;
  const platform = v.selection.platform;
  return v.intent === 'new-application' && v.selection.continuity === 'unknown' && v.changes.length >= 2 &&
    v.changes.every((r) => location(r, platform, true)) && uniqueLocations(v.changes) &&
    v.changes.filter((r) => r.role === 'saved-identity').length === 1 &&
    new Set(v.changes.map((r) => r.beforeId)).size === 1 && new Set(v.changes.map((r) => r.afterId)).size === 1 &&
    identityDataEqual(v.warnings, [IDENTITY_NEW_WARNING]) && identityDataEqual(v.invalidations, invalidations);
}
function recovery(v: unknown): v is IdentityRecovery {
  if (!keys(v, ['schemaVersion', 'kind', 'state', 'reason', 'action', 'transactionId', 'desiredIdentity', 'files', 'help', 'privateCleanup',
    'retainVersionReservations']) || v.schemaVersion !== 1 || v.kind !== 'project-identity-recovery' ||
    !oneOf(v.state, ['idle', 'recoverable', 'conflict']) || !oneOf(v.reason, recoveryReasons) || v.retainVersionReservations !== true ||
    !text(v.help, 1024) || !Array.isArray(v.files) || v.files.length > 64 ||
    !keys(v.privateCleanup, ['fileCount', 'directoryCount', 'scope']) || v.privateCleanup.scope !== 'inspected-owned-journal-only' ||
    !integer(v.privateCleanup.fileCount, 1024) || !integer(v.privateCleanup.directoryCount, 1025)) return false;
  if (v.state !== 'recoverable') return v.action === null && v.transactionId === null && v.desiredIdentity === null && v.files.length === 0 &&
    v.privateCleanup.fileCount === 0 && v.privateCleanup.directoryCount === 0 && (v.state === 'idle' ? v.reason === 'none' : v.reason !== 'none');
  if (v.reason !== 'none' || !token(v.transactionId) || !oneOf(v.action, ['rollback', 'preparing_cleanup', 'committed_cleanup', 'rolled_back_cleanup']) ||
    !(identityValueFits(v.desiredIdentity, 'android') || identityValueFits(v.desiredIdentity, 'ios')) || v.privateCleanup.directoryCount < 1 ||
    new Set(v.files.map((r) => record(r) ? r.path : null)).size !== v.files.length) return false;
  const rollback = v.action === 'rollback';
  return v.files.every((r) => keys(r, ['path', 'action', 'beforeBytes', 'afterBytes']) && path(r.path) &&
    integer(r.beforeBytes, 2 * 1024 * 1024) && (r.afterBytes === null || integer(r.afterBytes, 2 * 1024 * 1024)) &&
    r.action === (rollback && r.afterBytes !== null ? 'restore_original' : 'preserve'));
}
function outcome(v: unknown): v is CoreEditOutcome {
  return keys(v, ['effect', 'journal', 'resources', 'reason']) && oneOf(v.effect, ['not_started', 'unchanged', 'rolled_back', 'committed', 'unknown']) &&
    oneOf(v.journal, ['not_created', 'clean', 'recovery_required', 'unknown']) && oneOf(v.resources, ['settled', 'unknown']) && oneOf(v.reason, coreReasons) &&
    (v.effect !== 'unchanged' || v.journal === 'not_created') && (!oneOf(v.effect, ['committed', 'rolled_back']) || v.journal !== 'not_created') &&
    (v.reason !== 'none' || v.resources === 'settled' && v.effect !== 'unknown' && !oneOf(v.journal, ['unknown', 'recovery_required']));
}
export function identityPreviewMatches(view: IdentityPreview, captured: IdentityAnalysis, desired: string, intent: IdentityIntent): boolean {
  if (captured.state !== 'supported' || view.revision !== captured.revision || !identityDataEqual(view.selection, captured.selection) ||
    view.intent !== intent || !identityValueFits(desired, captured.selection.platform)) return false;
  if (desired === captured.identity) return view.state === 'unchanged';
  return intent === 'new-application' && captured.selection.continuity === 'unknown' && captured.identityStatus === 'unverified' &&
    view.state === 'change' && view.changes.length === captured.locations.length && view.changes.every((r, i) => {
      const original = captured.locations[i];
      return original !== undefined && r.path === original.path && r.line === original.line && r.column === original.column &&
        r.role === original.role && r.beforeId === captured.identity && r.afterId === desired;
    });
}
function projection(v: unknown): v is IdentityProjection {
  if (!keys(v, ['domain', 'intent', 'projectId', 'sessionId', 'ownerGeneration', 'phase', 'reviewRemainingMs', 'checkout', 'prepared',
    'diagnostic', 'applySubmitted', 'coreOutcome', 'nativeReason', 'nativeFinality', 'lateSettled']) || v.domain !== 'project_identity' ||
    !oneOf(v.intent, ['edit', 'recover']) || !projectId(v.projectId) || !token(v.sessionId) || !token(v.ownerGeneration) ||
    !oneOf(v.phase, phases) || !integer(v.reviewRemainingMs, 900_000) || typeof v.applySubmitted !== 'boolean' || typeof v.lateSettled !== 'boolean' ||
    !oneOf(v.nativeReason, nativeReasons) || !oneOf(v.nativeFinality, ['pending', 'settled', 'unknown']) ||
    !(v.diagnostic === null || diagnostic(v.diagnostic)) || !(v.coreOutcome === null || outcome(v.coreOutcome))) return false;
  if (v.checkout !== null && (!keys(v.checkout, ['revision', 'view']) || !token(v.checkout.revision) ||
    (v.intent === 'edit' ? !analysis(v.checkout.view) || v.checkout.revision !== v.checkout.view.revision : !recovery(v.checkout.view)))) return false;
  if (v.prepared !== null) {
    if (!keys(v.prepared, ['revision', 'planToken', 'view']) || !token(v.prepared.revision) || !token(v.prepared.planToken) ||
      v.prepared.planToken === v.prepared.revision || !record(v.checkout) || v.prepared.revision !== v.checkout.revision) return false;
    if (v.intent === 'edit') {
      if (!preview(v.prepared.view) || !analysis(v.checkout.view)) return false;
      const desired = v.prepared.view.state === 'unchanged' ? v.checkout.view.identity : v.prepared.view.changes[0]?.afterId;
      if (desired === null || desired === undefined || !identityPreviewMatches(v.prepared.view, v.checkout.view, desired, v.prepared.view.intent)) return false;
    } else if (!recovery(v.prepared.view) || v.prepared.view.state !== 'recoverable' || !identityDataEqual(v.prepared.view, v.checkout.view)) return false;
  }
  if (oneOf(v.phase, ['editing', 'preparing', 'reviewing', 'applying']) && v.checkout === null ||
    oneOf(v.phase, ['reviewing', 'applying']) && v.prepared === null ||
    v.phase === 'reviewing' && v.applySubmitted || v.phase === 'applying' && !v.applySubmitted || v.applySubmitted && v.prepared === null ||
    v.phase === 'opening' && (v.checkout !== null || v.prepared !== null || v.applySubmitted) ||
    oneOf(v.phase, ['editing', 'preparing']) && (v.prepared !== null || v.applySubmitted) ||
    oneOf(v.phase, ['opening', 'editing', 'preparing', 'reviewing']) && v.coreOutcome !== null ||
    oneOf(v.phase, ['opening', 'editing', 'preparing', 'reviewing', 'applying', 'finalizing']) && (v.nativeFinality !== 'pending' || v.lateSettled) ||
    v.phase === 'final' && (v.nativeFinality !== 'settled' || v.lateSettled) || v.phase === 'unknown' && v.nativeFinality !== 'unknown') return false;
  if (v.phase === 'final') {
    if (v.coreOutcome === null) return v.checkout === null && v.prepared === null && !v.applySubmitted && v.nativeReason !== 'none';
    if (v.coreOutcome.resources === 'unknown' || v.coreOutcome.effect === 'unknown' || v.coreOutcome.journal === 'unknown') return false;
  }
  return true;
}
function owner(v: unknown): v is IdentityOwnerSnapshot {
  if (!keys(v, ['busy', 'status']) || typeof v.busy !== 'boolean') return false;
  if (v.status === null) return true;
  const s = v.status;
  if (!keys(s, ['schemaVersion', 'domain', 'windowGeneration', 'statusRevision', 'capability', 'active', 'lastTerminal']) ||
    s.schemaVersion !== 1 || s.domain !== 'project_identity' || !token(s.windowGeneration) || !integer(s.statusRevision, 0xffff_ffff) ||
    !keys(s.capability, ['available', 'reason']) || !oneOf(s.capability.reason, availability) || s.capability.available !== (s.capability.reason === 'available') ||
    !(s.active === null || projection(s.active)) || !(s.lastTerminal === null || projection(s.lastTerminal))) return false;
  return (s.active === null || s.active.ownerGeneration === s.windowGeneration && s.active.phase !== 'final' && !s.active.lateSettled &&
      s.capability.reason !== 'other_edit_active' && s.active.sessionId !== s.lastTerminal?.sessionId) &&
    (s.lastTerminal === null || s.lastTerminal.ownerGeneration === s.windowGeneration &&
      (s.lastTerminal.phase === 'final' || s.lastTerminal.phase === 'unknown'));
}
function freeze<T>(v: T): T {
  if (v && typeof v === 'object') { Object.values(v).forEach(freeze); Object.freeze(v); }
  return v;
}
function parsed<T>(v: unknown, check: (v: unknown) => v is T, bytes = 128 * 1024): T | null {
  try { const safe = copyBoundedComparisonData(v, bytes, 12_000); return check(safe) ? freeze(safe) : null; }
  catch { return null; }
}
export const parseIdentityAnalysis = (v: unknown): IdentityAnalysis | null => parsed(v, analysis);
export const parseIdentityPreview = (v: unknown): IdentityPreview | null => parsed(v, preview);
export const parseIdentityRecovery = (v: unknown): IdentityRecovery | null => parsed(v, recovery);
export const parseIdentityOwnerSnapshot = (v: unknown): IdentityOwnerSnapshot | null => parsed(v, owner, 512 * 1024);
export const parseIdentityContext = (v: unknown): IdentityUiContext | null => parsed(v, (v): v is IdentityUiContext =>
  keys(v, ['projectId', 'selection', 'contextEpoch', 'preview', 'blocked']) && (v.projectId === null || projectId(v.projectId)) &&
  (v.selection === null || selection(v.selection)) && integer(v.contextEpoch, Number.MAX_SAFE_INTEGER) &&
  typeof v.preview === 'boolean' && typeof v.blocked === 'boolean', 4096);

// Both values must already be bounded, owned display copies. Object key order
// is immaterial, unlike arrays whose complete reviewed order is significant.
export function identityDataEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (Array.isArray(a) || Array.isArray(b)) return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => identityDataEqual(v, b[i]));
  if (!record(a) || !record(b)) return false;
  const names = Object.keys(a);
  return names.length === Object.keys(b).length && names.every((key) => Object.hasOwn(b, key) && identityDataEqual(a[key], b[key]));
}
export function identityTerminalResult(p: IdentityProjection): 'saved' | 'unchanged' | 'recovered' | null {
  // This is presentation of ORIGINAL owner finality, not a finality producer.
  if (p.phase !== 'final' || p.nativeFinality !== 'settled' || p.lateSettled || p.nativeReason !== 'none' || !p.applySubmitted ||
    !p.checkout || !p.prepared || p.checkout.revision !== p.prepared.revision || !p.coreOutcome ||
    p.coreOutcome.reason !== 'none' || p.coreOutcome.resources !== 'settled') return null;
  const core = p.coreOutcome, view = p.prepared.view;
  if (view.kind === 'project-identity-preview') return view.state === 'change'
    ? core.effect === 'committed' && core.journal === 'clean' ? 'saved' : null
    : core.effect === 'unchanged' && core.journal === 'not_created' ? 'unchanged' : null;
  const expected = view.action === 'committed_cleanup' ? 'committed' : view.action === 'preparing_cleanup' ? 'not_started' : 'rolled_back';
  return view.state === 'recoverable' && core.effect === expected && core.journal === 'clean' ? 'recovered' : null;
}
