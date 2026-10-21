import { parseToolSetupReview, sameToolSetupReview } from './agentToolSetup.ts';
import type { ToolSetupReview, ToolSetupDelegation } from './agentToolSetup.ts';
// App-held UI coordination, not a native owner. Only the original native
// status after its own joins can report completion. A Promise/event cannot.
import { isDirty } from './drafts.ts';
import type { ProjectSession, WorkspaceAction } from './drafts.ts';
import { offlineCounter, parseSavedConfigContent, savedConfigFromSnapshot, sameSavedConfig } from './offlinePreflightProtocol.ts';
import type { ToolAcquisitionApi } from './toolAcquisitionNative.ts';
import { parseToolAcquisitionContext, parseToolAcquisitionStatus, sameToolAcquisitionData, sameToolAcquisitionIdentity,
  TOOL_ACQUISITION_CONSENT, toolAcquisitionAvailabilityText, toolAcquisitionProgress } from './toolAcquisitionProtocol.ts';
import type { ToolAcquisitionContext, ToolAcquisitionIdentity, ToolAcquisitionOperation, ToolAcquisitionStatus,
  ToolAcquisitionStart, ToolRequirementsObservation } from './toolAcquisitionProtocol.ts';
import type { StagedToolPresentation } from './toolAcquisitionGuidance.ts';
import { stagedMatchesComponents } from './toolAcquisitionComponents.ts';
import { PreparedToolSourceHandoff } from './toolAcquisitionSourcePicker.ts';
import type { PreparedToolFolders, PreparedToolSourcePick, ToolSourceFolderContext } from './toolAcquisitionSourcePicker.ts';
import type { AndroidToolSourceRole } from './androidToolSources.ts';
import { toolAcquisitionPrerequisite, TOOL_ACQUISITION_PREREQUISITE_TEXT } from './toolAcquisitionPrerequisite.ts';
import type { ToolAcquisitionPrerequisite } from './toolAcquisitionPrerequisite.ts';

interface Source {
  selectedProject(): ProjectSession | null;
  otherOperationReason(): string | null; // Root excludes THIS controller.
  // Existing Android controller projections are invalidation DATA only. They
  // cannot grant an empty census, a tool lease, native qualification or consent.
  knownTools(): readonly [unknown, unknown, unknown];
}
interface Witness {
  context: ToolAcquisitionContext; observation: number; draft: ProjectSession['draft'];
  baseline: ProjectSession['baseline']; snapshot: ProjectSession['snapshot']; known: readonly [unknown, unknown, unknown];
}
interface Attempt {
  witness: Witness; epoch: number; context: ToolAcquisitionContext; after: number; previous: ToolAcquisitionIdentity | null;
  beforeStatus: ToolAcquisitionStatus; refusedBeforeAdmission: ToolAcquisitionPrerequisite | null; notAdmitted: boolean;
  identity: ToolAcquisitionIdentity | null; prepareSent: boolean; prepareJoined: boolean; prepareAccepted: boolean;
  startClaimed: boolean; startSent: boolean; startJoined: boolean; delegated: boolean; delegatedReturned: boolean; retired: boolean; unconfirmed: boolean;
  terminalRead: boolean; cancelRequested: boolean; cancelSent: boolean;
  requirements: ToolRequirementsObservation | null;
}
interface Inspection { witness: Witness; epoch: number; identity: ToolAcquisitionIdentity; result: ToolRequirementsObservation }
type Issue = 'unconfirmed' | 'protocol' | 'unknown';
export interface ToolAcquisitionState {
  native: boolean; visible: boolean; initialized: boolean; listening: boolean; reading: boolean;
  pending: 'inspect' | 'review' | 'download' | null; requestPending: boolean; cancelPending: boolean;
  projectId: string | null; status: ToolAcquisitionStatus | null; issue: Issue | null; historical: boolean;
  inspection: ToolRequirementsObservation | null;
  prerequisite: ToolAcquisitionPrerequisite | null;
  consent: (ToolAcquisitionIdentity & { acknowledged: boolean }) | null;
  presentation: StagedToolPresentation; preparedFolders: PreparedToolFolders | null; cancelRequested: boolean; cancelSent: boolean;
  checkReason: string | null; reviewReason: string | null; downloadReason: string | null;
  canRead: boolean; canCancel: boolean;
}
const identity = (v: ToolAcquisitionIdentity): ToolAcquisitionIdentity => ({ operationId: v.operationId, ownerGeneration: v.ownerGeneration });
const active = (op: ToolAcquisitionOperation | null | undefined): boolean => !!op && op.phase !== 'terminal';
function freeze<T>(v: T): T {
  if (v && typeof v === 'object' && !Object.isFrozen(v)) { Object.values(v).forEach(freeze); Object.freeze(v); }
  return v;
}
function sameWitness(a: Witness | null, b: Witness | null): boolean {
  return a === null || b === null ? a === b : a.observation === b.observation && a.draft === b.draft &&
    a.baseline === b.baseline && a.snapshot === b.snapshot && a.known.every((part, i) => part === b.known[i]) &&
    sameToolAcquisitionData(a.context, b.context);
}
const attention = 'The original tool request is unconfirmed. Check its status or cancel it; do not repeat the download or reconnect to dismiss it.';

export class ToolAcquisitionController {
  private readonly source: Source;
  private original: ToolAcquisitionApi | null = null;
  private api: ToolAcquisitionApi | null = null;
  private off: (() => void) | null = null;
  private subscribing: Promise<void> | null = null;
  private reading: Promise<ToolAcquisitionStatus | null> | null = null;
  private status: ToolAcquisitionStatus | null = null;
  private initialized = false;
  private issue: Issue | null = null;
  private attempt: Attempt | null = null;
  private inspection: Inspection | null = null;
  private witness: Witness | null = null;
  private readonly sourceFolders = new PreparedToolSourceHandoff();
  private epoch = 0;
  private mutation = 0;
  private action: ToolAcquisitionState['pending'] = null;
  private preparing = false;
  private starting = false;
  private cancelling = false;
  private cancelIdentity: ToolAcquisitionIdentity | null = null;
  private acknowledged = false;
  private consentOpen = false;
  private visible = false;
  private selectionPending = false;
  private connectionRetired = false;
  private disposed = false;
  private notifying = false;
  private listeners = new Set<() => void>();
  private state!: ToolAcquisitionState;
  constructor(source: Source) { this.source = source; this.witness = this.capture(); this.publish(); }
  getSnapshot = (): ToolAcquisitionState => this.state;
  subscribe = (listener: () => void): (() => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private capture(): Witness | null {
    try {
      const p = this.source.selectedProject();
      if (!p || !p.draft || !p.baseline || !p.snapshot || p.snapshot.root !== p.project.path || isDirty(p) ||
          p.snapshotRequest !== null || p.snapshotError !== null || p.snapshotPredatesSave || p.sourceChanged ||
          p.saveRecoveryRequired || p.saveRecoveryNeedsReload || p.observedAt === null || !Number.isFinite(p.observedAt) || p.observedAt < 0 ||
          !offlineCounter(p.observationGeneration) || p.observationGeneration < 1) return null;
      const observed = savedConfigFromSnapshot(p.snapshot), saved = parseSavedConfigContent(p.savedConfigContent);
      if (!observed || !saved || !sameSavedConfig(observed, saved)) return null;
      const context = parseToolAcquisitionContext({ projectId: p.project.id, draftRevision: p.revision,
        baselineGeneration: p.baselineGeneration, savedConfig: saved, action: 'inspect', review: null });
      if (!context) return null;
      const known = this.source.knownTools();
      return { context, observation: p.observationGeneration, draft: p.draft, baseline: p.baseline, snapshot: p.snapshot,
        known: [known[0], known[1], known[2]] };
    } catch { return null; }
  }
  private folderContext(witness = this.capture()): ToolSourceFolderContext | null {
    return witness && this.api && !this.disposed && !this.connectionRetired && !this.selectionPending && this.visible
      ? { connection: this.api, context: witness.context, observation: witness.observation, draft: witness.draft,
          baseline: witness.baseline, snapshot: witness.snapshot, catalog: witness.known[0], sources: witness.known[1], registration: witness.known[2] } : null;
  }
  private current(a: { witness: Witness; epoch: number }): boolean {
    return !this.disposed && !this.connectionRetired && !this.selectionPending && a.epoch === this.epoch && sameWitness(a.witness, this.capture());
  }
  private projectId(): string | null { try { return this.source.selectedProject()?.project.id ?? null; } catch { return null; } }
  private other(): string | null { try { return this.source.otherOperationReason(); } catch { return 'Wait for the other app operation to finish.'; } }
  private publish(): void {
    const a = this.attempt, op = this.status?.operation;
    const matched = !!a && sameToolAcquisitionIdentity(a.identity, op);
    const current = matched && !a.retired && this.current(a);
    const joined = matched && a.terminalRead && !this.preparing && !this.starting && !this.cancelling && !this.action && !this.reading && !this.issue;
    const consent = this.consentOpen && current && a.prepareAccepted && !a.startClaimed && op?.phase === 'awaiting-consent' && op.intentUsable
      ? { ...identity(op), acknowledged: this.acknowledged } : null;
    const presentation: StagedToolPresentation = this.issue || op?.phase === 'unknown' ? 'recovery-required' :
      op?.phase !== 'terminal' || !joined ? 'settling' : current && op.outcome === 'complete' &&
      ['available', 'busy'].includes(this.status!.availability) ? 'current-staged' : 'stale';
    this.state = freeze({ native: this.api !== null, visible: this.visible, initialized: this.initialized, listening: this.off !== null,
      reading: this.reading !== null || this.subscribing !== null, pending: this.action,
      requestPending: this.preparing || this.starting, cancelPending: this.cancelling, projectId: this.projectId(), status: this.status,
      issue: this.issue, historical: !!op && !current, inspection: this.inspection && this.current(this.inspection) ? this.inspection.result :
        current ? a.requirements : null,
      prerequisite: this.currentPrerequisite(),
      consent, presentation, preparedFolders: this.sourceFolders.preview(this.folderContext(),op,presentation), cancelRequested: a?.cancelRequested ?? this.cancelIdentity !== null,
      cancelSent: a?.cancelSent ?? this.cancelIdentity !== null, checkReason: this.checkReason(), reviewReason: this.reviewReason(),
      downloadReason: this.downloadReason(), canRead: !!this.api && !this.reading && !this.subscribing,
      canCancel: !!this.api && !!op && active(op) && !this.cancelling && !sameToolAcquisitionIdentity(this.cancelIdentity, op) });
    if (this.notifying) return;
    this.notifying = true;
    try { for (const listener of [...this.listeners]) { try { listener(); } catch { /* Rendering cannot release work. */ } } }
    finally { this.notifying = false; }
  }
  private retire(preserveSourceFolders = false): void {
    if (!preserveSourceFolders) this.sourceFolders.retire();
    if (this.epoch >= 0xffff_fffe) this.issue = 'protocol'; else this.epoch++;
    this.inspection = null; this.consentOpen = false; this.acknowledged = false;
    if (this.attempt) {
      this.attempt.retired = true;
      if (!this.attempt.startSent && !this.attempt.notAdmitted) this.attempt.cancelRequested = true;
    }
    this.publish(); this.cancelRetired();
  }
  // Call before the actual reducer, even if that action changes no bytes.
  beforeWorkspaceAction(action: WorkspaceAction): void {
    if (action.type === 'select' || action.type === 'switch') { this.selectionIntent(); return; }
    if (['snapshot-start', 'snapshot-done', 'snapshot-failed', 'new-draft', 'edit', 'remove-forbidden', 'undo-removal',
      'forget-removal', 'reset', 'adopt-suggestion', 'config-save-intent', 'config-save-final', 'config-save-recovery',
      'config-recovery-final', 'initialization-intent', 'initialization-final'].includes(action.type) &&
      (action.projectId === this.projectId() || action.projectId === this.attempt?.context.projectId)) this.retire();
  }
  selectionIntent(): void { this.retire(); }
  toolInputsIntent(): void { this.retire(); }
  async choosePreparedSource(role: AndroidToolSourceRole,
    choose: (role: AndroidToolSourceRole, original: PreparedToolSourcePick) => Promise<void>): Promise<void> {
    this.syncProject();
    if (this.ownerReason() || this.other()) return;
    const pick=this.sourceFolders.begin(this.folderContext(),this.status?.operation,this.state.presentation,role,() => this.folderContext());
    if (!pick) return;
    this.retire(true); // Only the separate directory nomination survives.
    try { if (pick.stillCurrent()) await choose(role,pick); }
    finally { pick.joined(); this.publish(); }
  }
  snapshotIntent(projectId: string): void { if (projectId === this.projectId() || projectId === this.attempt?.context.projectId) this.retire(); }
  versionIntent(): void { this.retire(); }
  syncProject(): void {
    const next = this.capture();
    const preserveFolders = this.sourceFolders.sync(this.folderContext(next));
    if (!sameWitness(this.witness, next)) { this.witness = next; this.retire(preserveFolders); } else this.publish();
  }
  setSelectionPending(value: boolean): void { if (value !== this.selectionPending) { this.selectionPending = value; this.retire(); } }
  setVisible(value: boolean): void {
    if (value === this.visible) return;
    this.visible = value;
    // Navigation never detaches a started operation. Only unstarted review is
    // retired; the compact app-level view keeps original status and Cancel.
    if (!value) this.retire(); else this.publish();
  }
  private fail(issue: Issue): void {
    this.sourceFolders.retire();
    if (this.issue === null || this.issue === 'unconfirmed') this.issue = issue;
    this.consentOpen = false; this.acknowledged = false; this.inspection = null;
    if (this.attempt && !this.attempt.startSent) { this.attempt.retired = true; this.attempt.cancelRequested = true; }
    this.publish(); this.cancelRetired();
  }
  ownerReason(): string | null {
    if (this.issue) return attention;
    if (this.action || this.preparing || this.starting || this.cancelling || this.reading || this.subscribing)
      return 'A tool request is still finishing. Its original status and cancel control remain available.';
    if (active(this.status?.operation) || this.attempt?.prepareSent && !this.attempt.terminalRead && !this.attempt.notAdmitted)
      return 'Finish or cancel the original tool preparation before starting another task.';
    return null;
  }
  private newWorkReason(ownIntent = false, peers = true): string | null {
    if (this.disposed || this.connectionRetired || !this.api) return 'Guided downloads need the original native app connection. Use existing tools or manual setup instead.';
    if (this.issue) return attention;
    if (!this.initialized || !this.off || !this.status) return 'Check the native tool status first.';
    if (this.status.statusRevision >= 0xffff_fffe) return 'The original tool status cannot accept another request.';
    if (this.status.availability !== 'available' && !(ownIntent && this.status.availability === 'busy'))
      return toolAcquisitionAvailabilityText[this.status.availability];
    if (!this.visible) return 'Open Check this computer to review tool preparation.';
    if (this.selectionPending) return 'Finish choosing the project first.';
    if (!this.capture()) return 'Save or revert your settings, then check the saved project files. An unsaved draft or earlier file check cannot prepare tools.';
    return peers ? this.other() : null;
  }
  checkReason(): string | null {
    const reason = this.newWorkReason(); if (reason) return reason;
    if (this.action || this.preparing || this.starting || this.cancelling || this.reading)
      return 'Wait for the current tool request to finish.';
    if (active(this.status?.operation) || this.attempt?.prepareSent && !this.attempt.terminalRead && !this.attempt.notAdmitted)
      return 'Finish or cancel the original tool request first.';
    const prerequisite = this.currentPrerequisite();
    return prerequisite ? TOOL_ACQUISITION_PREREQUISITE_TEXT[prerequisite] : null;
  }
  private currentPrerequisite(): ToolAcquisitionPrerequisite | null {
    const a = this.attempt;
    return !this.issue && a?.notAdmitted && !a.retired && this.current(a) ? a.refusedBeforeAdmission : null;
  }
  reviewReason(): string | null {
    const reason = this.checkReason(); if (reason) return reason;
    const i = this.inspection;
    if (!i || !this.current(i)) return 'Check this project’s required tools before reviewing a download.';
    if (i.result.protectedTools === 'reuse-selected')
      return 'The selected protected tools match this project. No download or replacement is needed; builds still run their own checks.';
    if (i.result.protectedTools !== 'none-in-supported-catalogue')
      return 'A matching supported tool selection was not confirmed. Use the existing Recover or Choose tools controls; do not replace working tools.';
    if (!i.result.components) return 'The selected folders have not been fully checked. Use the existing Choose and Inspect tools controls; nothing will be replaced.';
    if (i.result.discoveredSources?.compatibleComponents.length)
      return 'Found matching existing tools. Use the found folders or choose another installation, then check the remaining tools. No duplicate download will be offered.';
    if (!i.result.components.missing.length)
      return 'The chosen tool sources match. Nothing needs downloading. Inspect all selected tools and separately approve the protected copy.';
    const a = i.result.requirements.android;
    if ([a.jdk, a.agp, a.sdkPlatform, a.sdkBuildTools].some((hint) => hint.state === 'unknown') ||
        a.gradle.state !== 'literal' || a.gradle.sha256 === null)
      return 'Some required versions or the Gradle checksum could not be read safely. Use the manual route; no version will be guessed.';
    return null;
  }
  downloadReason(): string | null {
    const reason = this.newWorkReason(true); if (reason) return reason;
    const a = this.attempt, op = this.status?.operation;
    if (this.action || this.preparing || this.starting || this.cancelling || this.reading) return 'Wait for the original request to finish.';
    if (!a || a.context.action !== 'acquire' || a.retired || !this.current(a) || !a.prepareAccepted || a.startClaimed ||
        !this.consentOpen || !sameToolAcquisitionIdentity(a.identity, op) || op?.phase !== 'awaiting-consent' || !op.intentUsable)
      return 'Review this download again before giving approval.';
    return this.acknowledged ? null : 'Confirm the download below. Nothing is installed automatically.';
  }
  beginConnection(): boolean {
    this.connectionRetired = true; this.retire();
    if (this.ownerReason()) return false;
    this.detach(); this.original = null; this.api = null; this.status = null; this.initialized = false; this.attempt = null;
    this.cancelIdentity = null; this.publish(); return true;
  }
  async connect(api: ToolAcquisitionApi | null): Promise<void> {
    if (this.disposed || api === this.original) return;
    if (this.api && !this.beginConnection()) return; // Keep the OLD connection.
    if (!api) { this.publish(); return; }
    const { prepare, start, status, cancel, subscribe } = api;
    if (api.mode !== 'native' || ![prepare, start, status, cancel, subscribe].every((f) => typeof f === 'function')) { this.fail('protocol'); return; }
    this.original = api;
    this.api = Object.freeze({ mode: 'native' as const,
      prepare: (r: ToolAcquisitionContext) => prepare.call(api, r), start: (r: ToolAcquisitionStart) => start.call(api, r),
      status: () => status.call(api), cancel: (r: ToolAcquisitionIdentity) => cancel.call(api, r),
      subscribe: (listener: (v: unknown) => void) => subscribe.call(api, listener) });
    this.connectionRetired = false; this.issue = null; this.publish(); await this.checkStatus();
  }
  private async listen(): Promise<void> {
    if (this.off || !this.api) return;
    if (this.subscribing) return this.subscribing;
    const api = this.api;
    const work = Promise.resolve().then(async () => {
      try {
        const off = await api.subscribe((v) => { if (this.api === api) this.receive(v, 'event'); });
        if (typeof off !== 'function') { this.fail('protocol'); return; }
        this.off = off;
      } catch { this.fail('unconfirmed'); }
    });
    this.subscribing = work; this.publish();
    try { await work; } finally { if (this.subscribing === work) this.subscribing = null; this.publish(); this.detachIfFinished(); }
  }
  private receive(value: unknown, source: 'event' | 'reply' | 'read'): ToolAcquisitionStatus | null {
    const s = parseToolAcquisitionStatus(value);
    if (!s) { this.fail('protocol'); return null; }
    const before = this.status, p = before?.operation, op = s.operation, a = this.attempt;
    if (before && s.statusRevision < before.statusRevision) {
      if (p && op && sameToolAcquisitionIdentity(p, op) && !toolAcquisitionProgress(op, p)) this.fail('protocol');
      return null; // Out-of-order events/replies cannot renew a review.
    }
    if (before && s.statusRevision === before.statusRevision && !sameToolAcquisitionData(before, s) ||
        p && op && sameToolAcquisitionIdentity(p, op) && !toolAcquisitionProgress(p, op)) { this.fail('protocol'); return null; }
    if (a?.refusedBeforeAdmission && !a.notAdmitted && !sameToolAcquisitionData(a.beforeStatus, s)) {
      this.fail('protocol'); return null; // Never promote a refusal into an entered or different original.
    }
    const candidate = a?.prepareSent && !a.notAdmitted && op && s.statusRevision > a.after && !sameToolAcquisitionIdentity(a.previous, op) &&
      sameToolAcquisitionData(a.context, op.context);
    if (a?.prepareSent && !a.notAdmitted) {
      if (a.identity ? !sameToolAcquisitionIdentity(a.identity, op) : op && !sameToolAcquisitionIdentity(a.previous, op) && !candidate) {
        this.fail('protocol'); return null;
      }
      if (candidate) {
        if (!a.startSent && !a.delegated && (op.phase === 'starting' || op.phase === 'running' || op.outcome === 'complete')) { this.fail('protocol'); return null; }
        if (!a.identity) a.identity = identity(op);
      }
    } else if (before && (p || op) && !sameToolAcquisitionIdentity(p, op)) { this.fail('protocol'); return null; }
    if (a?.context.action === 'acquire' && op?.outcome === 'complete' && sameToolAcquisitionIdentity(a.identity, op) &&
        (op.result?.kind !== 'staged-tool-sources' || !stagedMatchesComponents(op.result, a.requirements?.components ?? null))) {
      this.fail('protocol'); return null; // A compatible installation must never appear in this download result.
    }
    this.status = s;
    if (source === 'read') this.initialized = true;
    if (s.availability === 'cleanup-unknown' || op?.phase === 'unknown') this.fail('unknown');
    if (op?.phase !== 'awaiting-consent' || !op.intentUsable) { this.consentOpen = false; this.acknowledged = false; }
    this.publish(); this.cancelRetired();
    if (source === 'event' && a?.startJoined && !a.terminalRead && op?.phase === 'terminal' && !this.reading && !this.cancelling)
      void this.checkStatus(); // Passive original read, never a Start/retry.
    return s;
  }
  async checkStatus(fresh = false): Promise<ToolAcquisitionStatus | null> {
    if (!this.api) return null;
    await this.listen();
    // A post-invoke check cannot reuse a read begun before that invocation
    // joined. Serialize actual reads even when several callers ask for fresh.
    while (this.reading) { const previous = await this.reading; if (!fresh) return previous; }
    if (!this.api) return null;
    const api = this.api, a = this.attempt, barrier = this.mutation;
    const afterInvoke = !!a && a.prepareJoined && (a.delegated ? a.delegatedReturned : !a.startSent || a.startJoined) && !this.preparing && !this.starting && !this.cancelling;
    const work = Promise.resolve().then(async () => {
      try {
        const s = this.receive(await api.status(), 'read');
        if (!s || api !== this.api) return null;
        const op = s.operation;
        if (a?.refusedBeforeAdmission && !a.notAdmitted && afterInvoke) {
          if (a === this.attempt && barrier === this.mutation && !this.issue && !a.unconfirmed && !a.retired && this.current(a) &&
              this.other() === null && a.prepareJoined && !a.identity && !a.prepareAccepted && !a.startSent && !active(op) &&
              sameToolAcquisitionData(a.beforeStatus, s) && s.statusRevision === a.after &&
              (a.previous === null ? op === null : sameToolAcquisitionIdentity(a.previous, op))) {
            a.notAdmitted = true; // A joined refused call, NOT a terminal operation or a native finality receipt.
          } else { a.unconfirmed = true; this.fail('unconfirmed'); }
        } else if (a && a === this.attempt && afterInvoke && barrier === this.mutation && sameToolAcquisitionIdentity(a.identity, op) && op?.phase === 'terminal') {
          a.terminalRead = true; a.unconfirmed = false;
          if (this.issue === 'unconfirmed') this.issue = null;
          if (!this.issue && (a.startSent || a.delegatedReturned) && !a.retired && this.current(a) && a.context.action === 'inspect' &&
              op.outcome === 'complete' && op.result?.kind === 'tool-requirements-observation')
            this.inspection = { witness: a.witness, epoch: a.epoch, identity: identity(op), result: op.result };
        } else if (this.issue === 'unconfirmed' && !a && !active(op)) this.issue = null;
        return s;
      } catch { this.fail('unconfirmed'); return null; }
    });
    this.reading = work; this.publish();
    try { return await work; } finally { if (this.reading === work) this.reading = null; this.publish(); this.detachIfFinished(); }
  }
  private usable(a: Attempt): boolean {
    const op = this.status?.operation;
    return !this.issue && !a.retired && this.current(a) && this.visible && a.prepareAccepted && !a.startSent && !a.delegated &&
      sameToolAcquisitionIdentity(a.identity, op) && op?.phase === 'awaiting-consent' && op.intentUsable && this.newWorkReason(true) === null;
  }
  async inspect(): Promise<void> { if (!this.checkReason()) await this.prepare('inspect'); }
  async reviewDownload(): Promise<void> { if (!this.reviewReason()) await this.prepare('acquire'); }
  private async prepare(action: 'inspect' | 'acquire', forCli = false): Promise<void> {
    const witness = this.capture(), api = this.api, inspected = this.inspection;
    if (!witness || !api || !this.status || action === 'acquire' && !inspected) return;
    const context: ToolAcquisitionContext = freeze({ ...witness.context, action, review: action === 'acquire' ?
      { ...inspected!.identity, requirementsSha256: inspected!.result.requirements.sourcesSha256 } : null });
    const a: Attempt = { witness, epoch: this.epoch, context, after: this.status.statusRevision,
      beforeStatus: this.status, refusedBeforeAdmission: null, notAdmitted: false,
      previous: this.status.operation && identity(this.status.operation), identity: null, prepareSent: false, prepareJoined: false, prepareAccepted: false,
      startClaimed: false, startSent: false, startJoined: false, delegated: false, delegatedReturned: false, retired: false, unconfirmed: false, terminalRead: false, cancelRequested: false, cancelSent: false,
      requirements: action === 'acquire' ? inspected!.result : null };
    this.sourceFolders.retire();
    this.attempt = a; this.cancelIdentity = null; this.consentOpen = false; this.acknowledged = false;
    this.inspection = null; // A checked observation can prepare at most one download.
    this.action = action === 'inspect' ? 'inspect' : 'review'; this.publish();
    try {
      if (!this.current(a) || a.retired || !this.visible) return;
      this.preparing = true; this.publish();
      try {
        if (!this.current(a) || a.retired || !this.visible) return;
        a.prepareSent = true; this.mutation++;
        const s = this.receive(await api.prepare(context), 'reply');
        a.prepareAccepted = !!s && sameToolAcquisitionIdentity(a.identity, s.operation) && s.operation?.phase === 'awaiting-consent' && s.operation.intentUsable;
        if (!s) { a.unconfirmed = true; this.fail('unconfirmed'); }
      } catch (error) {
        const prerequisite = toolAcquisitionPrerequisite(error);
        if (prerequisite && (a.identity || a.prepareAccepted || a.startSent)) {
          a.unconfirmed = true; this.fail('protocol'); // Contradicts an already observed admission.
        } else if (prerequisite && a.prepareSent && !this.issue && !a.unconfirmed && !a.retired && this.current(a))
          a.refusedBeforeAdmission = prerequisite;
        else { a.unconfirmed = true; this.fail('unconfirmed'); }
      }
      finally { a.prepareJoined = true; this.preparing = false; this.publish(); }
      const read = await this.checkStatus(true);
      if (a.refusedBeforeAdmission) {
        if (!a.notAdmitted) { a.unconfirmed = true; this.fail('unconfirmed'); }
        return; // Explicit catalogue/saved read then a NEW user check; never Start or retry this call.
      }
      if (!read || !this.usable(a)) { a.retired = true; a.cancelRequested = true; return; }
      if (action === 'inspect' && !forCli) {
        // Only this explicit Check click may chain its own INSPECT intent.
        a.startClaimed = true; await this.sendStart(a, api);
      } else if (action === 'acquire') { this.consentOpen = true; this.acknowledged = false; }
    } finally { this.action = null; this.publish(); this.cancelRetired(); this.detachIfFinished(); }
  }
  // Explicit Advanced action: real Prepare + post-return read, without the
  // ordinary Check button's automatic Start. No alternate native admission.
  async prepareForCli(): Promise<void> { if (!this.checkReason()) await this.prepare('inspect', true); }
  toolSetupReview(): ToolSetupReview | null {
    const a=this.attempt,op=this.status?.operation;
    if (!a||!op||a.delegated||a.startClaimed||!a.prepareJoined||!a.prepareAccepted||a.retired||!this.current(a)||this.issue||
        this.preparing||this.starting||this.cancelling||this.reading||this.action||this.newWorkReason(true,false)||
        !sameToolAcquisitionIdentity(a.identity,op)||op.phase!=='awaiting-consent'||!op.intentUsable)return null;
    return parseToolSetupReview({kind:a.context.action==='inspect'?'inspect-requirements':'acquire-missing',platform:'android',
      draftRevision:a.context.draftRevision,baselineGeneration:a.context.baselineGeneration,
      prepared:{...identity(op),statusRevision:this.status!.statusRevision},sources:null});
  }
  delegateToolSetup(review:ToolSetupReview):ToolSetupDelegation|null {
    if(!sameToolSetupReview(this.toolSetupReview(),review))return null;
    const a=this.attempt!,api=this.api!;
    a.delegated=true;a.startClaimed=true;this.consentOpen=false;this.acknowledged=false;this.publish();
    return {input:{projectId:a.context.projectId,review,doctorDraft:null,sourceContext:null,nativeConsent:TOOL_ACQUISITION_CONSENT,licenseAcknowledged:false},
      current:()=>{const status=this.status;return !!status&&this.attempt===a&&this.api===api&&!a.retired&&this.current(a)&&!this.issue&&status.statusRevision===review.prepared?.statusRevision&&
        sameToolAcquisitionIdentity(a.identity,status.operation)&&status.operation?.phase==='awaiting-consent'&&status.operation.intentUsable;},
      readAfterReturned:async status=>{
        if(this.attempt!==a||this.api!==api||status&&(!sameToolSetupReview(status.review,review)||status.settlement!=='settled'||
          status.operation!==null&&!sameToolAcquisitionIdentity(a.identity,{operationId:status.operation.operationId,ownerGeneration:status.operation.ownerGeneration??''})))return false;
        // Genuine service/caller return, NOT the GUI Start Promise. The fresh
        // read below alone may set terminalRead and restore the original result.
        a.delegatedReturned=true;const read=await this.checkStatus(true);
        return !!read&&this.attempt===a&&a.terminalRead&&!this.issue&&sameToolAcquisitionIdentity(a.identity,read.operation)&&read.operation?.phase==='terminal';
      }};
  }
  setAcknowledged(operationId: string, ownerGeneration: string, value: boolean): void {
    const a = this.attempt;
    if (!this.consentOpen || !a || a.context.action !== 'acquire' || a.startClaimed ||
        !sameToolAcquisitionIdentity(a.identity, { operationId, ownerGeneration }) || !this.usable(a)) return;
    this.acknowledged = value === true; this.publish();
  }
  async download(operationId: string, ownerGeneration: string): Promise<void> {
    const a = this.attempt, api = this.api;
    if (!a || !api || !sameToolAcquisitionIdentity(a.identity, { operationId, ownerGeneration }) || this.downloadReason()) return;
    // One-use approval is burned before the status await, subscriber or invoke.
    a.startClaimed = true; this.consentOpen = false; this.acknowledged = false; this.action = 'download'; this.publish();
    try {
      if (await this.checkStatus(true) && this.usable(a)) await this.sendStart(a, api);
      else { a.retired = true; a.cancelRequested = true; }
    } finally { this.action = null; this.publish(); this.cancelRetired(); this.detachIfFinished(); }
  }
  private async sendStart(a: Attempt, api: ToolAcquisitionApi): Promise<void> {
    if (!a.identity || !this.usable(a)) return;
    this.starting = true; this.publish();
    try {
      if (!this.usable(a)) { a.retired = true; a.cancelRequested = true; return; }
      a.startSent = true; this.mutation++; a.terminalRead = false;
      if (!this.receive(await api.start({ ...a.identity, consentVersion: TOOL_ACQUISITION_CONSENT }), 'reply')) a.unconfirmed = true;
    }
    catch { a.unconfirmed = true; this.fail('unconfirmed'); }
    finally { a.startJoined = true; this.starting = false; this.publish(); }
    await this.checkStatus(true); // Never call a Start reply a completed download.
  }
  private cancelRetired(): void {
    const a = this.attempt;
    if (a?.cancelRequested && a.identity && !a.cancelSent && !this.cancelling && this.status?.operation?.phase !== 'terminal') void this.cancel();
  }
  async cancel(): Promise<void> {
    const api = this.api, op = this.status?.operation, a = this.attempt;
    const target = a?.identity ?? (op ? identity(op) : null);
    if (a) { a.cancelRequested = true; a.retired = true; }
    this.consentOpen = false; this.acknowledged = false; this.inspection = null;
    if (!api || !target || this.cancelling || sameToolAcquisitionIdentity(this.cancelIdentity, target) || op?.phase === 'terminal' && sameToolAcquisitionIdentity(op, target)) { this.publish(); return; }
    this.cancelIdentity = target; if (a) { a.cancelSent = true; a.terminalRead = false; }
    this.cancelling = true; this.mutation++; this.publish();
    try { this.receive(await api.cancel(target), 'reply'); }
    catch { if (a) a.unconfirmed = true; this.fail('unconfirmed'); }
    finally { this.cancelling = false; this.publish(); }
    await this.checkStatus(true);
  }
  private detach(): void { const off = this.off; this.off = null; try { off?.(); } catch { /* Not native settlement. */ } }
  private detachIfFinished(): void { if (this.disposed && !this.ownerReason()) this.detach(); }
  dispose(): void {
    this.disposed = true; this.retire(); this.listeners.clear();
    if (active(this.status?.operation)) void this.cancel();
    this.detachIfFinished();
  }
}
