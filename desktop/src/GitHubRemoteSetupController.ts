import { parseGithubActionStatus, sameGithubActionSelection } from './agentGithubActionAccess.ts';
import type { GithubActionDelegate, GithubActionSelection, GithubActionStatus } from './agentGithubActionAccess.ts';
import { isGithubRemoteSettingsKind, parseGithubRemoteSettingsSelection, githubRemoteSettingsPreparedHash, githubRemoteSettingsResultMatches } from './githubRemoteSetupDelegation.ts';
import type { GithubRemoteSettingsKind, GithubRemoteSettingsSelection, RemoteSetting } from './githubRemoteSetupDelegation.ts';
// Coordinates only the original native Setup session. No token, HTTP, polling,
// retry, local workflow write or renderer-created consent is used here.
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { sameConnectionData as same } from './githubConnectionProtocol.ts';
import type { GitHubConnectionViewState } from './githubConnectionTypes.ts';
import { GITHUB_REMOTE_SETUP_HELP, githubRemoteSetupError, githubRemoteSetupObservationMatches, githubRemoteSetupSelection, githubRemoteSetupSecretReferences, githubRemoteSetupVariableReferences, parseGitHubRemoteSetupStatus } from './GitHubRemoteSetupProtocol.ts';
import type { GitHubRemoteSetupApi, GitHubRemoteSetupConsent, GitHubRemoteSetupReason, GitHubRemoteSetupSelection,
  GitHubRemoteSetupStatus, GitHubRemoteSetupView } from './GitHubRemoteSetupTypes.ts';
type MaterialBinding = { source: { recordId: string; recordRevision: number; contextRevision: number }; context: NonNullable<NonNullable<AssetDisplayState['status']>['context']>; mode: string; storage: string };
function usesMaterial(s: GitHubRemoteSetupSelection | null | undefined): s is Extract<GitHubRemoteSetupSelection, { kind: 'environment_secret' | 'environment_variable' }> {
  return s?.kind === 'environment_secret' || s?.kind === 'environment_variable';
}
type Port = GitHubRemoteSetupApi & { mode: 'native' | 'preview' | 'unavailable' };
type Context = { documentId: string; projectId: string; projectGeneration: number; repository: string; sessionId: string; accountId: string; repositoryId: string };
type Observer = { api: Port; active: boolean; unlisten: (() => void) | null; ready: Promise<void> | null; reading: Promise<void> | null; accepted: GitHubRemoteSetupStatus | null };
type Pending = { observer: Observer; context: Context; epoch: object; selection: GitHubRemoteSetupSelection; kind: 'prepare' | 'apply';
  revision: number; previousId: string | null; operationId: string | null; sent: boolean; cancelAfterAdmission: boolean; cancelRequested: boolean; reviewed: GitHubRemoteSetupConsent | null; asset: MaterialBinding | null };
type Review = { observer: Observer; context: Context; epoch: object; consent: GitHubRemoteSetupConsent; asset: MaterialBinding | null };
type AgentOrigin = { observer:Observer; context:Context; epoch:object; selection:GithubRemoteSettingsSelection; setting:RemoteSetting; asset:MaterialBinding|null; review:Review|null; originalId:string|null; allowed:boolean; unused:boolean; noAllow:boolean; terminal:GithubActionStatus|null; unknown:boolean; released:boolean };
type AgentCheck = { origin:AgentOrigin; allowed:boolean; unused:boolean; noAllow:boolean; terminal:GithubActionStatus|null; status:GitHubRemoteSetupStatus|null };
type Discard = { observer: Observer; session: string; consent: string; revision: number };
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); } return value;
}
function context(view: GitHubConnectionViewState): Context | null {
  const c = view.context, s = view.status, session = s?.session;
  if (!c || !session || view.mode !== 'native' || view.retirementPending || view.uncertain || view.blocked || view.busy ||
      session.state !== 'connected' || session.projectId !== c.projectId || session.targetRepository !== c.repository ||
      s.account.state !== 'observed' || !s.account.value || s.repository.state !== 'observed' || !s.repository.value ||
      s.repository.value.fullName.toLowerCase() !== c.repository.toLowerCase()) return null;
  return { ...c, repository: s.repository.value.fullName, sessionId: session.id, accountId: s.account.value.id, repositoryId: s.repository.value.id };
}
function inContext(consent: GitHubRemoteSetupConsent, c: Context, selection: GitHubRemoteSetupSelection): boolean {
  const t = consent.prepared.target;
  return t.repository === c.repository && t.accountId === c.accountId && t.repositoryId === c.repositoryId && same(t.selection, selection);
}
function progress(old: GitHubRemoteSetupStatus, next: GitHubRemoteSetupStatus): boolean {
  if (old.revision === next.revision) return same(old, next);
  if (old.revision > next.revision || old.reason === 'cleanup-unknown' || old.operation?.phase === 'cleanup-unknown') return false;
  const a = old.operation, b = next.operation;
  if (a && b?.id === a.id) {
    if (a.kind !== b.kind || a.phase === 'settled' && !same(a, b) || a.phase === 'stopping' && b.phase === 'running' ||
        a.effect === 'unknown' && b.phase !== 'settled' && b.effect !== 'unknown') return false;
  } else if (a && a.phase !== 'settled') return false;
  if (old.consent && next.consent && old.sessionId === next.sessionId && old.consent.id === next.consent.id && !same(old.consent, next.consent)) return false;
  return true;
}
export class GitHubRemoteSetupController {
  private state: GitHubRemoteSetupView = freeze({ mode: 'unavailable', status: null, selection: null, originalTarget: null, confirmed: false,
    pending: false, observing: false, cancelling: false, discarding: false, uncertain: false, error: null });
  private listeners = new Set<() => void>();
  private api: Port | null = null;
  private observer: Observer | null = null;
  private current: Context | null = null;
  private epoch: object = {};
  private pending: Pending | null = null;
  private actionCall: Pending | null = null; // Actual original Promise, not a terminal event.
  private agent: AgentOrigin | null = null;
  private review: Review | null = null;
  private discard: Discard | null = null;
  private retired: { observer: Observer; session: string; consent: string } | null = null;
  private discardUnknown = false;
  private blocked = false;
  private disposed = false;
  private cancelId: string | null = null;
  private cancelObserver: Observer | null = null;
  private connection: () => GitHubConnectionViewState;
  private otherOperationReason: () => string | null;
  private assets: () => AssetDisplayState | null;
  private selectedAsset: MaterialBinding | null = null;
  constructor(connection: () => GitHubConnectionViewState, otherOperationReason: () => string | null = () => null,
    assets: () => AssetDisplayState | null = () => null) { this.connection = connection; this.otherOperationReason = otherOperationReason; this.assets = assets; }
  private assetBinding(selection: GitHubRemoteSetupSelection): MaterialBinding | null {
    if (!usesMaterial(selection)) return null;
    const projectId = context(this.connection())?.projectId;
    if (!projectId) return null;
    const refs = (selection.kind === 'environment_secret' ? githubRemoteSetupSecretReferences(this.assets(), projectId, selection.requirement, selection.stage) :
      githubRemoteSetupVariableReferences(this.assets(), projectId, selection.requirement, selection.stage)).filter((r) => same(r.source, selection.source));
    const ref = refs[0];
    if (refs.length !== 1 || !ref) return null;
    const { source, context: c, mode, storage } = ref;
    return { source, context: c, mode, storage }; // Label/status revision is not material identity.
  }
  private assetCurrent(selection: GitHubRemoteSetupSelection, captured: MaterialBinding | null): boolean {
    return !usesMaterial(selection) || captured !== null && same(captured, this.assetBinding(selection));
  }
  syncAssetSession = (): void => {
    if (this.disposed) return;
    const selected = this.state.selection, p = this.pending, r = this.review;
    const changed = usesMaterial(selected) && !this.assetCurrent(selected, this.selectedAsset) ||
      p && usesMaterial(p.selection) && p.epoch === this.epoch && !this.assetCurrent(p.selection, p.asset) ||
      r && usesMaterial(r.consent.prepared.target.selection) && !this.assetCurrent(r.consent.prepared.target.selection, r.asset);
    if (changed) { this.selectedAsset = null; this.invalidate({ ...(usesMaterial(selected) ? { selection: null } : {}), error: 'material-changed' }); }
  };
  getSnapshot = (): GitHubRemoteSetupView => this.state;
  subscribe = (fn: () => void): (() => void) => { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; };
  private update(patch: Partial<GitHubRemoteSetupView>): void {
    if (this.disposed) return;
    this.state = freeze({ ...this.state, ...patch, pending: this.pending !== null || this.actionCall !== null || this.agent !== null }); this.listeners.forEach((fn) => fn());
  }
  private invalidate(patch: Partial<GitHubRemoteSetupView> = {}): void {
    this.epoch = {}; this.review = null;
    if (this.pending && !this.pending.sent) { this.pending = null; patch.pending = false; }
    else if (this.pending) this.pending.cancelAfterAdmission = true;
    this.update({ confirmed: false, ...patch }); this.stopInvalidatedOriginal(); this.retireConsent();
  }
  private stopInvalidatedOriginal(): void {
    const p = this.pending, op = p?.observer.accepted?.operation;
    // The private start/returned-status correlation, not an arbitrary visible ID,
    // must identify THIS controller's original. One automatic stop per original.
    if (!p || !p.cancelAfterAdmission || p.cancelRequested || !p.operationId || p.observer !== this.observer ||
        !op || op.id !== p.operationId || op.phase === 'settled' || this.cancelObserver) return;
    this.cancel();
  }
  // Called before reducer changes, including failed/unchanged edit attempts.
  beforeWorkspaceAction(): void { if (!this.disposed) this.invalidate({ error: 'target-changed' }); }
  syncContext = (): void => {
    if (this.disposed) return;
    const c = context(this.connection());
    if (!same(c, this.current)) { this.current = c; this.selectedAsset = null; this.invalidate({ selection: null, error: this.pending ? 'target-changed' : null }); }
  };
  setSelection(value: GitHubRemoteSetupSelection | null): void {
    if (this.disposed || value !== null && !githubRemoteSetupSelection(value) || same(value, this.state.selection)) return;
    this.selectedAsset = value === null ? null : this.assetBinding(value);
    this.invalidate({ selection: value === null ? null : structuredClone(value), error: null });
  }
  setConfirmed(value: boolean): void { this.update({ confirmed: value === true && !this.agent && this.currentConsent() !== null }); }
  private needsOriginal(o: Observer): boolean {
    return this.agent?.observer === o || this.actionCall?.observer === o || o.reading !== null || this.pending?.observer === o && this.pending.sent || this.cancelObserver === o || this.discard?.observer === o || this.retired?.observer === o ||
      !!o.accepted?.operation && o.accepted.operation.phase !== 'settled';
  }
  private detach(o: Observer): void {
    o.active = false; const stop = o.unlisten; o.unlisten = null; try { stop?.(); } catch { /* Listener closure is not native finality. */ }
  }
  private maintain(): Observer | null {
    if (this.observer && (this.disposed || this.observer.api !== this.api)) {
      if (this.needsOriginal(this.observer)) return this.observer;
      this.detach(this.observer); this.observer = null;
    }
    if (!this.observer && !this.disposed && this.api?.mode === 'native') {
      const o: Observer = { api: this.api, active: true, unlisten: null, ready: null, reading: null, accepted: null };
      this.observer = o; o.ready = this.monitor(o);
    }
    return this.observer;
  }
  async connect(api: Port | null): Promise<void> {
    if (this.disposed || api === this.api) return;
    this.api = api; this.syncContext(); this.invalidate({ mode: api?.mode ?? 'unavailable' }); await this.maintain()?.ready;
  }
  private async monitor(o: Observer): Promise<void> {
    try {
      const stop = await o.api.subscribeGitHubRemoteSetup((v) => { this.receive(o, v); });
      if (!o.active) { try { stop(); } catch { /* No native receipt. */ } return; }
      o.unlisten = stop; await this.read(o);
    } catch { if (o.active) this.fail('runtime-unavailable'); }
  }
  private fail(reason: GitHubRemoteSetupReason): void { this.blocked = true; this.review = null; this.update({ uncertain: true, confirmed: false, error: reason }); }
  private origin(p: Pending, s: GitHubRemoteSetupStatus): boolean {
    const op = s.operation;
    if (!p.sent || s.revision <= p.revision || s.sessionId !== p.context.sessionId || !op || op.kind !== p.kind ||
        op.id === p.previousId || p.operationId !== null && op.id !== p.operationId) return false;
    if (s.consent && (p.kind !== 'prepare' || !inContext(s.consent, p.context, p.selection))) return false;
    if (p.kind === 'apply' && (op.effect === 'readback-confirmed' || op.effect === 'accepted-not-value-verified') &&
        (!p.reviewed || (p.selection.kind === 'environment_secret') !== (op.effect === 'accepted-not-value-verified') || !githubRemoteSetupObservationMatches(p.reviewed.prepared, s.observed))) return false;
    return true;
  }
  private correlate(o: Observer, seen: GitHubRemoteSetupStatus): void {
    const p = this.pending;
    if (!p || p.observer !== o || !this.origin(p, seen)) return;
    p.operationId = seen.operation!.id;
    const s = o.accepted;
    if (!s || !this.origin(p, s)) return;
    if (s.operation!.phase === 'cleanup-unknown') { this.fail('cleanup-unknown'); this.stopInvalidatedOriginal(); return; }
    if (s.operation!.phase !== 'settled') { this.stopInvalidatedOriginal(); return; }
    this.pending = null;
    if (!this.blocked && p.kind === 'prepare' && s.consent && p.epoch === this.epoch && o.api === this.api &&
        same(p.context, context(this.connection())) && same(p.selection, this.state.selection) && this.assetCurrent(p.selection, p.asset)) {
      this.review = { observer: o, context: p.context, epoch: p.epoch, consent: s.consent, asset: p.asset };
    }
    this.update({ pending: false, uncertain: this.blocked, error: this.blocked ? this.state.error : s.operation!.reason === 'none' ? null : s.operation!.reason });
  }
  private receive(o: Observer, value: unknown): GitHubRemoteSetupStatus | null {
    if (!o.active) return null;
    this.syncAssetSession(); // Recheck even if an asset subscription was delayed.
    const parsed = parseGitHubRemoteSetupStatus(value);
    if (!parsed) { this.fail('response-invalid'); return null; }
    const s = freeze(structuredClone(parsed)), old = o.accepted;
    if (old && s.revision < old.revision) { if (progress(s, old)) this.correlate(o, s); return s; }
    if (old && !progress(old, s)) { this.fail('response-invalid'); return null; }
    o.accepted = s;
    if (s.reason === 'cleanup-unknown' || s.operation?.phase === 'cleanup-unknown') this.fail('cleanup-unknown');
    if (this.review && (s.sessionId !== this.review.context.sessionId || !same(s.consent, this.review.consent))) {
      this.review = null; this.update({ confirmed: false });
    }
    if (this.retired?.observer === o && (this.retired.session !== s.sessionId || this.retired.consent !== s.consent?.id)) {
      this.retired = null;
      if (this.discardUnknown) { this.discardUnknown = false; this.update({ uncertain: this.blocked || this.pending !== null || this.cancelId !== null }); }
    }
    this.update({ status: s }); this.correlate(o, s);
    if (this.cancelId === s.operation?.id && s.operation.phase === 'settled') { this.cancelId = null; this.update({ uncertain: this.blocked || this.pending !== null }); }
    this.retireConsent(); this.maintain(); return s;
  }
  private async read(o: Observer): Promise<void> {
    if (!o.active || o.reading) return o.reading ?? undefined;
    const d=this.agent, check:AgentCheck|null=d?.observer===o?{origin:d,allowed:d.allowed,unused:d.unused,noAllow:d.noAllow,terminal:d.terminal,status:null}:null;
    const work = Promise.resolve().then(async () => {
      if (!o.active) return;
      try { const status=this.receive(o, await o.api.githubRemoteSetupStatus()); if(check)check.status=status; } catch { if (o.active) this.update({ error: 'response-invalid' }); }
    });
    o.reading = work; this.update({ observing: true });
    try { await work; } finally { if (o.reading === work) { o.reading = null; this.update({ observing: false }); if(check)this.settleAgent(check); this.maintain(); } }
  }
  checkStatus(): Promise<void> { const o = this.maintain(); return !this.disposed && o ? this.read(o) : Promise.resolve(); }
  currentConsent(): GitHubRemoteSetupConsent | null {
    const r = this.review, c = context(this.connection()), s = this.state.status;
    return r && !this.blocked && !this.retired && !this.discard && r.epoch === this.epoch && r.observer === this.observer && r.observer.api === this.api &&
      c && same(c, r.context) && s?.sessionId === c.sessionId && same(s.consent, r.consent) && same(this.state.selection, r.consent.prepared.target.selection) && this.assetCurrent(r.consent.prepared.target.selection, r.asset) ? r.consent : null;
  }
  // Discard is local native grant retirement, never a remote write or retry.
  private retireConsent(): void {
    const o = this.observer, s = o?.accepted;
    if (!o || !s?.consent || !s.sessionId || s.operation?.phase !== 'settled' || this.review || this.pending || this.actionCall || this.agent?.observer === o || this.discard || this.retired) return;
    this.retired = { observer: o, session: s.sessionId, consent: s.consent.id }; this.sendDiscard(o, s);
  }
  private sendDiscard(o: Observer, s: GitHubRemoteSetupStatus): void {
    if (!s.consent || !s.sessionId || this.discard) return;
    const d: Discard = { observer: o, session: s.sessionId, consent: s.consent.id, revision: s.revision };
    this.discard = d; this.update({ discarding: true, confirmed: false });
    const done = () => { if (this.discard === d) { this.discard = null; this.update({ discarding: false }); this.maintain(); } };
    const failed = () => { if (this.discard === d && this.retired) { this.discardUnknown = true; this.update({ uncertain: true, error: 'response-invalid' }); } };
    try { void o.api.githubRemoteSetupDiscard({ sessionId: d.session, expectedRevision: d.revision, consentId: d.consent }).then((v) => {
      this.receive(o, v); if (this.retired) failed();
    }, failed).finally(done); } catch { failed(); done(); }
  }
  discardReview(): void {
    if (this.disposed) return;
    this.invalidate();
    const o = this.observer, s = o?.accepted;
    if (!this.discard && o && s?.consent && s.operation?.phase === 'settled' && this.retired) this.sendDiscard(o, s);
  }
  startReason(): string | null {
    if (this.disposed || this.state.mode !== 'native' || !this.api || this.observer?.api !== this.api) return 'A current native GitHub session is required. Browser preview never changes repository settings.';
    if (this.blocked || this.state.uncertain) return 'Original acknowledgement or cleanup is unconfirmed. Read local Status; do not repeat Apply.';
    if (this.agent || this.actionCall || this.pending || this.discard || this.retired || this.state.cancelling || this.state.status?.operation && this.state.status.operation.phase !== 'settled') return 'Wait for the original action or consent retirement. Status and Stop original remain available.';
    const c = context(this.connection()), s = this.state.status;
    if (!c || !s || !this.observer?.accepted || s.sessionId !== c.sessionId) return 'Connect the selected project’s repository and read local Status first.';
    if (s.consent && !this.currentConsent()) return 'The previous native consent must be retired before another operation.';
    if (!s.available) return GITHUB_REMOTE_SETUP_HELP[s.reason];
    return this.otherOperationReason();
  }
  prepareReason(): string | null { return this.startReason() ?? (usesMaterial(this.state.selection) && !this.assetCurrent(this.state.selection, this.selectedAsset) ? 'Choose a current assigned credential for this project and stage in Credentials. Native configuration and field checks are still required. Only secret previews also require the sealing helper.' : null) ?? (!this.state.selection ? 'Choose one repository setting and its intended values. No write is selected automatically.' : this.currentConsent() ? 'Apply or discard this exact review before preparing another.' : null); }
  applyReason(): string | null { return this.startReason() ?? (!this.currentConsent() ? 'Prepare and review this exact setting first.' : !this.state.confirmed ? 'Explicitly confirm this one exact before/after change.' : null); }
  private begin(kind: 'prepare' | 'apply', invoke: (api: Port, c: Context, revision: number) => Promise<GitHubRemoteSetupStatus>): void {
    this.syncAssetSession();
    if (this.startReason() || !this.state.selection) return;
    const o = this.observer!, c = context(this.connection())!, s = this.state.status!, selection = this.state.selection!;
    const p: Pending = { observer: o, context: c, epoch: this.epoch, selection, kind, revision: s.revision,
      previousId: s.operation?.id ?? null, operationId: null, sent: false, cancelAfterAdmission: false, cancelRequested: false, reviewed: this.currentConsent(), asset: this.selectedAsset };
    this.pending = p; this.review = null; this.update({ pending: true, confirmed: false, error: null,
      originalTarget: { repository: c.repository, accountId: c.accountId, repositoryId: c.repositoryId, selection: structuredClone(selection) } });
    if (this.pending !== p || p.epoch !== this.epoch || o.api !== this.api || !same(c, context(this.connection())) || !this.assetCurrent(p.selection, p.asset) || this.otherOperationReason()) {
      if (this.pending === p) { this.pending = null; this.update({ pending: false, error: 'target-changed' }); this.retireConsent(); } return;
    }
    p.sent = true; this.actionCall = p;
    const failed = (error: unknown) => {
      if (this.pending !== p) return;
      const e = githubRemoteSetupError(error);
      if (e.admission === 'not-admitted' && p.operationId === null && !this.blocked) {
        this.pending = null; this.update({ pending: false, error: e.reason }); this.retireConsent(); this.maintain();
      } else this.update({ uncertain: true, error: e.reason });
    };
    const done = () => { if(this.actionCall===p){this.actionCall=null;this.update({});this.retireConsent();this.maintain();} };
    try { void invoke(o.api, c, s.revision).then((v) => {
      const accepted = this.receive(o, v);
      if (this.pending === p && (!accepted || p.operationId === null)) this.update({ uncertain: true, error: 'response-invalid' });
    }, failed).finally(done); } catch (e) { failed(e); done(); }
  }
  prepare(): void {
    if (this.prepareReason()) return;
    const selection = structuredClone(this.state.selection!), connectionRevision = this.connection().status!.revision;
    this.begin('prepare', (api, c, revision) => api.githubRemoteSetupPrepare({ sessionId: c.sessionId, expectedRevision: revision, expectedConnectionRevision: connectionRevision, selection }));
  }
  apply(): void {
    if (this.applyReason()) return;
    const consent = this.currentConsent()!;
    this.begin('apply', (api, c, revision) => api.githubRemoteSetupApply({ sessionId: c.sessionId, expectedRevision: revision, consentId: consent.id, confirm: true }));
  }
  agentSelection(kind:GithubRemoteSettingsKind):GithubRemoteSettingsSelection|null {
    const o=this.observer,s=o?.accepted,c=context(this.connection()),selected=this.state.selection;
    if(!isGithubRemoteSettingsKind(kind)||this.disposed||this.agent||this.actionCall||this.pending||this.blocked||this.state.uncertain||this.cancelObserver||this.discard||this.retired||
       !o?.active||o.api!==this.api||o.reading||!c||!s?.available||s.sessionId!==c.sessionId||s.reason!=='none'||s.operation&&s.operation.phase!=='settled'||
       !selected||selected.kind==='environment_secret'||!this.assetCurrent(selected,this.selectedAsset))return null;
    const base={kind,sessionId:c.sessionId,expectedRevision:s.revision};
    if(kind==='remote-setup-prepare')return s.consent?null:parseGithubRemoteSettingsSelection({...base,expectedConnectionRevision:this.connection().status!.revision,selection:selected});
    const consent=this.currentConsent();
    return consent&&this.state.confirmed?parseGithubRemoteSettingsSelection({...base,consentId:consent.id,confirm:true}):null;
  }
  agentSelected(s:GithubActionSelection):boolean {
    return this.agent?sameGithubActionSelection(this.agent.selection,s)&&this.agentCurrent(this.agent):
      isGithubRemoteSettingsKind(s.kind)&&sameGithubActionSelection(this.agentSelection(s.kind),s);
  }
  private agentCurrent(d:AgentOrigin):boolean {
    return this.agent===d&&!d.unknown&&!this.disposed&&!this.blocked&&!this.pending&&!this.actionCall&&!this.cancelObserver&&!this.discard&&!this.retired&&
      d.observer===this.observer&&d.observer.api===this.api&&d.observer.active&&!d.observer.reading&&d.epoch===this.epoch&&
      same(d.context,context(this.connection()))&&d.observer.accepted?.revision===d.selection.expectedRevision&&
      same(d.setting,this.state.selection)&&this.assetCurrent(d.setting,d.asset)&&
      (d.selection.kind==='remote-setup-prepare'?this.review===null:d.review!==null&&this.review===d.review&&this.currentConsent()===d.review.consent);
  }
  delegatePrepared(raw:GithubActionSelection):GithubActionDelegate|null {
    this.syncContext();this.syncAssetSession();
    if(!isGithubRemoteSettingsKind(raw.kind))return null;
    const selection=this.agentSelection(raw.kind),setting=this.state.selection;
    if(!selection||!sameGithubActionSelection(selection,raw)||!setting||setting.kind==='environment_secret')return null;
    const o=this.observer!,d:AgentOrigin={observer:o,context:context(this.connection())!,epoch:this.epoch,selection,setting,asset:this.selectedAsset,review:this.review,
      originalId:o.accepted?.operation?.id??null,allowed:false,unused:false,noAllow:false,terminal:null,unknown:false,released:false};
    this.agent=d;this.update({confirmed:false,error:null,originalTarget:{repository:d.context.repository,accountId:d.context.accountId,repositoryId:d.context.repositoryId,selection:structuredClone(setting)}});
    const uncertain=()=>{if(this.agent===d){d.unknown=true;this.fail('cleanup-unknown');}};
    return Object.freeze({current:()=>this.agentCurrent(d),released:()=>d.released,
      allowReturned:()=>{if(this.agent===d&&!d.unknown){d.allowed=true;this.update({});}},
      observe:(raw:GithubActionStatus)=>{if(this.agent!==d||d.unknown)return;const status=parseGithubActionStatus(raw);
        if(!status||!sameGithubActionSelection(status.review,d.selection)||status.settlement==='unknown'){uncertain();return;}
        if(status.settlement==='settled'){d.terminal=status;this.update({});}},
      unusedReturned:()=>{if(this.agent===d&&!d.unknown){d.unused=true;this.update({});}},
      notSubmitted:()=>{if(this.agent===d&&!d.unknown){d.noAllow=true;d.unused=true;this.update({});}},uncertain});
  }
  private settleAgent(check:AgentCheck):void {
    const d=check.origin,s=check.status,f=check.terminal;
    if(this.agent!==d||!s||d.unknown||this.blocked||!(check.allowed||check.noAllow)||this.pending||this.actionCall||this.cancelObserver||this.discard||this.retired||
       d.observer.reading||!d.observer.active||d.observer!==this.observer||!same(s,d.observer.accepted)||s.sessionId!==d.selection.sessionId||
       s.reason==='cleanup-unknown'||s.operation&&s.operation.phase!=='settled')return;
    let adopt=false,unentered=false;
    if(f?.settlement==='settled'&&!f.neverAdmitted){
      const kind=d.selection.kind==='remote-setup-prepare'?'prepare':'apply',op=s.operation;
      if(!op||op.id!==f.operationId||op.kind!==kind)return;
      const nativeEffect=op.effect==='not-started'?(kind==='prepare'?'none':'not-sent'):op.effect==='unknown'?'potentially-applied':op.effect==='readback-confirmed'?'settings-readback-observed':null;
      if(nativeEffect===null||nativeEffect!==f.effect&&!(f.state!=='complete'&&f.effect==='potentially-applied'&&nativeEffect==='settings-readback-observed'))return;
      const result=f.result;
      if(result&&(result.type!=='remote-settings'||!githubRemoteSettingsResultMatches(result,s,d.setting)))return;
      if(f.state==='complete'){
        if(!result||result.type!=='remote-settings')return;
        if(d.selection.kind==='remote-setup-prepare'){
          if(result.reason==='none'){
            if(!s.consent||!inContext(s.consent,d.context,d.setting))return;
            adopt=true;
          }else if(result.reason!=='no-change'||s.consent!==null)return;
        }else{
          if(op.reason!=='none'||!d.review||!('preparedSha256'in f.review)||f.review.preparedSha256!==githubRemoteSettingsPreparedHash(d.review.consent.prepared)||
             !githubRemoteSetupObservationMatches(d.review.consent.prepared,s.observed))return;
        }
      }
    }else if(check.unused||f?.neverAdmitted){
      if((s.operation?.id??null)!==d.originalId||s.revision<d.selection.expectedRevision)return;
      unentered=true;
    }else return;
    d.released=true;this.agent=null;this.review=null;
    const current=d.epoch===this.epoch&&d.observer.api===this.api&&same(d.context,context(this.connection()))&&same(d.setting,this.state.selection)&&this.assetCurrent(d.setting,d.asset);
    if(current&&adopt&&s.consent)this.review={observer:d.observer,context:d.context,epoch:d.epoch,consent:s.consent,asset:d.asset};
    else if(current&&unentered&&d.review&&same(s.consent,d.review.consent))this.review=d.review;
    this.update({confirmed:false});this.retireConsent();this.maintain();
  }
  canCancel(): boolean { return !this.disposed && !this.cancelObserver && !this.state.cancelling && !!this.observer?.accepted?.operation && this.observer.accepted.operation.phase !== 'settled'; }
  cancel(): void {
    if (!this.canCancel()) return;
    const o = this.observer!, id = o.accepted!.operation!.id;
    this.cancelId = id; this.cancelObserver = o;
    if (this.pending?.observer === o && this.pending.operationId === id) this.pending.cancelRequested = true;
    this.epoch = {}; this.review = null; this.update({ cancelling: true, confirmed: false });
    const failed = () => { if (this.cancelId === id) this.update({ uncertain: true, error: 'response-invalid' }); };
    const done = () => { if (this.cancelObserver === o) { this.cancelObserver = null; this.update({ cancelling: false }); this.maintain(); } };
    try { void o.api.githubRemoteSetupCancel(id).then((v) => { this.receive(o, v); }, failed).finally(done); }
    catch { failed(); done(); }
  }
  dispose(): void { this.disposed = true; this.invalidate(); this.listeners.clear(); this.api = null; this.maintain(); }
}
export function githubRemoteSetupOwnerReason(state: GitHubRemoteSetupView): string | null {
  return state.pending || state.uncertain || state.cancelling || state.discarding || state.status?.consent || state.status?.operation && state.status.operation.phase !== 'settled'
    ? 'The original repository-settings action is running or unverified. Read local Status before starting another operation.' : null;
}
