// App-held UI coordination only. Neither promises, events nor comparison
// counters can settle the original native Session or its account-wide journal.
import { appleCliId, parseAppleCliReview, sameAppleCliReview } from './agentAppleProvisioning.ts';
import type { AppleCliReview, AppleCliStatus } from './agentAppleProvisioning.ts';
import type { AppleCliDelegate } from './agentAppleProvisioningController.ts';
import { appleP12InputBase, retainedAppleP12Input, isAppleP12Mode } from './appleP12SetupProtocol.ts';
import type { AppleP12Result } from './appleP12SetupProtocol.ts';
import { appleCertificateKeyChoices, appleDistributionCertificateInputBase, retainedAppleDistributionCertificateInput, isAppleDistributionCertificateMode } from './appleDistributionCertificateSetupProtocol.ts';
import type { AppleCertificateKeySelection, AppleDistributionCertificateResult, AppleCertificateRecoveryHistory } from './appleDistributionCertificateSetupProtocol.ts';
import { appleDistributionKeyInputBase, retainedAppleDistributionKeyInput, isAppleDistributionKeyMode } from './appleDistributionKeySetupProtocol.ts';
import type { AppleDistributionKeyResult, AppleDistributionKeySavedReference } from './appleDistributionKeySetupProtocol.ts';
import type { AppleProfileRecoveryHistory } from './appleProfileRecoverySelection.ts';
import { appleProfileInputBase, retainedAppleProfileInput, isAppleProfileMode } from './appleProfileSetup.ts';
import type { AppleProfileSetupResult, AppleProfileSavedReference } from './appleProfileSetup.ts';
import { localStoreRequest } from './localStorePreflight.ts';
import type { LocalStoreProject } from './localStorePreflight.ts';
import type { AssetDisplayState } from './assetSessionTypes.ts';
import { sameOfflineData } from './offlinePreflightProtocol.ts';
import { appleDisplayName, appleProvisioningConsent, appleProvisioningContext, appleProvisioningProgress,
  parseAppleProvisioningRequest, parseAppleProvisioningStatus, sameAppleIdentity } from './appleProvisioningProtocol.ts';
import type { AppleProvisioningApi } from './appleProvisioningNative.ts';
import type { AppleProvisioningIdentity, AppleProvisioningMode, AppleProvisioningOperation, AppleProvisioningResult,
  AppleProvisioningStatus, AppleRecoveryHistory, PrepareAppleProvisioning } from './appleProvisioningTypes.ts';

interface Source {
  project(): LocalStoreProject | null;
  assets(): AssetDisplayState | null;
  otherOperationReason(): string | null; // Root excludes THIS controller.
  now?(): number;
}
type Base = Omit<PrepareAppleProvisioning, 'mode' | 'reference' | 'newApplication' | 'displayName'>;
type InputFamily = 'bundle' | 'profile' | 'key' | 'certificate' | 'p12';
const inputFamily = (mode: AppleProvisioningMode): InputFamily => isAppleP12Mode(mode) ? 'p12' : isAppleDistributionCertificateMode(mode) || mode === 'key-recover' ? 'certificate' : isAppleDistributionKeyMode(mode) ? 'key' : isAppleProfileMode(mode) ? 'profile' : 'bundle';
interface Witness { family: InputFamily; base: Base; observation: number; entry: number }
interface DelegatedStart { nonce: string; review: AppleCliReview; anchor: number; allowJoined: boolean; submitted: boolean; final: boolean; checking: boolean; abandonedBeforeAllow: boolean }
interface Attempt {
  request: PrepareAppleProvisioning; witness: Witness; epoch: number; after: number;
  previous: AppleProvisioningIdentity | null; identity: AppleProvisioningIdentity | null;
  preparedAt: number; startedAt: number | null; keyReviewExpires: number | null; certificateReviewExpires: number | null; p12ReviewExpires: number | null; retired: boolean; prepareAccepted: boolean;
  prepareJoined: boolean; startClaimed: boolean; startJoined: boolean; terminalRead: boolean; delegated: DelegatedStart | null;
}
interface Reference { identity: AppleProvisioningIdentity; witness: Witness; displayName: string; expires: number | null }
interface ActionSlot { kind: 'prepare' | 'start'; joined: boolean; original: Promise<unknown> | null; promise: Promise<void> | null }
interface ReadSlot { mutation: number; afterInvoke: boolean; original: Promise<unknown> | null; promise: Promise<void> | null }
interface CancelSlot { identity: AppleProvisioningIdentity; joined: boolean; original: Promise<unknown> | null; promise: Promise<void> | null }
type Issue = 'unconfirmed' | 'protocol' | 'cleanup-unknown';
export interface AppleProvisioningState {
  native: boolean; visible: boolean; listening: boolean; initialized: boolean; reading: boolean;
  pending: 'prepare' | 'start' | null; requestPending: boolean; cancelPending: boolean;
  status: AppleProvisioningStatus | null; projectId: string | null; ios: boolean;
  previousAttempts: AppleRecoveryHistory | null; continueReason: string | null;
  previousProfileAttempts: AppleProfileRecoveryHistory | null; profileContinueReason: string | null;
  previousCertificateAttempts: AppleCertificateRecoveryHistory | null; certificateContinueReason: string | null;
  certificateKeyChoices: readonly AppleCertificateKeySelection[]; certificateKeySelection: AppleCertificateKeySelection | null;
  certificateResult: AppleDistributionCertificateResult | null; certificateTerminalRead: boolean;
  p12Result: AppleP12Result | null; savedP12: AppleProfileSavedReference | null; p12TerminalRead: boolean;
  p12ReviewReference: AppleProvisioningIdentity | null; p12ReviewReason: string | null; p12ReuseReason: string | null; p12SaveReason: string | null;
  certificateReviewReference: AppleProvisioningIdentity | null; certificateAttemptReference: AppleProvisioningIdentity | null;
  certificateReviewReason: string | null; certificateCreateReason: string | null; certificateReconcileReason: string | null;
  displayName: string; newApplication: boolean; issue: Issue | null; historical: boolean;
  consent: (AppleProvisioningIdentity & { mode: AppleProvisioningMode; acknowledged: boolean }) | null;
  result: AppleProvisioningResult | null; reviewReference: AppleProvisioningIdentity | null;
  registrationReference: AppleProvisioningIdentity | null;
  profileResult: AppleProfileSetupResult | null; savedProfile: AppleProfileSavedReference | null;
  keyResult: AppleDistributionKeyResult | null; savedKey: AppleDistributionKeySavedReference | null; keyTerminalRead: boolean;
  keyReviewReference: AppleProvisioningIdentity | null; keyReviewReason: string | null; keyPrepareReason: string | null; keyRecoverReason: string | null;
  profileReviewReference: AppleProvisioningIdentity | null; profileAttemptReference: AppleProvisioningIdentity | null;
  profileReviewReason: string | null; profileReuseReason: string | null; profileCreateReason: string | null; profileReconcileReason: string | null;
  reviewReason: string | null; registerReason: string | null; reconcileReason: string | null; startReason: string | null;
  canRead: boolean; canCancel: boolean; retained: boolean; cancelRequested: boolean;
}
const identity = (value: AppleProvisioningIdentity): AppleProvisioningIdentity => ({ operationId: value.operationId, ownerGeneration: value.ownerGeneration });
const active = (op: AppleProvisioningOperation | null | undefined) => !!op && op.phase !== 'terminal';
const sameWitness = (a: Witness | null, b: Witness | null): boolean => a === null || b === null ? a === b :
  a.family === b.family && a.observation === b.observation && a.entry === b.entry && sameOfflineData(a.base, b.base);
const attention = 'The original Apple setup operation is unconfirmed. Keep its status and cancellation; do not repeat registration or reconnect to dismiss it.';
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

export class AppleProvisioningController {
  private readonly source: Source;
  private original: AppleProvisioningApi | null = null;
  private off: (() => void) | null = null;
  private subscribing: Promise<void> | null = null;
  private read: ReadSlot | null = null;
  private action: ActionSlot | null = null;
  private cancellation: CancelSlot | null = null;
  private cancelClaim: AppleProvisioningIdentity | null = null;
  private attempt: Attempt | null = null;
  private review: Reference | null = null;
  private registration: Reference | null = null;
  private restored: Reference | null = null;
  private profileReview: (Reference & { action: 'profile-reuse' | 'profile-create' }) | null = null;
  private profileAttempt: Reference | null = null;
  private restoredProfile: Reference | null = null;
  private keyReview: Reference | null = null;
  private certificateKey: AppleCertificateKeySelection | null = null;
  private certificateReview: Reference | null = null;
  private p12Review: (Reference & { action: 'p12-reuse' | 'p12-save' }) | null = null;
  private certificateAttempt: Reference | null = null;
  private restoredCertificate: Reference | null = null;
  private inputFamily: InputFamily | null = null;
  private witness: Witness | null = null;
  private status: AppleProvisioningStatus | null = null;
  private issue: Issue | null = null;
  private epoch = 0;
  private mutation = 0;
  private visible = false;
  private initialized = false;
  private connectionRetired = false;
  private selectionPending = false;
  private disposed = false;
  private displayName = '';
  private declaredNew = false;
  private acknowledged = false;
  private consentUntil: number | null = null;
  private consentTimer: ReturnType<typeof setTimeout> | null = null;
  private cancelRequested = false;
  private readonly listeners = new Set<() => void>();
  private state: AppleProvisioningState;

  constructor(source: Source) { this.source = source; this.state = this.projected(); }
  getSnapshot = () => this.state;
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  private now(): number { return (this.source.now ?? (() => performance.now()))(); }
  private capture(requestedFamily: InputFamily | null = this.inputFamily): Witness | null {
    try {
      if (this.selectionPending) return null;
      const project = this.source.project(), assets = this.source.assets();
      const family = requestedFamily ?? (assets?.scope.purpose === 'provisioning' ? 'profile' : 'bundle');
      let base = family === 'p12' ? appleP12InputBase(project, assets, this.certificateKey) : family === 'certificate' ? appleDistributionCertificateInputBase(project, assets, this.certificateKey) : family === 'key' ? appleDistributionKeyInputBase(project, assets) :
        family === 'profile' ? appleProfileInputBase(project, assets) : localStoreRequest(project, assets);
      const a = this.attempt;
      if (!base && family === 'key' && a && (a.startClaimed || a.delegated !== null) && !a.terminalRead && !a.retired && !this.issue && isAppleDistributionKeyMode(a.request.mode)) {
        base = retainedAppleDistributionKeyInput(project, assets, a.witness.base);
      }
      if (!base && family === 'certificate' && a && (a.startClaimed || a.delegated !== null) && !a.terminalRead && !a.retired && !this.issue && (isAppleDistributionCertificateMode(a.request.mode) || a.request.mode === 'key-recover')) {
        base = retainedAppleDistributionCertificateInput(project, assets, this.certificateKey, a.witness.base);
      }
      if (!base && family === 'p12' && a && (a.startClaimed || a.delegated !== null) && !a.terminalRead && !a.retired && !this.issue && isAppleP12Mode(a.request.mode)) {
        base = retainedAppleP12Input(project, assets, this.certificateKey, a.witness.base, a.request.mode);
      }
      if (!base && family === 'profile' && a && (a.startClaimed || a.delegated !== null) && !a.terminalRead && !a.retired && !this.issue && isAppleProfileMode(a.request.mode)) {
        base = retainedAppleProfileInput(project, assets, a.witness.base);
      }
      if (!project || !assets || !base || base.platform !== 'ios' || Object.hasOwn(base, 'query') ||
          !Number.isSafeInteger(project.observationGeneration) || project.observationGeneration < 0 ||
          !Number.isSafeInteger(assets.entryGeneration) || assets.entryGeneration < 0) return null;
      return freeze({ family, base: { ...base, platform: 'ios' as const }, observation: project.observationGeneration, entry: assets.entryGeneration });
    } catch { return null; }
  }
  private current(attempt: Attempt): boolean {
    return !attempt.retired && attempt.epoch === this.epoch && sameWitness(attempt.witness, this.witness) &&
      attempt.request.displayName === this.displayName && !this.connectionRetired && !this.disposed;
  }
  private started(a: Attempt): boolean { return a.delegated ? a.delegated.submitted : a.startClaimed; }
  private startReturned(a: Attempt): boolean { return a.delegated ? a.delegated.allowJoined && a.delegated.final && !a.delegated.checking : a.startJoined; }
  private startAnchor(a: Attempt): number | null { return a.delegated?.anchor ?? a.startedAt; }
  private settled(): boolean {
    return !this.action && !this.cancellation && !this.read && !this.subscribing && !active(this.status?.operation) &&
      (!this.attempt || this.attempt.terminalRead && !this.attempt.delegated?.checking) && !this.issue;
  }
  ownerReason = (): string | null => this.issue || this.action || this.cancellation || this.subscribing || this.read ||
    active(this.status?.operation) || this.attempt && (!this.attempt.terminalRead || this.attempt.delegated?.checking) ?
    'An Apple setup intent, request or original cleanup is retained. Finish or cancel it before other work.' : null;
  private baseReason(family: InputFamily = 'bundle'): string | null {
    if (!this.original || this.connectionRetired) return 'Use the installed Mac app. Browser preview cannot run Apple setup.';
    if (this.issue) return attention;
    if (this.ownerReason() || this.read) return this.ownerReason() ?? 'Wait for the current original status response.';
    if (!this.initialized || !this.off || this.status?.availability !== 'available') return 'Apple setup is unavailable or busy. Refresh its status; no other account is selected automatically.';
    const witness = this.capture(family);
    if (family === 'key' && !witness) return 'Choose the App Store Connect key, unlock encrypted storage, then assess and assign its P8, Key ID and Issuer ID in Set up Apple signing. Save the app settings and read the saved version first. No P12 is needed.';
    if (family === 'certificate' && !witness) return 'Choose the current encrypted signing key and assign the App Store Connect P8 in Set up Apple signing. Unlock storage and save the app settings/version first. A previous saved-key result is not a current selection.';
    if (family === 'p12' && !witness) return 'Choose a current saved signing key above, unlock encrypted storage and assign the App Store Connect P8 in Set up Apple signing. To reuse a P12, assess and assign it in that same context first. Save the app settings and read its version.';
    if (family === 'profile' && !witness?.base.p12RecordId) return 'Choose Set up Apple signing, unlock encrypted storage, then assess and assign the existing P12/password and App Store Connect P8 in that context. Save the app settings and read its saved version first.';
    if (!witness) return 'Select This Mac → iOS → Store (or Full), save the configuration, read its saved version and assign the original App Store Connect P8 with its Key ID and Issuer ID.';
    if (!appleDisplayName(this.displayName)) return 'Enter an explicit Bundle ID display name (1–128 characters, no control characters).';
    return this.source.otherOperationReason();
  }
  private referenceCurrent(value: Reference | null): value is Reference {
    return !!value && sameWitness(value.witness, this.witness) && value.displayName === this.displayName &&
      (value.expires === null || this.now() < value.expires);
  }
  private reconciliationReference(): Reference | null {
    return this.referenceCurrent(this.restored) ? this.restored : this.referenceCurrent(this.registration) ? this.registration : null;
  }
  private previousAttempts(): AppleRecoveryHistory | null {
    const a = this.attempt, op = this.status?.operation;
    if (!a?.terminalRead || !this.started(a) || !this.startReturned(a) || !this.current(a) || this.action || this.read || this.cancellation || this.issue ||
        !sameAppleIdentity(a.identity, op) || a.request.mode !== 'review' || op?.phase !== 'terminal' || op.outcome !== 'complete') return null;
    return op.recovery;
  }
  private profileReconciliationReference(): Reference | null {
    return this.referenceCurrent(this.restoredProfile) ? this.restoredProfile : this.referenceCurrent(this.profileAttempt) ? this.profileAttempt : null;
  }
  private previousProfileAttempts(): AppleProfileRecoveryHistory | null {
    const a = this.attempt, op = this.status?.operation;
    if (!a?.terminalRead || !this.started(a) || !this.startReturned(a) || !this.current(a) || this.action || this.read || this.cancellation || this.issue ||
        !sameAppleIdentity(a.identity, op) || a.request.mode !== 'profile-review' || op?.phase !== 'terminal' || op.outcome !== 'complete') return null;
    return op.profileRecovery ?? null;
  }
  private certificateReconciliationReference(): Reference | null {
    return this.referenceCurrent(this.restoredCertificate) ? this.restoredCertificate : this.referenceCurrent(this.certificateAttempt) ? this.certificateAttempt : null;
  }
  private previousCertificateAttempts(): AppleCertificateRecoveryHistory | null {
    const a = this.attempt, op = this.status?.operation;
    if (!a?.terminalRead || !this.started(a) || !this.startReturned(a) || !this.current(a) || this.action || this.read || this.cancellation || this.issue ||
        !sameAppleIdentity(a.identity, op) || a.request.mode !== 'certificate-review' || op?.phase !== 'terminal' || op.outcome !== 'complete') return null;
    return op.certificateRecovery ?? null;
  }
  private reason(mode: AppleProvisioningMode): string | null {
    const base = this.baseReason(inputFamily(mode)); if (base) return base;
    if (mode === 'certificate-create' && !this.referenceCurrent(this.certificateReview)) return 'Finish a fresh certificate check for this saved key first. Its separate request review is one-use and expires; an old receipt cannot restore it.';
    if (mode === 'certificate-reconcile' && !this.certificateReconciliationReference()) return 'Choose a matching earlier certificate request. A read-only check never repeats issuance or clears earlier uncertainty.';
    if ((mode === 'p12-reuse' || mode === 'p12-save') && (!this.referenceCurrent(this.p12Review) || this.p12Review.action !== mode)) return 'Finish a fresh P12 review for the same saved key and assigned inputs. Only its exact reuse or new-save choice may continue; an old result cannot restore it.';
    if (mode === 'key-prepare' && !this.referenceCurrent(this.keyReview)) return 'Finish a fresh existing-key check first. Its one-use local-key review expires and cannot be restored from an old result.';
    if (mode === 'profile-reuse' || mode === 'profile-create') {
      if (!this.referenceCurrent(this.profileReview) || this.profileReview?.action !== mode) return 'Finish a current signing review first. Only its exact reuse or create choice can continue.';
    }
    if (mode === 'profile-reconcile' && !this.profileReconciliationReference()) return 'No matching profile attempt is selected. Keep earlier pending attempts; this action never repeats their request.';
    if (mode === 'register') {
      if (!this.referenceCurrent(this.review)) return 'First finish a current reuse-first review. A key-only not-returned result is not global availability or permission.';
      if (!this.declaredNew) return 'Explicitly declare this is a new application, not a change to an existing store identity.';
    }
    if (mode === 'reconcile' && !this.reconciliationReference()) return 'Choose a saved attempt below, or use the prior registration from this session. Readback never repeats the write.';
    return null;
  }
  // Pure provisional DATA. Only native Allow binds this actual Prepared;
  // neither a renderer result nor these fields constructs native authority.
  delegationReview = (): AppleCliReview | null => {
    const a = this.attempt, op = this.status?.operation;
    if (!this.visible || !this.original || !a || a.delegated || a.startClaimed || !a.prepareAccepted || !a.prepareJoined ||
        !a.identity || !this.current(a) || !sameWitness(a.witness, this.capture()) || !sameAppleIdentity(a.identity, op) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable || this.action || this.cancellation || this.read || this.issue ||
        this.consentUntil === null || this.now() >= this.consentUntil || a.request.mode === 'register' && !this.declaredNew || this.source.otherOperationReason()) return null;
    return parseAppleCliReview({mode:a.request.mode,...a.identity,statusRevision:this.status!.statusRevision,
      savedConfig:a.request.savedConfig,savedVersion:{bytes:a.request.savedVersion.bytes,sha256:a.request.savedVersion.sha256,name:a.request.savedVersion.name,build:a.request.savedVersion.build}});
  };
  delegatePrepared = (review: AppleCliReview, nonce: string): AppleCliDelegate | null => {
    this.syncProject();
    const a = this.attempt, api = this.original;
    if (!a || !api || !appleCliId(nonce) || !sameAppleCliReview(review, this.delegationReview())) return null;
    const d: DelegatedStart = {nonce,review,anchor:this.now(),allowJoined:false,submitted:false,final:false,checking:false,abandonedBeforeAllow:false};
    a.delegated = d; this.clearConsent(); this.mutation++;
    const original = () => this.attempt === a && a.delegated === d && this.original === api;
    const current = () => original() && this.current(a) && sameWitness(a.witness, this.capture()) && !this.issue && !this.cancelRequested;
    // Set origin BEFORE notification; a reentrant ordinary Start is refused.
    this.publish();
    const readFinal = async () => { await this.postInvokeRead(); };
    return {
      current,
      allowReturned: () => { if (original()) { d.allowJoined = true; this.publish(); } },
      observe: async (status: AppleCliStatus) => {
        if (!original() || !d.allowJoined || !sameAppleCliReview(review,status.review) || status.grantId !== nonce ||
            status.state === 'unknown') return;
        d.checking = true;
        if (!d.submitted) {
          d.submitted = true;
          if (a.request.mode === 'register') this.registration = freeze({identity:identity(a.identity!),witness:a.witness,displayName:a.request.displayName,expires:null});
          if (a.request.mode === 'profile-reuse' || a.request.mode === 'profile-create') this.profileAttempt = freeze({identity:identity(a.identity!),witness:a.witness,displayName:a.request.displayName,expires:null});
          if (a.request.mode === 'certificate-create') this.certificateAttempt = freeze({identity:identity(a.identity!),witness:a.witness,displayName:a.request.displayName,expires:null});
        }
        // Exact Query has returned only after native private retirement, relay
        // return AND history ACK. Read the SAME native owner as a separate cut.
        if (status.settlement === 'settled') {
          d.final = true; this.mutation++; await readFinal();
          const native = this.status;
          if (native && (!sameAppleIdentity(a.identity,native.operation) || native.statusRevision < (status.operation?.statusRevision ?? Infinity) ||
              native.operation?.phase !== 'terminal' || native.operation.outcome !== status.outcome)) this.fail('protocol');
        } else await this.checkStatus();
      },
      unusedReturned: async () => { if (original() && d.allowJoined && !d.submitted) { d.checking = true; d.final = true; this.mutation++; await readFinal(); } },
      checkReturned: () => { if (original()) { d.checking = false; this.publish(); } },
      uncertain: () => { if (original()) this.fail('unconfirmed'); },
      notSubmitted: async () => {
        if (!original() || d.allowJoined || d.submitted) return;
        // The original JS caller never entered Allow. Do not invent an Allow
        // return or restore Start: cancel/read the same real Prepared instead.
        d.abandonedBeforeAllow = true; await this.cancel();
      },
    };
  };
  private startReason(): string | null {
    const a = this.attempt, op = this.status?.operation;
    if (!a || !a.prepareAccepted || !a.prepareJoined || !a.identity || !this.current(a) || !sameAppleIdentity(a.identity, op) ||
        op?.phase !== 'awaiting-consent' || !op.intentUsable || this.action || this.cancellation || this.read || this.issue ||
        a.startClaimed || a.delegated !== null || this.consentUntil === null || this.now() >= this.consentUntil) return 'This original intent is unavailable, expired or still pending. Do not replay Start.';
    if (a.request.mode === 'register' && !this.declaredNew) return 'The explicit new-application declaration is required.';
    return this.source.otherOperationReason() ?? (this.acknowledged ? null : 'Confirm the separate permission for this exact original intent.');
  }
  private projected(): AppleProvisioningState {
    const a = this.attempt, op = this.status?.operation;
    const current = !!a && this.current(a) && sameAppleIdentity(a.identity, op);
    const readResult = !!a?.terminalRead && (!a.delegated || this.startReturned(a)) && !this.action && !this.cancellation && !this.issue && sameAppleIdentity(a.identity, op) ? op?.result ?? null : null;
    const keyTerminalRead = !!a?.terminalRead && a.prepareJoined && this.started(a) && this.startReturned(a) && !this.action && !this.cancellation &&
      !this.issue && isAppleDistributionKeyMode(a.request.mode) && sameAppleIdentity(a.identity, op) && op?.phase === 'terminal';
    const certificateTerminalRead = !!a?.terminalRead && a.prepareJoined && this.started(a) && this.startReturned(a) && !this.action && !this.cancellation &&
      !this.issue && isAppleDistributionCertificateMode(a.request.mode) && sameAppleIdentity(a.identity, op) && op?.phase === 'terminal';
    const p12TerminalRead = !!a?.terminalRead && a.prepareJoined && this.started(a) && this.startReturned(a) && !this.action && !this.cancellation &&
      !this.issue && isAppleP12Mode(a.request.mode) && sameAppleIdentity(a.identity, op) && op?.phase === 'terminal';
    const cancelId = a?.identity ?? (active(op) ? op : null);
    return Object.freeze({ native: !!this.original && !this.connectionRetired, visible: this.visible, initialized: this.initialized,
      listening: !!this.off, reading: !!this.read, pending: this.action?.kind ?? null, requestPending: !!this.action && !this.action.joined,
      cancelPending: !!this.cancellation, status: this.status, projectId: this.witness?.base.projectId ?? null,
      ios: this.source.assets()?.scope.platform === 'ios', displayName: this.displayName, newApplication: this.declaredNew,
      issue: this.issue, historical: !!op && !current,
      consent: a?.identity && this.consentUntil !== null && current && !a.startClaimed && !a.delegated ?
        Object.freeze({ ...identity(a.identity), mode: a.request.mode, acknowledged: this.acknowledged }) : null,
      result: readResult?.scope === 'local-ios-bundle-provisioning' ? readResult : null,
      profileResult: readResult?.scope === 'local-ios-profile-setup' ? readResult : null,
      certificateResult: certificateTerminalRead && readResult?.scope === 'local-ios-distribution-certificate' ? readResult : null, certificateTerminalRead,
      p12Result: p12TerminalRead && readResult?.scope === 'local-ios-p12-setup' ? readResult : null,
      savedP12: p12TerminalRead ? op?.savedP12 ?? null : null, p12TerminalRead,
      p12ReviewReference: this.referenceCurrent(this.p12Review) ? this.p12Review.identity : null,
      p12ReviewReason: this.reason('p12-review'), p12ReuseReason: this.reason('p12-reuse'), p12SaveReason: this.reason('p12-save'),
      certificateKeyChoices: appleCertificateKeyChoices(this.source.project(), this.source.assets()), certificateKeySelection: this.certificateKey,
      certificateReviewReference: this.referenceCurrent(this.certificateReview) ? this.certificateReview.identity : null,
      certificateAttemptReference: this.restoredCertificate?.identity ?? this.certificateAttempt?.identity ?? null,
      certificateReviewReason: this.reason('certificate-review'), certificateCreateReason: this.reason('certificate-create'), certificateReconcileReason: this.reason('certificate-reconcile'),
      previousCertificateAttempts: this.previousCertificateAttempts(), certificateContinueReason: this.baseReason('certificate'),
      keyResult: keyTerminalRead && readResult?.scope === 'local-ios-distribution-key' ? readResult : null,
      savedKey: keyTerminalRead ? op?.savedKey ?? null : null, keyTerminalRead,
      keyReviewReference: this.referenceCurrent(this.keyReview) ? this.keyReview.identity : null,
      keyReviewReason: this.reason('key-review'), keyPrepareReason: this.reason('key-prepare'), keyRecoverReason: this.reason('key-recover'),
      savedProfile: readResult?.scope === 'local-ios-profile-setup' ? op?.savedProfile ?? null : null,
      profileReviewReference: this.referenceCurrent(this.profileReview) ? this.profileReview.identity : null,
      profileAttemptReference: this.restoredProfile?.identity ?? this.profileAttempt?.identity ?? null,
      profileReviewReason: this.reason('profile-review'), profileReuseReason: this.reason('profile-reuse'),
      profileCreateReason: this.reason('profile-create'), profileReconcileReason: this.reason('profile-reconcile'),
      reviewReference: this.referenceCurrent(this.review) ? this.review.identity : null,
      registrationReference: this.restored?.identity ?? this.registration?.identity ?? null,
      previousAttempts: this.previousAttempts(), continueReason: this.baseReason(),
      previousProfileAttempts: this.previousProfileAttempts(), profileContinueReason: this.baseReason('profile'),
      reviewReason: this.reason('review'), registerReason: this.reason('register'), reconcileReason: this.reason('reconcile'),
      startReason: this.startReason(), canRead: !!this.original && !this.read && (!this.connectionRetired || !this.settled()),
      canCancel: !!this.original && !!cancelId && !this.cancellation && !sameAppleIdentity(this.cancelClaim, cancelId) && active(op),
      retained: this.ownerReason() !== null, cancelRequested: this.cancelRequested });
  }
  private publish(): void { this.state = this.projected(); if (!this.disposed) for (const listener of this.listeners) listener(); }
  private clearP12Review(): void { this.p12Review = null; }
  private clearCertificateReview(): void { this.certificateReview = null; this.restoredCertificate = null; }
  private clearConsent(): void {
    this.acknowledged = false; this.consentUntil = null;
    if (this.consentTimer !== null) clearTimeout(this.consentTimer); this.consentTimer = null;
  }
  private fail(issue: Issue = 'unconfirmed'): void {
    this.issue ??= issue; this.clearConsent(); this.clearCertificateReview(); this.clearP12Review(); this.review = null; this.restored = null; this.profileReview = null; this.restoredProfile = null; this.keyReview = null;
    if (this.attempt) this.attempt.retired = true;
    this.cancelRequested = true; this.publish(); void this.cancelOriginal();
  }
  syncProject = (): void => {
    const next = this.capture();
    if (!sameWitness(next, this.witness)) { this.invalidate(); this.witness = next; }
    // Peer-owner changes can disable/enable the view without changing saved
    // comparison inputs. Reproject only; this does not renew a native intent.
    this.publish();
  };
  invalidate = (): void => {
    this.epoch++; this.clearConsent(); this.clearCertificateReview(); this.clearP12Review(); this.review = null; this.restored = null; this.profileReview = null; this.restoredProfile = null; this.keyReview = null; this.declaredNew = false;
    if (this.attempt) this.attempt.retired = true;
    if (this.action || active(this.status?.operation)) { this.cancelRequested = true; void this.cancelOriginal(); }
    this.publish();
  };
  beforeWorkspaceAction = (): void => this.invalidate();
  selectionIntent = (): void => this.invalidate();
  snapshotIntent = (): void => this.invalidate();
  versionIntent = (): void => this.invalidate();
  setSelectionPending = (value: boolean): void => { if (value !== this.selectionPending) { this.selectionPending = value; this.syncProject(); } };
  setVisible = (value: boolean): void => { if (!value && this.consentUntil !== null) this.invalidate(); this.visible = value; this.publish(); };
  selectCertificateKey = (recordId: string | null, recordRevision: number | null): void => {
    if (this.disposed || this.ownerReason()) return;
    const choices = appleCertificateKeyChoices(this.source.project(), this.source.assets());
    const next = recordId === null && recordRevision === null ? null : choices.find(row => row.recordId === recordId && row.recordRevision === recordRevision);
    if (next === undefined || sameOfflineData(next, this.certificateKey)) return;
    const api = this.original, previous = this.certificateKey, witness = this.capture('key'), epoch = this.epoch + 1;
    this.invalidate();
    if (this.original !== api || this.epoch !== epoch || this.certificateKey !== previous || this.disposed || this.ownerReason() ||
        !sameWitness(witness, this.capture('key')) || next && !appleCertificateKeyChoices(this.source.project(), this.source.assets()).some(row => sameOfflineData(row, next))) return;
    this.certificateKey = next ? freeze({ ...next }) : null; this.witness = this.capture(); this.publish();
  };
  setDisplayName = (value: string): void => {
    if (value === this.displayName || value.length > 512) return;
    this.invalidate(); this.displayName = value; this.publish();
  };
  setNewApplication = (value: boolean): void => {
    if (value === this.declaredNew) return;
    if (this.attempt?.request.mode === 'register' && !this.attempt.terminalRead) this.invalidate();
    this.declaredNew = value; this.publish();
  };
  acknowledge = (operationId: string, ownerGeneration: string, value: boolean): void => {
    if (sameAppleIdentity(this.attempt?.identity, { operationId, ownerGeneration }) && this.consentUntil !== null &&
        this.now() < this.consentUntil && this.attempt && this.current(this.attempt) && !this.attempt.startClaimed && !this.attempt.delegated) {
      this.acknowledged = value; this.publish();
    }
  };
  beginConnection = (): void => {
    this.connectionRetired = true; this.invalidate();
    if (!this.settled()) this.fail();
  };
  async connect(api: AppleProvisioningApi | null): Promise<void> {
    if (this.disposed || this.original === api && !this.connectionRetired) return;
    if (this.original) {
      if (!this.settled()) { this.beginConnection(); return; }
      try { this.off?.(); } catch { this.fail(); return; }
    }
    this.original = api; this.off = null; this.connectionRetired = false; this.initialized = false;
    this.status = null; this.attempt = null; this.review = null; this.registration = null; this.restored = null; this.profileReview = null; this.profileAttempt = null; this.restoredProfile = null; this.keyReview = null; this.clearCertificateReview(); this.clearP12Review(); this.certificateAttempt = null; this.certificateKey = null; this.inputFamily = null; this.clearConsent(); this.witness = this.capture(); this.publish();
    if (!api) return;
    const pending = (async () => {
      try {
        const off = await api.subscribe(value => {
          if (this.original !== api) return;
          this.receive(value, 'event');
          if (this.status?.operation?.phase === 'terminal' && !this.action && !this.cancellation) void this.checkStatus();
        });
        if (this.original !== api) { off(); return; }
        this.off = off;
      } catch { this.fail(); }
    })();
    this.subscribing = pending; this.publish();
    await pending; if (this.subscribing === pending) this.subscribing = null;
    await this.checkStatus(); this.cleanupListener(); this.publish();
  }
  private receive(value: unknown, source: 'event' | 'invoke' | 'read', read?: ReadSlot): AppleProvisioningStatus | null {
    const next = parseAppleProvisioningStatus(value), before = this.status;
    if (!next) { this.fail('protocol'); return null; }
    if (before && next.statusRevision < before.statusRevision) return next;
    if (before && next.statusRevision === before.statusRevision && !sameOfflineData(before, next)) { this.fail('protocol'); return null; }
    const op = next.operation, a = this.attempt;
    if (before?.operation && sameAppleIdentity(before.operation, op) && !appleProvisioningProgress(before.operation, op!)) { this.fail('protocol'); return null; }
    if (before?.operation && active(before.operation) && !sameAppleIdentity(before.operation, op)) { this.fail('protocol'); return null; }
    if (a && !a.identity && op && next.statusRevision > a.after && !sameAppleIdentity(a.previous, op) &&
        sameOfflineData(op.context, appleProvisioningContext(a.request))) a.identity = freeze(identity(op));
    if (a?.identity && sameAppleIdentity(a.identity, op) && !sameOfflineData(op!.context, appleProvisioningContext(a.request))) { this.fail('protocol'); return null; }
    if (a?.identity && !a.terminalRead && !sameAppleIdentity(a.identity, op)) { this.fail('protocol'); return null; }
    this.status = freeze(next);
    if (next.availability === 'cleanup-unknown' || op?.phase === 'unknown') this.fail('cleanup-unknown');
    if (a && source === 'read' && read?.afterInvoke && read.mutation === this.mutation && a.prepareJoined &&
        (a.delegated ? a.delegated.abandonedBeforeAllow || a.delegated.allowJoined && a.delegated.final : !a.startClaimed || a.startJoined) && sameAppleIdentity(a.identity, op) && op?.phase === 'terminal' && !this.issue) {
      a.terminalRead = true; this.clearConsent();
      const anchor = this.startAnchor(a);
      if (this.current(a) && this.started(a) && anchor !== null && a.request.mode === 'review' && op.outcome === 'complete' &&
          op.result?.scope === 'local-ios-bundle-provisioning' && op.result.decision === 'review-required' && op.result.observation === 'not-returned' && this.now() < anchor + 300000) {
        this.review = freeze({ identity: identity(op), witness: a.witness, displayName: a.request.displayName, expires: anchor + 300000 });
      }
      if (this.current(a) && this.started(a) && anchor !== null && a.request.mode === 'key-review' && op.outcome === 'complete' &&
          op.result?.scope === 'local-ios-distribution-key' && op.result.decision === 'prepare-review' && op.result.reason === 'local-key-required' &&
          this.now() < anchor + 300000) {
        // Conservative UI age only: native expires from its original provider
        // observation. A read/event/reconnect never starts another 300 seconds.
        this.keyReview = freeze({ identity: identity(op), witness: a.witness, displayName: a.request.displayName, expires: anchor + 300000 });
      }
      if (this.current(a) && this.started(a) && anchor !== null && a.request.mode === 'certificate-review' && op.outcome === 'complete' &&
          op.result?.scope === 'local-ios-distribution-certificate' && op.result.decision === 'request-review' && op.result.reason === 'certificate-required' &&
          this.now() < anchor + 300000) {
        this.certificateReview = freeze({ identity: identity(op), witness: a.witness, displayName: a.request.displayName, expires: anchor + 300000 });
      }
      if (this.current(a) && this.started(a) && anchor !== null && a.request.mode === 'p12-review' && op.outcome === 'complete' &&
          op.result?.scope === 'local-ios-p12-setup' && ['assemble-review', 'reuse-review'].includes(op.result.decision) &&
          this.now() < anchor + 300000) {
        this.p12Review = freeze({ identity: identity(op), witness: a.witness, displayName: a.request.displayName, expires: anchor + 300000,
          action: op.result.decision === 'reuse-review' ? 'p12-reuse' : 'p12-save' });
      }
      if (this.current(a) && this.started(a) && anchor !== null && a.request.mode === 'profile-review' && op.outcome === 'complete' &&
          op.result?.scope === 'local-ios-profile-setup' && ['reuse-available', 'create-available'].includes(op.result.decision) &&
          this.now() < anchor + 300000) {
        this.profileReview = freeze({ identity: identity(op), witness: a.witness, displayName: a.request.displayName, expires: anchor + 300000,
          action: op.result.decision === 'reuse-available' ? 'profile-reuse' : 'profile-create' });
      }
    }
    if (this.cancelRequested || a?.retired) void this.cancelOriginal();
    this.publish(); return next;
  }
  checkStatus = (): Promise<void> => {
    if (this.read) return this.read.promise ?? Promise.resolve();
    const api = this.original; if (!api || this.connectionRetired && this.settled()) return Promise.resolve();
    const slot: ReadSlot = { mutation: this.mutation, afterInvoke: (!this.action || this.action.joined) && (!this.cancellation || this.cancellation.joined), original: null, promise: null };
    this.read = slot;
    slot.promise = (async () => {
      try { slot.original = api.status(); this.receive(await slot.original, 'read', slot); this.initialized = true; }
      catch { this.fail(); }
      finally { if (this.read === slot) this.read = null; this.cleanupListener(); this.publish(); }
    })(); this.publish(); return slot.promise;
  };
  private async postInvokeRead(): Promise<void> {
    const previous = this.read?.promise; if (previous) await previous;
    await this.checkStatus();
  }
  continuePrevious = (operationId: string, ownerGeneration: string): Promise<void> => {
    this.syncProject();
    if (this.disposed || !this.visible || this.baseReason() || !this.original || !this.witness) return Promise.resolve();
    const row = this.previousAttempts()?.attempts.find(candidate => sameAppleIdentity(candidate.reference, { operationId, ownerGeneration }));
    if (!row) return Promise.resolve();
    const continuation = { api: this.original, witness: this.witness, epoch: this.epoch + 1 };
    const sameContinuation = () => this.original === continuation.api && this.witness === continuation.witness &&
      this.epoch === continuation.epoch && !this.disposed && !this.connectionRetired;
    this.invalidate();
    if (!sameContinuation()) return Promise.resolve();
    // Only this explicit UI choice adopts a DISPLAY name and historical IDs.
    // No saved identity/key/state is edited, and no Register review is minted.
    this.displayName = row.displayName;
    this.restored = freeze({ identity: identity(row.reference), witness: continuation.witness, displayName: row.displayName, expires: null });
    this.publish();
    if (!sameContinuation()) return Promise.resolve();
    return this.prepareIntent('reconcile', continuation);
  };
  continuePreviousProfile = (operationId: string, ownerGeneration: string): Promise<void> => {
    this.syncProject();
    if (this.disposed || !this.visible || this.baseReason('profile') || !this.original || !this.witness) return Promise.resolve();
    const row = this.previousProfileAttempts()?.attempts.find(candidate => sameAppleIdentity(candidate.reference, { operationId, ownerGeneration }));
    if (!row) return Promise.resolve();
    const continuation = { api: this.original, witness: this.witness, epoch: this.epoch + 1 };
    const sameContinuation = () => this.original === continuation.api && this.witness === continuation.witness &&
      this.epoch === continuation.epoch && !this.disposed && !this.connectionRetired;
    this.invalidate();
    if (!sameContinuation()) return Promise.resolve();
    // Explicit historical selection adopts DISPLAY text and a read-only prior
    // reference, never the old Review/save destination/key/native settlement.
    this.displayName = row.displayName;
    this.restoredProfile = freeze({ identity: identity(row.reference), witness: continuation.witness, displayName: row.displayName, expires: null });
    this.publish();
    if (!sameContinuation()) return Promise.resolve();
    return this.prepareIntent('profile-reconcile', continuation);
  };
  continuePreviousCertificate = (operationId: string, ownerGeneration: string): Promise<void> => {
    this.syncProject();
    if (this.disposed || !this.visible || this.baseReason('certificate') || !this.original || !this.witness) return Promise.resolve();
    const row = this.previousCertificateAttempts()?.attempts.find(candidate => sameAppleIdentity(candidate.reference, { operationId, ownerGeneration }));
    if (!row) return Promise.resolve();
    const continuation = { api: this.original, witness: this.witness, epoch: this.epoch + 1 };
    const sameContinuation = () => this.original === continuation.api && this.witness === continuation.witness &&
      this.epoch === continuation.epoch && !this.disposed && !this.connectionRetired;
    this.invalidate();
    if (!sameContinuation()) return Promise.resolve();
    // Only display text and the historical reference survive this explicit
    // choice. No key loan, Create review or earlier native join is restored.
    this.displayName = row.displayName;
    this.restoredCertificate = freeze({ identity: identity(row.reference), witness: continuation.witness, displayName: row.displayName, expires: null });
    this.publish();
    if (!sameContinuation()) return Promise.resolve();
    return this.prepareIntent('certificate-reconcile', continuation);
  };
  prepare = (mode: AppleProvisioningMode): Promise<void> => this.prepareIntent(mode);
  private prepareIntent(mode: AppleProvisioningMode, continuation?: { api: AppleProvisioningApi; witness: Witness; epoch: number }): Promise<void> {
    const family = inputFamily(mode), api = this.original, target = this.capture(family);
    if (this.disposed || !this.visible || this.reason(mode) || !api || !target || !this.status) return Promise.resolve();
    // Only an explicit, settled Prepare can switch input families. Retire the
    // old comparison locally before publishing; no pending original is replaced.
    if (this.inputFamily !== family) {
      if (continuation || this.ownerReason()) return Promise.resolve();
      this.epoch++; this.clearConsent(); this.clearCertificateReview(); this.clearP12Review(); this.review = null; this.restored = null;
      this.profileReview = null; this.restoredProfile = null; this.keyReview = null;
      this.declaredNew = false; if (this.attempt) this.attempt.retired = true;
      this.inputFamily = family; this.witness = target;
    }
    const handoffEpoch = this.epoch;
    this.syncProject();
    // syncProject publishes to subscribers. Cancellation, source ABA, another
    // owner or connection retirement during that notification vetoes THIS call.
    if (this.original !== api || this.epoch !== handoffEpoch || this.inputFamily !== family ||
        !sameWitness(target, this.witness) || !sameWitness(target, this.capture(family)) ||
        continuation && (this.original !== continuation.api || this.witness !== continuation.witness || this.epoch !== continuation.epoch) ||
        this.disposed || !this.visible || this.reason(mode) || !this.witness || !this.status) return Promise.resolve();
    const reference = mode === 'review' || mode === 'profile-review' || mode === 'key-review' || mode === 'certificate-review' || mode === 'p12-review' || mode === 'key-recover' ? null :
      mode === 'p12-reuse' || mode === 'p12-save' ? this.p12Review?.identity :
      mode === 'certificate-create' ? this.certificateReview?.identity : mode === 'certificate-reconcile' ? this.certificateReconciliationReference()?.identity : mode === 'key-prepare' ? this.keyReview?.identity :
      mode === 'register' ? this.review?.identity : mode === 'profile-reuse' || mode === 'profile-create' ? this.profileReview?.identity :
      mode === 'profile-reconcile' ? this.profileReconciliationReference()?.identity : this.reconciliationReference()?.identity;
    const request = parseAppleProvisioningRequest({ ...this.witness.base, mode, reference, newApplication: mode === 'register', displayName: this.displayName });
    if (!request) return Promise.resolve();
    const a: Attempt = { request: freeze(request), witness: this.witness, epoch: this.epoch, after: this.status.statusRevision,
      previous: this.status.operation ? identity(this.status.operation) : null, identity: null, preparedAt: this.now(), startedAt: null, keyReviewExpires: mode === 'key-prepare' ? this.keyReview?.expires ?? null : null,
      certificateReviewExpires: mode === 'certificate-create' ? this.certificateReview?.expires ?? null : null,
      p12ReviewExpires: mode === 'p12-reuse' || mode === 'p12-save' ? this.p12Review?.expires ?? null : null,
      retired: false, prepareAccepted: false, prepareJoined: false, startClaimed: false, startJoined: false, terminalRead: false, delegated: null };
    this.attempt = a; if (isAppleProfileMode(mode)) this.profileReview = null;
    if (isAppleP12Mode(mode)) this.clearP12Review(); // An uncertain Prepare never restores save/reuse consent.
    if (isAppleDistributionKeyMode(mode)) this.keyReview = null; // Consumed even if Prepare's reply is lost.
    if (mode === 'key-recover') { this.clearCertificateReview(); this.clearP12Review(); }
    if (isAppleDistributionCertificateMode(mode)) this.certificateReview = null; // Lost Prepare never restores issuance review.
    if (mode === 'register') this.review = null; // Consumed once, including failed/lost Prepare.
    this.cancelClaim = null; this.cancelRequested = false; this.clearConsent(); this.mutation++;
    const slot: ActionSlot = { kind: 'prepare', joined: false, original: null, promise: null }; this.action = slot;
    slot.promise = (async () => {
      try {
        slot.original = api.prepare(request); const reply = this.receive(await slot.original, 'invoke');
        const op = reply?.operation;
        if (!op || !sameAppleIdentity(a.identity, op) || !sameOfflineData(op.context, appleProvisioningContext(a.request))) this.fail('protocol');
        else a.prepareAccepted = op.phase === 'awaiting-consent' && op.intentUsable;
      } catch { this.fail(); }
      finally {
        a.prepareJoined = true; slot.joined = true; this.publish(); await this.postInvokeRead();
        if (this.action === slot) this.action = null;
        const op = this.status?.operation;
        if (!this.issue && this.current(a) && a.prepareAccepted && sameAppleIdentity(a.identity, op) && op?.phase === 'awaiting-consent' && op.intentUsable) {
          this.consentUntil = Math.min(a.preparedAt + 60000, a.keyReviewExpires ?? Infinity, a.certificateReviewExpires ?? Infinity, a.p12ReviewExpires ?? Infinity); this.acknowledged = false;
          if (this.now() >= this.consentUntil) this.invalidate();
          else this.consentTimer = setTimeout(() => { if (this.attempt === a && !a.startClaimed && !a.delegated) this.invalidate(); }, this.consentUntil - this.now());
        }
        this.cleanupListener(); this.publish();
      }
    })(); this.publish(); return slot.promise;
  }
  start = (operationId: string, ownerGeneration: string): Promise<void> => {
    this.syncProject(); const a = this.attempt, api = this.original;
    if (!a || !api || a.startClaimed || a.delegated || !sameAppleIdentity(a.identity, { operationId, ownerGeneration }) || this.startReason()) return Promise.resolve();
    a.startClaimed = true; a.startedAt = this.now(); this.clearConsent(); this.mutation++;
    if (a.request.mode === 'profile-reuse' || a.request.mode === 'profile-create') this.profileAttempt = freeze({ identity: identity(a.identity!), witness: a.witness, displayName: a.request.displayName, expires: null });
    if (a.request.mode === 'certificate-create') this.certificateAttempt = freeze({ identity: identity(a.identity!), witness: a.witness, displayName: a.request.displayName, expires: null });
    if (a.request.mode === 'register') this.registration = freeze({ identity: identity(a.identity!), witness: a.witness, displayName: a.request.displayName, expires: null });
    const slot: ActionSlot = { kind: 'start', joined: false, original: null, promise: null }; this.action = slot;
    slot.promise = (async () => {
      try { slot.original = api.start({ ...a.identity!, consentVersion: appleProvisioningConsent(a.request.mode) }); this.receive(await slot.original, 'invoke'); }
      catch { this.fail(); }
      finally {
        a.startJoined = true; slot.joined = true; this.publish(); await this.postInvokeRead();
        if (this.action === slot) this.action = null; this.cleanupListener(); this.publish();
      }
    })(); this.publish(); return slot.promise;
  };
  cancel = (): Promise<void> => { this.invalidate(); this.cancelRequested = true; this.publish(); return this.cancelOriginal(); };
  private cancelOriginal(): Promise<void> {
    if (this.cancellation?.promise) return this.cancellation.promise;
    const api = this.original, op = this.status?.operation, id = this.attempt?.identity ?? (active(op) ? op : null);
    if (!api || !id || !this.cancelRequested || sameAppleIdentity(this.cancelClaim, id) || sameAppleIdentity(id, op) && op?.phase === 'terminal') return Promise.resolve();
    this.cancelClaim = freeze(identity(id)); this.mutation++;
    const slot: CancelSlot = { identity: this.cancelClaim, joined: false, original: null, promise: null }; this.cancellation = slot;
    slot.promise = (async () => {
      try { slot.original = api.cancel(slot.identity); this.receive(await slot.original, 'invoke'); }
      catch { this.fail(); }
      finally { slot.joined = true; this.publish(); await this.postInvokeRead(); if (this.cancellation === slot) this.cancellation = null; this.cleanupListener(); this.publish(); }
    })(); this.publish(); return slot.promise;
  }
  private cleanupListener(): void {
    if (!this.disposed || !this.settled() || !this.off) return;
    const off = this.off; this.off = null; try { off(); } catch { this.issue ??= 'unconfirmed'; }
  }
  dispose = (): void => {
    if (this.disposed) return;
    this.disposed = true; this.invalidate(); this.listeners.clear(); this.cleanupListener();
  };
}
