import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { ProjectSession } from '../drafts.ts';
import type { CredentialGuide, CredentialKind, HelpContent } from '../types.ts';
import type { AssetDisplayState, AssetKind, AssetScope, CredentialAssessment, CredentialIssue } from '../assetSessionTypes.ts';
import { AssetSessionController, assetCancellationReason, assetContextReason, assetImageOperationPending, assetIntentPending, assetSessionReason } from '../assetSessionController.ts';
import { ASSET_KINDS, ASSET_PLATFORMS, ASSET_PURPOSES, ASSET_REASON_HELP, ASSET_STAGES, SESSION_FIELDS, assetLabelFits, assetStorageWritable, isAssetFileKind } from '../assetSessionProtocol.ts';
import { sessionControlHelp, sessionKindHelp, sessionTargetLabel } from '../assetSessionHelp.ts';
import { RELEASE_INPUT_STAGES, preparationScopeChanged, preparationSessionReason, sessionPreparationKind } from '../releaseInputGuidance.ts';
import type { ReleaseInputPreparationLocal, ReleaseInputPreparationTarget } from '../releaseInputGuidance.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const issueHelp: Record<CredentialIssue, string> = {
  'not-run': 'This check was not run.', incomplete: 'The supplied observation is incomplete.',
  'unsupported-format': 'This file format is not supported by this importer.', 'unsupported-variant': 'This variant is not supported; it has not been declared invalid.',
  'material-limit': 'The file exceeds the material-size limit.', 'parser-limit': 'The file exceeds a supported complexity limit.',
  'empty-file': 'The selected file is empty.', 'suffix-conflict': 'The file extension does not match this input kind.',
  'malformed-container': 'The supported container could not be parsed completely.', 'required-missing': 'Supply this required field before preparing again.',
  'value-nul': 'This field contains an unsupported NUL character.', 'scalar-format': 'The value does not match the required identifier format. Open its field help.',
  'pkcs8-algorithm': 'The selected key identifiers are not supported.', 'firebase-shape': 'The Firebase document lacks a supported Android client structure or iOS dictionary with a string BUNDLE_ID.',
  'identity-mismatch': 'The Firebase application identity does not match the submitted project draft.',
};
const stateLabel = { 'not-applicable': 'Not required here', missing: 'Missing', unknown: 'Not established', invalid: 'Needs correction', configured: 'Configured only', 'format-valid': 'Format / identity match' };

function Assessment({ value, guide, onHelp }: { value: CredentialAssessment; guide: CredentialGuide; onHelp: (help: HelpContent) => void }) {
  const original = guide.kinds.find((item) => item.id === value.kind);
  const kind = original ? sessionKindHelp(original) : null;
  return <div className="session-assessment">
    <div className="credential-row-heading"><h3>Supplied-input assessment</h3><Badge tone={value.state === 'invalid' || value.state === 'missing' ? 'warning' : 'info'}>{stateLabel[value.state]}</Badge></div>
    <p>The core assessed the supplied fields and mechanical file observation. It did not test signing, account access or release readiness.</p>
    {value.applicability.state === 'not-applicable' && <p className="review-caution">This item is not required for the submitted context. No keep or assignment permission follows.</p>}
    <ul className="session-field-results">{value.fields.map((field) => {
      const help = kind?.fields.find((item) => item.id === field.id);
      return <li key={field.id}><div className="inline-heading"><strong>{help?.label ?? 'Credential field'}</strong>{help && <HelpButton content={help} onHelp={onHelp} />}<Badge tone={field.state === 'invalid' || field.state === 'missing' ? 'warning' : 'neutral'}>{stateLabel[field.state]}</Badge></div>
        <p>{field.presence === 'supplied' ? 'Supplied · value not displayed' : 'Not supplied'}</p>
        {field.issues.length > 0 && <ul>{field.issues.map((issue) => <li key={issue}>{issueHelp[issue]}</li>)}</ul>}
        {field.checks.some((check) => check.scope === 'jks-header') && <p>JKS header only: no password, alias entry, whole-file digest or signing verification.</p>}
        {field.checks.some((check) => check.scope === 'pfx-envelope') && <p>P12 envelope only: the password has not been tested, and no certificate, private key, expiry or signing identity has been verified.</p>}
        {field.checks.some((check) => check.scope === 'cms-signed-data-envelope') && <p>CMS envelope only: this does not establish an Apple issuer, profile validity, team, bundle ID or signing permission.</p>}
        {field.checks.some((check) => check.scope === 'pkcs8-envelope' || check.scope === 'ec-p256-identifiers') && <p>P8 envelope and EC/P-256 identifiers only: no mathematical private-key validity, account ownership, revocation, permissions or Store access has been verified.</p>}
        {value.kind === 'ios-firebase' && <p>iOS Firebase scope: XML plist format and bundle-ID match only. This is not iOS signing or Firebase account verification.</p>}
      </li>;
    })}</ul>
    <div className="session-assurance"><Badge>Native validation: not run</Badge><Badge>Service validation: not run</Badge><Badge>Release readiness: unknown</Badge></div>
  </div>;
}

function WriteOnlyFields({ kind, disabled, encrypted, labelHelp, prepareHelp, onPrepare, onHelp }: { kind: CredentialKind; disabled: boolean; encrypted: boolean; labelHelp: HelpContent | null; prepareHelp: HelpContent | null; onPrepare: (fields: Record<string, string | null>, label: string | null) => boolean; onHelp: (help: HelpContent) => void }) {
  const id = useId();
  const [values, setValues] = useState<Record<string, string>>({});
  const [label, setLabel] = useState('');
  const proposedLabel = label === '' ? null : label;
  const labelValid = !encrypted || assetLabelFits(proposedLabel);
  const names = SESSION_FIELDS[kind.id as AssetKind];
  return <form className="session-inputs" autoComplete="off" onSubmit={(event) => {
    event.preventDefault();
    if (disabled || !labelValid || encrypted && !labelHelp) return;
    const fields = Object.fromEntries(names.map((name) => [name, values[name] ?? null]));
    if (onPrepare(fields, encrypted ? proposedLabel : null)) { setValues({}); setLabel(''); }
  }}>
    {names.map((name) => {
      const help = kind.fields.find((field) => field.id === name);
      if (!help) return <p role="alert" key={name}>Field guidance is unavailable. Do not provide this private input.</p>;
      return <div className="field session-private-field" key={name}>
        <div className="field-label"><label htmlFor={`${id}-${name}`}>{help.label}</label><HelpButton content={help} onHelp={onHelp} /></div>
        <p className="field-description">{help.what}</p>
        <input id={`${id}-${name}`} type="password" autoComplete="new-password" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={4096} disabled={disabled}
          value={values[name] ?? ''} onChange={(event) => setValues((current) => ({ ...current, [name]: event.target.value }))} aria-describedby={`${id}-${name}-help`} />
        <div className="session-field-help" id={`${id}-${name}-help`}><p><strong>Find it:</strong> {help.where}</p><p><strong>Format:</strong> {help.format}</p><p><strong>Required when:</strong> {help.requiredWhen}</p></div>
      </div>;
    })}
    {encrypted && <div className="field">
      <div className="field-label"><label htmlFor={`${id}-label`}>Vault label (optional)</label>{labelHelp && <HelpButton content={labelHelp} onHelp={onHelp} />}</div>
      <p className="field-description">Choose a short nonsecret name, or leave empty to use the input kind and item number. This name is encrypted on disk; it is not proof of identity.</p>
      <input id={`${id}-label`} type="text" autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} maxLength={128}
        disabled={disabled || !labelHelp} value={label} onChange={(event) => setLabel(event.target.value)} aria-describedby={`${id}-label-help`} aria-invalid={!labelValid} />
      <p id={`${id}-label-help`}>At most 128 UTF-8 bytes, without control characters. No passwords, tokens or private identifiers. An unsupported label prevents preparation; your original file is not renamed.</p>
      {!labelValid && <p className="review-caution" role="alert">Use a shorter nonsecret label without control characters. Some characters take several UTF-8 bytes.</p>}
      {!labelHelp && <p role="alert">Label guidance is unavailable. No private input can be prepared.</p>}
    </div>}
    <p className="subtle-note"><Icon name="lock" size={16} />Write-only entry. Values are cleared after handoff or cancellation; they are not put into project settings or browser storage. Complete memory erasure is not promised.</p>
    <div className="button-row"><button className="button" type="submit" disabled={disabled || !labelValid || encrypted && !labelHelp || names.some((name) => !kind.fields.some((field) => field.id === name))}><Icon name="shield" size={16} />Prepare private review</button>{prepareHelp && <HelpButton content={prepareHelp} onHelp={onHelp} />}</div>
  </form>;
}

export function CredentialSession({ state, controller, project, guide, onHelp, nativeBusyReason = null,
  preparation, isPreparationCurrent, takePreparation, dismissPreparation }: {
  state: AssetDisplayState; controller: AssetSessionController; project: ProjectSession | null; guide: CredentialGuide | null;
  onHelp: (help: HelpContent) => void; nativeBusyReason?: string | null; preparation: ReleaseInputPreparationTarget | null;
  isPreparationCurrent: (target: ReleaseInputPreparationTarget) => boolean; takePreparation: (target: ReleaseInputPreparationTarget) => boolean;
  dismissPreparation: (target: ReleaseInputPreparationTarget) => void;
}) {
  const id = useId();
  type LocalChoices = Omit<ReleaseInputPreparationLocal, 'writeOnlyFormMounted'>;
  const [local, setLocal] = useState<LocalChoices>({ kindId: 'android-keystore', replacementId: null, confirmLock: false });
  const localRef = useRef(local);
  const { kindId, replacementId, confirmLock } = local;
  const changeLocal = (patch: Partial<LocalChoices>) => {
    const next = { ...localRef.current, ...patch };
    if (next.kindId === localRef.current.kindId && next.replacementId === localRef.current.replacementId && next.confirmLock === localRef.current.confirmLock) return;
    // Retained callbacks must see an already queued local choice, not wait for
    // React to render it. This reference never contains private form values.
    localRef.current = next; setLocal(next);
  };
  const mounted = useRef(true), sessionRef = useRef<HTMLElement>(null);
  const render = {}, renderRef = useRef<object | null>(null);
  // Bind only a committed view: an abandoned concurrent render must not disable
  // the still-visible handler. Local changes above retire callbacks immediately.
  useLayoutEffect(() => {
    mounted.current = true; renderRef.current = render;
    return () => { mounted.current = false; renderRef.current = null; };
  }, [render]);
  const [, expireView] = useState(0);
  useEffect(() => {
    if (state.previewDeadline === null) return;
    const timer = setTimeout(() => expireView((value) => value + 1), Math.max(0, state.previewDeadline - performance.now()) + 1);
    return () => clearTimeout(timer);
  }, [state.previewDeadline]);
  useEffect(() => { changeLocal({ replacementId: null, confirmLock: false }); }, [project?.project.id, state.scope.platform, state.scope.stage, state.scope.purpose]);
  const status = state.status;
  const operation = status?.operation;
  const projectPathOperation = operation?.operation === 'choose-project-path';
  const imageOperation = operation?.operation === 'choose-images';
  const imageActive = assetImageOperationPending(status) || imageOperation && state.blocked;
  const baseReason = nativeBusyReason ?? assetSessionReason(state);
  const contextReason = nativeBusyReason ?? assetContextReason(state);
  const cancellationReason = assetCancellationReason(state);
  const inSession = status?.mode === 'session';
  const encrypted = status?.mode === 'encrypted';
  const storage = encrypted ? 'encrypted' : 'session';
  const writable = assetStorageWritable(status);
  const persistence = status?.persistence;
  const nativeAvailable = state.mode === 'native' && status?.capability.available === true && !state.blocked && !state.observationFailed;
  const idle = !operation || (operation.phase === 'idle' && operation.settlement === 'known');
  const projectPathActive = projectPathOperation && !idle;
  const intentPending = assetIntentPending(state);
  const effectiveKindId = intentPending && state.intent?.type === 'record' ? state.intent.kind : kindId;
  const originalKind = guide?.kinds.find((item) => item.id === (operation?.selectionToken ? state.selectionKind : effectiveKindId));
  const kind = originalKind ? sessionKindHelp(originalKind) : null;
  const originalSelectedKind = guide?.kinds.find((item) => item.id === effectiveKindId);
  const selectedKind = originalSelectedKind ? sessionKindHelp(originalSelectedKind) : null;
  const selectionVisible = !!(nativeAvailable && writable && guide && !projectPathActive && !imageActive);
  // The complete existing outer + inner render condition protects even an
  // unsubmitted private form. Navigation never inspects or resets its values.
  const writeOnlyFormMounted = selectionVisible && !!kind && (!!(operation?.selectionToken && state.selectionKind) ||
    (idle && !intentPending && (kindId === 'google-wif' || kindId === 'project-read-token')));
  const replacement = controller.replacement(kindId, replacementId);
  const preview = operation?.preview;
  const expired = state.previewDeadline === null || performance.now() >= state.previewDeadline;
  const usable = writable && state.contextCurrent && !baseReason && !state.busy && !state.updatingContext;
  const controlHelp = (name: string) => {
    const help = sessionControlHelp(guide, name, storage);
    return help ? <HelpButton content={help} onHelp={onHelp} /> : null;
  };
  const intentTarget = state.intent?.type === 'record' ? sessionTargetLabel(guide, { type: 'record', kind: state.intent.kind, change: state.intent.change,
    recordId: state.intent.record?.recordId ?? null, recordRevision: state.intent.record?.expectedRevision ?? null }, status?.records ?? [], storage) : null;
  const reviewTarget = preview ? sessionTargetLabel(guide, preview.subject, status?.records ?? [], storage) : null;
  const scopeChange = (name: keyof AssetScope, value: string) => controller.setScope({ ...state.scope, [name]: value } as AssetScope);
  const prepare = (fields: Record<string, string | null>, label: string | null): boolean => {
    if (operation?.selectionToken) return controller.prepareSelection(state.selectionKind === 'android-keystore' ?
      { storePassword: fields.storePassword ?? null, keyAlias: fields.keyAlias ?? null, keyPassword: fields.keyPassword ?? null } :
      state.selectionKind === 'apple-p12' ? { password: fields.password ?? null } :
      state.selectionKind === 'asc-p8' ? { keyId: fields.keyId ?? null, issuerId: fields.issuerId ?? null } : {}, label);
    if (replacement === undefined) return false;
    if (kindId === 'google-wif') return controller.prepareScalar('google-wif', { provider: fields.provider ?? null, serviceAccount: fields.serviceAccount ?? null }, replacement, label);
    if (kindId === 'project-read-token') return controller.prepareScalar('project-read-token', { token: fields.token ?? null }, replacement, label);
    return false;
  };
  const preparationCurrent = preparation !== null && isPreparationCurrent(preparation);
  const originalPreparationKind = preparationCurrent ? preparation.source.help.guide?.kinds.find((entry) => entry.id === preparation.guideId) : null;
  const preparationKind = originalPreparationKind ? sessionKindHelp(originalPreparationKind) : null;
  const preparationReason = !preparationCurrent ? 'This preparation guide is no longer current. Open the relevant current-draft requirement again.' :
    !guide?.kinds.some((entry) => entry.id === preparation.guideId) ? 'The session field guide is unavailable. No private input should be provided.' :
      preparationSessionReason(preparation, state, { ...local, writeOnlyFormMounted }, nativeBusyReason);
  const preparationHelp = (content: HelpContent) => { if (preparation && isPreparationCurrent(preparation)) onHelp(content); };
  const continuePreparation = () => {
    if (!mounted.current || renderRef.current !== render || localRef.current !== local || !preparation ||
        controller.getSnapshot() !== state || !isPreparationCurrent(preparation)) return;
    const nextKind = sessionPreparationKind(preparation.guideId);
    if (!nextKind || !guide?.kinds.some((entry) => entry.id === nextKind) ||
        preparationSessionReason(preparation, controller.getSnapshot(), { ...localRef.current, writeOnlyFormMounted }, nativeBusyReason) !== null) return;
    if (!takePreparation(preparation)) return;
    if (preparationScopeChanged(preparation, state.scope)) controller.setScope({ ...preparation.scope });
    if (nextKind !== local.kindId) changeLocal({ kindId: nextKind });
    sessionRef.current?.focus();
  };
  return <section ref={sessionRef} tabIndex={-1} className="card credential-session" aria-labelledby={`${id}-title`}>
    <SectionHeading title="Private inputs, one guided step at a time" description="Choose storage → select and assess → review saving → assess and assign to this release context. These are separate decisions." />
    <h3 id={`${id}-title`} className="inline-heading">Private-input storage {controlHelp('mode')}<Badge tone={writable ? 'info' : 'neutral'}>{inSession ? 'Memory-only session' : encrypted ? `Encrypted vault · ${persistence?.state ?? 'unknown'}` : 'Storage closed'}</Badge></h3>
    <p>Nothing is uploaded or written into your repository. Native selection preserves the original. Memory-only copies last for this launch; explicitly saved encrypted records can remain for later launches. Neither mode automatically assigns an input or starts a release.</p>
    {encrypted && persistence && <div className="session-context" role="status"><p><strong>Key access:</strong> {persistence.keyAccess}. {persistence.reason !== 'none' ? ASSET_REASON_HELP[persistence.reason] : writable ? 'Unlocked descriptors are not proof that their stored payloads are ready. Assess the exact revision before assigning.' : 'Wait for the original operation to settle before continuing.'}</p>{persistence.keyAccess === 'read-only' && <p>Read-only interrupted vault: authenticated labels only. Preparing, saving, removing and assigning inputs are unavailable; no automatic repair is attempted.</p>}</div>}
    {preparation && <div className="session-context" aria-label="Current requirement preparation guide">
      <div className="inline-heading"><h3>Prepare this input</h3><Badge>Guidance only · no input checked</Badge></div>
      {preparationCurrent && preparationKind && <>
        <p><strong>{preparationKind.label}</strong> · {project?.project.name ?? 'Selected project'} · draft revision {preparation.source.project?.draftRevision}</p>
        <p>{preparation.scope.platform === 'project' ? 'Project dependency access' : preparation.scope.platform === 'ios' ? 'iOS' : 'Android'} · {RELEASE_INPUT_STAGES.find((stage) => stage.id === preparation.scope.stage)?.label} · All selected input roles (full)</p>
        <p><strong>Current-draft requirement:</strong> {preparation.requirement.name}<br />{preparation.requirement.reason}</p>
        <p>Current in-memory draft only: saved files, credential presence, signing and account access have not been checked. Release readiness is unknown.</p>
        <details><summary>What this input is, where to find it, and supported formats</summary>
          <p>These fields belong to one input. Companion field help is not an additional requirement or presence result; the core decides what your draft requires.</p>
          {preparationKind.fields.map((field) => <div key={field.id} className="session-field-help">
            <div className="inline-heading"><h4>{field.label}</h4><HelpButton content={field} onHelp={preparationHelp} /></div>
            <p>{field.what}</p><p><strong>Find it:</strong> {field.where}</p><p><strong>Format:</strong> {field.format}</p><p><strong>If incorrect:</strong> {field.failure}</p>
          </div>)}
        </details>
        <p>Continue sets the choices in the existing private-input controls. When storage is writable, changing release context submits that context and makes earlier assignment displays stale. It does not unlock a vault, choose a file, read a credential, save an input, assign it or start a release.</p>
        <p><strong>Next explicit step:</strong> {!nativeAvailable ? 'Read the availability reason below; this guide cannot enable collection.' : !writable ? encrypted ? 'Use the vault status and explicit initialization or unlock action below; locked and interrupted storage cannot collect inputs.' : 'Choose a storage mode when you are ready.' : !state.contextCurrent || preparationScopeChanged(preparation, state.scope) ? 'Wait for the changed context, or use Submit current context if it is not current.' : isAssetFileKind(preparation.guideId) ? 'Use Select file, then prepare and review separately.' : 'Use the private fields, then Prepare private review.'}</p>
      </>}
      {preparationReason && <p className="review-caution" role="status">{preparationReason}</p>}
      <div className="button-row"><button type="button" className="button secondary" disabled={preparationReason !== null} onClick={continuePreparation}>Continue with this context</button><button type="button" className="button secondary" onClick={() => dismissPreparation(preparation)}>Close guidance</button></div>
    </div>}
    {!nativeAvailable && <div className="notice notice-warning"><Icon name="lock" size={18} /><div><strong>Private input is unavailable in this build</strong><p>{baseReason ?? 'Native qualification is required before collection.'}</p><p>Guides remain available. Do not paste credentials into project configuration to work around this gate.</p></div></div>}
    {state.error && <ErrorNotice error={state.error} title="The session action was not confirmed" />}
    <div className="button-row">
      {status?.mode === 'closed' && <><button className="button" disabled={!!baseReason || !guide || !idle} onClick={() => controller.open()}><Icon name="key" size={16} />Start session — keep inputs in memory</button><button className="button secondary" disabled={!!baseReason || !guide || !idle} onClick={() => controller.open('encrypted')}>Open encrypted vault</button></>}
      {encrypted && persistence?.state === 'uninitialized' && <><button className="button" disabled={!!baseReason || !guide || !idle} onClick={() => controller.prepareInitialize()}>Review vault initialization…</button>{controlHelp('initialize')}</>}
      {encrypted && persistence?.keyAccess === 'locked' && ['locked', 'interrupted'].includes(persistence.state) && <><button className="button" disabled={!!baseReason || !guide || !idle} onClick={() => controller.unlock()}>Unlock vault</button>{controlHelp('unlock')}</>}
      <button className="button secondary" disabled={state.mode !== 'native' || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={16} />{state.observing ? 'Checking original status…' : 'Check storage status'}</button>
      {(inSession || encrypted) && <button className="button secondary" disabled={!!state.busy || projectPathActive || imageActive} onClick={() => changeLocal({ confirmLock: true })}>{encrypted ? 'Lock vault…' : 'Discard session…'}</button>}
    </div>
    {confirmLock && <div className="session-review" role="group" aria-label="Confirm private-input lock"><div className="inline-heading"><h3>{encrypted ? 'Lock vault and revoke all current assignments?' : 'Discard all session copies and assignments?'}</h3>{controlHelp('lock')}</div><p>{encrypted ? 'Saved encrypted records stay on disk. Decrypted copies become unavailable and are released as original work settles. You must explicitly unlock and reassess records before assigning again.' : 'Original files stay untouched. No session record is kept for your next launch.'} This cannot force cleanup of an unsettled operation or guarantee memory erasure.</p><div className="button-row"><button className="button secondary" onClick={() => changeLocal({ confirmLock: false })}>Go back</button><button className="button danger" disabled={!!state.busy || projectPathActive || imageActive} onClick={() => { if (controller.lock()) changeLocal({ confirmLock: false }); }}>{encrypted ? 'Lock vault' : 'Discard session copies'}</button></div></div>}
    <div className="session-context">
      <div className="inline-heading"><h3>Release context</h3>{controlHelp('project')}<Badge tone={state.contextCurrent ? 'info' : 'warning'}>{state.contextCurrent ? 'Context submitted · not yet policy-validated' : 'Context not current'}</Badge></div>
      <p><strong>Project:</strong> {project?.project.name ?? 'Choose a project first'} · {project?.draft ? 'Current in-memory draft' : 'Prepare a draft in Project settings'}</p>
      <div className="session-context-fields">{([
        ['platform', 'Platform', ASSET_PLATFORMS], ['stage', 'Release stage', ASSET_STAGES], ['purpose', 'Input purpose', ASSET_PURPOSES],
      ] as const).map(([name, label, options]) => <div className="field" key={name}><div className="field-label"><label htmlFor={`${id}-${name}`}>{label}</label>{controlHelp(name)}</div><select id={`${id}-${name}`} value={state.scope[name]} onChange={(event) => scopeChange(name, event.target.value)} disabled={state.blocked || nativeBusyReason !== null || imageActive}>{options.map((option) => <option key={option} value={option}>{option === 'project' ? 'Project dependency access' : option === 'candidate' ? 'Candidate / internal testing' : option === 'production' ? 'Production preparation' : option === 'full' ? 'All selected input roles' : option === 'store' ? 'Store access only' : option === 'signing' ? 'Build / signing only' : option === 'external-testing' ? 'External testing' : option === 'ios' ? 'iOS' : 'Android'}</option>)}</select></div>)}</div>
      <p>Changing the project, draft, platform, stage or purpose makes prior assignment displays stale immediately. The core—not these selectors—decides which inputs are required.</p>
      <p>For local signed iOS export, first save the intended draft, then use <strong>iOS · Candidate / internal testing · Build / signing only</strong>. Keep and assign the P12/password and App Store profile here before reviewing the saved export in Releases. ASC P8 and Store access are not needed.</p>
      <p>For App Store Connect P8 registration on an admitted Mac, use <strong>iOS · your intended stage · All selected input roles or Store access only</strong>. Those Mac contexts admit only ASC P8, not P12/profile, Firebase or project-token preparation. This does not enable a Store operation; encrypted storage remains Linux-only.</p>
      <button className="button secondary small" disabled={!nativeAvailable || !writable || !project || state.updatingContext || nativeBusyReason !== null || imageActive} onClick={() => controller.submitContext()}>{state.updatingContext ? 'Submitting current context…' : 'Submit current context'}</button>
    </div>
    {selectionVisible && guide && <>
      <div className="session-selection">
        {idle && !intentPending ? <>
          <div className="field"><div className="field-label"><label htmlFor={`${id}-kind`}>What would you like to provide?</label>{controlHelp('choose')}</div><select id={`${id}-kind`} value={kindId} disabled={!!state.busy} onChange={(event) => changeLocal({ kindId: event.target.value as AssetKind, replacementId: null })}>{ASSET_KINDS.map((kind) => <option key={kind} value={kind}>{guide.kinds.find((entry) => entry.id === kind)?.label ?? 'Supported session input'}</option>)}</select></div>
          <div className="field"><div className="field-label"><label htmlFor={`${id}-replace`}>New or replacement copy?</label>{controlHelp('replace')}</div><select id={`${id}-replace`} value={replacementId ?? ''} disabled={!!state.busy} onChange={(event) => changeLocal({ replacementId: event.target.value || null })}><option value="">{encrypted ? 'Save a new encrypted record' : 'Keep a new session record'}</option>{status?.records.map((record, index) => record.kind === kindId && <option key={record.recordId} value={record.recordId}>Replace item {index + 1}{record.label ? ` · ${record.label}` : ''} · revision {record.revision}</option>)}</select><p>Starting a replacement makes old assignments unavailable, even if you cancel. The old record is not silently reassigned.</p></div>
        </> : <div className="session-intent" role="status"><strong>Original requested action:</strong> {state.intent?.change === 'replace' ? 'Replace' : state.intent?.change === 'assign' ? 'Assess for assignment' : state.intent?.change === 'delete' ? 'Review removal of' : 'Prepare'} {intentTarget ?? 'an unconfirmed target'}<p>Page navigation cannot change this target. Cancel the original operation before choosing a different action.</p></div>}
        {isAssetFileKind(effectiveKindId) && <>
          <p>{effectiveKindId === 'android-keystore' ? 'Select a private .jks or .keystore original outside project folders. Only its JKS header is recognized; PKCS#12 is not supported for Android here.' : effectiveKindId === 'apple-p12' ? 'On separately admitted Apple-silicon macOS, select the authorized Apple Distribution .p12 or .pfx export outside project folders, then enter its original password below. Envelope assessment does not test the password or authenticate a certificate.' : effectiveKindId === 'apple-profile' ? 'On separately admitted Apple-silicon macOS, select the Apple-issued App Store .mobileprovision profile for this team, bundle ID and distribution certificate. DER CMS envelope assessment alone proves none of those matches.' : effectiveKindId === 'asc-p8' ? 'Select the original private .p8 downloaded from App Store Connect, outside registered projects, then enter its key ID and issuer ID. Only the unencrypted PKCS#8 envelope and EC/P-256 identifiers are assessed; the key and account are not validated.' : effectiveKindId === 'ios-firebase' ? 'Select the iOS GoogleService-Info.plist downloaded from Firebase project settings, in XML format. The core checks its BUNDLE_ID against your submitted draft; binary plist is not supported.' : 'Select the Android google-services.json downloaded from Firebase project settings. Every supported client is checked against your draft by the core.'}</p>
          {selectedKind?.fields.find((field) => field.id === 'file') && <div className="inline-heading"><span>Where to find this file and what to expect</span><HelpButton content={selectedKind.fields.find((field) => field.id === 'file')!} onHelp={onHelp} /></div>}
          <button className="button secondary" disabled={!!contextReason || !idle || replacement === undefined} onClick={() => { if (replacement !== undefined) controller.choose(effectiveKindId, replacement); }}><Icon name="folder" size={17} />Select file…</button>
          <p>No path entry, manual registration, renaming or copy into an internal folder. Native selection never sends the original filename or bytes to this view.</p>
        </>}
        {contextReason && <p className="review-caution">{contextReason}</p>}
        {writeOnlyFormMounted && kind &&
          <WriteOnlyFields key={`${state.entryGeneration}-${kind.id}-${replacementId ?? 'new'}`} kind={kind} encrypted={encrypted} labelHelp={sessionControlHelp(guide, 'label', storage)} disabled={!!contextReason || (idle && replacement === undefined)} prepareHelp={sessionControlHelp(guide, 'prepare', storage)} onPrepare={prepare} onHelp={onHelp} />}
      </div>
    </>}
    {cancellationReason && <p className="review-caution" role="status">{cancellationReason}</p>}
    {operation && (imageOperation ? <div className="session-progress" role="status" aria-live="polite"><div className="credential-row-heading"><h3>Original image selection status</h3><Badge tone={operation.settlement === 'unknown' || operation.settlement === 'late-known' ? 'warning' : 'neutral'}>{operation.phase}</Badge></div><p><strong>Source custody:</strong> {operation.source} · <strong>Settlement:</strong> {operation.settlement} · <strong>Reason:</strong> {operation.reason}</p><p>This is a passive busy and retirement display, not a credential selection or review. Captured images are not imported or Store-validated. Image review, copy consent and Stop remain with the original image operation in Metadata.</p><p>Pending, unknown or late-known status does not confirm cleanup. These controls cannot discard, replace or cancel that image owner.</p></div>
      : projectPathOperation ? <div className="session-progress" role="status" aria-live="polite"><div className="credential-row-heading"><h3>Original project-path picker status</h3><Badge>{operation.phase}</Badge></div><p><strong>Settlement:</strong> {operation.settlement} · <strong>Reason:</strong> {operation.reason}</p><p>This selects a project-relative draft path, not a credential or asset. Only the original picker offers Cancel; a pending or unknown result does not confirm selection or cleanup.</p></div>
      : <div className="session-progress" role="status" aria-live="polite"><div className="credential-row-heading"><h3>Original operation status</h3><Badge tone={operation.settlement === 'unknown' || operation.settlement === 'late-known' ? 'warning' : 'neutral'}>{operation.phase}</Badge></div><p><strong>Action:</strong> {operation.operation} · <strong>Source custody:</strong> {operation.source} · <strong>Settlement:</strong> {operation.settlement}</p><p>{ASSET_REASON_HELP[operation.reason]}</p>
        {operation.storageOutcome && <div><p><strong>Storage effect:</strong> {operation.storageOutcome.effect} · <strong>Durability:</strong> {operation.storageOutcome.durability} · <strong>Cleanup:</strong> {operation.storageOutcome.cleanup}</p><p>These are separate facts. An applied change is not a successful operation if cancellation, failure, uncertain durability or unconfirmed cleanup remains. Locking does not erase this receipt. No rollback or retry is inferred.</p></div>}
        {operation.phase !== 'idle' && <button className="button secondary small" disabled={!!cancellationReason} onClick={() => controller.discard()}>Request cancel / discard this operation</button>}<p>A pending result is not a successful import. Cancellation does not erase an unknown owner or restore an old assignment.</p></div>)}
    {operation?.assessment && guide && <Assessment value={operation.assessment} guide={guide} onHelp={onHelp} />}
    {preview && <div className="session-review" aria-label="Explicit private-input review"><div className="inline-heading"><h3>{preview.action === 'initialize' ? 'Create a new encrypted vault?' : preview.action === 'save' ? encrypted ? 'Save this encrypted input?' : 'Keep this input for this session?' : preview.action === 'bind' ? 'Assign this record to the submitted context?' : encrypted ? 'Remove this encrypted copy?' : 'Remove this session copy?'}</h3>{controlHelp(preview.action === 'bind' ? 'assign' : preview.action)}</div>
      <p><strong>Exact target:</strong> {reviewTarget ?? 'Not established — confirmation is unavailable'}{preview.subject.change === 'replace' ? ' · Replace this revision' : ''}</p>
      {!state.reviewReady && <p className="review-caution">The original action and this review have not been positively matched. Check status, or discard and prepare explicitly again. No confirmation will be sent.</p>}
      <p>{preview.action === 'initialize' ? 'Create application-managed encrypted storage outside your projects and its new protected OS keyring entry. Existing, conflicting or inaccessible state is not overwritten, adopted or repaired. No credential or assignment is created.' : preview.action === 'save' ? encrypted ? 'Save the captured snapshot and supplied fields as an encrypted copy. Saved means not assigned: the stored payload has not yet been checked for use. Next, explicitly choose Assess and assign on the actual saved revision.' : 'Only the native-captured snapshot and supplied fields are retained in memory. Keeping is not assigning; review the separate assignment step next.' : preview.action === 'bind' ? 'This assigns the exact freshly assessed revision to the submitted project draft and release scope. It does not start a build, verify an account or authorize a release.' : 'Only this stored copy is removed. The original file is never deleted, and old assignments will not be restored if you cancel.'}</p>
      <p>{expired ? 'This review has expired or is no longer current. No confirmation will be submitted.' : 'The original review lasts at most five minutes. Refreshing or moving from Keep to Assign does not extend it.'}</p>
      <div className="button-row"><button className="button secondary" disabled={!!cancellationReason} onClick={() => controller.discard()}>Discard review</button>{controlHelp('discard')}<button className={`button${preview.action === 'delete' ? ' danger' : ''}`} disabled={!!baseReason || expired || !state.reviewReady || !reviewTarget || (preview.action === 'save' || preview.action === 'bind') && !usable || preview.action === 'delete' && !writable} onClick={() => controller.confirmPreview(preview.token, preview.action)}>{preview.action === 'initialize' ? 'Create encrypted vault' : preview.action === 'save' ? encrypted ? 'Save encrypted copy' : 'Keep for this session' : preview.action === 'bind' ? 'Assign to this context' : encrypted ? 'Remove encrypted copy' : 'Remove session copy'}</button></div>
    </div>}
    {!!status?.records.length && <div className="session-records"><div className="inline-heading"><h3>{encrypted ? 'Encrypted stored records' : 'Kept session records'}</h3>{controlHelp('assign')}</div><p>{encrypted ? 'Authenticated descriptors only; a listed label is not payload assessment or assignment. At most 128 records / 1 GiB on disk. Labels are optional user text, never filled from original filenames.' : 'Fixed labels only; no secret value or original filename is displayed. At most 32 records / 64 MiB; retained only for this launch.'}</p>
      {status.records.map((record, index) => {
        const assigned = usable && status.assignments.some((assignment) => assignment.recordId === record.recordId && assignment.recordRevision === record.revision && assignment.kind === record.kind && assignment.contextRevision === status.context?.revision && assignment.availability === 'available');
        return <article key={record.recordId}><div><h4>{guide?.kinds.find((kind) => kind.id === record.kind)?.label ?? 'Private input'} · item {index + 1}{record.label ? ` · ${record.label}` : ''}</h4><p>Revision {record.revision} · {encrypted ? 'encrypted stored copy' : 'retained only in this session'}</p><Badge tone={assigned ? 'info' : 'neutral'}>{assigned ? 'Assigned to current submitted context' : record.availability === 'mutation-pending' ? 'Change pending · unavailable' : 'Not assigned to the current draft'}</Badge><p>{record.payloadState === 'not-checked' ? 'Payload not checked for the current session and draft. Assess this exact revision before assigning.' : 'Payload assessed for its submitted context; a changed draft needs preparation again. Native signing, account access and release readiness remain unverified.'}</p></div><div className="button-row"><button className="button secondary small" disabled={!usable || !idle || record.availability === 'mutation-pending'} onClick={() => controller.prepareRecord({ recordId: record.recordId, expectedRevision: record.revision })}>{encrypted ? 'Assess and assign…' : 'Review assignment'}</button><button className="button secondary small" disabled={!!baseReason || !writable || !idle || record.availability === 'mutation-pending'} onClick={() => controller.prepareDelete({ recordId: record.recordId, expectedRevision: record.revision })}>Review removal…</button></div></article>;
      })}
    </div>}
    <p className="session-limit-note">Encrypted storage and input collection require their qualified native profile; UI controls never enable that gate. Windows import, ASC P8 and binary plist are unavailable here. Apple P12/profile selection needs its separately admitted macOS profile and performs envelope assessment only. Actual password, identity, Apple profile and artifact checks belong to the separately admitted signed-export operation in Releases, not this session assessment. iOS Firebase supports XML plist checks only. No Store action is requested.</p>
  </section>;
}
