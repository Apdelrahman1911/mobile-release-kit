import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import type { ProjectSession } from '../drafts.ts';
import type { CredentialGuide, CredentialKind, HelpContent } from '../types.ts';
import type { AssetDisplayState, AssetKind, AssetScope, CredentialAssessment, CredentialIssue } from '../assetSessionTypes.ts';
import { AssetSessionController, assetCancellationReason, assetContextReason, assetIntentPending, assetSessionReason } from '../assetSessionController.ts';
import { ASSET_KINDS, ASSET_PLATFORMS, ASSET_PURPOSES, ASSET_REASON_HELP, ASSET_STAGES, SESSION_FIELDS, isAssetFileKind } from '../assetSessionProtocol.ts';
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
        {value.kind === 'ios-firebase' && <p>iOS Firebase scope: XML plist format and bundle-ID match only. This is not iOS signing or Firebase account verification.</p>}
      </li>;
    })}</ul>
    <div className="session-assurance"><Badge>Native validation: not run</Badge><Badge>Service validation: not run</Badge><Badge>Release readiness: unknown</Badge></div>
  </div>;
}

function WriteOnlyFields({ kind, disabled, prepareHelp, onPrepare, onHelp }: { kind: CredentialKind; disabled: boolean; prepareHelp: HelpContent | null; onPrepare: (fields: Record<string, string | null>) => boolean; onHelp: (help: HelpContent) => void }) {
  const id = useId();
  const [values, setValues] = useState<Record<string, string>>({});
  const names = SESSION_FIELDS[kind.id as AssetKind];
  return <form className="session-inputs" autoComplete="off" onSubmit={(event) => {
    event.preventDefault();
    if (disabled) return;
    const fields = Object.fromEntries(names.map((name) => [name, values[name] ?? null]));
    if (onPrepare(fields)) setValues({});
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
    <p className="subtle-note"><Icon name="lock" size={16} />Write-only entry. Values are cleared after handoff or cancellation; they are not put into project settings or browser storage. Complete memory erasure is not promised.</p>
    <div className="button-row"><button className="button" type="submit" disabled={disabled || names.some((name) => !kind.fields.some((field) => field.id === name))}><Icon name="shield" size={16} />Prepare private review</button>{prepareHelp && <HelpButton content={prepareHelp} onHelp={onHelp} />}</div>
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
  const baseReason = nativeBusyReason ?? assetSessionReason(state);
  const contextReason = nativeBusyReason ?? assetContextReason(state);
  const cancellationReason = assetCancellationReason(state);
  const inSession = status?.mode === 'session';
  const nativeAvailable = state.mode === 'native' && status?.capability.available === true && !state.blocked && !state.observationFailed;
  const idle = !operation || (operation.phase === 'idle' && operation.settlement === 'known');
  const projectPathActive = projectPathOperation && !idle;
  const intentPending = assetIntentPending(state);
  const effectiveKindId = intentPending && state.intent ? state.intent.kind : kindId;
  const originalKind = guide?.kinds.find((item) => item.id === (operation?.selectionToken ? state.selectionKind : effectiveKindId));
  const kind = originalKind ? sessionKindHelp(originalKind) : null;
  const originalSelectedKind = guide?.kinds.find((item) => item.id === effectiveKindId);
  const selectedKind = originalSelectedKind ? sessionKindHelp(originalSelectedKind) : null;
  const selectionVisible = !!(nativeAvailable && inSession && guide && !projectPathActive);
  // The complete existing outer + inner render condition protects even an
  // unsubmitted private form. Navigation never inspects or resets its values.
  const writeOnlyFormMounted = selectionVisible && !!kind && (!!(operation?.selectionToken && state.selectionKind) ||
    (idle && !intentPending && (kindId === 'google-wif' || kindId === 'project-read-token')));
  const replacement = controller.replacement(kindId, replacementId);
  const preview = operation?.preview;
  const expired = state.previewDeadline === null || performance.now() >= state.previewDeadline;
  const usable = state.contextCurrent && !baseReason && !state.busy && !state.updatingContext;
  const controlHelp = (name: string) => {
    const help = sessionControlHelp(guide, name);
    return help ? <HelpButton content={help} onHelp={onHelp} /> : null;
  };
  const intentTarget = state.intent ? sessionTargetLabel(guide, { kind: state.intent.kind, change: state.intent.change,
    recordId: state.intent.record?.recordId ?? null, recordRevision: state.intent.record?.expectedRevision ?? null }, status?.records ?? []) : null;
  const reviewTarget = preview ? sessionTargetLabel(guide, preview.subject, status?.records ?? []) : null;
  const scopeChange = (name: keyof AssetScope, value: string) => controller.setScope({ ...state.scope, [name]: value } as AssetScope);
  const prepare = (fields: Record<string, string | null>): boolean => {
    if (operation?.selectionToken) return controller.prepareSelection(state.selectionKind === 'android-keystore' ? { storePassword: fields.storePassword ?? null, keyAlias: fields.keyAlias ?? null, keyPassword: fields.keyPassword ?? null } : {});
    if (replacement === undefined) return false;
    if (kindId === 'google-wif') return controller.prepareScalar('google-wif', { provider: fields.provider ?? null, serviceAccount: fields.serviceAccount ?? null }, replacement);
    if (kindId === 'project-read-token') return controller.prepareScalar('project-read-token', { token: fields.token ?? null }, replacement);
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
    <SectionHeading title="Private inputs, one guided step at a time" description="Select → assess → keep for this session → assign to this release context. Each is a separate step." />
    <h3 id={`${id}-title`} className="inline-heading">Session-only storage {controlHelp('mode')}<Badge tone={inSession ? 'info' : 'neutral'}>{inSession ? 'Session open · no persistence' : 'Session closed'}</Badge></h3>
    <p>Nothing is uploaded, written into your repository, or stored in a persistent vault. Native file selection preserves the original. Quitting discards session copies only after their original owners settle.</p>
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
        <p>Continue sets the choices in the existing session controls. If a session is open, changing its release context submits that context and makes earlier assignment displays stale. It does not choose a file, read a credential, keep an input, assign it or start a release.</p>
        <p><strong>Next explicit step:</strong> {!nativeAvailable ? 'Read the availability reason below; this guide cannot enable collection.' : !inSession ? 'Start a session when you are ready.' : !state.contextCurrent || preparationScopeChanged(preparation, state.scope) ? 'Wait for the changed context, or use Submit current context if it is not current.' : isAssetFileKind(preparation.guideId) ? 'Use Select file, then prepare and review separately.' : 'Use the private fields, then Prepare private review.'}</p>
      </>}
      {preparationReason && <p className="review-caution" role="status">{preparationReason}</p>}
      <div className="button-row"><button type="button" className="button secondary" disabled={preparationReason !== null} onClick={continuePreparation}>Continue with this context</button><button type="button" className="button secondary" onClick={() => dismissPreparation(preparation)}>Close guidance</button></div>
    </div>}
    {!nativeAvailable && <div className="notice notice-warning"><Icon name="lock" size={18} /><div><strong>Private input is unavailable in this build</strong><p>{baseReason ?? 'Native qualification is required before collection.'}</p><p>Guides remain available. Do not paste credentials into project configuration to work around this gate.</p></div></div>}
    {state.error && <ErrorNotice error={state.error} title="The session action was not confirmed" />}
    <div className="button-row">
      {!inSession && <button className="button" disabled={!!baseReason || !guide} onClick={() => controller.open()}><Icon name="key" size={16} />Start session — keep inputs in memory</button>}
      <button className="button secondary" disabled={state.mode !== 'native' || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={16} />{state.observing ? 'Checking original status…' : 'Check session status'}</button>
      {inSession && <button className="button secondary" disabled={!!state.busy || projectPathActive} onClick={() => changeLocal({ confirmLock: true })}>Discard session…</button>}
    </div>
    {confirmLock && <div className="session-review" role="group" aria-label="Confirm session discard"><div className="inline-heading"><h3>Discard all session copies and assignments?</h3>{controlHelp('lock')}</div><p>Original files stay untouched. This cannot force cleanup of an unsettled operation. No record is kept for your next launch.</p><div className="button-row"><button className="button secondary" onClick={() => changeLocal({ confirmLock: false })}>Keep this session</button><button className="button danger" disabled={!!state.busy || projectPathActive} onClick={() => { if (controller.lock()) changeLocal({ confirmLock: false }); }}>Discard session copies</button></div></div>}
    <div className="session-context">
      <div className="inline-heading"><h3>Release context</h3>{controlHelp('project')}<Badge tone={state.contextCurrent ? 'info' : 'warning'}>{state.contextCurrent ? 'Context submitted · not yet policy-validated' : 'Context not current'}</Badge></div>
      <p><strong>Project:</strong> {project?.project.name ?? 'Choose a project first'} · {project?.draft ? 'Current in-memory draft' : 'Prepare a draft in Project settings'}</p>
      <div className="session-context-fields">{([
        ['platform', 'Platform', ASSET_PLATFORMS], ['stage', 'Release stage', ASSET_STAGES], ['purpose', 'Input purpose', ASSET_PURPOSES],
      ] as const).map(([name, label, options]) => <div className="field" key={name}><div className="field-label"><label htmlFor={`${id}-${name}`}>{label}</label>{controlHelp(name)}</div><select id={`${id}-${name}`} value={state.scope[name]} onChange={(event) => scopeChange(name, event.target.value)} disabled={state.blocked || nativeBusyReason !== null}>{options.map((option) => <option key={option} value={option}>{option === 'project' ? 'Project dependency access' : option === 'candidate' ? 'Candidate / internal testing' : option === 'production' ? 'Production preparation' : option === 'full' ? 'All selected input roles' : option === 'store' ? 'Store access only' : option === 'signing' ? 'Build / signing only' : option === 'external-testing' ? 'External testing' : option === 'ios' ? 'iOS' : 'Android'}</option>)}</select></div>)}</div>
      <p>Changing the project, draft, platform, stage or purpose makes prior assignment displays stale immediately. The core—not these selectors—decides which inputs are required.</p>
      <button className="button secondary small" disabled={!nativeAvailable || !inSession || !project || state.updatingContext || nativeBusyReason !== null} onClick={() => controller.submitContext()}>{state.updatingContext ? 'Submitting current context…' : 'Submit current context'}</button>
    </div>
    {selectionVisible && guide && <>
      <div className="session-selection">
        {idle && !intentPending ? <>
          <div className="field"><div className="field-label"><label htmlFor={`${id}-kind`}>What would you like to provide?</label>{controlHelp('choose')}</div><select id={`${id}-kind`} value={kindId} disabled={!!state.busy} onChange={(event) => changeLocal({ kindId: event.target.value as AssetKind, replacementId: null })}>{ASSET_KINDS.map((kind) => <option key={kind} value={kind}>{guide.kinds.find((entry) => entry.id === kind)?.label ?? 'Supported session input'}</option>)}</select></div>
          <div className="field"><div className="field-label"><label htmlFor={`${id}-replace`}>New or replacement copy?</label>{controlHelp('replace')}</div><select id={`${id}-replace`} value={replacementId ?? ''} disabled={!!state.busy} onChange={(event) => changeLocal({ replacementId: event.target.value || null })}><option value="">Keep a new session record</option>{status?.records.map((record, index) => record.kind === kindId && <option key={record.recordId} value={record.recordId}>Replace session item {index + 1} · revision {record.revision}</option>)}</select><p>Starting a replacement makes old assignments unavailable, even if you cancel. The old record is not silently reassigned.</p></div>
        </> : <div className="session-intent" role="status"><strong>Original requested action:</strong> {state.intent?.change === 'replace' ? 'Replace' : state.intent?.change === 'assign' ? 'Assess for assignment' : state.intent?.change === 'delete' ? 'Review removal of' : 'Prepare'} {intentTarget ?? 'an unconfirmed target'}<p>Page navigation cannot change this target. Cancel the original operation before choosing a different action.</p></div>}
        {isAssetFileKind(effectiveKindId) && <>
          <p>{effectiveKindId === 'android-keystore' ? 'Select a private .jks or .keystore original outside project folders. Only its JKS header is recognized; PKCS#12 is not supported here.' : effectiveKindId === 'ios-firebase' ? 'Select the iOS GoogleService-Info.plist downloaded from Firebase project settings, in XML format. The core checks its BUNDLE_ID against your submitted draft; binary plist is not supported.' : 'Select the Android google-services.json downloaded from Firebase project settings. Every supported client is checked against your draft by the core.'}</p>
          {selectedKind?.fields.find((field) => field.id === 'file') && <div className="inline-heading"><span>Where to find this file and what to expect</span><HelpButton content={selectedKind.fields.find((field) => field.id === 'file')!} onHelp={onHelp} /></div>}
          <button className="button secondary" disabled={!!contextReason || !idle || replacement === undefined} onClick={() => { if (replacement !== undefined) controller.choose(effectiveKindId, replacement); }}><Icon name="folder" size={17} />Select file…</button>
          <p>No path entry, manual registration, renaming or copy into an internal folder. Native selection never sends the original filename or bytes to this view.</p>
        </>}
        {contextReason && <p className="review-caution">{contextReason}</p>}
        {writeOnlyFormMounted && kind &&
          <WriteOnlyFields key={`${state.entryGeneration}-${kind.id}-${replacementId ?? 'new'}`} kind={kind} disabled={!!contextReason || (idle && replacement === undefined)} prepareHelp={sessionControlHelp(guide, 'prepare')} onPrepare={prepare} onHelp={onHelp} />}
      </div>
    </>}
    {cancellationReason && <p className="review-caution" role="status">{cancellationReason}</p>}
    {operation && (projectPathOperation ? <div className="session-progress" role="status" aria-live="polite"><div className="credential-row-heading"><h3>Original project-path picker status</h3><Badge>{operation.phase}</Badge></div><p><strong>Settlement:</strong> {operation.settlement} · <strong>Reason:</strong> {operation.reason}</p><p>This selects a project-relative draft path, not a credential or asset. Only the original picker offers Cancel; a pending or unknown result does not confirm selection or cleanup.</p></div>
      : <div className="session-progress" role="status" aria-live="polite"><div className="credential-row-heading"><h3>Original operation status</h3><Badge tone={operation.settlement === 'unknown' || operation.settlement === 'late-known' ? 'warning' : 'neutral'}>{operation.phase}</Badge></div><p><strong>Source custody:</strong> {operation.source} · <strong>Settlement:</strong> {operation.settlement}</p><p>{ASSET_REASON_HELP[operation.reason]}</p>{operation.phase !== 'idle' && <button className="button secondary small" disabled={!!cancellationReason} onClick={() => controller.discard()}>Request cancel / discard this operation</button>}<p>A pending result is not a successful import. Cancellation does not erase an unknown owner or restore an old assignment.</p></div>)}
    {operation?.assessment && guide && <Assessment value={operation.assessment} guide={guide} onHelp={onHelp} />}
    {preview && <div className="session-review" aria-label="Explicit session review"><div className="inline-heading"><h3>{preview.action === 'save' ? 'Keep this input for this session?' : preview.action === 'bind' ? 'Assign this record to the submitted context?' : 'Remove this session copy?'}</h3>{controlHelp(preview.action === 'bind' ? 'assign' : preview.action)}</div>
      <p><strong>Exact target:</strong> {reviewTarget ?? 'Not established — confirmation is unavailable'}{preview.subject.change === 'replace' ? ' · Replace this revision' : ''}</p>
      {!state.reviewReady && <p className="review-caution">The original action and this review have not been positively matched. Check status, or discard and prepare explicitly again. No confirmation will be sent.</p>}
      <p>{preview.action === 'save' ? 'Only the native-captured snapshot and supplied fields are retained in memory. Keeping is not assigning; review the separate assignment step next.' : preview.action === 'bind' ? 'This assigns the exact retained revision to the submitted project draft and release scope. It does not start a build, verify an account or authorize a release.' : 'Only this session record is removed. The original file is never deleted, and old assignments will not be restored if you cancel.'}</p>
      <p>{expired ? 'This review has expired or is no longer current. No confirmation will be submitted.' : 'The original review lasts at most five minutes. Refreshing or moving from Keep to Assign does not extend it.'}</p>
      <div className="button-row"><button className="button secondary" disabled={!!cancellationReason} onClick={() => controller.discard()}>Discard review</button>{controlHelp('discard')}<button className={`button${preview.action === 'delete' ? ' danger' : ''}`} disabled={!!baseReason || expired || !state.reviewReady || !reviewTarget || (preview.action !== 'delete' && !usable)} onClick={() => controller.confirmPreview(preview.token, preview.action)}>{preview.action === 'save' ? 'Keep for this session' : preview.action === 'bind' ? 'Assign to this context' : 'Remove session copy'}</button></div>
    </div>}
    {!!status?.records.length && <div className="session-records"><div className="inline-heading"><h3>Kept session records</h3>{controlHelp('assign')}</div><p>Fixed labels only; no secret value or original filename is displayed. At most 32 records / 64 MiB; secure persistence is not enabled.</p>
      {status.records.map((record, index) => {
        const assigned = usable && status.assignments.some((assignment) => assignment.recordId === record.recordId && assignment.recordRevision === record.revision && assignment.kind === record.kind && assignment.contextRevision === status.context?.revision && assignment.availability === 'available');
        return <article key={record.recordId}><div><h4>{guide?.kinds.find((kind) => kind.id === record.kind)?.label ?? 'Session input'} · item {index + 1}</h4><p>Revision {record.revision} · retained only in this session</p><Badge tone={assigned ? 'info' : 'neutral'}>{assigned ? 'Assigned to current submitted context' : record.availability === 'mutation-pending' ? 'Change pending · unavailable' : 'Not assigned to the current draft'}</Badge></div><div className="button-row"><button className="button secondary small" disabled={!usable || !idle || record.availability === 'mutation-pending'} onClick={() => controller.prepareRecord({ recordId: record.recordId, expectedRevision: record.revision })}>Review assignment</button><button className="button secondary small" disabled={!!baseReason || !idle || record.availability === 'mutation-pending'} onClick={() => controller.prepareDelete({ recordId: record.recordId, expectedRevision: record.revision })}>Review removal…</button></div></article>;
      })}
    </div>}
    <p className="session-limit-note">Not available in this increment: persistent encrypted storage, macOS/Windows import, PKCS#12, Apple profiles/P8 and binary plist. iOS Firebase supports XML plist checks only, subject to native availability. No native signing or online credential verification is claimed.</p>
  </section>;
}
