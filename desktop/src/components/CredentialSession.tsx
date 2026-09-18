import { useEffect, useId, useState } from 'react';
import type { ProjectSession } from '../drafts.ts';
import type { CredentialGuide, CredentialKind, HelpContent } from '../types.ts';
import type { AssetDisplayState, AssetKind, AssetScope, CredentialAssessment, CredentialIssue } from '../assetSessionTypes.ts';
import { AssetSessionController, assetCancellationReason, assetContextReason, assetIntentPending, assetSessionReason } from '../assetSessionController.ts';
import { ASSET_KINDS, ASSET_PLATFORMS, ASSET_PURPOSES, ASSET_REASON_HELP, ASSET_STAGES, SESSION_FIELDS } from '../assetSessionProtocol.ts';
import { sessionControlHelp, sessionKindHelp, sessionTargetLabel } from '../assetSessionHelp.ts';
import { Badge, ErrorNotice, HelpButton, SectionHeading } from './Common.tsx';
import { Icon } from './Icon.tsx';

const issueHelp: Record<CredentialIssue, string> = {
  'not-run': 'This check was not run.', incomplete: 'The supplied observation is incomplete.',
  'unsupported-format': 'This file format is not supported by this importer.', 'unsupported-variant': 'This variant is not supported; it has not been declared invalid.',
  'material-limit': 'The file exceeds the material-size limit.', 'parser-limit': 'The file exceeds a supported complexity limit.',
  'empty-file': 'The selected file is empty.', 'suffix-conflict': 'The file extension does not match this input kind.',
  'malformed-container': 'The supported container could not be parsed completely.', 'required-missing': 'Supply this required field before preparing again.',
  'value-nul': 'This field contains an unsupported NUL character.', 'scalar-format': 'The value does not match the required identifier format. Open its field help.',
  'pkcs8-algorithm': 'The selected key identifiers are not supported.', 'firebase-shape': 'The Firebase document is missing a supported client structure.',
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

export function CredentialSession({ state, controller, project, guide, onHelp, nativeBusyReason = null }: { state: AssetDisplayState; controller: AssetSessionController; project: ProjectSession | null; guide: CredentialGuide | null; onHelp: (help: HelpContent) => void; nativeBusyReason?: string | null }) {
  const id = useId();
  const [kindId, setKind] = useState<AssetKind>('android-keystore');
  const [replacementId, setReplacement] = useState<string | null>(null);
  const [confirmLock, setConfirmLock] = useState(false);
  const [, expireView] = useState(0);
  useEffect(() => {
    if (state.previewDeadline === null) return;
    const timer = setTimeout(() => expireView((value) => value + 1), Math.max(0, state.previewDeadline - performance.now()) + 1);
    return () => clearTimeout(timer);
  }, [state.previewDeadline]);
  useEffect(() => { setReplacement(null); setConfirmLock(false); }, [project?.project.id, state.scope.platform, state.scope.stage, state.scope.purpose]);
  const status = state.status;
  const operation = status?.operation;
  const baseReason = nativeBusyReason ?? assetSessionReason(state);
  const contextReason = nativeBusyReason ?? assetContextReason(state);
  const cancellationReason = assetCancellationReason(state);
  const inSession = status?.mode === 'session';
  const nativeAvailable = state.mode === 'native' && status?.capability.available === true && !state.blocked && !state.observationFailed;
  const idle = !operation || (operation.phase === 'idle' && operation.settlement === 'known');
  const intentPending = assetIntentPending(state);
  const effectiveKindId = intentPending && state.intent ? state.intent.kind : kindId;
  const originalKind = guide?.kinds.find((item) => item.id === (operation?.selectionToken ? state.selectionKind : effectiveKindId));
  const kind = originalKind ? sessionKindHelp(originalKind) : null;
  const originalSelectedKind = guide?.kinds.find((item) => item.id === effectiveKindId);
  const selectedKind = originalSelectedKind ? sessionKindHelp(originalSelectedKind) : null;
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
    if (operation?.selectionToken) return controller.prepareSelection(state.selectionKind === 'android-firebase' ? {} : { storePassword: fields.storePassword ?? null, keyAlias: fields.keyAlias ?? null, keyPassword: fields.keyPassword ?? null });
    if (replacement === undefined) return false;
    if (kindId === 'google-wif') return controller.prepareScalar('google-wif', { provider: fields.provider ?? null, serviceAccount: fields.serviceAccount ?? null }, replacement);
    if (kindId === 'project-read-token') return controller.prepareScalar('project-read-token', { token: fields.token ?? null }, replacement);
    return false;
  };
  return <section className="card credential-session" aria-labelledby={`${id}-title`}>
    <SectionHeading title="Private inputs, one guided step at a time" description="Select → assess → keep for this session → assign to this release context. Each is a separate step." />
    <h3 id={`${id}-title`} className="inline-heading">Session-only storage {controlHelp('mode')}<Badge tone={inSession ? 'info' : 'neutral'}>{inSession ? 'Session open · no persistence' : 'Session closed'}</Badge></h3>
    <p>Nothing is uploaded, written into your repository, or stored in a persistent vault. Native file selection preserves the original. Quitting discards session copies only after their original owners settle.</p>
    {!nativeAvailable && <div className="notice notice-warning"><Icon name="lock" size={18} /><div><strong>Private input is unavailable in this build</strong><p>{baseReason ?? 'Native qualification is required before collection.'}</p><p>Guides remain available. Do not paste credentials into project configuration to work around this gate.</p></div></div>}
    {state.error && <ErrorNotice error={state.error} title="The session action was not confirmed" />}
    <div className="button-row">
      {!inSession && <button className="button" disabled={!!baseReason || !guide} onClick={() => controller.open()}><Icon name="key" size={16} />Start session — keep inputs in memory</button>}
      <button className="button secondary" disabled={state.mode !== 'native' || state.observing} onClick={() => void controller.checkStatus()}><Icon name="refresh" size={16} />{state.observing ? 'Checking original status…' : 'Check session status'}</button>
      {inSession && <button className="button secondary" disabled={!!state.busy} onClick={() => setConfirmLock(true)}>Discard session…</button>}
    </div>
    {confirmLock && <div className="session-review" role="group" aria-label="Confirm session discard"><div className="inline-heading"><h3>Discard all session copies and assignments?</h3>{controlHelp('lock')}</div><p>Original files stay untouched. This cannot force cleanup of an unsettled operation. No record is kept for your next launch.</p><div className="button-row"><button className="button secondary" onClick={() => setConfirmLock(false)}>Keep this session</button><button className="button danger" disabled={!!state.busy} onClick={() => { if (controller.lock()) setConfirmLock(false); }}>Discard session copies</button></div></div>}
    <div className="session-context">
      <div className="inline-heading"><h3>Release context</h3>{controlHelp('project')}<Badge tone={state.contextCurrent ? 'info' : 'warning'}>{state.contextCurrent ? 'Context submitted · not yet policy-validated' : 'Context not current'}</Badge></div>
      <p><strong>Project:</strong> {project?.project.name ?? 'Choose a project first'} · {project?.draft ? 'Current in-memory draft' : 'Prepare a draft in Project settings'}</p>
      <div className="session-context-fields">{([
        ['platform', 'Platform', ASSET_PLATFORMS], ['stage', 'Release stage', ASSET_STAGES], ['purpose', 'Input purpose', ASSET_PURPOSES],
      ] as const).map(([name, label, options]) => <div className="field" key={name}><div className="field-label"><label htmlFor={`${id}-${name}`}>{label}</label>{controlHelp(name)}</div><select id={`${id}-${name}`} value={state.scope[name]} onChange={(event) => scopeChange(name, event.target.value)} disabled={state.blocked || nativeBusyReason !== null}>{options.map((option) => <option key={option} value={option}>{option === 'project' ? 'Project dependency access' : option === 'candidate' ? 'Candidate / internal testing' : option === 'production' ? 'Production preparation' : option === 'full' ? 'All selected input roles' : option === 'store' ? 'Store access only' : option === 'signing' ? 'Build / signing only' : option === 'external-testing' ? 'External testing' : option === 'ios' ? 'iOS' : 'Android'}</option>)}</select></div>)}</div>
      <p>Changing the project, draft, platform, stage or purpose makes prior assignment displays stale immediately. The core—not these selectors—decides which inputs are required.</p>
      <button className="button secondary small" disabled={!nativeAvailable || !inSession || !project || state.updatingContext || nativeBusyReason !== null} onClick={() => controller.submitContext()}>{state.updatingContext ? 'Submitting current context…' : 'Submit current context'}</button>
    </div>
    {nativeAvailable && inSession && guide && <>
      <div className="session-selection">
        {idle && !intentPending ? <>
          <div className="field"><div className="field-label"><label htmlFor={`${id}-kind`}>What would you like to provide?</label>{controlHelp('choose')}</div><select id={`${id}-kind`} value={kindId} disabled={!!state.busy} onChange={(event) => { setKind(event.target.value as AssetKind); setReplacement(null); }}>{ASSET_KINDS.map((kind) => <option key={kind} value={kind}>{guide.kinds.find((entry) => entry.id === kind)?.label ?? 'Supported session input'}</option>)}</select></div>
          <div className="field"><div className="field-label"><label htmlFor={`${id}-replace`}>New or replacement copy?</label>{controlHelp('replace')}</div><select id={`${id}-replace`} value={replacementId ?? ''} disabled={!!state.busy} onChange={(event) => setReplacement(event.target.value || null)}><option value="">Keep a new session record</option>{status?.records.map((record, index) => record.kind === kindId && <option key={record.recordId} value={record.recordId}>Replace session item {index + 1} · revision {record.revision}</option>)}</select><p>Starting a replacement makes old assignments unavailable, even if you cancel. The old record is not silently reassigned.</p></div>
        </> : <div className="session-intent" role="status"><strong>Original requested action:</strong> {state.intent?.change === 'replace' ? 'Replace' : state.intent?.change === 'assign' ? 'Assess for assignment' : state.intent?.change === 'delete' ? 'Review removal of' : 'Prepare'} {intentTarget ?? 'an unconfirmed target'}<p>Page navigation cannot change this target. Cancel the original operation before choosing a different action.</p></div>}
        {(effectiveKindId === 'android-keystore' || effectiveKindId === 'android-firebase') && <>
          <p>{effectiveKindId === 'android-keystore' ? 'Select a private .jks or .keystore original outside project folders. Only its JKS header is recognized; PKCS#12 is not supported here.' : 'Select the Android google-services.json downloaded from Firebase project settings. Every supported client is checked against your draft by the core.'}</p>
          {selectedKind?.fields.find((field) => field.id === 'file') && <div className="inline-heading"><span>Where to find this file and what to expect</span><HelpButton content={selectedKind.fields.find((field) => field.id === 'file')!} onHelp={onHelp} /></div>}
          <button className="button secondary" disabled={!!contextReason || !idle || replacement === undefined} onClick={() => { if (replacement !== undefined) controller.choose(effectiveKindId, replacement); }}><Icon name="folder" size={17} />Select file…</button>
          <p>No path entry, manual registration, renaming or copy into an internal folder. Native selection never sends the original filename or bytes to this view.</p>
        </>}
        {contextReason && <p className="review-caution">{contextReason}</p>}
        {kind && ((operation?.selectionToken && state.selectionKind) || (idle && !intentPending && (kindId === 'google-wif' || kindId === 'project-read-token'))) &&
          <WriteOnlyFields key={`${state.entryGeneration}-${kind.id}-${replacementId ?? 'new'}`} kind={kind} disabled={!!contextReason || (idle && replacement === undefined)} prepareHelp={sessionControlHelp(guide, 'prepare')} onPrepare={prepare} onHelp={onHelp} />}
      </div>
    </>}
    {cancellationReason && <p className="review-caution" role="status">{cancellationReason}</p>}
    {operation && <div className="session-progress" role="status" aria-live="polite"><div className="credential-row-heading"><h3>Original operation status</h3><Badge tone={operation.settlement === 'unknown' || operation.settlement === 'late-known' ? 'warning' : 'neutral'}>{operation.phase}</Badge></div><p><strong>Source custody:</strong> {operation.source} · <strong>Settlement:</strong> {operation.settlement}</p><p>{ASSET_REASON_HELP[operation.reason]}</p>{operation.phase !== 'idle' && <button className="button secondary small" disabled={!!cancellationReason} onClick={() => controller.discard()}>Request cancel / discard this operation</button>}<p>A pending result is not a successful import. Cancellation does not erase an unknown owner or restore an old assignment.</p></div>}
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
    <p className="session-limit-note">Not available in this increment: persistent encrypted storage, macOS/Windows import, PKCS#12, Apple profiles/P8 and iOS plist import. Their guides remain below. No native signing or online credential verification is claimed.</p>
  </section>;
}
