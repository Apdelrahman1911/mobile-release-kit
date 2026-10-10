import { useId, useState } from 'react';
import type { AssetDisplayState } from '../assetSessionTypes.ts';
import type { HelpContent } from '../types.ts';
import type { GitHubRemoteSetupController } from '../GitHubRemoteSetupController.ts';
import type { GitHubRemoteSetupVariableSelection, GitHubRemoteSetupSecretSelection, GitHubRemoteSetupEnvironmentPolicy, GitHubRemoteSetupEnvironmentSelection, GitHubRemoteSetupObservation, GitHubRemoteSetupPolicy, GitHubRemoteSetupView } from '../GitHubRemoteSetupTypes.ts';
import { GITHUB_REMOTE_SETUP_VARIABLE_FIELDS, GITHUB_REMOTE_SETUP_VARIABLE_PREVIOUS, GITHUB_REMOTE_SETUP_VARIABLE_ACCEPTANCE, githubRemoteSetupVariableReferences, GITHUB_REMOTE_SETUP_ENVIRONMENTS, GITHUB_REMOTE_SETUP_HELP, GITHUB_REMOTE_SETUP_SECRET_FIELDS, GITHUB_REMOTE_SETUP_SECRET_ACCEPTANCE, githubRemoteSetupSecretReferences, githubRemoteSetupSelection } from '../GitHubRemoteSetupProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
const HELP: Record<'setting' | 'environment' | 'secret' | 'variable' | 'access' | 'consent' | 'outcome', HelpContent> = {
  setting: { label: 'Repository setting', requiredness: 'required', requiredWhen: 'Before requesting a remote policy preview.',
    what: 'One fixed setting: Actions, default workflow token permissions, or the shown deployment-environment policy fields.',
    why: 'Each preview reads the actual account, repository and policy. Local workflow files and editor drafts cannot prove remote settings.',
    where: 'Choose the setting here after connecting to this project’s explicit repository. No URL, token or arbitrary policy JSON is accepted.',
    format: 'Explicit boolean values and read/write token permission. For Actions, allowed_actions and sha_pinning_required are observed and preserved, never defaulted.',
    failure: 'Missing, unsupported or changed policies are refused. Enabling Actions can allow already-configured workflows to run.' },
  environment: { label: 'Deployment environment policy', requiredness: 'required', requiredWhen: 'When reviewing an environment create-or-update request.',
    what: 'One toolkit environment: mobile-candidate, mobile-external-testing or mobile-production. Configure existing changes only the wait timer and optional self-review flag; reviewer identities and branch mode are preserved.',
    why: 'Create if observed absent requires one explicit GitHub username with current repository access, self-review prevention, and a branch choice. Existing environments can retain up to six User/Team reviewers, but this editor does not replace that list.',
    where: 'Use the reviewer’s GitHub profile username (without @), not display name, email or team name. Check repository Settings → Environments for plan restrictions, administrator bypass and other protection settings.',
    format: 'Wait timer: whole minutes from 0 (no delay) to 43,200. Protected-branches mode allows all branches if none are protected; it does not create branch protection. All branches is an explicit less restrictive choice.',
    failure: 'Unsupported/custom policies and changed identities refuse before a write. GitHub uses create-or-update, not atomic compare-and-set: a concurrent edit may be overwritten or a deleted environment recreated. Cancellation cannot undo a sent request; secrets and complete protection remain unverified.' },
  secret: { label: 'One assigned required secret', requiredness: 'conditional', requiredWhen: 'Only when you explicitly select a required environment secret.',
    what: 'One fixed requirement from an already assessed and assigned credential. This card handles opaque references only, never secret text or a file path.',
    why: 'Open Credentials to choose a file with the native picker, enter its existing credential fields, assess it and assign it to this project, platform and stage. Return here and explicitly select the exact field.',
    where: 'Android keystore provides file/store password/key password; Firebase provides its file. Apple P12 provides file/password; profile, Firebase and App Store Connect P8 provide their files. Project read token uses its existing scalar record.',
    format: 'Files are Base64-encoded once by the native borrower: at most 36 KiB raw and 48 KiB encoded. Text fields remain UTF-8; smaller field limits still apply. Actual saved configuration must require the field and match the assigned context. Nonsecret identifiers use the separate variable choice. App Review and commitment fields without a record mapping remain unsupported here.',
    failure: 'An assigned record is not proof that the fixed sealing helper is installed or usable. Preview checks the native helper, configuration, destination and permissions. Secret previews require GitHub Environments read; confirmed Apply requires Environments write, separate from repository Administration. Existing connection read permissions still apply; use only the intended repository. Missing prerequisites refuse without a browser, PATH or manual-value fallback.' },
  variable: { label: 'Required nonsecret identifier', requiredness: 'required', requiredWhen: 'Before explicitly previewing one required GitHub environment variable.',
    what: 'One fixed identifier from an assessed and assigned credential: Android key alias, Google WIF provider/service account, or App Store Connect key/issuer ID.',
    why: 'Variables are not secrets. Permitted GitHub users and workflows can read them. Passwords, private keys and arbitrary record fields cannot be selected here.',
    where: 'Use Credentials to choose this project, platform and stage, assess and assign the intended record, then return and select its current reference. The exact desired text appears only in the settled native preview.',
    format: 'A variable identifier must fit its native field format and 4 KiB; the actual escaped preview must fit 8 KiB. The core saved configuration decides whether it is required. The commitment-key version has no supported record mapping here.',
    failure: 'A matching assigned reference does not prove native variable support. Preview checks the runtime, saved configuration, destination and permissions. Variables use GitHub Environments read for preview and write for Apply; this does not require the secret sealing helper. No ambient CLI, plaintext entry or browser fallback is offered.' },
  access: { label: 'Separate remote permissions', requiredness: 'required', requiredWhen: 'For a settings preview or confirmed Apply.',
    what: 'The existing native session-only GitHub connection; this card never collects or saves another token.',
    why: 'Repository settings require Administration read for preview and write to apply. Secrets and variables instead need Environments read/write. A successful connection does not prove those permissions.',
    where: 'Configure only the intended repository and permissions in GitHub’s token settings. Organization approval or SSO may also be required.',
    format: 'Keep Actions read and Metadata read for the existing connection, then only the permission for the selected operation. Administration does not substitute for Environments permission. GitHub plan/organization restrictions may apply; no workflow dispatch is authorized here.',
    failure: 'A refusal does not trigger permission escalation, reconnection or retry. Retire the original connection before explicitly replacing it.' },
  consent: { label: 'Exact before/after confirmation', requiredness: 'required', requiredWhen: 'After a fully settled preview and before one Apply.',
    what: 'A short-lived native one-use review bound to this original project, account, repository and selection.',
    why: 'Write tokens and review approvals increase privileges. GitHub provides no atomic compare-and-set; another administrator can race this review.',
    where: 'Read every before/after row and the exact confirmation, then check the confirmation box. Apply submits only the native consent ID.',
    format: 'Changing a selection or project edit invalidates and discards the original consent. Expiry is enforced natively; the displayed time is not a clock grant.',
    failure: 'No rollback or automatic retry is offered. A stale or consumed review requires a fresh explicit preview after known settlement.' },
  outcome: { label: 'Observation, write uncertainty and cleanup', requiredness: 'optional', requiredWhen: 'After requesting Stop, losing a reply, or receiving a terminal result.',
    what: 'Local Status reads the same native original; it does not query GitHub or create a new operation.',
    why: 'A stopped or failed request may already have changed a setting. Unknown write flags are not false.',
    where: 'Use Read local Status and Stop original below. Keep the app open when original cleanup is unknown.',
    format: 'Readback-confirmed means this bounded request observed its intended policy or nonsecret identifier after an acknowledged write, not future stability or release readiness.',
    failure: 'A late response cannot erase unknown cleanup. Fresh preview is explicit and only available after the original action is known settled.' },
};
function PolicyRows({ policy }: { policy: GitHubRemoteSetupPolicy | GitHubRemoteSetupEnvironmentPolicy }) {
  if ('waitTimerMinutes' in policy) return <dl className="description-list">
    <div><dt>Wait timer (minutes)</dt><dd>{policy.waitTimerMinutes}</dd></div>
    <div><dt>Deployment branches</dt><dd>{policy.protectedBranches ? 'Protected branches · all branches if none are protected' : 'All branches'}</dd></div>
    <div><dt>Prevent self-review</dt><dd>{policy.requiredReviewers === null ? 'No required-reviewer rule' : String(policy.requiredReviewers.preventSelfReview)}</dd></div>
    <div><dt>Required reviewer identities</dt><dd>{policy.requiredReviewers === null ? 'No required-reviewer rule' : <ul>{policy.requiredReviewers.reviewers.map((r) => <li key={`${r.type}:${r.id}`}>{r.type} · ID {r.id}</li>)}</ul>}</dd></div>
  </dl>;
  return <dl className="description-list">{'enabled' in policy ? <>
    <div><dt>Actions enabled</dt><dd>{String(policy.enabled)}</dd></div>
    <div><dt>Allowed actions (preserved)</dt><dd>{policy.allowed_actions}</dd></div>
    <div><dt>SHA pinning required (preserved)</dt><dd>{String(policy.sha_pinning_required)}</dd></div>
  </> : <><div><dt>Default workflow token permissions</dt><dd>{policy.default_workflow_permissions}</dd></div>
    <div><dt>Can approve pull requests</dt><dd>{String(policy.can_approve_pull_request_reviews)}</dd></div></>}</dl>;
}
function ObservationRows({ observed }: { observed: GitHubRemoteSetupObservation }) {
  if ('environmentName' in observed && 'value' in observed) return <><dl className="description-list">
    <div><dt>Environment</dt><dd>{observed.environmentName} · ID {observed.environmentId}</dd></div>
    <div><dt>Required nonsecret variable</dt><dd>{observed.name}</dd></div>
    <div><dt>Value observation</dt><dd>{observed.value === null ? 'Observed absent for this exact admitted destination' : `${observed.value.bytes} bytes · SHA-256 ${observed.value.sha256}`}</dd></div>
    {observed.metadata && <><div><dt>Created at</dt><dd>{observed.metadata.createdAt}</dd></div><div><dt>Updated at</dt><dd>{observed.metadata.updatedAt}</dd></div></>}
  </dl><p>{GITHUB_REMOTE_SETUP_VARIABLE_PREVIOUS}</p></>;
  if ('environmentName' in observed) return <dl className="description-list">
    <div><dt>Environment</dt><dd>{observed.environmentName} · ID {observed.environmentId}</dd></div>
    <div><dt>Required secret</dt><dd>{observed.name}</dd></div>
    <div><dt>Metadata</dt><dd>{observed.metadata === null ? 'Observed absent for this exact admitted destination' : 'Observed present · value cannot be read or compared'}</dd></div>
    {observed.metadata && <><div><dt>Created at</dt><dd>{observed.metadata.createdAt}</dd></div><div><dt>Updated at</dt><dd>{observed.metadata.updatedAt}</dd></div></>}
  </dl>;
  if (!('policy' in observed)) return <PolicyRows policy={observed} />;
  return <><dl className="description-list"><div><dt>Environment</dt><dd>{observed.name}</dd></div>
    <div><dt>Environment ID</dt><dd>{observed.id ?? 'Observed absent in the complete bounded list'}</dd></div></dl>
    {observed.policy && <PolicyRows policy={observed.policy} />}</>;
}
type EnvironmentInputs = { mode: 'configure' | 'create'; stage: GitHubRemoteSetupEnvironmentSelection['stage']; timer: string;
  selfReview: 'preserve' | 'true' | 'false'; reviewer: string; branches: '' | 'all' | 'protected' };
function environmentInputs(selected?: GitHubRemoteSetupEnvironmentSelection): EnvironmentInputs {
  return { mode: selected?.mode ?? 'configure', stage: selected?.stage ?? 'candidate', timer: String(selected?.waitTimerMinutes ?? 0),
    selfReview: selected?.preventSelfReview == null ? 'preserve' : String(selected.preventSelfReview) as 'true' | 'false',
    reviewer: selected?.reviewerLogin ?? '', branches: selected?.branches ?? '' };
}
type SecretInputs = { mode: '' | 'create' | 'replace'; stage: GitHubRemoteSetupSecretSelection['stage']; requirement: '' | GitHubRemoteSetupSecretSelection['requirement']; recordId: string };
type VariableInputs = { mode: '' | 'create' | 'replace'; stage: GitHubRemoteSetupVariableSelection['stage']; requirement: '' | GitHubRemoteSetupVariableSelection['requirement']; recordId: string };
export function GitHubRemoteSetup({ state, controller, onHelp, compact = false, onShow, assets = null, projectId = null, onCredentials }: {
  state: GitHubRemoteSetupView; controller: GitHubRemoteSetupController; onHelp: (help: HelpContent) => void; compact?: boolean; onShow?: () => void;
  assets?: AssetDisplayState | null; projectId?: string | null; onCredentials?: () => void;
}) {
  const choiceId = useId(), enabledId = useId(), permissionsId = useId(), approvalsId = useId(), confirmId = useId(), reasonId = useId();
  const environmentId = useId(), modeId = useId(), timerId = useId(), selfReviewId = useId(), reviewerId = useId(), branchesId = useId();
  const [environment, setEnvironment] = useState<EnvironmentInputs | null>(() => state.selection?.kind === 'environment_protection' ? environmentInputs(state.selection) : null);
  const changeEnvironment = (next: EnvironmentInputs) => {
    setEnvironment(next);
    const selection = { kind: 'environment_protection', mode: next.mode, stage: next.stage,
      waitTimerMinutes: /^(0|[1-9][0-9]{0,4})$(?![\s\S])/.test(next.timer) ? Number(next.timer) : NaN,
      preventSelfReview: next.mode === 'create' ? true : next.selfReview === 'preserve' ? null : next.selfReview === 'true',
      reviewerLogin: next.mode === 'create' ? next.reviewer : null, branches: next.mode === 'create' ? next.branches : null };
    // Incomplete text stays local. Every invalid edit retires the previous consent,
    // never leaves a previously valid selection eligible for Prepare.
    controller.setSelection(githubRemoteSetupSelection(selection) ? selection : null);
  };
  const secretModeId = useId(), secretStageId = useId(), requirementId = useId(), recordId = useId();
  const [secret, setSecret] = useState<SecretInputs | null>(() => state.selection?.kind === 'environment_secret' ? {
    mode: state.selection.mode, stage: state.selection.stage, requirement: state.selection.requirement, recordId: state.selection.source.recordId } : null);
  const secretRefs = secret?.requirement && projectId ? githubRemoteSetupSecretReferences(assets, projectId, secret.requirement, secret.stage) : [];
  const changeSecret = (next: SecretInputs) => {
    setSecret(next);
    const refs = next.requirement && projectId ? githubRemoteSetupSecretReferences(assets, projectId, next.requirement, next.stage).filter((r) => r.source.recordId === next.recordId) : [];
    const ref = refs[0];
    const selection = refs.length === 1 && ref ? { kind: 'environment_secret', mode: next.mode, stage: next.stage, requirement: next.requirement, source: ref.source } : null;
    controller.setSelection(githubRemoteSetupSelection(selection) ? selection : null);
  };
  const variableModeId = useId(), variableStageId = useId(), variableRequirementId = useId(), variableRecordId = useId();
  const [variable, setVariable] = useState<VariableInputs | null>(() => state.selection?.kind === 'environment_variable' ? {
    mode: state.selection.mode, stage: state.selection.stage, requirement: state.selection.requirement, recordId: state.selection.source.recordId } : null);
  const variableRefs = variable?.requirement && projectId ? githubRemoteSetupVariableReferences(assets, projectId, variable.requirement, variable.stage) : [];
  const changeVariable = (next: VariableInputs) => {
    setVariable(next);
    const refs = next.requirement && projectId ? githubRemoteSetupVariableReferences(assets, projectId, next.requirement, next.stage).filter((r) => r.source.recordId === next.recordId) : [];
    const ref = refs[0];
    const selection = refs.length === 1 && ref ? { kind: 'environment_variable', mode: next.mode, stage: next.stage, requirement: next.requirement, source: ref.source } : null;
    controller.setSelection(githubRemoteSetupSelection(selection) ? selection : null);
  };
  const status = state.status, op = status?.operation, consent = controller.currentConsent(), selected = state.selection;
  const retained = state.pending || state.uncertain || state.discarding || state.cancelling || !!op && op.phase !== 'settled';
  if (compact && !retained) return null;
  const controls = <div className="button-row">
    <button type="button" className="button secondary" disabled={state.observing || state.mode !== 'native' && !retained} onClick={() => { void controller.checkStatus(); }}>Read local Status</button>
    <button type="button" className="button secondary" disabled={!controller.canCancel()} onClick={() => controller.cancel()}>Stop original</button>
    <HelpButton content={HELP.outcome} onHelp={onHelp} />
  </div>;
  if (compact) return <section className="card" aria-label="Retained repository settings original"><SectionHeading title="Repository settings original retained" description="A page change never cancels or replaces a native action." /><p role="status">{state.error ? GITHUB_REMOTE_SETUP_HELP[state.error] : 'Read the original local Status before starting another operation.'}</p>{controls}<button className="button secondary" type="button" onClick={onShow}>Show repository settings</button></section>;
  return <section className="card" aria-label="Authenticated repository settings">
    <SectionHeading title="Repository settings · separate remote confirmation" description="Fixed settings, assigned secrets and five nonsecret identifiers use separate native previews and one-use confirmation. This does not change local workflows, dispatch a workflow or qualify a release."><Badge tone="neutral">{state.mode === 'native' ? 'Native session required' : 'Unavailable in preview'}</Badge></SectionHeading>
    <p>Connecting alone never changes settings. Enabling Actions can allow configured workflows to run; write tokens and pull-request approval permissions grant additional privileges.</p>
    <div className="button-row"><HelpButton content={HELP.setting} onHelp={onHelp} /><HelpButton content={HELP.access} onHelp={onHelp} /></div>
    <div className="form-field"><label htmlFor={choiceId}>Setting to review</label><select id={choiceId} value={variable !== null ? 'environment_variable' : secret !== null ? 'environment_secret' : environment !== null ? 'environment_protection' : selected?.kind ?? ''} onChange={(e) => {
      if (e.target.value === 'environment_variable') { setSecret(null); setEnvironment(null); changeVariable({ mode: '', stage: 'candidate', requirement: '', recordId: '' }); }
      else if (e.target.value === 'environment_secret') { setVariable(null); setEnvironment(null); changeSecret({ mode: '', stage: 'candidate', requirement: '', recordId: '' }); }
      else if (e.target.value === 'environment_protection') { setVariable(null); setSecret(null); changeEnvironment(environmentInputs()); }
      else { setVariable(null); setSecret(null); setEnvironment(null); controller.setSelection(e.target.value === 'actions_enabled' ? { kind: 'actions_enabled', enabled: false } : e.target.value === 'workflow_token_policy' ? { kind: 'workflow_token_policy', defaultWorkflowPermissions: 'read', canApprovePullRequestReviews: false } : null); }
    }}>
      <option value="">Choose one setting</option><option value="actions_enabled">Enable or disable Actions</option><option value="workflow_token_policy">Default workflow token permissions</option><option value="environment_protection">Deployment environment policy</option><option value="environment_secret">Required environment secret · assigned credential</option><option value="environment_variable">Required environment variable · nonsecret assigned identifier</option></select></div>
    {selected?.kind === 'actions_enabled' && <div className="form-field"><label htmlFor={enabledId}>Intended Actions enabled value</label><select id={enabledId} value={String(selected.enabled)} onChange={(e) => controller.setSelection({ ...selected, enabled: e.target.value === 'true' })}><option value="false">false · disable</option><option value="true">true · enable</option></select></div>}
    {selected?.kind === 'workflow_token_policy' && <div className="form-grid"><div className="form-field"><label htmlFor={permissionsId}>Intended default token permissions</label><select id={permissionsId} value={selected.defaultWorkflowPermissions} onChange={(e) => { if (e.target.value === 'read' || e.target.value === 'write') controller.setSelection({ ...selected, defaultWorkflowPermissions: e.target.value }); }}><option value="read">read</option><option value="write">write</option></select></div>
      <div className="form-field"><label htmlFor={approvalsId}>Intended pull-request approval permission</label><select id={approvalsId} value={String(selected.canApprovePullRequestReviews)} onChange={(e) => controller.setSelection({ ...selected, canApprovePullRequestReviews: e.target.value === 'true' })}><option value="false">false · do not allow</option><option value="true">true · allow</option></select></div></div>}
    {secret && <section aria-label="Assigned secret selection"><div className="button-row"><HelpButton content={HELP.secret} onHelp={onHelp} />
      <button type="button" className="button secondary" disabled={!onCredentials} onClick={onCredentials}>Open Credentials to assess and assign</button></div>
      <p>This list contains public record references, not secret values. Nothing is sent until a native preview settles and you confirm its exact one-use review.</p>
      <div className="form-grid"><div className="form-field"><label htmlFor={secretModeId}>Secret action · choose explicitly</label><select id={secretModeId} value={secret.mode} onChange={(e) => {
        if (e.target.value === '' || e.target.value === 'create' || e.target.value === 'replace') changeSecret({ ...secret, mode: e.target.value });
      }}><option value="">Choose an action</option><option value="create">Create if metadata is observed absent</option><option value="replace">Replace if metadata is observed present</option></select></div>
      <div className="form-field"><label htmlFor={secretStageId}>Toolkit environment</label><select id={secretStageId} value={secret.stage} onChange={(e) => {
        if (e.target.value === 'candidate' || e.target.value === 'external-testing' || e.target.value === 'production') changeSecret({ ...secret, stage: e.target.value, recordId: '' });
      }}>{Object.entries(GITHUB_REMOTE_SETUP_ENVIRONMENTS).map(([stage, name]) => <option key={stage} value={stage}>{name}</option>)}</select></div>
      <div className="form-field"><label htmlFor={requirementId}>Exact required secret</label><select id={requirementId} value={secret.requirement} onChange={(e) => {
        const name = e.target.value;
        if (name === '' || Object.hasOwn(GITHUB_REMOTE_SETUP_SECRET_FIELDS, name)) changeSecret({ ...secret, requirement: name as SecretInputs['requirement'], recordId: '' });
      }}><option value="">Choose a supported requirement</option>{Object.keys(GITHUB_REMOTE_SETUP_SECRET_FIELDS).map((name) => <option key={name} value={name}>{name}</option>)}</select></div>
      <div className="form-field"><label htmlFor={recordId}>Current assigned credential reference</label><select id={recordId} value={selected?.kind === 'environment_secret' && secretRefs.some((r) => r.source.recordId === secret.recordId) ? secret.recordId : ''} onChange={(e) => changeSecret({ ...secret, recordId: e.target.value })}>
        <option value="">Choose the exact assigned record</option>{secretRefs.map((r) => <option key={`${r.source.recordId}:${r.source.recordRevision}`} value={r.source.recordId}>{r.label ?? r.kind} · ID {r.source.recordId} · revision {r.source.recordRevision}</option>)}</select></div></div>
      {secretRefs.length === 0 && <p role="status">No matching current assignment is available. In Credentials, choose this project, platform and stage, assess the required credential and assign it. Return here and reselect it; the app never guesses another record.</p>}
      {selected?.kind !== 'environment_secret' && <p role="status">Choose the action, requirement and current assignment before previewing. After a context change, reselect the intended values.</p>}
      <p>The saved configuration and fixed native sealing helper are checked during Preview. An available settings session does not prove secret provisioning is available. Nonsecret identifiers use the separate variable choice. Recordless App Review or commitment inputs remain unsupported here.</p>
      <p>GitHub cannot show or compare a stored secret value. Its create-or-update endpoint can overwrite a concurrent change or recreate a deleted secret; metadata checks are not atomic compare-and-set. Cancel cannot undo a sent request.</p>
    </section>}
    {variable && <section aria-label="Assigned nonsecret variable selection"><div className="button-row"><HelpButton content={HELP.variable} onHelp={onHelp} />
      <button type="button" className="button secondary" disabled={!onCredentials} onClick={onCredentials}>Open Credentials to assess and assign</button></div>
      <p>Variables are readable by permitted GitHub users and workflows. Select only the intended nonsecret identifier, never a password or private key. The exact desired text is shown after the native preview settles; nothing is sent to GitHub until you confirm Apply.</p>
      <div className="form-grid"><div className="form-field"><label htmlFor={variableModeId}>Variable action · choose explicitly</label><select id={variableModeId} value={variable.mode} onChange={(e) => {
        if (e.target.value === '' || e.target.value === 'create' || e.target.value === 'replace') changeVariable({ ...variable, mode: e.target.value });
      }}><option value="">Choose an action</option><option value="create">Create if observed absent</option><option value="replace">Replace if observed present</option></select></div>
      <div className="form-field"><label htmlFor={variableStageId}>Toolkit environment</label><select id={variableStageId} value={variable.stage} onChange={(e) => {
        if (e.target.value === 'candidate' || e.target.value === 'external-testing' || e.target.value === 'production') changeVariable({ ...variable, stage: e.target.value, recordId: '' });
      }}>{Object.entries(GITHUB_REMOTE_SETUP_ENVIRONMENTS).map(([stage, name]) => <option key={stage} value={stage}>{name}</option>)}</select></div>
      <div className="form-field"><label htmlFor={variableRequirementId}>Exact required nonsecret variable</label><select id={variableRequirementId} value={variable.requirement} onChange={(e) => {
        const name = e.target.value;
        if (name === '' || Object.hasOwn(GITHUB_REMOTE_SETUP_VARIABLE_FIELDS, name)) changeVariable({ ...variable, requirement: name as VariableInputs['requirement'], recordId: '' });
      }}><option value="">Choose a supported identifier</option>{Object.keys(GITHUB_REMOTE_SETUP_VARIABLE_FIELDS).map((name) => <option key={name} value={name}>{name}</option>)}</select></div>
      <div className="form-field"><label htmlFor={variableRecordId}>Current assigned credential reference</label><select id={variableRecordId} value={selected?.kind === 'environment_variable' && variableRefs.some((r) => r.source.recordId === variable.recordId) ? variable.recordId : ''} onChange={(e) => changeVariable({ ...variable, recordId: e.target.value })}>
        <option value="">Choose the exact assigned record</option>{variableRefs.map((r) => <option key={`${r.source.recordId}:${r.source.recordRevision}`} value={r.source.recordId}>{r.label ?? r.kind} · ID {r.source.recordId} · revision {r.source.recordRevision}</option>)}</select></div></div>
      {variableRefs.length === 0 && <p role="status">No matching current assignment is available. Open Credentials, choose this project, platform and stage, assess and assign the record, then return and reselect it.</p>}
      {selected?.kind !== 'environment_variable' && <p role="status">Choose an action, requirement and current assignment before previewing. A context change requires an explicit new selection.</p>}
      <p>The existing destination environment and saved configuration must pass native checks. An available settings session does not prove variable support; no sealing helper is required for variables. Commitment-key version and other recordless inputs remain unavailable.</p>
      <p>Create never falls back to Replace. These observations are not atomic compare-and-set; another actor may change or delete a variable. Cancel does not undo a sent request.</p>
    </section>}
    {environment && <section aria-label="Environment policy selection"><div className="button-row"><HelpButton content={HELP.environment} onHelp={onHelp} /></div>
      <div className="form-grid"><div className="form-field"><label htmlFor={environmentId}>Toolkit environment</label><select id={environmentId} value={environment.stage} onChange={(e) => {
        if (e.target.value === 'candidate' || e.target.value === 'external-testing' || e.target.value === 'production') changeEnvironment({ ...environment, stage: e.target.value });
      }}>{Object.entries(GITHUB_REMOTE_SETUP_ENVIRONMENTS).map(([stage, name]) => <option key={stage} value={stage}>{name}</option>)}</select></div>
      <div className="form-field"><label htmlFor={modeId}>Environment action</label><select id={modeId} value={environment.mode} onChange={(e) => {
        if (e.target.value === 'configure' || e.target.value === 'create') changeEnvironment({ ...environment, mode: e.target.value, selfReview: e.target.value === 'create' ? 'true' : 'preserve', reviewer: '', branches: '' });
      }}><option value="configure">Configure existing · preserve reviewer identities and branches</option><option value="create">Create if observed absent · explicit reviewer and branch choice</option></select></div>
      <div className="form-field"><label htmlFor={timerId}>Wait timer in whole minutes · 0–43,200</label><input id={timerId} type="text" inputMode="numeric" maxLength={5} value={environment.timer} onChange={(e) => changeEnvironment({ ...environment, timer: e.target.value })} /><p>0 means no delay. Preview shows the actual before and requested after values.</p></div>
      {environment.mode === 'configure' ? <div className="form-field"><label htmlFor={selfReviewId}>Self-review prevention</label><select id={selfReviewId} value={environment.selfReview} onChange={(e) => {
        if (e.target.value === 'preserve' || e.target.value === 'true' || e.target.value === 'false') changeEnvironment({ ...environment, selfReview: e.target.value });
      }}><option value="preserve">Preserve existing rule</option><option value="true">Prevent the requester from approving</option><option value="false">Allow self-review</option></select><p>An explicit change is refused if no required-reviewer rule exists. This mode never replaces reviewers or the branch mode.</p></div> : <>
      <div className="form-field"><label htmlFor={reviewerId}>Required reviewer’s GitHub username</label><input id={reviewerId} type="text" autoComplete="off" maxLength={39} spellCheck={false} value={environment.reviewer} placeholder="username (without @)" onChange={(e) => changeEnvironment({ ...environment, reviewer: e.target.value })} /><p>One user, not a team. The preview checks current repository access and shows the resolved ID. Self-review prevention is required.</p></div>
      <div className="form-field"><label htmlFor={branchesId}>Deployment branch choice</label><select id={branchesId} value={environment.branches} onChange={(e) => {
        if (e.target.value === '' || e.target.value === 'all' || e.target.value === 'protected') changeEnvironment({ ...environment, branches: e.target.value });
      }}><option value="">Choose explicitly</option><option value="protected">Protected branches</option><option value="all">All branches</option></select><p>Protected mode allows all branches if none are protected. It does not create branch protection.</p></div></>}
      </div>{selected?.kind !== 'environment_protection' && <p role="status">Complete a valid timer, reviewer and explicit branch choice for this mode. After a project change, reselect the intended values before previewing.</p>}
      <p>GitHub uses create-or-update, not a create-only operation. Another administrator’s edit may be overwritten or a deleted environment recreated. Administrator bypass and complete environment protection must be reviewed separately on GitHub.</p>
    </section>}
    <p>Changing the selection or project draft retires this review and requests Stop for this controller’s pending original. A stop request does not prove rollback or completed cleanup.</p>
    <button type="button" className="button primary" disabled={controller.prepareReason() !== null} aria-describedby={reasonId} onClick={() => controller.prepare()}>Preview remote setting</button>
    <p id={reasonId}>{controller.prepareReason() ?? 'Reads the selected destination through the existing native connection; a secret preview also seals the assigned field. No GitHub write occurs during preview.'}</p>
    {consent && <section aria-label="Exact remote settings review"><h3>Review this account and repository</h3><dl className="description-list"><div><dt>Repository</dt><dd>{consent.prepared.target.repository}</dd></div><div><dt>Account ID</dt><dd>{consent.prepared.target.accountId}</dd></div><div><dt>Repository ID</dt><dd>{consent.prepared.target.repositoryId}</dd></div><div><dt>Observed at</dt><dd>{consent.prepared.observedAt}</dd></div></dl>
      <h4>Before</h4><ObservationRows observed={consent.prepared.before} /><h4>Intended after</h4>{'configuration' in consent.prepared ? <dl className="description-list">
        {'value' in consent.prepared.after ? <><div><dt>Required nonsecret variable</dt><dd>{consent.prepared.after.name}</dd></div>
          <div><dt>Exact desired nonsecret identifier</dt><dd><code>{consent.prepared.after.value.text}</code></dd></div>
          <div><dt>Native value byte count and digest</dt><dd>{consent.prepared.after.value.bytes} bytes · SHA-256 {consent.prepared.after.value.sha256}</dd></div></> :
          <><div><dt>Required secret</dt><dd>{consent.prepared.after.name}</dd></div><div><dt>Encoding and native measured value bytes</dt><dd>{consent.prepared.after.encoding} · {consent.prepared.after.plaintextBytes}</dd></div></>}
        <div><dt>Assigned record reference</dt><dd>{consent.prepared.target.selection.source.recordId} · revision {consent.prepared.target.selection.source.recordRevision} · context {consent.prepared.target.selection.source.contextRevision}</dd></div>
        <div><dt>Saved configuration binding</dt><dd>{consent.prepared.configuration.savedConfig.bytes} bytes · SHA-256 {consent.prepared.configuration.savedConfig.sha256}</dd></div>
        <div><dt>Canonical configuration binding</dt><dd>{consent.prepared.configuration.canonicalConfig.bytes} bytes · SHA-256 {consent.prepared.configuration.canonicalConfig.sha256}</dd></div>
      </dl> : <PolicyRows policy={consent.prepared.after} />}
      {'reviewer' in consent.prepared && consent.prepared.reviewer && <dl className="description-list"><div><dt>Resolved reviewer</dt><dd>{consent.prepared.reviewer.login} · User ID {consent.prepared.reviewer.id}</dd></div><div><dt>Observed repository permission</dt><dd>{consent.prepared.reviewer.permission}</dd></div></dl>}
      <p>{consent.prepared.confirmation}</p><p>Native consent expiry: <time dateTime={consent.expiresAt}>{consent.expiresAt}</time>. Display only; native clocks decide.</p>
      <label htmlFor={confirmId}><input id={confirmId} type="checkbox" checked={state.confirmed} onChange={(e) => controller.setConfirmed(e.target.checked)} /> I reviewed this exact before/after change and authorize one Apply.</label>
      <HelpButton content={HELP.consent} onHelp={onHelp} />
      <div className="button-row"><button type="button" className="button primary" disabled={controller.applyReason() !== null} onClick={() => controller.apply()}>Apply reviewed setting once</button><button type="button" className="button secondary" disabled={state.discarding} onClick={() => controller.discardReview()}>Discard review</button></div><p>{controller.applyReason()}</p>
    </section>}
    {!consent && status?.consent && <p role="status">The native review is retained but not eligible in this view. It must be retired, not adopted as a new grant. <button className="button secondary" type="button" disabled={state.discarding} onClick={() => controller.discardReview()}>Discard retained review</button></p>}
    {state.error && <p role="status">{GITHUB_REMOTE_SETUP_HELP[state.error]}</p>}
    {state.originalTarget && <p>Requested context: <strong>{state.originalTarget.repository}</strong> · account ID {state.originalTarget.accountId} · repository ID {state.originalTarget.repositoryId} · setting {state.originalTarget.selection.kind}. Retained display, not current authorization.</p>}
    {op && <section aria-label="Original settings outcome"><h3>Original {op.kind} · {op.phase}</h3><p>{GITHUB_REMOTE_SETUP_HELP[op.reason]}</p><dl className="description-list"><div><dt>Remote effect</dt><dd>{op.effect}</dd></div><div><dt>Write claimed</dt><dd>{op.writeClaimed === null ? 'unknown · no accepted final result' : String(op.writeClaimed)}</dd></div><div><dt>Write acknowledged</dt><dd>{op.writeAcknowledged === null ? 'unknown · no accepted final result' : String(op.writeAcknowledged)}</dd></div></dl>
      {op.effect === 'readback-confirmed' && <p>{status?.observed && 'value' in status.observed ? GITHUB_REMOTE_SETUP_VARIABLE_ACCEPTANCE : 'The bounded request observed the intended policy after an acknowledged write. Another administrator can change it later. This is not release readiness.'}</p>}
      {op.effect === 'accepted-not-value-verified' && <p>{GITHUB_REMOTE_SETUP_SECRET_ACCEPTANCE}</p>}
      {op.effect === 'unknown' && <p>A write may have occurred. Stopping locally cannot roll it back. Never retry Apply automatically.</p>}
    </section>}
    {status?.observed && <section aria-label="Last remote observation"><h3>Last native remote observation · not a fresh authorization</h3><ObservationRows observed={status.observed} /></section>}
    {controls}
  </section>;
}
