import { useId, useState } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubRemoteSetupController } from '../GitHubRemoteSetupController.ts';
import type { GitHubRemoteSetupEnvironmentPolicy, GitHubRemoteSetupEnvironmentSelection, GitHubRemoteSetupObservation, GitHubRemoteSetupPolicy, GitHubRemoteSetupView } from '../GitHubRemoteSetupTypes.ts';
import { GITHUB_REMOTE_SETUP_ENVIRONMENTS, GITHUB_REMOTE_SETUP_HELP, githubRemoteSetupSelection } from '../GitHubRemoteSetupProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
const HELP: Record<'setting' | 'environment' | 'access' | 'consent' | 'outcome', HelpContent> = {
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
  access: { label: 'Repository Administration permission', requiredness: 'required', requiredWhen: 'For a settings preview or confirmed Apply.',
    what: 'The existing native session-only GitHub connection; this card never collects or saves another token.',
    why: 'GitHub requires repository Administration read for the preview and Administration write to apply. A successful connection does not prove either permission.',
    where: 'Configure only the intended repository and permissions in GitHub’s token settings. Organization approval or SSO may also be required.',
    format: 'Keep Actions read and Metadata read for the existing connection, plus Administration write for a confirmed settings change. GitHub plan/organization restrictions may apply. These permissions do not authorize secrets or workflow dispatch.',
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
    format: 'Readback-confirmed means this bounded request observed its intended policy after an acknowledged write, not future policy stability or release readiness.',
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
export function GitHubRemoteSetup({ state, controller, onHelp, compact = false, onShow }: {
  state: GitHubRemoteSetupView; controller: GitHubRemoteSetupController; onHelp: (help: HelpContent) => void; compact?: boolean; onShow?: () => void;
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
    <SectionHeading title="Repository settings · separate remote confirmation" description="Actions, workflow token defaults and bounded environment policy only. This does not change local workflows, provision secrets, dispatch a workflow or qualify a release."><Badge tone="neutral">{state.mode === 'native' ? 'Native session required' : 'Unavailable in preview'}</Badge></SectionHeading>
    <p>Connecting alone never changes settings. Enabling Actions can allow configured workflows to run; write tokens and pull-request approval permissions grant additional privileges.</p>
    <div className="button-row"><HelpButton content={HELP.setting} onHelp={onHelp} /><HelpButton content={HELP.access} onHelp={onHelp} /></div>
    <div className="form-field"><label htmlFor={choiceId}>Setting to review</label><select id={choiceId} value={environment !== null ? 'environment_protection' : selected?.kind ?? ''} onChange={(e) => {
      if (e.target.value === 'environment_protection') changeEnvironment(environmentInputs());
      else { setEnvironment(null); controller.setSelection(e.target.value === 'actions_enabled' ? { kind: 'actions_enabled', enabled: false } : e.target.value === 'workflow_token_policy' ? { kind: 'workflow_token_policy', defaultWorkflowPermissions: 'read', canApprovePullRequestReviews: false } : null); }
    }}>
      <option value="">Choose one setting</option><option value="actions_enabled">Enable or disable Actions</option><option value="workflow_token_policy">Default workflow token permissions</option><option value="environment_protection">Deployment environment policy</option></select></div>
    {selected?.kind === 'actions_enabled' && <div className="form-field"><label htmlFor={enabledId}>Intended Actions enabled value</label><select id={enabledId} value={String(selected.enabled)} onChange={(e) => controller.setSelection({ ...selected, enabled: e.target.value === 'true' })}><option value="false">false · disable</option><option value="true">true · enable</option></select></div>}
    {selected?.kind === 'workflow_token_policy' && <div className="form-grid"><div className="form-field"><label htmlFor={permissionsId}>Intended default token permissions</label><select id={permissionsId} value={selected.defaultWorkflowPermissions} onChange={(e) => { if (e.target.value === 'read' || e.target.value === 'write') controller.setSelection({ ...selected, defaultWorkflowPermissions: e.target.value }); }}><option value="read">read</option><option value="write">write</option></select></div>
      <div className="form-field"><label htmlFor={approvalsId}>Intended pull-request approval permission</label><select id={approvalsId} value={String(selected.canApprovePullRequestReviews)} onChange={(e) => controller.setSelection({ ...selected, canApprovePullRequestReviews: e.target.value === 'true' })}><option value="false">false · do not allow</option><option value="true">true · allow</option></select></div></div>}
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
    <p id={reasonId}>{controller.prepareReason() ?? 'Reads the current policy through the existing native connection; no settings write occurs during preview.'}</p>
    {consent && <section aria-label="Exact remote settings review"><h3>Review this account and repository</h3><dl className="description-list"><div><dt>Repository</dt><dd>{consent.prepared.target.repository}</dd></div><div><dt>Account ID</dt><dd>{consent.prepared.target.accountId}</dd></div><div><dt>Repository ID</dt><dd>{consent.prepared.target.repositoryId}</dd></div><div><dt>Observed at</dt><dd>{consent.prepared.observedAt}</dd></div></dl>
      <h4>Before</h4><ObservationRows observed={consent.prepared.before} /><h4>Intended after</h4><PolicyRows policy={consent.prepared.after} />
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
      {op.effect === 'readback-confirmed' && <p>The bounded request observed the intended policy after an acknowledged write. Another administrator can change it later. This is not release readiness.</p>}
      {op.effect === 'unknown' && <p>A write may have occurred. Stopping locally cannot roll it back. Never retry Apply automatically.</p>}
    </section>}
    {status?.observed && <section aria-label="Last policy observation"><h3>Last native policy observation · not a fresh authorization</h3><ObservationRows observed={status.observed} /></section>}
    {controls}
  </section>;
}
