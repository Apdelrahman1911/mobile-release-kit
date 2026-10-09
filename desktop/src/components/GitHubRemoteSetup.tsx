import { useId } from 'react';
import type { HelpContent } from '../types.ts';
import type { GitHubRemoteSetupController } from '../GitHubRemoteSetupController.ts';
import type { GitHubRemoteSetupPolicy, GitHubRemoteSetupView } from '../GitHubRemoteSetupTypes.ts';
import { GITHUB_REMOTE_SETUP_HELP } from '../GitHubRemoteSetupProtocol.ts';
import { Badge, HelpButton, SectionHeading } from './Common.tsx';
const HELP: Record<'setting' | 'access' | 'consent' | 'outcome', HelpContent> = {
  setting: { label: 'Repository setting', requiredness: 'required', requiredWhen: 'Before requesting a remote policy preview.',
    what: 'One fixed setting: whether Actions are enabled, or the default workflow token permissions and pull-request approval permission.',
    why: 'Each preview reads the actual account, repository and policy. Local workflow files and editor drafts cannot prove remote settings.',
    where: 'Choose the setting here after connecting to this project’s explicit repository. No URL, token or arbitrary policy JSON is accepted.',
    format: 'Explicit boolean values and read/write token permission. For Actions, allowed_actions and sha_pinning_required are observed and preserved, never defaulted.',
    failure: 'Missing, unsupported or changed policies are refused. Enabling Actions can allow already-configured workflows to run.' },
  access: { label: 'Repository Administration permission', requiredness: 'required', requiredWhen: 'For a settings preview or confirmed Apply.',
    what: 'The existing native session-only GitHub connection; this card never collects or saves another token.',
    why: 'GitHub requires repository Administration read for the preview and Administration write to apply. A successful connection does not prove either permission.',
    where: 'Configure only the intended repository and permissions in GitHub’s token settings. Organization approval or SSO may also be required.',
    format: 'Keep the connection’s existing read permissions. These additional requirements do not authorize secrets, environment changes or workflow dispatch.',
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
function PolicyRows({ policy }: { policy: GitHubRemoteSetupPolicy }) {
  return <dl className="description-list">{'enabled' in policy ? <>
    <div><dt>Actions enabled</dt><dd>{String(policy.enabled)}</dd></div>
    <div><dt>Allowed actions (preserved)</dt><dd>{policy.allowed_actions}</dd></div>
    <div><dt>SHA pinning required (preserved)</dt><dd>{String(policy.sha_pinning_required)}</dd></div>
  </> : <><div><dt>Default workflow token permissions</dt><dd>{policy.default_workflow_permissions}</dd></div>
    <div><dt>Can approve pull requests</dt><dd>{String(policy.can_approve_pull_request_reviews)}</dd></div></>}</dl>;
}
export function GitHubRemoteSetup({ state, controller, onHelp, compact = false, onShow }: {
  state: GitHubRemoteSetupView; controller: GitHubRemoteSetupController; onHelp: (help: HelpContent) => void; compact?: boolean; onShow?: () => void;
}) {
  const choiceId = useId(), enabledId = useId(), permissionsId = useId(), approvalsId = useId(), confirmId = useId(), reasonId = useId();
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
    <SectionHeading title="Repository settings · separate remote confirmation" description="Two fixed settings only. This does not change local workflows, provision environments or secrets, dispatch a workflow or qualify a release."><Badge tone="neutral">{state.mode === 'native' ? 'Native session required' : 'Unavailable in preview'}</Badge></SectionHeading>
    <p>Connecting alone never changes settings. Enabling Actions can allow configured workflows to run; write tokens and pull-request approval permissions grant additional privileges.</p>
    <div className="button-row"><HelpButton content={HELP.setting} onHelp={onHelp} /><HelpButton content={HELP.access} onHelp={onHelp} /></div>
    <div className="form-field"><label htmlFor={choiceId}>Setting to review</label><select id={choiceId} value={selected?.kind ?? ''} onChange={(e) => controller.setSelection(e.target.value === 'actions_enabled' ? { kind: 'actions_enabled', enabled: false } : e.target.value === 'workflow_token_policy' ? { kind: 'workflow_token_policy', defaultWorkflowPermissions: 'read', canApprovePullRequestReviews: false } : null)}>
      <option value="">Choose one setting</option><option value="actions_enabled">Enable or disable Actions</option><option value="workflow_token_policy">Default workflow token permissions</option></select></div>
    {selected?.kind === 'actions_enabled' && <div className="form-field"><label htmlFor={enabledId}>Intended Actions enabled value</label><select id={enabledId} value={String(selected.enabled)} onChange={(e) => controller.setSelection({ ...selected, enabled: e.target.value === 'true' })}><option value="false">false · disable</option><option value="true">true · enable</option></select></div>}
    {selected?.kind === 'workflow_token_policy' && <div className="form-grid"><div className="form-field"><label htmlFor={permissionsId}>Intended default token permissions</label><select id={permissionsId} value={selected.defaultWorkflowPermissions} onChange={(e) => { if (e.target.value === 'read' || e.target.value === 'write') controller.setSelection({ ...selected, defaultWorkflowPermissions: e.target.value }); }}><option value="read">read</option><option value="write">write</option></select></div>
      <div className="form-field"><label htmlFor={approvalsId}>Intended pull-request approval permission</label><select id={approvalsId} value={String(selected.canApprovePullRequestReviews)} onChange={(e) => controller.setSelection({ ...selected, canApprovePullRequestReviews: e.target.value === 'true' })}><option value="false">false · do not allow</option><option value="true">true · allow</option></select></div></div>}
    <p>Changing the selection or project draft retires this review and requests Stop for this controller’s pending original. A stop request does not prove rollback or completed cleanup.</p>
    <button type="button" className="button primary" disabled={controller.prepareReason() !== null} aria-describedby={reasonId} onClick={() => controller.prepare()}>Preview remote setting</button>
    <p id={reasonId}>{controller.prepareReason() ?? 'Reads the current policy through the existing native connection; no settings write occurs during preview.'}</p>
    {consent && <section aria-label="Exact remote settings review"><h3>Review this account and repository</h3><dl className="description-list"><div><dt>Repository</dt><dd>{consent.prepared.target.repository}</dd></div><div><dt>Account ID</dt><dd>{consent.prepared.target.accountId}</dd></div><div><dt>Repository ID</dt><dd>{consent.prepared.target.repositoryId}</dd></div><div><dt>Observed at</dt><dd>{consent.prepared.observedAt}</dd></div></dl>
      <h4>Before</h4><PolicyRows policy={consent.prepared.before} /><h4>Intended after</h4><PolicyRows policy={consent.prepared.after} />
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
    {status?.observed && <section aria-label="Last policy observation"><h3>Last native policy observation · not a fresh authorization</h3><PolicyRows policy={status.observed} /></section>}
    {controls}
  </section>;
}
