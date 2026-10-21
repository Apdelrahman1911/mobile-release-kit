import { GITHUB_ACTIVITY_NOTICE } from '../githubActivityDelegation.ts';
import { useSyncExternalStore } from 'react';
import type { AgentGithubActionAccessController } from '../agentGithubActionAccessController.ts';
import { GITHUB_ACTION_KINDS, githubActionCommands } from '../agentGithubActionAccess.ts';
import type { GithubActionKind } from '../agentGithubActionAccess.ts';
const labels:Readonly<Record<GithubActionKind,string>>={'repository-create':'Create the reviewed empty repository','draft-pr-create':'Create the reviewed draft pull request','pr-create':'Create the reviewed ready-for-review pull request','failed-jobs-retry':'Retry the reviewed failed and dependent jobs','setup-publish':'Publish the exact five-file setup review','setup-reconcile':'GET-only reconcile the selected original setup intent','activity-overview':'Read a fresh GitHub Activity overview once'};
const effects:Readonly<Record<GithubActionKind,string>>={
  'activity-overview':GITHUB_ACTIVITY_NOTICE,
  'repository-create':'Creates only the exact reviewed empty GitHub repository with its displayed owner and visibility. No local initialization, files, commit or push.',
  'draft-pr-create':'Creates the exact same-repository draft PR shown in the original review. Creating even a draft PR can trigger that repository’s CI and existing workflow privileges.',
  'pr-create':'Creates the exact same-repository READY-FOR-REVIEW PR shown in the original review. Reviewers may be notified and repository workflows can run. This does not approve, merge, convert a draft or authorize a release.',
  'setup-publish':'Creates only the five reviewed setup files on the reviewed NEW branch and opens a draft PR. Existing push/PR workflows can run. No merge, existing-branch update, version-counter setup, release or local Git change.',
  'setup-reconcile':'GET-only comparison of one original intent loaded in this same session. No resend, new branch/PR, missing-step completion, counter setup or attribution of an earlier uncertain write.',
  'failed-jobs-retry':'Retries failed AND dependent jobs for the reviewed run, attempt and source. Jobs may publish or change external services using existing workflow privileges. Accepted does not mean jobs passed.',
};
export function AgentGithubActionAccess({controller}:{controller:AgentGithubActionAccessController}) {
  const state=useSyncExternalStore(controller.subscribe,controller.getSnapshot,controller.getSnapshot);
  const commands=githubActionCommands(state.access,state.status);
  return <details className="card"><summary>Advanced: delegate one GitHub action or Activity read</summary>
    <p>Uses the same selected account, native intent, original cleanup and service history. First finish Review in the relevant panel, or choose a fresh Activity overview after connecting the intended account and repository. This permission does not start the action, and ordinary READ access alone never authorizes these actions.</p>
    <label>Action <select value={state.selected} disabled={!!controller.ownerReason()} onChange={e=>controller.choose(e.target.value as GithubActionKind)}>
      {GITHUB_ACTION_KINDS.map(kind=><option key={kind} value={kind}>{labels[kind]}</option>)}
    </select></label>
    <p className="notice">{effects[state.selected]} {state.selected==='activity-overview'?'This separate one-use read consent does not authorize any write.':'Stop cannot undo an accepted remote action. Recheck all details in the original visible review.'}</p>
    {state.review&&<p>Original review <code>{state.review.kind==='activity-overview'?state.review.sessionId:state.review.kind==='setup-reconcile'?state.review.marker:state.review.consentId}</code> · native revision {state.review.expectedRevision}. No draft, account token, URL or provider arguments are accepted by the CLI.</p>}
    <label><input type="checkbox" checked={state.acknowledged} disabled={!!controller.consentReason()} onChange={e=>controller.acknowledge(e.target.checked)}/> I allow one local CLI submission of this exact action, GET-only reconciliation, or fresh Activity overview with its displayed effects.</label>
    <button disabled={!!controller.allowReason()} onClick={()=>void controller.allow()}>Allow this exact action once</button>
    {controller.allowReason()&&<p className="save-note">{controller.allowReason()}</p>}
    <button disabled={!!controller.checkReason()} onClick={()=>void controller.check()}>Check original CLI permission/request</button>
    <button disabled={!!controller.revokeReason()} onClick={()=>void controller.revoke()}>Revoke permission / request Stop</button>
    {(state.pending||state.revoking)&&<p role="status">The original permission caller is still returning. Do not replace or replay it.</p>}
    {state.issue&&<p role="alert">{state.issue}</p>}
    {state.access&&<p>{state.stale?'Earlier context · ':''}{state.status?`${state.status.state} · ${state.status.settlement} · ${state.status.effect}`:state.access.enabled?'One-use permission observed; its original native expiry is unchanged.':'No unused permission observed.'}</p>}
    {state.status?.snapshot&&<p>Historical Activity · account {state.status.snapshot.accountId}, repository {state.status.snapshot.repositoryId} · {state.status.snapshot.observedAt}. PRs: {state.status.snapshot.pullRequests.state} / {state.status.snapshot.pullRequests.coverage}; runs: {state.status.snapshot.workflowRuns.state} / {state.status.snapshot.workflowRuns.coverage}. Full compact row IDs and statuses are available with <code>github-status --json</code>; no titles, heads, jobs or artifact content.</p>}
    {commands.length>0&&<><p>Run manually. Keep the request ID printed before submission. A lost response needs the original Status/Cancel, never a new Submit.</p><pre>{commands.join('\n')}</pre></>}
    {state.status?.settlement==='settled'&&<p>{state.status.neverAdmitted?'The original relay refused before native registration; no native retirement is claimed.':'The same native owner, Connection acceptance, relay caller and service-history publication returned.'} The effect label is point-in-time evidence, not CI success or permission for another action. Original recovery controls remain in their panel. {state.selected==='activity-overview'?'Activity has no GUI-owned Read attempt here; this result is not adopted as a selectable PR or retry input.':'Read that panel’s local Status to release its retained original; a CLI row alone cannot do so.'}</p>}
  </details>;
}
