import type { GitHubActivityController, GitHubActivityView } from '../githubActivityController.ts';
import type { GitHubPullRequestController, PullRequestView } from '../githubPullRequestController.ts';
import { BROWSER_HELP, readPullRequestCompletion } from '../githubPullRequestManagement.ts';
import { activityLink } from '../githubActivityProtocol.ts';

function BrowserNote({state,address}:{state:GitHubActivityView['browserState'];address:string}) {
  return <><p className="save-note" role="status">{BROWSER_HELP[state]}</p>
    <details><summary>Copy GitHub address</summary><p className="review-text">{address}</p></details></>;
}
export function SelectedPullRequestActions({controller,state}:{controller:GitHubActivityController;state:GitHubActivityView}) {
  const result=controller.currentResult();if(!result||result.data.kind!=='pull-request')return null;
  const p=result.data.pullRequest,address=activityLink(result.target.repository,'pull',p.number)!;
  return <div className="review-item">
    <div className="button-row">
      <button type="button" className="button small" disabled={!!controller.readReason(result.selection)} onClick={()=>controller.refreshResult(result)}>Refresh this pull request</button>
      <button type="button" className="button small secondary" disabled={!!controller.browserReason(result)} onClick={()=>controller.openPullRequest(result,'conversation')}>Open pull request in browser</button>
      <button type="button" className="button small secondary" disabled={!!controller.browserReason(result)} onClick={()=>controller.openPullRequest(result,'files')}>Open full diff in browser</button>
    </div>
    <BrowserNote state={state.browserState} address={address}/>
    <p className="save-note">Refresh reads this PR’s current head, reviews and checks. It does not approve, merge, mark ready or rerun anything.</p>
  </div>;
}
export function PullRequestFollowup({controller,state,activity}:{controller:GitHubPullRequestController;state:PullRequestView;activity:GitHubActivityController}) {
  const completed=controller.currentCompletion(),review=controller.currentConsent();
  const ack=completed?.status.acknowledged??completed?.status.observed;
  if(review) {
    const p=review.prepared,address=`https://github.com/${p.target.scope.repository}/compare/${p.baseSha}...${p.headSha}`;
    return <div className="review-item"><button type="button" className="button small secondary" disabled={!!controller.comparisonBrowserReason(review)} onClick={()=>controller.openComparison(review)}>Review full comparison in browser</button>
      <BrowserNote state={state.browserState} address={address}/></div>;
  }
  if(!completed||!ack)return null;
  const isClosed=completed.status.operation?.effect==='closed-confirmed';
  return <div className="notice notice-info"><div>
    <strong>{isClosed?'Earlier pull request confirmed closed':`Pull request #${ack.number}`}</strong>
    {isClosed?<p>Its acknowledged identity and closed state were checked. To create a later PR for these branches, refresh saved attempts below, then make a new review. A reopened PR will still block creation.</p>:
      <p>Read this PR’s current status, review records and CI results before choosing what to do next. A saved creation receipt is not its current approval or merge status.</p>}
    <div className="button-row">
      <button type="button" className="button small" disabled={!activity.matchesContext(completed.context)||!!activity.readReason({kind:'pull-request',number:ack.number})} onClick={()=>readPullRequestCompletion(controller,activity,completed)}>Read status, reviews & checks</button>
      <button type="button" className="button small secondary" disabled={!!controller.completionBrowserReason(completed)} onClick={()=>controller.openCompletedPullRequest(completed,'conversation')}>Open pull request in browser</button>
      {isClosed&&<button type="button" className="button small secondary" disabled={!!controller.pendingReason()} onClick={()=>controller.loadPending()}>Refresh saved attempts</button>}
    </div>
    {completed.status.acknowledged===null&&<p className="review-caution">This matching PR was observed, not attributed to the original creation request. It does not permit a replacement Create.</p>}
    <BrowserNote state={state.browserState} address={ack.url}/>
  </div></div>;
}
