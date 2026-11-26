// Selected-PR navigation DATA only. Existing controllers retain native requests;
// no browser URL, account, token or write capability is accepted by the command.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionOpaqueId as id, connectionNumericId as numeric,
  connectionUtc as utc } from './githubConnectionProtocol.ts';
import type { GitHubActivityController } from './githubActivityController.ts';
import type { GitHubPullRequestController, PullRequestCompletion } from './githubPullRequestController.ts';
import type { PullRequestAcknowledgement } from './githubPullRequestProtocol.ts';

export type GitHubBrowserPage = 'conversation' | 'files';
type Binding = { sessionId:string;expectedRevision:number;expectedConnectionRevision:number };
export type GitHubBrowserRequest = Binding & (
  {kind:'activity-pull-request'|'created-pull-request';operationId:string;page:GitHubBrowserPage} |
  {kind:'comparison';consentId:string}
);
export type GitHubBrowserState = 'idle'|'requesting'|'request-sent'|'unconfirmed'|'unavailable'|'stale';
export const BROWSER_HELP:Readonly<Record<GitHubBrowserState,string>>=Object.freeze({
  idle:'Your browser may be signed into a different GitHub account. Review that account before taking any action there.',
  requesting:'Sending this GitHub page to your browser…',
  'request-sent':'The page was sent to your browser. Browser visibility and its signed-in account are not confirmed.',
  unconfirmed:'The browser request is unconfirmed. Check your browser, or copy the address below. It has not been repeated.',
  unavailable:'Browser handoff is unavailable in this runtime. Copy the GitHub address below into your browser.',
  stale:'This selection changed. Read or review it again before opening its page.',
});
const rev=(v:unknown):v is number=>typeof v==='number'&&Number.isInteger(v)&&v>0&&v<=0xffff_fffe;
const hex=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{32}$(?![\s\S])/.test(v);
export function encodeGitHubBrowserRequest(raw:unknown):Uint8Array|null {
  try {
    const v=copyBoundedComparisonData(raw,1024,16);
    const comparison=keys(v,['kind','sessionId','expectedRevision','expectedConnectionRevision','consentId'])&&v.kind==='comparison'&&hex(v.consentId);
    const pull=keys(v,['kind','sessionId','expectedRevision','expectedConnectionRevision','operationId','page'])&&
      (v.kind==='activity-pull-request'||v.kind==='created-pull-request')&&id(v.operationId)&&(v.page==='conversation'||v.page==='files');
    if(!(comparison||pull)||!id(v.sessionId)||!rev(v.expectedRevision)||!rev(v.expectedConnectionRevision))return null;
    const bytes=new TextEncoder().encode(JSON.stringify(v));return bytes.length<=1024?bytes:null;
  }catch{return null;}
}
export function browserRequestReturned(raw:unknown):boolean {
  try{const v=copyBoundedComparisonData(raw,256,8);return keys(v,['state','browserVisibility'])&&v.state==='request-sent'&&v.browserVisibility==='unconfirmed';}catch{return false;}
}
export function browserFailure(raw:unknown):GitHubBrowserState {
  try {
    const descriptor=raw&&typeof raw==='object'?Object.getOwnPropertyDescriptor(raw,'code'):null;
    const value=descriptor&&Object.hasOwn(descriptor,'value')?descriptor.value:null;
    if(value==='github_browser_unavailable')return 'unavailable';
    if(value==='github_browser_refused')return 'stale';
  }catch{/* No provider/error text, getter or fallback request. */}
  return 'unconfirmed';
}
export interface PullRequestClosed {id:string;number:string;closedAt:string;merged:boolean}
// Called on the strict bounded copy made by the original status parser.
export function pullRequestClosed(v:unknown,ack:PullRequestAcknowledgement|null):v is PullRequestClosed {
  return !!ack&&keys(v,['id','number','closedAt','merged'])&&numeric(v.id)&&numeric(v.number)&&v.id===ack.id&&v.number===ack.number&&utc(v.closedAt)&&typeof v.merged==='boolean';
}
export function readPullRequestCompletion(pr:GitHubPullRequestController,activity:GitHubActivityController,expected:PullRequestCompletion):void {
  const number=expected.status.acknowledged?.number??expected.status.observed?.number;
  const current=()=>pr.currentCompletion()===expected&&activity.matchesContext(expected.context);
  if(!number||!current())return;
  // Veto is checked again after all synchronous listeners, immediately before
  // the existing Activity read. A status-shaped historical receipt is not enough.
  activity.read({kind:'pull-request',number},current);
}
