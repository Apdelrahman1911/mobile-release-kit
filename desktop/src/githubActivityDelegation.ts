// Historical compact DATA only. No token, endpoint, Prepared or native receipt.
import { connectionKeys as keys, connectionUtc as utc } from './githubConnectionProtocol.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
export interface GithubActivitySelection { readonly kind:'activity-overview'; readonly sessionId:string; readonly expectedRevision:number; readonly expectedConnectionRevision:number }
export interface GithubActivityReference extends GithubActivitySelection { readonly accountId:string; readonly repositoryId:string }
export interface GithubActivityPull {readonly number:string;readonly state:'open'|'closed';readonly draft:boolean}
export interface GithubActivityRun {readonly id:string;readonly attempt:number;readonly status:string;readonly conclusion:string|null}
export interface GithubActivitySection<T> {readonly state:'read'|'unavailable';readonly reason:string;readonly coverage:'complete'|'windowed'|'unknown';readonly total:number|null;readonly rows:readonly T[]}
export interface GithubActivitySnapshot {readonly accountId:string;readonly repositoryId:string;readonly observedAt:string;readonly pullRequests:GithubActivitySection<GithubActivityPull>;readonly workflowRuns:GithubActivitySection<GithubActivityRun>}
const integer=(v:unknown,a:number,b:number):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&!Object.is(v,-0)&&v>=a&&v<=b;
export function permissionRevision(v:unknown):v is string {return typeof v==='string'&&/^(?:0|[1-9][0-9]{0,19})$/.test(v)&&v.length<=20&&BigInt(v)<=18446744073709551615n;}
const id=(v:unknown):v is string=>permissionRevision(v)&&v!=='0';
function selection(v:unknown,reference:boolean):boolean {return keys(v,['kind','sessionId','expectedRevision','expectedConnectionRevision',...(reference?['accountId','repositoryId']:[])])&&v.kind==='activity-overview'&&
  typeof v.sessionId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v.sessionId)&&integer(v.expectedRevision,1,0xffff_fff6)&&integer(v.expectedConnectionRevision,1,0xffff_fffd)&&
  (!reference||id(v.accountId)&&id(v.repositoryId));}
export function parseGithubActivitySelection(v:unknown):GithubActivitySelection|null {try{const c=copyBoundedComparisonData(v,512,16);return selection(c,false)?Object.freeze(c) as unknown as GithubActivitySelection:null;}catch{return null;}}
export function parseGithubActivityReference(v:unknown):GithubActivityReference|null {try{const c=copyBoundedComparisonData(v,512,20);return selection(c,true)?Object.freeze(c) as unknown as GithubActivityReference:null;}catch{return null;}}
export function sameGithubActivitySelection(a:GithubActivitySelection,b:GithubActivitySelection):boolean {return a.kind===b.kind&&a.sessionId===b.sessionId&&a.expectedRevision===b.expectedRevision&&a.expectedConnectionRevision===b.expectedConnectionRevision;}
export function sameGithubActivityReference(a:GithubActivityReference,b:GithubActivityReference):boolean {return sameGithubActivitySelection(a,b)&&a.accountId===b.accountId&&a.repositoryId===b.repositoryId;}
const runs=['queued','in_progress','completed','waiting','pending','requested'];
const conclusions=['success','failure','neutral','cancelled','skipped','timed_out','action_required','stale','startup_failure'];
function section(v:unknown,run:boolean):boolean {
  if(!keys(v,['state','reason','coverage','total','rows'])||!Array.isArray(v.rows)||v.rows.length>30)return false;
  if(v.state==='unavailable')return ['forbidden','not-found-or-inaccessible'].includes(String(v.reason))&&v.coverage==='unknown'&&v.total===null&&v.rows.length===0;
  if(v.state!=='read'||v.reason!=='none'||v.total!==null&&!integer(v.total,v.rows.length,0x7fff_ffff)||v.coverage!==(v.total===v.rows.length?'complete':'windowed'))return false;
  const ids=new Set<string>();
  return v.rows.every(r=>{
    if(!keys(r,run?['id','attempt','status','conclusion']:['number','state','draft']))return false;
    const n=run?r.id:r.number;if(!id(n)||ids.has(n))return false;ids.add(n);
    return run?integer(r.attempt,1,1000)&&typeof r.status==='string'&&runs.includes(r.status)&&(r.conclusion===null||typeof r.conclusion==='string'&&conclusions.includes(r.conclusion))&&(r.status==='completed'||r.conclusion===null):
      (r.state==='open'||r.state==='closed')&&typeof r.draft==='boolean';
  });
}
export function parseGithubActivitySnapshot(v:unknown,reference:GithubActivityReference):GithubActivitySnapshot|null {
  try{const c=copyBoundedComparisonData(v,8192,640);
    if(!keys(c,['accountId','repositoryId','observedAt','pullRequests','workflowRuns'])||c.accountId!==reference.accountId||c.repositoryId!==reference.repositoryId||!id(c.accountId)||!id(c.repositoryId)||
      !utc(c.observedAt)||
      !section(c.pullRequests,false)||!section(c.workflowRuns,true))return null;
    return c as unknown as GithubActivitySnapshot;
  }catch{return null;}
}
export const GITHUB_ACTIVITY_NOTICE='One new authenticated repository-wide read: at most the first 30 open PRs and 30 workflow runs. Rows are sequential historical observations, not a complete or atomic history, current-head/CI proof, or permission to create or retry anything. No jobs, logs or artifacts are downloaded.';
