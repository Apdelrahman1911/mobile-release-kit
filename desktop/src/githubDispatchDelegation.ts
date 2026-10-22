// Closed comparison DATA for the existing Preflight/Release/Publication owners.
// No provider, command transport, permission, timer or native receipt lives here.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, connectionNumericId as numericId, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { githubPreflightRequestFits } from './githubPreflightProtocol.ts';
import { githubReleaseRequestFits } from './githubReleaseProtocol.ts';
import { publicationRequestFits, publicationPrepared } from './githubPublicationProtocol.ts';
import type { GitHubPreflightPrepare, GitHubPreflightDispatch, GitHubPreflightControl, GitHubPreflightPrepared, GitHubPreflightRecord } from './githubPreflightTypes.ts';
import type { GitHubReleasePrepare, GitHubReleaseDispatch, GitHubReleaseControl, GitHubReleasePrepared, GitHubReleaseRecord } from './githubReleaseTypes.ts';
import type { CounterPrepared } from './versionCounterSetup.ts';
import type { PublicationPending, PublicationPrepared } from './githubPublicationTypes.ts';
export const GITHUB_DISPATCH_KINDS=['preflight-prepare','preflight-dispatch','preflight-pending','preflight-observe','release-prepare','release-dispatch','release-pending','release-observe','setup-prepare','counter-prepare','counter-create','publication-pending','counter-reconcile'] as const;
export type GithubDispatchKind=typeof GITHUB_DISPATCH_KINDS[number];
interface Original {readonly sessionId:string;readonly expectedRevision:number}
export interface WorkflowObserveSelection extends Original {readonly kind:'preflight-observe'|'release-observe';readonly marker:string;readonly observe:'track'|'reconcile';readonly runId:string|null}
export type GithubDispatchSelection=
 ({readonly kind:'preflight-prepare'}&GitHubPreflightPrepare)|({readonly kind:'preflight-dispatch'}&GitHubPreflightDispatch)|({readonly kind:'preflight-pending'}&GitHubPreflightControl)|
 ({readonly kind:'release-prepare'}&GitHubReleasePrepare)|({readonly kind:'release-dispatch'}&GitHubReleaseDispatch)|({readonly kind:'release-pending'}&GitHubReleaseControl)|WorkflowObserveSelection|
 ({readonly kind:'setup-prepare';readonly expectedConnectionRevision:number;readonly base:string}&Original)|
 ({readonly kind:'counter-prepare';readonly expectedConnectionRevision:number;readonly base:string;readonly purpose:'version-counter'}&Original)|
 ({readonly kind:'counter-create';readonly consentId:string;readonly confirm:true}&Original)|
 ({readonly kind:'publication-pending';readonly expectedConnectionRevision:number}&Original)|({readonly kind:'counter-reconcile';readonly marker:string}&Original);
export type GithubDispatchReference=(Original&{readonly kind:'preflight-prepare'|'preflight-pending'|'release-prepare'|'release-pending'|'setup-prepare'|'counter-prepare'|'publication-pending';readonly requestSha256:string})|
 (Original&{readonly kind:'preflight-dispatch'|'release-dispatch'|'counter-create';readonly consentId:string;readonly preparedSha256:string})|
 (WorkflowObserveSelection&{readonly recordSha256:string})|(Original&{readonly kind:'counter-reconcile';readonly marker:string;readonly recordSha256:string});
export type GithubDispatchSnapshot={readonly type:'prepared';readonly marker:string;readonly preparedSha256:string;readonly sourceSha:string;readonly platform:'android'|'ios'|'both'|null;readonly stage:'candidate'|'external-testing'|'production-submit'|null}|
 {readonly type:'pending';readonly rows:readonly {readonly marker:string;readonly runId:string|null;readonly purpose:'preflight'|'release'|'setup'|'counter'}[]}|
 {readonly type:'observed';readonly marker:string;readonly runId:string;readonly attempt:1;readonly status:string;readonly conclusion:string|null}|
 {readonly type:'counter';readonly marker:string;readonly commitSha:string;readonly ledgerId:string;readonly genesisSha256:string};
export const isGithubDispatchKind=(v:unknown):v is GithubDispatchKind=>typeof v==='string'&&(GITHUB_DISPATCH_KINDS as readonly string[]).includes(v);
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const revision=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0&&v<=0xffff_fffe;
const original=(v:Record<string,unknown>)=>typeof v.sessionId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v.sessionId)&&revision(v.expectedRevision);
function freeze<T>(v:T):T{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
function pick(v:Record<string,unknown>,names:readonly string[]):Record<string,unknown>{const o:Record<string,unknown>={};for(const k of names)if(Object.hasOwn(v,k))o[k]=v[k];return o;}
const selectionOrder=['stage','candidateRunId','externalRunId','recoveryRunId','originalSourceSha','originalVersion','recoveryConfirmation'];
function releaseSelection(v:Record<string,unknown>):Record<string,unknown>{const s=pick(v,selectionOrder);if(s.originalVersion)s.originalVersion=pick(s.originalVersion as Record<string,unknown>,['name','build']);return s;}
/** Reconstruct only the fixed native Args declaration order used by its hash. */
function orderedInput(v:GithubDispatchSelection):GithubDispatchSelection {
 const names=['kind','sessionId','expectedRevision'];
 if(v.kind==='setup-prepare')names.push('expectedConnectionRevision','base');
 else if(v.kind.endsWith('-prepare'))names.push('expectedConnectionRevision',v.kind==='counter-prepare'?'base':'branch',...(v.kind==='counter-prepare'?['purpose']:['platform',...(v.kind==='release-prepare'?['selection']:[])]));
 else if(v.kind==='publication-pending')names.push('expectedConnectionRevision');
 else if(v.kind==='counter-create'||v.kind.endsWith('-dispatch'))names.push('consentId','confirm',...(v.kind==='release-dispatch'?['confirmation']:[]));
 else if(v.kind.endsWith('-observe'))names.push('marker','observe','runId');
 else if(v.kind==='counter-reconcile')names.push('marker');
 const o=pick(v as unknown as Record<string,unknown>,names);if(v.kind==='release-prepare')o.selection=releaseSelection(v.selection as unknown as Record<string,unknown>);
 return freeze(o) as unknown as GithubDispatchSelection;
}
export function parseGithubDispatchSelection(raw:unknown):GithubDispatchSelection|null {
 try{const v=copyBoundedComparisonData(raw,4096,80);if(!v||typeof v!=='object'||!('kind'in v)||!isGithubDispatchKind(v.kind))return null;
 const {kind,...a}=v as Record<string,unknown>&{kind:GithubDispatchKind};let valid=false;
 switch(kind){
 case 'preflight-prepare':valid=githubPreflightRequestFits('github_preflight_prepare',a);break;
 case 'preflight-dispatch':valid=githubPreflightRequestFits('github_preflight_dispatch',a);break;
 case 'preflight-pending':valid=githubPreflightRequestFits('github_preflight_pending',a);break;
 case 'release-prepare':valid=githubReleaseRequestFits('github_release_prepare',a);break;
 case 'release-dispatch':valid=githubReleaseRequestFits('github_release_dispatch',a);break;
 case 'release-pending':valid=githubReleaseRequestFits('github_release_pending',a);break;
 case 'preflight-observe':case 'release-observe':valid=keys(a,['sessionId','expectedRevision','marker','observe','runId'])&&original(a)&&hex(a.marker,32)&&
   (a.observe==='track'&&numericId(a.runId)||a.observe==='reconcile'&&a.runId===null);break;
 case 'setup-prepare':valid=keys(a,['sessionId','expectedRevision','expectedConnectionRevision','base'])&&publicationRequestFits('github_setup_publication_prepare',a);break;
 case 'counter-prepare':valid=a.purpose==='version-counter'&&publicationRequestFits('github_setup_publication_prepare',a);break;
 case 'counter-create':valid=publicationRequestFits('github_setup_publication_publish',a);break;
 case 'publication-pending':valid=publicationRequestFits('github_setup_publication_pending',a);break;
 case 'counter-reconcile':valid=publicationRequestFits('github_setup_publication_reconcile',a);break;
 }
 if(!valid||new TextEncoder().encode(JSON.stringify(v)).length>(kind.endsWith('-prepare')?4096:1024))return null;
 return orderedInput(v as unknown as GithubDispatchSelection);
 }catch{return null;}
}
export function parseGithubDispatchReference(raw:unknown):GithubDispatchReference|null{
 try{const v=copyBoundedComparisonData(raw,768,24) as Record<string,unknown>|null;if(!v||typeof v!=='object'||!('kind'in v)||!isGithubDispatchKind(v.kind)||!original(v as Record<string,unknown>))return null;
 const k=v.kind,n=['kind','sessionId','expectedRevision'];let valid=false;
 if(k.endsWith('-prepare')||k.endsWith('-pending'))valid=keys(v,[...n,'requestSha256'])&&hex(v.requestSha256,64);
 else if(k.endsWith('-dispatch')||k==='counter-create')valid=keys(v,[...n,'consentId','preparedSha256'])&&hex(v.consentId,32)&&hex(v.preparedSha256,64);
 else if(k==='counter-reconcile')valid=keys(v,[...n,'marker','recordSha256'])&&hex(v.marker,32)&&hex(v.recordSha256,64);
 else valid=keys(v,[...n,'marker','recordSha256','observe','runId'])&&hex(v.marker,32)&&hex(v.recordSha256,64)&&
   (v.observe==='track'&&numericId(v.runId)||v.observe==='reconcile'&&v.runId===null);
 return valid?freeze(v) as unknown as GithubDispatchReference:null;
 }catch{return null;}
}
// Small bounded SHA-256 comparison, not a credential/signature/provenance issuer.
// Fixed 64-word working schedule; input is already closed copied native DATA.
const K=Uint32Array.from([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
export function githubDispatchHash(v:unknown):string { return boundedHash(v,16384); }
// Only the validated ordinary five-file comparator below uses its existing
//384KiB review bound. Every original dispatch hash keeps its16KiB bound.
function boundedHash(v:unknown,limit:number):string {
 const json=JSON.stringify(v);if(json.length>limit)throw new Error('Comparison limit');
 const data=new TextEncoder().encode(json);if(data.length>limit)throw new Error('Comparison limit');
 const padded=new Uint8Array(Math.ceil((data.length+9)/64)*64);padded.set(data);padded[data.length]=128;
 new DataView(padded.buffer).setUint32(padded.length-4,data.length*8);const w=new Uint32Array(64),h=Uint32Array.from([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
 const rotate=(n:number,b:number)=>(n>>>b)|(n<<(32-b));
 for(let off=0;off<padded.length;off+=64){for(let i=0;i<16;i++)w[i]=new DataView(padded.buffer).getUint32(off+4*i);
 for(let i=16;i<64;i++){const a=w[i-15]!,b=w[i-2]!;w[i]=(w[i-16]!+(rotate(a,7)^rotate(a,18)^(a>>>3))+w[i-7]!+(rotate(b,17)^rotate(b,19)^(b>>>10)))>>>0;}
 let [a,b,c,d,e,f,g,z]=Array.from(h) as [number,number,number,number,number,number,number,number];
 for(let i=0;i<64;i++){const t=(z+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+K[i]!+w[i]!)>>>0,q=((rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c)))>>>0;z=g;g=f;f=e;e=(d+t)>>>0;d=c;c=b;b=a;a=(t+q)>>>0;}
 [a,b,c,d,e,f,g,z].forEach((n,i)=>{h[i]=(h[i]!+n)>>>0;});}
 return Array.from(h,n=>n.toString(16).padStart(8,'0')).join('');
}
export function githubDispatchReferenceMatches(r:GithubDispatchReference,s:GithubDispatchSelection):boolean{
 if(r.kind!==s.kind||r.sessionId!==s.sessionId||r.expectedRevision!==s.expectedRevision)return false;
 if('requestSha256'in r)return r.requestSha256===githubDispatchHash(orderedInput(s));
 if('consentId'in r)return 'consentId'in s&&r.consentId===s.consentId;
 if(!('marker'in s)||r.marker!==s.marker)return false;
 return !('observe'in r)||'observe'in s&&r.observe===s.observe&&r.runId===s.runId;
}
export const sameGithubDispatchSelection=(a:GithubDispatchSelection,b:GithubDispatchSelection)=>same(a,b);
export function githubDispatchEffect(k:GithubDispatchKind,e:unknown):boolean{
 return typeof e==='string'&&(k==='counter-create'?['not-sent','potentially-applied','counter-observed']:k==='counter-reconcile'?['none','unresolved','counter-observed']:
 k.endsWith('-dispatch')?['not-sent','potentially-applied','accepted']:['none']).includes(e);
}
export const githubDispatchInitial=(k:GithubDispatchKind)=>k.endsWith('-dispatch')||k==='counter-create'?'not-sent':'none';
export function parseGithubDispatchSnapshot(v:unknown,k:GithubDispatchKind):GithubDispatchSnapshot|null{
 try{const c=copyBoundedComparisonData(v,8192,540) as Record<string,unknown>|null;if(!c||typeof c!=='object'||!('type'in c))return null;let valid=false;
 switch(c.type){case 'prepared':valid=keys(c,['type','marker','preparedSha256','sourceSha','platform','stage'])&&hex(c.marker,32)&&hex(c.preparedSha256,64)&&hex(c.sourceSha,40)&&
 (k==='setup-prepare'||k==='counter-prepare'?c.platform===null&&c.stage===null:k==='preflight-prepare'?['android','ios','both'].includes(String(c.platform))&&c.stage===null:
 k==='release-prepare'&&['android','ios'].includes(String(c.platform))&&['candidate','external-testing','production-submit'].includes(String(c.stage)));break;
 case 'pending':valid=keys(c,['type','rows'])&&Array.isArray(c.rows)&&c.rows.length<=64&&['preflight-pending','release-pending','publication-pending'].includes(k)&&c.rows.every((r,i,rows)=>keys(r,['marker','runId','purpose'])&&hex(r.marker,32)&&!rows.slice(0,i).some(x=>x.marker===r.marker)&&(r.runId===null||numericId(r.runId))&&
 (k==='preflight-pending'?r.purpose==='preflight':k==='release-pending'?r.purpose==='release':r.runId===null&&['setup','counter'].includes(String(r.purpose))));break;
 case 'observed':valid=keys(c,['type','marker','runId','attempt','status','conclusion'])&&k.endsWith('-observe')&&hex(c.marker,32)&&numericId(c.runId)&&c.attempt===1&&['queued','in_progress','completed','waiting','pending','requested'].includes(String(c.status))&&
 (c.conclusion===null||['success','failure','neutral','cancelled','skipped','timed_out','action_required','stale','startup_failure'].includes(String(c.conclusion)))&&(c.status==='completed')===(c.conclusion!==null);break;
 case 'counter':valid=keys(c,['type','marker','commitSha','ledgerId','genesisSha256'])&&['counter-create','counter-reconcile'].includes(k)&&hex(c.marker,32)&&hex(c.commitSha,40)&&typeof c.ledgerId==='string'&&/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(c.ledgerId)&&hex(c.genesisSha256,64);break;}
 return valid?freeze(c) as unknown as GithubDispatchSnapshot:null;
 }catch{return null;}
}
/** Ordinary native Prepared declaration order. Large file strings are only
 * borrowed into this fixed shallow projection; JSON/UTF8/padding scratch are
 * bounded by384KiB each (UTF16 JSON <=768KiB), never retained in a service row.
 * This comparison neither creates nor refreshes native publication authority. */
export function githubSetupPreparedHash(p:PublicationPrepared):string {
 if(!publicationPrepared(p))throw new Error('Invalid ordinary setup review');
 const target=pick(p.target as unknown as Record<string,unknown>,['projectBinding','repository','accountId','repositoryId','base','toolingRepository','toolingSha','marker']);
 const o=pick(p as unknown as Record<string,unknown>,['protocol','target','baseCommit','baseTree','desiredTree','files','head','confirmation']);
 o.target=target;o.files=p.files.map(f=>pick(f as unknown as Record<string,unknown>,['path','before','after']));
 return boundedHash(o,384*1024);
}
const targetKeys=['projectBinding','repository','accountId','repositoryId','branch','toolingRepository','toolingSha','platform','marker'];
function workflowPrepared(p:GitHubPreflightPrepared|GitHubReleasePrepared):unknown{
 const release='sourceTree'in p;
 const target=pick(p.target as unknown as Record<string,unknown>,[...targetKeys,...(release?['selection']:[])]);if(release)target.selection=releaseSelection(p.target.selection as unknown as Record<string,unknown>);
 const names=release?['target','sourceSha','sourceTree','workflowId','workflowPath','callerSha256','observedAt','expectedRef','displayTitle','configSha256','versionSource','versionSha256','currentVersion','destination','checklist','environment','confirmation','originalAssurance']:
 ['target','sourceSha','workflowId','workflowPath','callerSha256','observedAt','expectedRef','displayTitle','confirmation'];
 const o=pick(p as unknown as Record<string,unknown>,names);o.target=target;
 if(release){o.currentVersion=pick(p.currentVersion as unknown as Record<string,unknown>,['name','build']);o.destination=pick(p.destination as unknown as Record<string,unknown>,['applicationId','destination','assurance']);o.checklist=p.checklist.map(r=>pick(r as unknown as Record<string,unknown>,['name','kind','reason']));}return o;
}
export function githubDispatchPreparedHash(p:GitHubPreflightPrepared|GitHubReleasePrepared|CounterPrepared):string{
 if(!('protocol'in p))return githubDispatchHash(workflowPrepared(p));
 const target=pick(p.target as unknown as Record<string,unknown>,['purpose','projectBinding','repository','accountId','repositoryId','base','marker','projectId','ledgerId','initialVersion','savedConfig','savedVersion']);
 target.initialVersion=pick(p.target.initialVersion as unknown as Record<string,unknown>,['name','build']);target.savedConfig=pick(p.target.savedConfig as unknown as Record<string,unknown>,['bytes','sha256']);target.savedVersion=pick(p.target.savedVersion as unknown as Record<string,unknown>,['path','bytes','sha256']);
 const o=pick(p as unknown as Record<string,unknown>,['protocol','target','baseCommit','baseTree','desiredTree','ledgerBlob','genesisSha256','ledger','head','confirmation']);o.target=target;return githubDispatchHash(o);
}
function sorted(v:unknown):unknown{return Array.isArray(v)?v.map(sorted):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,sorted((v as Record<string,unknown>)[k])])):v;}
export function githubDispatchRecordHash(r:GitHubPreflightRecord|GitHubReleaseRecord|PublicationPending):string{return githubDispatchHash('summary'in r?sorted(r):{prepared:workflowPrepared(r.prepared),runId:r.runId});}
