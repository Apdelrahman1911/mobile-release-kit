// Fixed public comparison DATA. Native retains the original account, material,
// Consent and returns; this helper cannot acquire any of them or execute a call.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { connectionKeys as keys, sameConnectionData as same } from './githubConnectionProtocol.ts';
import { githubDispatchHash } from './githubDispatchDelegation.ts';
import { githubRemoteSetupRequestFits, githubRemoteSetupPreparedData, parseGitHubRemoteSetupStatus } from './GitHubRemoteSetupProtocol.ts';
import type { GitHubRemoteSetupSelection, GitHubRemoteSetupPrepared, GitHubRemoteSetupObservation, GitHubRemoteSetupStatus } from './GitHubRemoteSetupTypes.ts';
export const GITHUB_REMOTE_SETTINGS_KINDS=['remote-setup-prepare','remote-setup-apply'] as const;
export type GithubRemoteSettingsKind=typeof GITHUB_REMOTE_SETTINGS_KINDS[number];
export type RemoteSetting=Exclude<GitHubRemoteSetupSelection,{kind:'environment_secret'}>;
interface Original {readonly sessionId:string;readonly expectedRevision:number}
export type GithubRemoteSettingsSelection=(Original&{readonly kind:'remote-setup-prepare';readonly expectedConnectionRevision:number;readonly selection:RemoteSetting})|
 (Original&{readonly kind:'remote-setup-apply';readonly consentId:string;readonly confirm:true});
export type GithubRemoteSettingsReference=(Original&{readonly kind:'remote-setup-prepare';readonly requestSha256:string})|
 (Original&{readonly kind:'remote-setup-apply';readonly consentId:string;readonly preparedSha256:string});
const nativeReasons=['none','no-change','policy-unsupported','policy-changed','organization-restricted','repository-archived','unauthorized','forbidden','not-found-or-inaccessible','target-changed','rate-limited','network-unavailable','tls-failed','response-invalid','response-limit','expired','cancelled','unqualified','not-connected','busy','invalid-input','runtime-unavailable','consent-expired','material-unavailable','material-changed','material-too-large','requirement-unsupported','configuration-changed','resources-unavailable','variable-exists','variable-missing','variable-changed'] as const;
export interface GithubRemoteSettingsResult {
 readonly type:'remote-settings';readonly setting:RemoteSetting['kind'];readonly reason:typeof nativeReasons[number];
 readonly writeClaimed:boolean|null;readonly writeAcknowledged:boolean|null;readonly consentId:string|null;readonly preparedSha256:string|null;readonly observationSha256:string|null;
}
const one=(v:unknown,options:readonly string[]):v is string=>typeof v==='string'&&options.includes(v);
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const revision=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>0&&v<=0xffff_fffe;
const original=(v:Record<string,unknown>)=>typeof v.sessionId==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(v.sessionId)&&revision(v.expectedRevision);
export const isGithubRemoteSettingsKind=(v:unknown):v is GithubRemoteSettingsKind=>one(v,GITHUB_REMOTE_SETTINGS_KINDS);
function freeze<T>(v:T):T{if(v&&typeof v==='object'&&!Object.isFrozen(v)){Object.values(v).forEach(freeze);Object.freeze(v);}return v;}
function pick(v:object,names:readonly string[]):Record<string,unknown>{const r=v as Record<string,unknown>,out:Record<string,unknown>={};for(const name of names)out[name]=r[name];return out;}
function orderedSelection(v:RemoteSetting):Record<string,unknown>{
 switch(v.kind){
 case 'actions_enabled':return {kind:v.kind,enabled:v.enabled};
 case 'workflow_token_policy':return {kind:v.kind,defaultWorkflowPermissions:v.defaultWorkflowPermissions,canApprovePullRequestReviews:v.canApprovePullRequestReviews};
 case 'environment_protection':return pick(v,['kind','mode','stage','waitTimerMinutes','preventSelfReview','reviewerLogin','branches']);
 case 'environment_variable':return {...pick(v,['kind','mode','stage','requirement']),source:pick(v.source,['recordId','recordRevision','contextRevision'])};
 }
}
function orderedInput(s:GithubRemoteSettingsSelection):GithubRemoteSettingsSelection{
 const base={kind:s.kind,sessionId:s.sessionId,expectedRevision:s.expectedRevision};
 return (s.kind==='remote-setup-prepare'?{...base,expectedConnectionRevision:s.expectedConnectionRevision,selection:orderedSelection(s.selection)}:
 {...base,consentId:s.consentId,confirm:s.confirm}) as GithubRemoteSettingsSelection;
}
export function parseGithubRemoteSettingsSelection(raw:unknown):GithubRemoteSettingsSelection|null{
 try{const v=copyBoundedComparisonData(raw,4096,80);if(!v||typeof v!=='object'||!('kind'in v)||!isGithubRemoteSettingsKind(v.kind))return null;
 const {kind,...input}=v as Record<string,unknown>&{kind:GithubRemoteSettingsKind};
 if(!githubRemoteSetupRequestFits(kind==='remote-setup-prepare'?'github_remote_setup_prepare':'github_remote_setup_apply',input)||
    kind==='remote-setup-prepare'&&(!input.selection||typeof input.selection!=='object'||!('kind'in input.selection)||input.selection.kind==='environment_secret'))return null;
 return freeze(orderedInput(v as unknown as GithubRemoteSettingsSelection));
 }catch{return null;}
}
export function parseGithubRemoteSettingsReference(raw:unknown):GithubRemoteSettingsReference|null{
 try{const v=copyBoundedComparisonData(raw,768,24) as Record<string,unknown>|null;
 if(!v||!isGithubRemoteSettingsKind(v.kind)||!original(v))return null;
 const base=['kind','sessionId','expectedRevision'];
 const valid=v.kind==='remote-setup-prepare'?keys(v,[...base,'requestSha256'])&&hex(v.requestSha256,64):keys(v,[...base,'consentId','preparedSha256'])&&hex(v.consentId,32)&&hex(v.preparedSha256,64);
 return valid?freeze(v) as unknown as GithubRemoteSettingsReference:null;
 }catch{return null;}
}
export function githubRemoteSettingsReferenceMatches(r:GithubRemoteSettingsReference,s:GithubRemoteSettingsSelection):boolean{
 if(r.kind!==s.kind||r.sessionId!==s.sessionId||r.expectedRevision!==s.expectedRevision)return false;
 return r.kind==='remote-setup-prepare'?r.requestSha256===githubDispatchHash(orderedInput(s)):
 s.kind==='remote-setup-apply'&&r.consentId===s.consentId;
}
export function sameGithubRemoteSettingsSelection(a:unknown,b:unknown):boolean{
 const ar=parseGithubRemoteSettingsReference(a),br=parseGithubRemoteSettingsReference(b),sa=parseGithubRemoteSettingsSelection(a),sb=parseGithubRemoteSettingsSelection(b);
 return ar&&sb?githubRemoteSettingsReferenceMatches(ar,sb):br&&sa?githubRemoteSettingsReferenceMatches(br,sa):ar&&br?same(ar,br):!!sa&&!!sb&&same(sa,sb);
}
export const githubRemoteSettingsInitial=(k:GithubRemoteSettingsKind)=>k==='remote-setup-prepare'?'none':'not-sent';
export const githubRemoteSettingsEffect=(k:GithubRemoteSettingsKind,e:unknown)=>k==='remote-setup-prepare'?e==='none':one(e,['not-sent','potentially-applied','settings-readback-observed']);
export function githubRemoteSettingsReason(reason:GithubRemoteSettingsResult['reason']):string{
 if(reason==='none'||reason==='no-change')return 'none';
 if(reason==='cancelled')return 'user-cancelled';
 if(reason==='expired'||reason==='consent-expired')return 'expired';
 if(reason==='target-changed')return 'context-changed';
 if(reason==='busy')return 'busy';
 return one(reason,['not-connected','unqualified','runtime-unavailable'])?'unavailable':'native-refused';
}
export function parseGithubRemoteSettingsResult(raw:unknown,k:GithubRemoteSettingsKind):GithubRemoteSettingsResult|null{
 try{const v=copyBoundedComparisonData(raw,1024,30);
 if(!keys(v,['type','setting','reason','writeClaimed','writeAcknowledged','consentId','preparedSha256','observationSha256'])||v.type!=='remote-settings'||
 !one(v.setting,['actions_enabled','workflow_token_policy','environment_protection','environment_variable'])||!one(v.reason,nativeReasons)||
 !(v.writeClaimed===null||typeof v.writeClaimed==='boolean')||!(v.writeAcknowledged===null||typeof v.writeAcknowledged==='boolean')||
 (v.writeClaimed===null)!==(v.writeAcknowledged===null)||v.writeAcknowledged===true&&v.writeClaimed!==true||
 !(v.consentId===null||hex(v.consentId,32))||!(v.preparedSha256===null||hex(v.preparedSha256,64))||
 !(v.observationSha256===null||hex(v.observationSha256,64))||(v.consentId===null)!==(v.preparedSha256===null)||
 v.setting!=='environment_variable'&&one(v.reason,['material-unavailable','material-changed','material-too-large','requirement-unsupported','configuration-changed','variable-exists','variable-missing','variable-changed']))return null;
 const success=v.reason==='none'||v.reason==='no-change';
 if(k==='remote-setup-prepare'?(v.writeClaimed===true||(v.reason==='none')!==(v.consentId!==null)||success&&v.observationSha256===null||success&&v.writeClaimed!==false):
 (v.consentId!==null||v.reason==='no-change'||(v.reason==='none')!==(v.observationSha256!==null)||v.reason==='none'&&v.writeAcknowledged!==true))return null;
 return freeze(v) as unknown as GithubRemoteSettingsResult;
 }catch{return null;}
}
export function githubRemoteSettingsRow(k:GithubRemoteSettingsKind,state:unknown,reason:unknown,effect:unknown,result:GithubRemoteSettingsResult):boolean{
 if(!githubRemoteSettingsEffect(k,effect)||reason!==githubRemoteSettingsReason(result.reason))return false;
 const success=result.reason==='none'||result.reason==='no-change';
 if(success?state!=='complete':!one(state,['refused','cancelled']))return false;
 return k==='remote-setup-prepare'?effect==='none':result.reason==='none'?effect==='settings-readback-observed':
 one(effect,['not-sent','potentially-applied'])&&(result.writeClaimed!==true||effect==='potentially-applied');
}
function policy(v:object):unknown{
 if('enabled'in v)return pick(v,['enabled','allowed_actions','sha_pinning_required']);
 if('default_workflow_permissions'in v)return pick(v,['default_workflow_permissions','can_approve_pull_request_reviews']);
 const p=v as Record<string,unknown>,r=p.requiredReviewers as Record<string,unknown>|null;
 return {...pick(v,['waitTimerMinutes','protectedBranches']),requiredReviewers:r===null?null:{preventSelfReview:r.preventSelfReview,reviewers:(r.reviewers as object[]).map(v=>pick(v,['type','id']))}};
}
function orderedObservation(v:GitHubRemoteSetupObservation):unknown{
 if('environmentName'in v){if(!('value'in v))throw new Error('Secret comparison refused');
 return {...pick(v,['environmentName','environmentId','name']),value:v.value===null?null:pick(v.value,['bytes','sha256']),metadata:v.metadata===null?null:pick(v.metadata,['createdAt','updatedAt'])};}
 if('policy'in v)return {name:v.name,id:v.id,policy:v.policy===null?null:policy(v.policy)};
 return policy(v);
}
/** Complete original declaration order, bounded by its existing8KiB review.
 * The validated helper is DATA-only; no clock, ownership or native proof is made. */
export function githubRemoteSettingsPreparedHash(raw:GitHubRemoteSetupPrepared):string{
 const p=copyBoundedComparisonData(raw,8192,1024);
 if(!githubRemoteSetupPreparedData(p)||p.target.selection.kind==='environment_secret')throw new Error('Invalid non-secret review');
 const target={...pick(p.target,['projectBinding','repository','accountId','repositoryId']),selection:orderedSelection(p.target.selection)};
 const base={target,before:orderedObservation(p.before)};
 if('configuration'in p){if(!('value'in p.after))throw new Error('Secret comparison refused');
 return githubDispatchHash({...base,after:{name:p.after.name,value:pick(p.after.value,['text','bytes','sha256'])},configuration:{savedConfig:pick(p.configuration.savedConfig,['bytes','sha256']),canonicalConfig:pick(p.configuration.canonicalConfig,['bytes','sha256'])},observedAt:p.observedAt,confirmation:p.confirmation});}
 const after=policy(p.after);
 return githubDispatchHash('reviewer'in p?{...base,after,reviewer:p.reviewer===null?null:pick(p.reviewer,['id','login','permission']),observedAt:p.observedAt,confirmation:p.confirmation}:
 {...base,after,observedAt:p.observedAt,confirmation:p.confirmation});
}
export function githubRemoteSettingsResultMatches(result:GithubRemoteSettingsResult,status:GitHubRemoteSetupStatus,selection:RemoteSetting):boolean{
 try{const s=parseGitHubRemoteSetupStatus(status),op=s?.operation;if(!s||!op||op.phase!=='settled'||result.setting!==selection.kind||result.reason!==op.reason||
 result.writeClaimed!==op.writeClaimed||result.writeAcknowledged!==op.writeAcknowledged)return false;
 if(result.observationSha256!==(s.observed===null?null:githubDispatchHash(orderedObservation(s.observed))))return false;
 return result.consentId===(s.consent?.id??null)&&result.preparedSha256===(s.consent?githubRemoteSettingsPreparedHash(s.consent.prepared):null);
 }catch{return false;}
}
