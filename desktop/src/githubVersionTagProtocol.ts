// Closed proposal/comparison DATA. Only the protected hosted binder creates T.
import { connectionKeys as keys } from './githubConnectionProtocol.ts';
import { futureVersionTag } from './futureVersionTag.ts';
import type { PlayCleanupPrepared, PlayCleanupCandidate, PlayCleanupTarget } from './githubPlayCleanupProtocol.ts';
export interface VersionTagSelection { candidateId:string; rowSha256:string; finalCommit:string }
export interface VersionTagCandidate {
  candidateId:string;rowSha256:string;platform:'android'|'ios'|'both';source:PlayCleanupCandidate['source'];
  identityRevision:string;baseVersion:{name:string;build:number};version:{name:string;build:number};futureTag:string;
}
export interface VersionTagObservation { counterCommit:string;ledgerSha256:string;binding:'unclaimed'|'claimed-tag-absent'|'claimed-tag-matches'|'mismatch';assurance:'later-binding-read-not-creation-proof' }
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&!/[^0-9a-f]/.test(v);
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/.test(v);
export function versionTagSelection(v:unknown):v is VersionTagSelection {
  return keys(v,['candidateId','rowSha256','finalCommit'])&&uuid(v.candidateId)&&hex(v.rowSha256,64)&&hex(v.finalCommit,40);
}
export function isVersionTagCandidate(c:PlayCleanupCandidate|VersionTagCandidate):c is VersionTagCandidate {return 'futureTag' in c;}
function version(v:unknown,ios:boolean):boolean {
  return keys(v,['name','build'])&&typeof v.name==='string'&&v.name.length<=64&&/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))?$(?![\s\S])/.test(v.name)&&
    Number.isSafeInteger(v.build)&&typeof v.build==='number'&&v.build>0&&v.build<=(ios?9999:2100000000);
}
export function versionTagCandidate(v:unknown):v is VersionTagCandidate {
  if(!keys(v,['candidateId','rowSha256','platform','source','identityRevision','baseVersion','version','futureTag'])||!uuid(v.candidateId)||!hex(v.rowSha256,64)||
    !['android','ios','both'].includes(v.platform as string)||!futureVersionTag(v.futureTag)||!hex(v.identityRevision,64)||
    !keys(v.source,['commit','tree','ref','configurationSha256','versionSha256'])||!hex(v.source.commit,40)||!hex(v.source.tree,40)||
    typeof v.source.ref!=='string'||!v.source.ref.startsWith('refs/heads/')||v.source.configurationSha256!==v.identityRevision||!hex(v.source.versionSha256,64))return false;
  return version(v.baseVersion,v.platform!=='android')&&version(v.version,v.platform!=='android');
}
export function versionTagConfirmation(p:Pick<PlayCleanupPrepared,'target'|'branch'> & {sourceSha?:string},c:VersionTagCandidate):string {
  return `Dispatch a future-tag binding for ${c.futureTag} to ${p.sourceSha} in ${p.target.scope.repository}? Reserved version ${c.version.name} (build ${c.version.build}) came from branch source ${c.source.commit}. The tag name does not determine that number. The protected workflow must prove the exact version-only commit and claim this candidate once. It creates only an absent lightweight tag; it never moves an existing tag. Creating it may trigger your other automation. This job does not build, sign, access Stores or upload. Candidate builds remain branch-triggered. The configured branch ${p.branch} is mutable; a changed dispatch head must refuse. An acknowledgement is not a tag receipt or a run ID. Stopping cannot undo a sent request.`;
}
export function versionTagObservation(v:unknown):v is VersionTagObservation {
 return keys(v,['counterCommit','ledgerSha256','binding','assurance'])&&hex(v.counterCommit,40)&&hex(v.ledgerSha256,64)&&
  ['unclaimed','claimed-tag-absent','claimed-tag-matches','mismatch'].includes(v.binding as string)&&v.assurance==='later-binding-read-not-creation-proof';
}
export const targetPurpose=(t:PlayCleanupTarget):'play-cleanup'|'version-tag'=>t.versionTag||t.purpose==='version-tag'?'version-tag':'play-cleanup';
