// Pure bounded result DATA and fixed help. No native action or ownership grant.
// Native owns raw JSON duplicate-key rejection and actual input/finality custody.
import type { ApiError, HelpContent } from './types.ts';
import type { ArtifactInspectionIdentity, ArtifactInspectionOperation, ArtifactInspectionReason, ArtifactInspectionStatus, PrepareArtifactInspection } from './artifactInspectionTypes.ts';
import { offlineReasonText, sameOfflineData, sameSavedConfig } from './offlinePreflightProtocol.ts';
import type { ArtifactCheck, ArtifactCheckReason, ArtifactCheckStatus, ArtifactInspectionResult, ArtifactLimitation } from './artifactInspectionTypes.ts';

export const ARTIFACT_RESULT_LIMIT = 16 * 1024; // Leaves space inside the unchanged 64KiB owner terminal.
export const ARTIFACT_CHECKS: readonly ArtifactCheck[] = ['byte-identity','structure','manifest','expected-identity','expected-version',
  'signature','profile-entitlements','current-validity','signer-policy','archive-pair','symbols'];
export const ARTIFACT_REASONS: readonly ArtifactCheckReason[] = ['none','unsupported-format','input-limit','malformed-structure',
  'identity-mismatch','version-mismatch','tools-unavailable','signature-invalid','signer-unobserved','saved-policy-missing',
  'signer-mismatch','profile-invalid','signing-time-invalid','archive-not-selected','pair-mismatch','symbols-not-selected',
  'symbols-mismatch','prerequisite-not-run'];
export const ARTIFACT_LIMITATIONS: readonly ArtifactLimitation[] = ['byte-observation-not-source-provenance',
  'current-signature-not-store-or-release-authority','saved-inputs-not-unsaved-draft',
  'no-build-sign-upload-or-store-operation','external-changes-can-make-results-stale'];
const statuses: readonly ArtifactCheckStatus[] = ['pass','fail','unavailable','not_applicable'];
const encoder = new TextEncoder();
const integer = (value: unknown,max=Number.MAX_SAFE_INTEGER): value is number => typeof value==='number'&&Number.isSafeInteger(value)&&!Object.is(value,-0)&&value>=0&&value<=max;
const record = (value: unknown): value is Record<string,unknown> => value!==null&&typeof value==='object'&&!Array.isArray(value);
const keys = (value: unknown,names:readonly string[]): value is Record<string,unknown> => record(value)&&Object.keys(value).length===names.length&&names.every(name=>Object.hasOwn(value,name));
const member = <T extends string>(value:unknown,values:readonly T[]):value is T=>typeof value==='string'&&values.includes(value as T);
const hex = (value:unknown,length:number):value is string=>typeof value==='string'&&value.length===length&&/^[0-9a-f]+$/.test(value);
const text = (value:unknown,bytes:number):value is string=>typeof value==='string'&&value.length>0&&value.length<=bytes&&!/[\x00-\x1f\x7f-\x9f\ud800-\udfff]/u.test(value)&&encoder.encode(value).byteLength<=bytes;
const ascii = (value:unknown,bytes:number):value is string=>text(value,bytes)&&typeof value==='string'&&/^[\x20-\x7e]+$/.test(value);
const nullable = (value:unknown,check:(input:unknown)=>boolean):boolean=>value===null||check(value);

// Descriptor inspection precedes value access or serialization. This is a
// domain-local copy, not a global parser/framework and not a source observation.
function copyResult(input:unknown,maxBytes=ARTIFACT_RESULT_LIMIT):unknown {
  let nodes=0,bytes=0;
  const ancestors=new Set<object>();
  const charge=(count:number)=>{bytes+=count;if(bytes>maxBytes)throw new Error();};
  const copy=(value:unknown,depth:number):unknown=>{
    if(++nodes>2048||depth>12)throw new Error();
    if(value===null){charge(4);return null;}
    if(typeof value==='boolean'){charge(value?4:5);return value;}
    if(typeof value==='number'){if(!integer(value))throw new Error();charge(String(value).length);return value;}
    if(typeof value==='string'){
      if(value.length>maxBytes||/[\ud800-\udfff]/u.test(value))throw new Error();
      charge(encoder.encode(JSON.stringify(value)).byteLength);return value;
    }
    if(typeof value!=='object'||ancestors.has(value))throw new Error();
    ancestors.add(value);
    try{
      const prototype:unknown=Object.getPrototypeOf(value);
      if(Array.isArray(value)){
        const length=Object.getOwnPropertyDescriptor(value,'length');
        if(prototype!==Array.prototype||!length||!Object.hasOwn(length,'value')||!integer(length.value,128)||length.value>2048-nodes)throw new Error();
        if(Reflect.ownKeys(value).length!==length.value+1)throw new Error();
        charge(2+Math.max(0,length.value-1));const output:unknown[]=[];
        for(let index=0;index<length.value;index++){
          const item=Object.getOwnPropertyDescriptor(value,String(index));
          if(!item?.enumerable||!Object.hasOwn(item,'value'))throw new Error();
          output.push(copy(item.value,depth+1));
        }
        return output;
      }
      if(prototype!==Object.prototype&&prototype!==null)throw new Error();
      const names=Reflect.ownKeys(value);if(names.length>2048-nodes)throw new Error();
      charge(2+names.length+Math.max(0,names.length-1));
      const output:Record<string,unknown>=Object.create(null) as Record<string,unknown>;
      for(const name of names){
        if(typeof name!=='string'||name==='toJSON')throw new Error();
        const item=Object.getOwnPropertyDescriptor(value,name);
        if(!item?.enumerable||!Object.hasOwn(item,'value'))throw new Error();
        copy(name,depth+1);output[name]=copy(item.value,depth+1);
      }
      return output;
    }finally{ancestors.delete(value);}
  };
  return copy(input,0);
}

// The fixed matrix is transport shape from the core protocol. It never derives
// a signature/policy outcome from observed metadata or supplies a missing check.
const checkReasons:Record<ArtifactCheck,{fail:readonly ArtifactCheckReason[];unavailable:readonly ArtifactCheckReason[]}>= {
  'byte-identity':{fail:[],unavailable:[]},
  structure:{fail:['unsupported-format','input-limit','malformed-structure'],unavailable:[]},
  manifest:{fail:['malformed-structure'],unavailable:['tools-unavailable','prerequisite-not-run']},
  'expected-identity':{fail:['identity-mismatch'],unavailable:['prerequisite-not-run']},
  'expected-version':{fail:['version-mismatch'],unavailable:['prerequisite-not-run']},
  signature:{fail:['signature-invalid'],unavailable:['tools-unavailable','prerequisite-not-run']},
  'profile-entitlements':{fail:['profile-invalid'],unavailable:['tools-unavailable','prerequisite-not-run']},
  'current-validity':{fail:['signing-time-invalid'],unavailable:['tools-unavailable','prerequisite-not-run']},
  'signer-policy':{fail:['signer-mismatch'],unavailable:['saved-policy-missing','signer-unobserved','prerequisite-not-run']},
  'archive-pair':{fail:['pair-mismatch'],unavailable:['archive-not-selected','prerequisite-not-run']},
  symbols:{fail:['symbols-mismatch'],unavailable:['symbols-not-selected','prerequisite-not-run']},
};
const aabIrrelevant:readonly ArtifactCheck[]=['profile-entitlements','archive-pair','symbols'];
function resultShape(value:unknown):boolean {
  if(!keys(value,['schemaVersion','scope','format','usedConfig','usedVersion','artifacts','observed','checks','limitations'])||
    value.schemaVersion!==1||value.scope!=='selected-artifact-bytes-only'||!member(value.format,['aab','ipa'] as const))return false;
  const config=value.usedConfig, version=value.usedVersion;
  if(!keys(config,['bytes','sha256'])||!integer(config.bytes,512*1024)||config.bytes===0||!hex(config.sha256,64)||
    !keys(version,['bytes','sha256','name','build'])||!integer(version.bytes,65536)||version.bytes===0||!hex(version.sha256,64)||
    typeof version.name!=='string'||!/^[0-9A-Za-z.+-]{1,64}$/.test(version.name)||!integer(version.build,2_100_000_000)||version.build===0)return false;
  if(!Array.isArray(value.artifacts)||value.artifacts.length<1||value.artifacts.length>3||
    (value.format==='aab'&&value.artifacts.length!==1))return false;
  const roles=['artifact','archive','dsyms'] as const, ids=new Set<string>();
  let rawBytes=0;
  for(let index=0;index<value.artifacts.length;index++){
    const input:unknown=value.artifacts[index];
    if(!keys(input,['role','selectionId','label','kind','bytes','entries','identity'])||input.role!==roles[index]||
      !hex(input.selectionId,32)||ids.has(input.selectionId)||!text(input.label,255)||/[\\/]/.test(input.label)||
      !member(input.kind,['file','directory'] as const)||(index===0&&input.kind!=='file')||
      !keys(input.identity,['method','sha256'])||!hex(input.identity.sha256,64))return false;
    const byteCap=input.kind==='directory'?16*1024**3:value.format==='aab'?1024**3:4*1024**3;
    if(!integer(input.bytes,byteCap)||!integer(input.entries,8192)||input.entries===0||
      (input.kind==='file'&&(input.entries!==1||input.identity.method!=='sha256-file'))||
      (input.kind==='directory'&&input.identity.method!=='sha256-tree-v1'))return false;
    rawBytes+=input.bytes;if(rawBytes>16*1024**3)return false;
    ids.add(input.selectionId);
  }
  const observed=value.observed;
  if(!keys(observed,['applicationId','bundleId','versionName','versionBuild','signerSha256','teamId'])||
    !nullable(observed.applicationId,input=>text(input,255))||!nullable(observed.bundleId,input=>text(input,255))||
    !nullable(observed.versionName,input=>text(input,256))||!nullable(observed.versionBuild,input=>ascii(input,64))||
    !nullable(observed.signerSha256,input=>hex(input,64))||!nullable(observed.teamId,input=>ascii(input,128)))return false;
  if(value.format==='aab'&&(observed.bundleId!==null||observed.teamId!==null)||value.format==='ipa'&&observed.applicationId!==null)return false;
  if(!Array.isArray(value.checks)||value.checks.length!==ARTIFACT_CHECKS.length)return false;
  for(const [index,check] of ARTIFACT_CHECKS.entries()){
    const row:unknown=value.checks[index];
    if(!keys(row,['check','status','reason'])||row.check!==check||!member(row.status,statuses)||!member(row.reason,ARTIFACT_REASONS))return false;
    const artifact=value.artifacts[0] as Record<string,unknown>;
    if(check==='structure'&&artifact.bytes===0&&row.status!=='fail')return false;
    if(value.format==='aab'&&aabIrrelevant.includes(check)){
      if(row.status!=='not_applicable'||row.reason!=='none')return false;
    }else if(value.format==='aab'&&check==='current-validity'){
      // This schema has no independent AAB current-time observer. A strict JAR
      // signature result is not a separate current-validity observation.
      if(row.status!=='unavailable'||row.reason!=='prerequisite-not-run')return false;
    }else if(value.format==='ipa'&&((check==='archive-pair'&&value.artifacts.length<2)||(check==='symbols'&&value.artifacts.length<3))){
      if(row.status!=='unavailable'||row.reason!==(check==='archive-pair'?'archive-not-selected':'symbols-not-selected'))return false;
    }else if(row.status==='pass'){
      if(row.reason!=='none')return false;
    }else if(row.status==='not_applicable'||!checkReasons[check][row.status].includes(row.reason)||
      row.reason==='archive-not-selected'||row.reason==='symbols-not-selected')return false;
  }
  return Array.isArray(value.limitations)&&value.limitations.length===ARTIFACT_LIMITATIONS.length&&
    value.limitations.every((item:unknown,index:number)=>item===ARTIFACT_LIMITATIONS[index]);
}

// Returns a fresh bounded DATA copy or null; neither return value admits native
// input custody, a current result, a saved expectation or future finality.
export function parseArtifactInspectionResult(input:unknown):ArtifactInspectionResult|null {
  try{const copied=copyResult(input);return resultShape(copied)?copied as ArtifactInspectionResult:null;}
  catch{return null;}
}

export const artifactInspectionHelp:HelpContent={
  label:'Inspect selected artifact bytes',requiredness:'optional',
  requiredWhen:'Choose an existing AAB or IPA for the current registered project only after saved configuration is current and your draft is clean.',
  what:'Inspect existing files without building, signing, uploading or contacting a Store. Reading bytes, checking structure, comparing saved context, verifying a signature and matching signer policy are separate checks.',
  why:'Understand what was actually observed without treating a filename, file picker or completed operation as release approval.',
  where:'Use the native picker for the AAB or IPA. For an IPA, you may also choose its Xcode archive and matching debug symbols; debug symbols require the archive. No artifact path is entered as text.',
  format:'A picker accepts only the supported file or directory form for its role. A selected label and accepted form do not mean its contents have been inspected. The report distinguishes a file-byte SHA256 from a canonical directory-inventory commitment.',
  failure:'Refresh stale saved inputs and resolve an invalid or unsaved draft deliberately; inspection never saves or discards it for you. Missing verification tools or saved signer policy leave checks unavailable, not passed. Cancel requests a stop, not immediate cleanup; retain original status when finality is unknown.',
};
export const artifactInspectionLimitationText:Record<ArtifactLimitation,string>={
  'byte-observation-not-source-provenance':'The observed bytes do not authenticate their original source or build provenance.',
  'current-signature-not-store-or-release-authority':'A current signature check is not Store acceptance or permission to release.',
  'saved-inputs-not-unsaved-draft':'Expected identity, version and policy come from the saved originals, not your unsaved draft.',
  'no-build-sign-upload-or-store-operation':'This inspection does not build, sign, upload or perform a Store operation.',
  'external-changes-can-make-results-stale':'External changes can make this recorded result stale; it is not ongoing custody of a path.',
};
const labels:Record<ArtifactCheck,string>={
  'byte-identity':'Observed byte identity',structure:'Package or archive structure',manifest:'Manifest metadata',
  'expected-identity':'Saved application identity comparison','expected-version':'Saved version comparison',
  signature:'Cryptographic signature','profile-entitlements':'Profile and entitlement correspondence',
  'current-validity':'Current validity','signer-policy':'Saved signer policy comparison',
  'archive-pair':'IPA and archive correspondence',symbols:'Debug-symbol correspondence',
};
const reasons:Record<ArtifactCheckReason,string>={
  none:'No additional issue was reported for this check.',
  'unsupported-format':'The selected format is not supported for this check.',
  'input-limit':'The input exceeded a supported inspection limit; it was not silently truncated.',
  'malformed-structure':'The observed structure did not meet the supported format rules.',
  'identity-mismatch':'The observed application identity differs from the saved expected identity.',
  'version-mismatch':'The observed version differs from the saved expected version.',
  'tools-unavailable':'A required verification tool was unavailable; its check was not established.',
  'signature-invalid':'Signature verification reported an invalid signature.',
  'signer-unobserved':'No signer identity was established for this comparison.',
  'saved-policy-missing':'The saved configuration does not supply the required signer policy; artifact metadata cannot replace it.',
  'signer-mismatch':'The observed signer differs from the saved expected policy.',
  'profile-invalid':'The profile or its correspondence did not pass validation.',
  'signing-time-invalid':'The checked validity constraints were not satisfied.',
  'archive-not-selected':'No corresponding archive was selected; correspondence was not established.',
  'pair-mismatch':'The IPA and selected archive did not correspond.',
  'symbols-not-selected':'No corresponding debug symbols were selected; their correspondence was not established.',
  'symbols-mismatch':'The selected debug symbols did not correspond.',
  'prerequisite-not-run':'A required earlier check was not completed; this dependent check is not established.',
};
const statusLabels:Record<ArtifactCheckStatus,string>={pass:'Passed this check',fail:'Failed this check',unavailable:'Unavailable / not established',not_applicable:'Not applicable'};
export function artifactInspectionCheckRows(result:ArtifactInspectionResult){
  return result.checks.map(row=>({check:row.check,label:labels[row.check],statusLabel:statusLabels[row.status],
    explanation:reasons[row.reason]}));
}

export const ARTIFACT_INSPECTION_EVENT='artifact-inspection-state-changed';
export const ARTIFACT_INSPECTION_CONSENT='selected-artifact-inspection-v1';
export const ARTIFACT_INSPECTION_COUNTER_MAX=0xffff_fffe;
export const ARTIFACT_INSPECTION_CONSENT_MS=300_000;
export type ArtifactInspectionCommand='artifact_inspection_pick'|'artifact_inspection_prepare'|'artifact_inspection_start'|
  'artifact_inspection_cancel'|'artifact_inspection_status'|'artifact_inspection_discard';
export const artifactCounter=(value:unknown):value is number=>integer(value,ARTIFACT_INSPECTION_COUNTER_MAX);
const projectId=(value:unknown):value is string=>typeof value==='string'&&/^[A-Za-z0-9_-]{1,64}$/.test(value);
const identity=(value:unknown):value is ArtifactInspectionIdentity=>record(value)&&hex(value.operationId,32)&&hex(value.ownerGeneration,32);
function prepareShape(value:unknown):value is PrepareArtifactInspection {
  if(!keys(value,['projectId','draftRevision','baselineGeneration','savedConfig','format','selections'])||!projectId(value.projectId)||
    !artifactCounter(value.draftRevision)||!artifactCounter(value.baselineGeneration)||!member(value.format,['aab','ipa'] as const)||
    !keys(value.savedConfig,['bytes','sha256'])||!integer(value.savedConfig.bytes,524288)||value.savedConfig.bytes===0||!hex(value.savedConfig.sha256,64)||
    !keys(value.selections,['artifact','archive','dsyms'])||!hex(value.selections.artifact,32)||
    !nullable(value.selections.archive,input=>hex(input,32))||!nullable(value.selections.dsyms,input=>hex(input,32)))return false;
  const ids=[value.selections.artifact,value.selections.archive,value.selections.dsyms].filter(input=>input!==null);
  return new Set(ids).size===ids.length&&(value.selections.dsyms===null||value.selections.archive!==null)&&
    (value.format!=='aab'||value.selections.archive===null&&value.selections.dsyms===null);
}
export function copyArtifactInspectionRequest(command:ArtifactInspectionCommand,value:unknown):unknown|null {
  try{
    const safe=copyResult(value,8192);
    if(command==='artifact_inspection_prepare')return prepareShape(safe)?safe:null;
    if(command==='artifact_inspection_status')return keys(safe,[])?safe:null;
    if(command==='artifact_inspection_pick')return keys(safe,['projectId','format','role'])&&projectId(safe.projectId)&&
      member(safe.format,['aab','ipa'] as const)&&member(safe.role,['artifact','archive','dsyms'] as const)&&
      (safe.format!=='aab'||safe.role==='artifact')?safe:null;
    if(command==='artifact_inspection_start')return keys(safe,['operationId','ownerGeneration','consentVersion'])&&identity(safe)&&safe.consentVersion===ARTIFACT_INSPECTION_CONSENT?safe:null;
    if(command==='artifact_inspection_cancel')return keys(safe,['operationId','ownerGeneration'])&&identity(safe)?safe:null;
    if(command==='artifact_inspection_discard')return keys(safe,['selectionGeneration','operationId','ownerGeneration'])&&artifactCounter(safe.selectionGeneration)&&
      (safe.operationId===null&&safe.ownerGeneration===null||identity(safe))?safe:null;
    return null;
  }catch{return null;}
}
export function encodeArtifactInspectionRequest(command:ArtifactInspectionCommand,value:unknown):Uint8Array|null {
  const safe=copyArtifactInspectionRequest(command,value);return safe===null?null:encoder.encode(JSON.stringify(safe));
}
export const artifactAvailabilityText={
  available:'This native document supports reviewing selected artifact bytes. Actual originals and runtime are rechecked before inspection.',
  busy:'An original native operation is retained. Finish or cancel that original operation before new work.',
  shutdown:'The native application is stopping. No new inspection can start.',
  'cleanup-unknown':'Original cleanup is unknown. Retain the owner and status; conflicting work remains disabled.',
  'document-lost':'The original native document was lost. A replacement cannot adopt its operation.',
  'unsupported-platform':'Artifact inspection is unavailable on this host. No fallback runner is selected.',
  'runtime-unqualified':'The required bundled runtime is not qualified for this document. Missing optional verification tools are a separate unavailable check.',
};
export const artifactReasonText:Record<ArtifactInspectionReason,string>={...offlineReasonText,
  none:'No lifecycle failure was reported. A complete observation can still contain failed or unavailable checks.',
  'platform-disabled':'The selected platform is not enabled in the saved configuration.',
  'intent-expired':'This original review expired. Status reads cannot renew consent; explicitly review again.',
  'saved-version-missing':'The configured saved version file is missing. Correct it separately, then refresh and select again.',
  'saved-version-invalid':'The saved version file is invalid; artifact metadata cannot replace the expected version.',
  'saved-version-changed':'The saved version changed during inspection. No stale result is current.',
  'saved-version-unsafe':'The saved version could not be admitted safely.',
  'saved-version-too-large':'The saved version exceeds its supported bound.',
  'selection-missing':'A required original selection is missing. Choose it using the native picker.',
  'selection-changed':'A selected original changed. The prior selection is not reusable.',
  'selection-unsafe':'A selected original could not be admitted safely.',
  'toolchain-unavailable':'A required runtime tool provider could not be admitted. This is not a passed verification.',
  'toolchain-mismatch':'The actual tool provider did not match its retained source binding.',
  'resources-unavailable':'The required bounded resources could not be admitted. No inspection success was reported.',
};
export function parseArtifactInspectionStatus(value:unknown):ArtifactInspectionStatus|null {
  try{
    const safe=copyResult(value,65536);
    if(!keys(safe,['schemaVersion','statusRevision','availability','selection','operation'])||safe.schemaVersion!==1||!artifactCounter(safe.statusRevision)||
      !member(safe.availability,Object.keys(artifactAvailabilityText)))return null;
    const selection=safe.selection;
    if(!keys(selection,['generation','projectId','format','phase','reason','operation','items'])||!artifactCounter(selection.generation)||
      !nullable(selection.projectId,projectId)||!nullable(selection.format,input=>member(input,['aab','ipa'] as const))||
      !member(selection.phase,['idle','picking','ready','stopping','unknown'] as const)||
      !member(selection.reason,['none','cancelled','context-changed','document-lost','shutdown','source-refused','source-changed','unsupported-format','input-limit','cleanup-unknown'] as const)||
      !Array.isArray(selection.items)||selection.items.length>3)return null;
    const picker=selection.operation;
    if(picker!==null&&(!keys(picker,['operationId','role'])||!artifactCounter(picker.operationId)||picker.operationId===0||
      !member(picker.role,['artifact','archive','dsyms'] as const)))return null;
    if((selection.projectId===null)!==(selection.format===null)||
      (selection.items.length>0&&(selection.projectId===null||selection.format===null))||
      (selection.generation===0&&selection.items.length!==0)||
      (selection.phase==='unknown'&&selection.reason!=='cleanup-unknown'))return null;
    if(selection.phase==='idle'&&(selection.items.length!==0||picker!==null||selection.projectId!==null)||
      selection.phase==='ready'&&(selection.items.length===0||picker!==null||selection.projectId===null)||
      (selection.phase==='picking'||selection.phase==='stopping')&&(picker===null||selection.projectId===null))return null;
    const roles=['artifact','archive','dsyms'] as const,ids=new Set<string>();
    for(let index=0;index<selection.items.length;index++){
      const item:unknown=selection.items[index];
      if(!keys(item,['selectionId','role','label','kind'])||!hex(item.selectionId,32)||ids.has(item.selectionId)||item.role!==roles[index]||
        !text(item.label,255)||/[\\/]/.test(item.label)||!member(item.kind,['file','directory'] as const)||(index===0&&item.kind!=='file')||
        (selection.format==='aab'&&index!==0))return null;
      ids.add(item.selectionId);
    }
    const op=safe.operation;
    if(op===null)return safe as unknown as ArtifactInspectionStatus;
    if(!keys(op,['operationId','ownerGeneration','context','phase','intentUsable','outcome','reason','result'])||!identity(op)||!prepareShape(op.context)||
      !member(op.phase,['awaiting-consent','starting','running','stopping','terminal','unknown'] as const)||typeof op.intentUsable!=='boolean'||
      !member(op.reason,Object.keys(artifactReasonText)))return null;
    if(op.phase==='awaiting-consent'){
      if(op.outcome!==null||op.result!==null||op.reason!=='none')return null;
    }else if(op.phase==='unknown'){
      if(op.intentUsable||op.outcome!=='unknown'||op.result!==null||op.reason!=='cleanup-unknown')return null;
    }else if(op.phase==='terminal'){
      if(op.intentUsable||!member(op.outcome,['complete','refused','cancelled','timed-out','failed'] as const)||
        (op.reason==='none')!==(op.outcome==='complete'))return null;
      if(op.outcome==='complete'){
        const result=parseArtifactInspectionResult(op.result);
        if(!result||result.format!==op.context.format||!sameSavedConfig(result.usedConfig,op.context.savedConfig))return null;
        const expected=op.context.selections;
        if(result.artifacts.length!==Object.values(expected).filter(item=>item!==null).length||
          result.artifacts.some(item=>expected[item.role]!==item.selectionId))return null;
        op.result=result;
      }else if(op.result!==null||(op.outcome==='cancelled'&&op.reason!=='cancelled')||(op.outcome==='timed-out'&&op.reason!=='timed-out'))return null;
    }else if(op.intentUsable||op.outcome!==null||op.result!==null)return null;
    return safe as unknown as ArtifactInspectionStatus;
  }catch{return null;}
}
export const sameArtifactData=sameOfflineData;
export function sameArtifactIdentity(a:ArtifactInspectionIdentity|null,b:ArtifactInspectionIdentity|null):boolean {
  return !!a&&!!b&&a.operationId===b.operationId&&a.ownerGeneration===b.ownerGeneration;
}
export function artifactOperationProgress(a:ArtifactInspectionOperation,b:ArtifactInspectionOperation):boolean {
  if(!sameArtifactIdentity(a,b)||!sameArtifactData(a.context,b.context))return false;
  if(a.phase==='unknown')return b.phase==='unknown';
  if(a.phase==='terminal')return sameArtifactData(a,b);
  if(!a.intentUsable&&b.intentUsable)return false;
  const order=['awaiting-consent','starting','running','stopping','terminal','unknown'];
  return order.indexOf(b.phase)>=order.indexOf(a.phase);
}
const artifactErrors:Record<string,string>={
  protocol_error:'The native original returned an invalid protocol. Retain status; no new inspection or replay is authorized.',
  cleanup_unknown:'Original native cleanup is unknown. Keep its status and owner; conflicting work remains blocked.',
  artifact_inspection_invalid:'This is not a valid closed artifact-inspection request.',
  artifact_inspection_unavailable:'The native artifact-inspection capability is unavailable; no preview or ambient fallback is used.',
  artifact_inspection_busy:'An original native operation owns the slot. Retain its status and cancellation.',
  artifact_inspection_owner:'The selection or intent belongs to another original, is stale or is already consumed.',
  artifact_inspection_protocol:'A usable original status was not received. Keep retained status and do not repeat Start.',
};
export function artifactInspectionError(value:unknown):ApiError {
  let code='artifact_inspection_protocol';
  try{
    const descriptor=value!==null&&typeof value==='object'?Object.getOwnPropertyDescriptor(value,'code'):undefined;
    const candidate:unknown=descriptor&&Object.hasOwn(descriptor,'value')?descriptor.value:null;
    if(typeof candidate==='string'&&Object.hasOwn(artifactErrors,candidate))code=candidate;
  }catch{/* Never expose raw exceptions, paths or tool output. */}
  return {code,message:artifactErrors[code]!,retryable:false};
}
