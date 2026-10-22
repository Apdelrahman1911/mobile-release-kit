// Compact DATA only. Full draft and four-file before/after review stay with
// the genuine main-Webview WorkflowEdit owner. This installed facet is macOS-only.
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
import { workflowEditRequestFits, parseGitHubWorkflowEditStatus } from './githubWorkflowEditProtocol.ts';
import { GITHUB_WORKFLOWS } from './githubSetupProtocol.ts';
import type { GitHubWorkflowEditStatus, PrepareGitHubWorkflowEditRequest } from './githubWorkflowEditTypes.ts';
import type { ConfigurationOrigin, ConfigurationOriginal, ConfigurationResult } from './serviceConfigurationProtocol.ts';
import type { GitHubWorkflowId } from './types.ts';

export const WORKFLOW_EDIT_CONSENT = 'agent-exact-workflow-preview-v1';
export const WORKFLOW_EDIT_EVENT = 'mrk:agent-workflow-edit';
export type WorkflowEditOrigin = ConfigurationOrigin;
export type WorkflowEditOriginal = ConfigurationOriginal;
export interface WorkflowEditDigest { byteLength: number; sha256: string }
export interface WorkflowEditFile { id: GitHubWorkflowId; action: 'create'|'preserve'|'update'; observed: WorkflowEditDigest|null; generated: WorkflowEditDigest }
export interface WorkflowEditAgentReview {
  planToken: string; nativeStatusRevision: number; draftRevision: number; baselineGeneration: number;
  files: WorkflowEditFile[]; createdDirectories: number; coreVersion: string; resourceVersion: 1; resourceSha256: string;
  toolingRepository: string; toolingSha: string;
}
export type WorkflowEditAgentPhase = 'queued-open'|'opening'|'opened'|'preparing'|'reviewing'|'queued-apply'|'applying'|'stopping'|'refused'|'final'|'unknown';
export interface WorkflowEditAgentRequest {
  schemaVersion: 1; origin: WorkflowEditOrigin; runtimeProjectId: string; revision: number;
  phase: WorkflowEditAgentPhase; settlement: 'pending'|'settled'|'unknown';
  original: WorkflowEditOriginal|null; review: WorkflowEditAgentReview|null;
  permissionAvailable: boolean; permissionConsumed: boolean; remainingMs: number; cancelRequested: boolean;
  result: ConfigurationResult|null; doNotReplay: true;
}
export interface WorkflowEditAgentStatus { serviceInstance: string; request: WorkflowEditAgentRequest|null }
export interface WorkflowEditAgentAllow {
  origin: WorkflowEditOrigin; original: WorkflowEditOriginal; planToken: string;
  expectedNativeStatusRevision: number; expectedRequestRevision: number; consentVersion: typeof WORKFLOW_EDIT_CONSENT;
}
export interface WorkflowEditAgentOpen {
  projectId: string; draftRevision: number; baselineGeneration: number; toolingRepository: string; toolingSha: string;
}
export interface WorkflowEditAgentApi {
  status(origin?: WorkflowEditOrigin): Promise<WorkflowEditAgentStatus>;
  allow(input: WorkflowEditAgentAllow): Promise<WorkflowEditAgentStatus>;
  revoke(origin: WorkflowEditOrigin): Promise<WorkflowEditAgentStatus>;
  open(origin: WorkflowEditOrigin, input: WorkflowEditAgentOpen): Promise<GitHubWorkflowEditStatus>;
  prepare(origin: WorkflowEditOrigin, input: PrepareGitHubWorkflowEditRequest): Promise<GitHubWorkflowEditStatus>;
  apply(origin: WorkflowEditOrigin, sessionId: string, planToken: string): Promise<GitHubWorkflowEditStatus>;
  subscribe(listener: (status: unknown) => void): Promise<() => void>;
}
const keys = (v: unknown, names: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) &&
  Object.keys(v).length === names.length && names.every(k => Object.hasOwn(v,k));
const id = (v: unknown): v is string => typeof v === 'string' && /^[0-9a-f]{32}(?![\s\S])/.test(v) && !/^0+$/.test(v);
const uint = (v: unknown, max=0xfffffffe, min=0): v is number => typeof v === 'number' && Number.isInteger(v) && v>=min && v<=max;
const hex = (v: unknown): v is string => typeof v==='string' && /^[0-9a-f]{64}(?![\s\S])/.test(v);
const runtimeId = (v: unknown): v is string => typeof v==='string' && /^[A-Za-z0-9_-]{1,64}(?![\s\S])/.test(v);
const nullable = <T>(v: unknown, f: (x: unknown) => x is T): v is T|null => v===null || f(v);
const origin = (v: unknown): v is WorkflowEditOrigin => keys(v,['projectId','serviceInstance','requestId']) && Object.values(v).every(id);
const original = (v: unknown): v is WorkflowEditOriginal => keys(v,['sessionId','ownerGeneration','revision']) && Object.values(v).every(id);
const repository = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?(?![\s\S])/;
const phases: readonly string[] = ['queued-open','opening','opened','preparing','reviewing','queued-apply','applying','stopping','refused','final','unknown'];
export const sameWorkflowEditOrigin = (a: WorkflowEditOrigin,b: WorkflowEditOrigin): boolean => a.projectId===b.projectId && a.serviceInstance===b.serviceInstance && a.requestId===b.requestId;
export function freezeWorkflowEditData<T>(value:T):T {
  if(value && typeof value==='object' && !Object.isFrozen(value)){for(const child of Object.values(value))freezeWorkflowEditData(child);Object.freeze(value);} return value;
}
const digest = (v: unknown, generated: boolean): v is WorkflowEditDigest => keys(v,['byteLength','sha256']) && uint(v.byteLength,generated?16384:1048576,generated?1:0) && hex(v.sha256);
function file(v: unknown,index:number):boolean {
  if(!keys(v,['id','action','observed','generated']) || v.id!==GITHUB_WORKFLOWS[index]?.id || !digest(v.generated,true))return false;
  if(v.action==='create')return v.observed===null;
  if(!digest(v.observed,v.action==='update'))return false;
  return v.action==='preserve' ? v.observed.byteLength===v.generated.byteLength && v.observed.sha256===v.generated.sha256 :
    v.action==='update' && v.observed.sha256!==v.generated.sha256;
}
function review(v: unknown):v is WorkflowEditAgentReview {
  return keys(v,['planToken','nativeStatusRevision','draftRevision','baselineGeneration','files','createdDirectories','coreVersion','resourceVersion','resourceSha256','toolingRepository','toolingSha']) &&
    id(v.planToken) && uint(v.nativeStatusRevision) && uint(v.draftRevision) && uint(v.baselineGeneration) &&
    Array.isArray(v.files) && v.files.length===4 && v.files.every(file) && uint(v.createdDirectories,2) &&
    (v.createdDirectories===0 || v.files.every(f=>f.action==='create')) && typeof v.coreVersion==='string' && v.coreVersion.length<=32 &&
    /^[0-9]+\.[0-9]+\.[0-9]+(?![\s\S])/.test(v.coreVersion) && v.resourceVersion===1 && hex(v.resourceSha256) &&
    typeof v.toolingRepository==='string' && repository.test(v.toolingRepository) && typeof v.toolingSha==='string' && /^[0-9a-f]{40}(?![\s\S])/.test(v.toolingSha);
}
function result(v: unknown):v is ConfigurationResult {
  return keys(v,['effect','journal','cancelled','applySubmitted']) && ['not_started','unchanged','rolled_back','committed'].includes(String(v.effect)) &&
    ['not_created','clean','recovery_required'].includes(String(v.journal)) && typeof v.cancelled==='boolean' && typeof v.applySubmitted==='boolean';
}
function request(v:unknown):v is WorkflowEditAgentRequest {
  if(!keys(v,['schemaVersion','origin','runtimeProjectId','revision','phase','settlement','original','review','permissionAvailable','permissionConsumed','remainingMs','cancelRequested','result','doNotReplay']) ||
    v.schemaVersion!==1 || !origin(v.origin) || !runtimeId(v.runtimeProjectId) || !uint(v.revision,0xfffffffe,1) || !phases.includes(String(v.phase)) ||
    v.settlement!==(v.phase==='final'?'settled':v.phase==='unknown'?'unknown':'pending') || !nullable(v.original,original) || !nullable(v.review,review) ||
    !nullable(v.result,result) || (v.phase==='final')!==(v.result!==null) || typeof v.permissionAvailable!=='boolean' || typeof v.permissionConsumed!=='boolean' ||
    typeof v.cancelRequested!=='boolean' || !uint(v.remainingMs,900000) || v.doNotReplay!==true)return false;
  return !(v.review && !v.original || v.permissionAvailable && (v.permissionConsumed || v.cancelRequested || v.phase!=='reviewing' || !v.review) ||
    v.permissionConsumed && !v.review || ['opened','preparing','reviewing','queued-apply','applying'].includes(String(v.phase)) && !v.original ||
    ['reviewing','queued-apply','applying'].includes(String(v.phase)) && !v.review);
}
export function parseWorkflowEditAgentStatus(value:unknown):WorkflowEditAgentStatus|null {
  try {const v=copyBoundedComparisonData(value,16*1024,256);
    if(!keys(v,['serviceInstance','request']) || !id(v.serviceInstance) || !nullable(v.request,request) || v.request && v.request.origin.serviceInstance!==v.serviceInstance)return null;
    return freezeWorkflowEditData(v as unknown as WorkflowEditAgentStatus);
  } catch{return null;}
}
type Invoke=<T>(command:string,input?:Record<string,unknown>|Uint8Array)=>Promise<T>;
type Listen=(event:typeof WORKFLOW_EDIT_EVENT,callback:(value:unknown)=>void)=>Promise<()=>void>;
export function createWorkflowEditAgentApi(mode:string,invoke:Invoke,listen?:Listen):WorkflowEditAgentApi|null {
  if(mode!=='native' || !listen)return null;
  const failure=()=>({code:'agent_workflow_edit_unconfirmed',message:'Inspect or stop this original macOS workflow request; never repeat Apply.',retryable:false});
  const query=(q:unknown):WorkflowEditOrigin=>{const v=copyBoundedComparisonData(q,512,16);if(!origin(v))throw failure();return v;};
  const controls=async(command:string,input:unknown)=>{try{const bytes=new TextEncoder().encode(JSON.stringify(input));if(bytes.length>4096)throw failure();const s=parseWorkflowEditAgentStatus(await invoke(command,bytes));if(!s)throw failure();return s;}catch{throw failure();}};
  const continuation=async(step:'open'|'prepare'|'apply',q:WorkflowEditOrigin,input:unknown):Promise<GitHubWorkflowEditStatus>=>{
    try{
      const command=({open:'github_workflow_edit_open',prepare:'github_workflow_edit_prepare',apply:'github_workflow_edit_apply'} as const)[step];
      if(step==='open'){
        if(!keys(input,['projectId','draftRevision','baselineGeneration','toolingRepository','toolingSha']) || !runtimeId(input.projectId) || !uint(input.draftRevision) || !uint(input.baselineGeneration) ||
          typeof input.toolingRepository!=='string' || !repository.test(input.toolingRepository) || typeof input.toolingSha!=='string' || !/^[0-9a-fA-F]{40}(?![\s\S])/.test(input.toolingSha))throw failure();
      }else if(!workflowEditRequestFits(command,input) || (input as {intent?:unknown}).intent!==undefined)throw failure();
      const bytes=new TextEncoder().encode(JSON.stringify({agentWorkflowEdit:true,origin:query(q),input}));if(bytes.length>1024*1024)throw failure();
      const s=parseGitHubWorkflowEditStatus(await invoke(command,bytes));if(!s)throw failure();return s;
    }catch{throw failure();}
  };
  return Object.freeze({
    status:(q?:WorkflowEditOrigin)=>controls('agent_workflow_edit_status',{origin:q===undefined?null:query(q)}),
    allow:(input:WorkflowEditAgentAllow)=>{try{const a=copyBoundedComparisonData(input,4096,80);
      if(!keys(a,['origin','original','planToken','expectedNativeStatusRevision','expectedRequestRevision','consentVersion']) || !origin(a.origin) || !original(a.original) || !id(a.planToken) ||
        !uint(a.expectedNativeStatusRevision) || !uint(a.expectedRequestRevision,0xfffffffe,1) || a.consentVersion!==WORKFLOW_EDIT_CONSENT)throw failure();
      return controls('allow_agent_workflow_edit',a);
    }catch{return Promise.reject(failure());}},
    revoke:(q:WorkflowEditOrigin)=>controls('revoke_agent_workflow_edit',query(q)),
    open:(q:WorkflowEditOrigin,input:WorkflowEditAgentOpen)=>continuation('open',q,input),
    prepare:(q:WorkflowEditOrigin,input:PrepareGitHubWorkflowEditRequest)=>continuation('prepare',q,input),
    apply:(q:WorkflowEditOrigin,sessionId:string,planToken:string)=>continuation('apply',q,{sessionId,planToken}),
    subscribe:(fn:(value:unknown)=>void)=>listen(WORKFLOW_EDIT_EVENT,fn),
  });
}
