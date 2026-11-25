// Bounded recovery comparison DATA. No report, origin or session label is a
// native IOSRecoveryObservation or permission to bypass its original checks.
import {copyBoundedComparisonData} from './offlinePreflightProtocol.ts';
import {validAgentIOSArchiveOrigin, sameAgentIOSArchiveOrigin} from './agentIOSArchiveOrigin.ts';
import type {AgentIOSArchiveOrigin} from './agentIOSArchiveOrigin.ts';
import {parseBuildPermissionAccess} from './agentBuildPermissionProtocol.ts';
import type {BuildPermissionAccess} from './agentBuildPermissionProtocol.ts';
import type {IOSRecoveryOperation} from './iosArchiveTypes.ts';
export const AGENT_IOS_RECOVERY_CONSENT = 'agent-local-ios-recovery-v1';
export const ACCOUNT_CONFIRMATION = 'account-signing-is-idle-and-restore-owned-state';
export const PROJECT_CONFIRMATION = 'project-build-inputs-are-idle-and-restore-owned-state';
export interface IOSRecoveryInspection {operationId: string; ownerGeneration: string}
export type IOSRecoverySelection = {action:'inspect'} | {action:'account'|'project'; inspection:IOSRecoveryInspection};
export interface IOSRecoveryApproval {projectId:string; recovery:IOSRecoverySelection}
export interface AcknowledgedIOSRecovery {origin:AgentIOSArchiveOrigin; inspection:IOSRecoveryInspection}
export interface IOSRecoveryAccess extends BuildPermissionAccess {recoveryInspection?:AcknowledgedIOSRecovery}
const record=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const keys=(v:unknown,k:string[]):v is Record<string,unknown>=>record(v)&&Object.keys(v).length===k.length&&k.every(n=>Object.hasOwn(v,n));
const id=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{32}$/.test(v)&&v!=='0'.repeat(32);
const inspection=(v:unknown):v is IOSRecoveryInspection=>keys(v,['operationId','ownerGeneration'])&&id(v.operationId)&&id(v.ownerGeneration);
function selected(v:unknown):v is IOSRecoverySelection {
  return keys(v,['action'])&&v.action==='inspect'||keys(v,['action','inspection'])&&
    (v.action==='account'||v.action==='project')&&inspection(v.inspection);
}
export function copyIOSRecoveryApproval(value:unknown):IOSRecoveryApproval|null {
  try {
    const v=copyBoundedComparisonData(value,4096,32);
    if (!keys(v,['projectId','recovery'])||typeof v.projectId!=='string'||!v.projectId.length||v.projectId.length>64||
      !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(v.projectId)||!selected(v.recovery)) return null;
    if(v.recovery.action!=='inspect')Object.freeze(v.recovery.inspection);
    return Object.freeze({projectId:v.projectId,recovery:Object.freeze(v.recovery)});
  } catch{return null;}
}
export function recoveryConfirmation(action:IOSRecoverySelection['action']):string|undefined {
  return action==='inspect'?undefined:action==='account'?ACCOUNT_CONFIRMATION:PROJECT_CONFIRMATION;
}
export function parseIOSRecoveryAccess(value:unknown):IOSRecoveryAccess|null {
  try {
    const v=copyBoundedComparisonData(value,4096,48);
    if(!record(v))return null;
    const has=Object.hasOwn(v,'recoveryInspection');
    const names=['enabled','remainingMs','projectId','observationRevision','consumed','permissionRevision'];
    if(!keys(v,[...names,...(has?['recoveryInspection']:[])]))return null;
    const old=Object.fromEntries(names.map(n=>[n,v[n]]));
    const access=parseBuildPermissionAccess(old);if(!access)return null;
    if(!has)return Object.freeze(access);
    const r=v.recoveryInspection;
    if(!keys(r,['origin','inspection'])||!validAgentIOSArchiveOrigin(r.origin)||!inspection(r.inspection))return null;
    const receipt=Object.freeze({origin:Object.freeze(r.origin),inspection:Object.freeze(r.inspection)});
    return Object.freeze({...access,recoveryInspection:receipt});
  }catch{return null;}
}
export function recoveryAcknowledgementMatches(value:AcknowledgedIOSRecovery|null, original:IOSRecoveryOperation):boolean {
  return !!value&&!!original.agentIosArchive&&sameAgentIOSArchiveOrigin(value.origin,original.agentIosArchive)&&
    value.inspection.operationId===original.operationId&&value.inspection.ownerGeneration===original.ownerGeneration;
}
