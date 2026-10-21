// Fixed native permission DATA. No renderer observation is native authority.
import { gitReadPathOrder } from './gitReadProtocol.ts';
import { copyBoundedComparisonData } from './offlinePreflightProtocol.ts';
// MAIN-only comparison on the existing shared Git Book, not CLI authority.
export function gitPermissionRevision(v: unknown): v is string {
 return typeof v === 'string' && /^(?:0|[1-9][0-9]{0,19})$/.test(v) && BigInt(v) <= 18446744073709551615n;
}
export const GIT_INDEX_CONSENT='agent-local-git-index-once-v1';
export type GitIndexAction='stage'|'unstage';
export interface GitIndexApproval {readonly projectId:string;readonly expectedDocumentRevision:number;readonly readOperationId:string;readonly action:GitIndexAction;readonly paths:readonly string[]}
export interface GitIndexSelection {readonly summary:{readonly action:GitIndexAction;readonly repositoryRevision:string;readonly pathCount:number;readonly selectionSha256:string};readonly paths:readonly string[]}
export interface GitIndexAccess {readonly permissionRevision:string;readonly enabled:boolean;readonly remainingMs:number;readonly consumed:boolean;readonly projectId:string|null;readonly grantId:string|null;readonly selection:GitIndexSelection|null}
const keys=(v:unknown,k:string[]):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===k.length&&k.every(n=>Object.hasOwn(v,n));
const hex=(v:unknown,n:number):v is string=>typeof v==='string'&&v.length===n&&/^[0-9a-f]+$/.test(v)&&(n!==32||!/^0+$/.test(v));
const id=(v:unknown):v is string=>typeof v==='string'&&/^[a-zA-Z0-9_-]{1,96}$/.test(v);
const bytes=(v:string)=>new TextEncoder().encode(v).length;
function paths(v:unknown):v is string[]{return Array.isArray(v)&&v.length>0&&v.length<=64&&v.every((p,i)=>typeof p==='string'&&p.length>0&&bytes(p)<=1024&&!/[\p{Cs}]/u.test(p)&&
 !/[\\\x00-\x1f\x7f]/.test(p)&&p.split('/').length<=32&&p.split('/').every(s=>s.length>0&&bytes(s)<=255&&!['.','..','.git'].includes(s))&&(i===0||gitReadPathOrder(v[i-1],p)<0));}
export function copyGitIndexApproval(value:unknown):GitIndexApproval|null {
 try{const v=copyBoundedComparisonData(value,96*1024-96,180);if(!keys(v,['projectId','expectedDocumentRevision','readOperationId','action','paths'])||!id(v.projectId)||v.projectId.length>64||!id(v.readOperationId)||
 !Number.isSafeInteger(v.expectedDocumentRevision)||typeof v.expectedDocumentRevision!=='number'||v.expectedDocumentRevision<1||v.expectedDocumentRevision>=0xffffffff||!['stage','unstage'].includes(String(v.action))||!paths(v.paths))return null;
 return Object.freeze({projectId:v.projectId,expectedDocumentRevision:v.expectedDocumentRevision,readOperationId:v.readOperationId,action:v.action as GitIndexAction,paths:Object.freeze([...v.paths])});}catch{return null;}
}
export function parseGitIndexAccess(value:unknown):GitIndexAccess|null {
 try{const v=copyBoundedComparisonData(value,128*1024,220);if(!keys(v,['enabled','remainingMs','consumed','projectId','grantId','selection','permissionRevision'])||!gitPermissionRevision(v.permissionRevision)||typeof v.enabled!=='boolean'||typeof v.consumed!=='boolean'||typeof v.remainingMs!=='number'||
 !Number.isSafeInteger(v.remainingMs)||v.remainingMs<0||v.remainingMs>900000||v.enabled&&(v.consumed||!v.remainingMs)||!v.enabled&&v.remainingMs!==0)return null;
 if(v.projectId===null||v.grantId===null||v.selection===null){return v.projectId===null&&v.grantId===null&&v.selection===null&&!v.enabled&&!v.consumed?Object.freeze({permissionRevision:v.permissionRevision,enabled:false,remainingMs:0,consumed:false,projectId:null,grantId:null,selection:null}):null;}
 if(!hex(v.projectId,32)||!hex(v.grantId,32)||!keys(v.selection,['summary','paths'])||!paths(v.selection.paths)||!keys(v.selection.summary,['action','repositoryRevision','pathCount','selectionSha256']))return null;
 const s=v.selection.summary;if(!['stage','unstage'].includes(String(s.action))||!hex(s.repositoryRevision,64)||!hex(s.selectionSha256,64)||s.pathCount!==v.selection.paths.length)return null;
 return Object.freeze({permissionRevision:v.permissionRevision,enabled:v.enabled,remainingMs:v.remainingMs,consumed:v.consumed,projectId:v.projectId,grantId:v.grantId,selection:Object.freeze({summary:Object.freeze({action:s.action as GitIndexAction,repositoryRevision:s.repositoryRevision,pathCount:v.selection.paths.length,selectionSha256:s.selectionSha256}),paths:Object.freeze([...v.selection.paths])})});}catch{return null;}
}
export interface GitIndexApi {status():Promise<GitIndexAccess>;allow(input:GitIndexApproval,expectedPermissionRevision:string):Promise<GitIndexAccess>;revoke():Promise<GitIndexAccess>}
type Invoke=<T>(command:string,input?:Record<string,unknown>|Uint8Array)=>Promise<T>;
export function createGitIndexApi(mode:string,invoke:Invoke):GitIndexApi|null {
 if(mode!=='native')return null;
 const failure=()=>({code:'agent_git_index_unconfirmed',message:'Permission was not confirmed. Inspect or stop it in the original Desktop; do not repeat the change.',retryable:false});
 const call=async(command:'agent_git_index_access'|'allow_agent_git_index'|'revoke_agent_git_index',input:unknown):Promise<GitIndexAccess>=>{
  try{const raw=new TextEncoder().encode(JSON.stringify(input));if(raw.length+96>96*1024)throw failure();const result=parseGitIndexAccess(await invoke<unknown>(command,raw));if(!result)throw failure();return result;}catch{throw failure();}};
 return Object.freeze({status:()=>call('agent_git_index_access',{}),revoke:()=>call('revoke_agent_git_index',{}),allow:(input:GitIndexApproval,expectedPermissionRevision:string)=>{const safe=copyGitIndexApproval(input);return safe&&gitPermissionRevision(expectedPermissionRevision)?call('allow_agent_git_index',{...safe,expectedPermissionRevision,consentVersion:GIT_INDEX_CONSENT}):Promise.reject(failure());}});
}
export interface PermissionApi<A, R = GitIndexAccess> {status():Promise<R>;allow(input:A,expectedPermissionRevision:string):Promise<R>;revoke():Promise<R>}
export interface PermissionState<R = GitIndexAccess> { access: R | null; acknowledged: boolean; pending: 'allow' | 'status' | null; revokePending: boolean; uncertain: boolean; message: string | null }
export interface PermissionContext<A, R = GitIndexAccess> { api: PermissionApi<A, R> | null; project: A | null; blocked: boolean }
interface Work<A, R> { api: PermissionApi<A, R>; epoch: number; context: A | null; permissionRevision: string | null; superseded: boolean }
interface Checked<A, R> { readonly api: PermissionApi<A, R>; readonly epoch: number; readonly context: A; readonly permissionRevision: string }
/** App-owned finite UI requests: one read/allow and one independent revoke.
 * Native consent/epoch and original native owner remain authoritative. */
export class Permission<A, R extends { readonly enabled: boolean; readonly permissionRevision: string } = GitIndexAccess> {
  private readonly copy:(value:unknown)=>A|null;
  private api: PermissionApi<A, R> | null = null;
  private original: PermissionApi<A, R> | null = null;
  private context: A | null = null;
  private epoch = 0;
  private blocked = false;
  private readonly current: (() => PermissionContext<A, R>) | null;
  private work: Work<A, R> | null = null;
  private revokeWork: Work<A, R> | null = null;
  private checked: Checked<A, R> | null = null;
  private listeners = new Set<(state: PermissionState<R>) => void>();
  private state: PermissionState<R> = { access: null, acknowledged: false, pending: null, revokePending: false, uncertain: false, message: null };
  constructor(copy: (value:unknown)=>A|null,current?:()=>PermissionContext<A, R>) {this.copy=copy;this.current=current??null;}
  getState(): PermissionState<R> { return this.state; }
  subscribe(listener: (state: PermissionState<R>) => void): () => void { this.listeners.add(listener); listener(this.state); return () => { this.listeners.delete(listener); }; }
  private update(value: Partial<PermissionState<R>>): void { this.state = Object.freeze({ ...this.state, ...value }); for (const fn of this.listeners) fn(this.state); }
  bind(api: PermissionApi<A, R> | null, input: A | null): void {
    const context = input ? this.copy(input) : null;
    if (this.api === api && JSON.stringify(this.context) === JSON.stringify(context)) return;
    this.api = api; this.context = context; this.checked = null;
    // Do not lose an in-flight original on service/selection change. It can
    // still be explicitly revoked, never adopted as a new permission.
    this.update({ acknowledged: false, message: this.original && this.original !== api ? 'Revoke the original Desktop permission before using a different connection.' : null });
  }
  syncContext(): void {
    if (!this.current) return;
    const current = this.current();
    this.blocked = current.blocked;
    this.bind(current.api, current.project);
  }
  acknowledge(value: boolean): void {
    this.update({ acknowledged: value === true && !!this.checked && !this.work && !this.revokeWork && !this.state.uncertain });
  }
  canAllow(): boolean {
    const checked = this.checked;
    return !this.blocked && !!this.api && !!this.context && !!checked && checked.api === this.api && checked.context === this.context && checked.epoch === this.epoch &&
      gitPermissionRevision(checked.permissionRevision) && checked.permissionRevision !== '18446744073709551615' &&
      (!this.original || this.original === this.api) && !this.work && !this.revokeWork && !this.state.uncertain && this.state.acknowledged && this.epoch < Number.MAX_SAFE_INTEGER;
  }
  async allow(): Promise<void> {
    this.syncContext(); // Native invocation uses current event-time selection, not an earlier render/effect.
    if (!this.canAllow()) return;
    const api = this.api!, context = this.context!, work: Work<A, R> = { api, context, epoch: this.epoch, permissionRevision: this.checked!.permissionRevision, superseded: false };
    // Consume the checked origin before notifying synchronous listeners. Even
    // a pre-send veto needs a fresh joined Check and a new explicit checkbox.
    this.checked = null;
    this.original = api; this.work = work; this.update({ pending: 'allow', acknowledged: false, message: null });
    try {
      // Notification is synchronous: a subscriber can revoke or change the
      // current selection before invocation. Do not send a fresh Allow after
      // that original Revoke merely because its eventual ACK would be ignored.
      this.syncContext();
      if (this.work !== work || work.superseded || work.epoch !== this.epoch || this.revokeWork ||
          this.api !== api || this.context !== context || this.blocked) return;
      const result = await api.allow(context, work.permissionRevision!);
      if (this.work === work && !work.superseded && work.epoch === this.epoch && this.api === api && this.context === context) this.update({ access: result, uncertain: false });
      else if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: 'Selection changed while permission was pending. Revoke the original permission before allowing again.' });
    } catch { if (!work.superseded && work.epoch === this.epoch) this.update({ uncertain: true, message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the Git change.' }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async status(): Promise<void> {
    this.syncContext();
    const api = this.original ?? this.api; if (!api || this.work || this.revokeWork) return;
    // A status-only reconnect can observe a previously enabled permission.
    // Keep that exact connection until original Revoke, even after rebinding.
    this.original = api;
    const work: Work<A, R> = { api, context: this.context, epoch: this.epoch, permissionRevision: null, superseded: false };
    this.checked = null; this.work = work; this.update({ pending: 'status', acknowledged: false });
    try {
      const result = await api.status();
      this.syncContext();
      if (this.work === work && !work.superseded && work.epoch === this.epoch) {
        // Native Access and its counter returned together. Historical status
        // from a changed context/host is display-only, and never clears Unknown.
        if (!this.state.uncertain && this.api === api && this.context === work.context && work.context && gitPermissionRevision(result.permissionRevision)) {
          this.checked = Object.freeze({ api, context: work.context, epoch: work.epoch, permissionRevision: result.permissionRevision });
        }
        this.update({ access: result, acknowledged: false, message: null });
      }
    }
    catch { if (!work.superseded && work.epoch === this.epoch) this.update({ message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the Git change.' }); }
    finally { if (this.work === work) { this.work = null; this.update({ pending: null }); } }
  }
  async revoke(): Promise<void> {
    this.syncContext();
    const api = this.work?.api ?? this.original ?? this.api; if (!api || this.revokeWork) return;
    // Even counter saturation still invokes original Revoke. There is no
    // late Allow display after it and never a new action on an old ACK.
    this.checked = null;
    this.epoch = Math.min(this.epoch + 1, Number.MAX_SAFE_INTEGER);
    if (this.work) this.work.superseded = true;
    const work: Work<A, R> = { api, context: null, epoch: this.epoch, permissionRevision: null, superseded: false }; this.revokeWork = work;
    this.update({ revokePending: true, access: null, acknowledged: false });
    try {
      const result = await api.revoke();
      if (result.enabled) throw new Error("Permission remains enabled");
      if (this.revokeWork === work) { this.original = null; this.update({ access: result, uncertain: false, message: 'Permission stopped. Wait for any running Git change to finish stopping.' }); }
    } catch { this.original = api; this.update({ uncertain: true, message: 'Permission was not confirmed. Refresh or stop it in the original Desktop; do not repeat the Git change.' }); }
    finally { if (this.revokeWork === work) { this.revokeWork = null; this.update({ revokePending: false }); } }
  }
}

export class GitIndexPermission extends Permission<GitIndexApproval> {
 private readonly choice:{value:GitIndexAction};
 constructor(current:(action:GitIndexAction)=>PermissionContext<GitIndexApproval>){const choice:{value:GitIndexAction}={value:'stage'};super(copyGitIndexApproval,()=>current(choice.value));this.choice=choice;}
 getAction():GitIndexAction{return this.choice.value;}
 chooseAction(action:GitIndexAction):void{if(action!=='stage'&&action!=='unstage')return;this.choice.value=action;this.acknowledge(false);this.syncContext();}
}
