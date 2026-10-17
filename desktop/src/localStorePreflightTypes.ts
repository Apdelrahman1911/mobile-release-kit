import type { AndroidBuildSavedVersion } from './androidBuildTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome, OfflineCoreStatus, SavedConfigContent } from './offlinePreflightTypes.ts';
export interface PrepareLocalStorePreflight {
  projectId:string; draftRevision:number; baselineGeneration:number; savedConfig:SavedConfigContent; savedVersion:AndroidBuildSavedVersion;
  credentialContextRevision:number; recordId:string; recordRevision:number; executionMode:'local'; platform?:'ios';
}
export interface LocalStoreContext extends Omit<PrepareLocalStorePreflight,'platform'> {platform:'android'|'ios';operation:'local-store-preflight'}
export interface LocalStoreIdentity {operationId:string;ownerGeneration:string}
export type LocalStoreReason='none'|'cancelled'|'context-changed'|'document-lost'|'shutdown'|'timed-out'|'protocol-error'|'runtime-unavailable'|'intent-expired'|'stale-intent'|'saved-source-changed'|'saved-source-invalid'|'credentials-unavailable'|'query-prerequisites'|'command-incomplete'|'cleanup-unknown';
export type StoreCheck='credential-format'|'query-prerequisites'|'runtime-unavailable'|'bundle-unavailable'|'store-access';
export interface LocalStoreResult {schemaVersion:1;scope:'local-android-store-access-no-publishing'|'local-ios-store-access-no-publishing';findings:{check:StoreCheck;status:OfflineCoreStatus}[];limitations:string[]}
export interface LocalStoreOperation extends LocalStoreIdentity {context:LocalStoreContext;phase:OfflinePreflightPhase;intentUsable:boolean;outcome:OfflinePreflightOutcome|null;reason:LocalStoreReason;result:LocalStoreResult|null}
export interface LocalStoreStatus {schemaVersion:1;statusRevision:number;availability:OfflinePreflightAvailability;operation:LocalStoreOperation|null}
export interface LocalStorePreflightApi {
 prepareLocalStorePreflight(request:PrepareLocalStorePreflight):Promise<LocalStoreStatus>;
 startLocalStorePreflight(request:LocalStoreIdentity&{consentVersion:'local-android-store-access-v1'|'local-ios-store-access-v1'}):Promise<LocalStoreStatus>;
 localStorePreflightStatus():Promise<LocalStoreStatus>;
 cancelLocalStorePreflight(operationId:string,ownerGeneration:string):Promise<LocalStoreStatus>;
 subscribeLocalStorePreflight(listener:(status:unknown)=>void):Promise<()=>void>;
}
