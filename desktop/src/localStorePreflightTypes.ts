import type { PairedCurrentVersions } from './pairedStoreVersions.ts';
import type { AndroidCurrentVersions } from './androidStoreVersions.ts';
import type { IOSCurrentVersions } from './iosStoreVersions.ts';
import type { AndroidBuildSavedVersion } from './androidBuildTypes.ts';
import type { OfflinePreflightAvailability, OfflinePreflightPhase, OfflinePreflightOutcome, OfflineCoreStatus, SavedConfigContent } from './offlinePreflightTypes.ts';
export interface PrepareLocalStorePreflight {
  projectId:string; draftRevision:number; baselineGeneration:number; savedConfig:SavedConfigContent; savedVersion:AndroidBuildSavedVersion;
  credentialContextRevision:number; recordId:string; recordRevision:number; executionMode:'local'; platform?:'ios'|'android'|'both';query?:'bundle-id-registration'|'app-store-profile-reuse'|'ios-current-versions'|'android-current-versions'|'paired-current-versions';iosRecord?:{recordId:string;recordRevision:number};
}
export interface LocalStoreContext extends Omit<PrepareLocalStorePreflight,'platform'> {platform:'android'|'ios'|'both';operation:'local-store-preflight'}
export interface LocalStoreIdentity {operationId:string;ownerGeneration:string}
export type LocalStoreReason='none'|'cancelled'|'context-changed'|'document-lost'|'shutdown'|'timed-out'|'protocol-error'|'runtime-unavailable'|'intent-expired'|'stale-intent'|'saved-source-changed'|'saved-source-invalid'|'credentials-unavailable'|'query-prerequisites'|'command-incomplete'|'cleanup-unknown';
export type StoreCheck='credential-format'|'query-prerequisites'|'runtime-unavailable'|'bundle-unavailable'|'store-access';
export type BundleIdObservation='found'|'not-returned'|'not-permitted'|'inconclusive'|'not-checked';
export interface ProfileReuseSummary {observation:BundleIdObservation;counts:{matchingProfiles:number;activeProfiles:number;currentMetadataCandidates:number;relatedCertificates:number}|null;checkedAt:string|null}
export interface LocalStoreResult {schemaVersion:1;scope:'local-android-store-access-no-publishing'|'local-ios-store-access-no-publishing'|'local-ios-bundle-id-registration-read'|'local-ios-profile-reuse-metadata-read'|'local-ios-current-version-inventory'|'local-android-current-version-inventory'|'local-shared-current-version-inventory';findings:{check:StoreCheck;status:OfflineCoreStatus}[];limitations:string[];observation?:BundleIdObservation;profileReuse?:ProfileReuseSummary;currentVersions?:IOSCurrentVersions|AndroidCurrentVersions|PairedCurrentVersions}
export interface LocalStoreOperation extends LocalStoreIdentity {context:LocalStoreContext;phase:OfflinePreflightPhase;intentUsable:boolean;outcome:OfflinePreflightOutcome|null;reason:LocalStoreReason;result:LocalStoreResult|null}
export interface LocalStoreStatus {schemaVersion:1;statusRevision:number;availability:OfflinePreflightAvailability;operation:LocalStoreOperation|null}
export interface LocalStorePreflightApi {
 prepareLocalStorePreflight(request:PrepareLocalStorePreflight):Promise<LocalStoreStatus>;
 startLocalStorePreflight(request:LocalStoreIdentity&{consentVersion:'local-android-store-access-v1'|'local-ios-store-access-v1'|'local-ios-bundle-id-read-v1'|'local-ios-profile-reuse-read-v1'|'local-ios-current-versions-read-v1'|'local-android-current-versions-edit-v1'|'local-paired-current-versions-edit-v1'}):Promise<LocalStoreStatus>;
 localStorePreflightStatus():Promise<LocalStoreStatus>;
 cancelLocalStorePreflight(operationId:string,ownerGeneration:string):Promise<LocalStoreStatus>;
 subscribeLocalStorePreflight(listener:(status:unknown)=>void):Promise<()=>void>;
}
