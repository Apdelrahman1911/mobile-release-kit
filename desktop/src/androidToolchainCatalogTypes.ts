// Protected registered-tool comparison DATA. No paths, tool execution or
// qualification are authorized by this catalog or by renderer values.
import type { AndroidBuildAvailability, AndroidMacToolchainSelection } from './androidBuildTypes.ts';
export interface AndroidToolchainVersions {
  jdkVendor: string; jdkVersion: string; gradleVersion: string; agpVersion: string;
  sdkPlatform: string; sdkBuildToolsVersion: string;
}
export interface AndroidToolchainEntry { selection: AndroidMacToolchainSelection; versions: AndroidToolchainVersions }
export type AndroidCatalogPhase = 'idle' | 'reading' | 'stopping' | 'ready' | 'refused' | 'cancelled' | 'unknown';
export type AndroidCatalogReason = 'none' | 'not-inspected' | 'cancelled' | 'timed-out' | 'document-lost' |
  'shutdown' | 'catalog-changed' | 'catalog-unavailable' | 'cleanup-unknown';
export interface AndroidToolchainCatalogStatus {
  schemaVersion: 1; statusRevision: number; catalogGeneration: number; operationId: string | null;
  availability: AndroidBuildAvailability; phase: AndroidCatalogPhase; reason: AndroidCatalogReason;
  entries: AndroidToolchainEntry[]; selected: AndroidMacToolchainSelection | null;
}
export interface AndroidCatalogIdentity { catalogGeneration: number; operationId: string }
export interface SelectAndroidToolchain { schemaVersion: 1; catalogGeneration: number; instance: string; recordSha256: string }
export type CancelAndroidToolchainCatalog = AndroidCatalogIdentity & { schemaVersion: 1 };
export interface AndroidToolchainCatalogApi {
  androidToolchainCatalogStatus(): Promise<AndroidToolchainCatalogStatus>;
  refreshAndroidToolchainCatalog(): Promise<AndroidToolchainCatalogStatus>;
  selectAndroidToolchain(request: SelectAndroidToolchain): Promise<AndroidToolchainCatalogStatus>;
  cancelAndroidToolchainCatalog(request: CancelAndroidToolchainCatalog): Promise<AndroidToolchainCatalogStatus>;
  subscribeAndroidToolchainCatalog(onStatus: (status: unknown) => void): Promise<() => void>;
}
