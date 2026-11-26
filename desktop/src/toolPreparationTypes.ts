import type { SelectAndroidToolchain } from './androidToolchainCatalogTypes.ts';
import type { AndroidToolSourceRole } from './androidToolSources.ts';

export type ToolPreparationHost = 'macos-arm64' | 'macos-x86_64' | 'linux-x86_64' | 'unsupported';
export interface ToolPreparationContext {
  projectId: string; sessionId: string; observationRevision: number;
  savedConfigSha256: string; requirementsSha256: string; host: ToolPreparationHost;
}
export interface ToolPreparationStamp {
  catalogGeneration: number; catalogRevision: number; sourceGeneration: number; sourceRevision: number;
  registrationGeneration: number; registrationRevision: number; serviceGeneration: number; serviceRevision: number;
  diagnosticsRevision: number;
}
export type ToolPreparationAction = 'check-project-requirements' | 'refresh-registered-tools' | 'choose-registered-copy' |
  'use-selected-copy' | 'choose-jdk' | 'choose-sdk' | 'choose-gradle' | 'inspect-sources' | 'review-protected-copy' |
  'review-source-problem' | 'check-tool-service' | 'register-tool-service' | 'open-tool-service-settings' |
  'reconcile-setup' | 'wait-for-setup' | 'check-xcode' | 'install-xcode-manually' | 'inspect-xcode-copy' | 'unsupported-host';
export type ToolPreparationReason = 'not-checked' | 'requirements-unknown' | 'policy-mismatch' | 'existing-selected' |
  'existing-unselected' | 'existing-sources' | 'selection-missing' | 'source-problem' | 'service-required' |
  'original-unsettled' | 'original-busy' | 'host-unavailable' | 'xcode-missing' | 'xcode-mismatch' | 'xcode-needs-native-check';
export interface ToolPreparationPolicy {
  host: ToolPreparationHost; jdkVendor: string; jdk: string; gradle: string; agp: string;
  sdkPlatform: string; sdkBuildTools: string; distributionUrl: string; distributionSha256: string;
}
export interface ToolPreparationPlan {
  schemaVersion: 1; basis: 'tool-preparation-guidance'; context: ToolPreparationContext; stamp: ToolPreparationStamp;
  platform: 'android' | 'ios'; state: 'needs-check' | 'needs-review' | 'can-reuse' | 'needs-preparation' | 'recovery-required' | 'busy' | 'unsupported';
  action: ToolPreparationAction; reason: ToolPreparationReason; reusable: SelectAndroidToolchain[];
  // Missing selection is NOT evidence that a component must be downloaded.
  unselectedSources: AndroidToolSourceRole[]; policy: ToolPreparationPolicy | null;
  xcode: { version: string; build: string };
  assurance: { writesPerformed: false; projectCodeExecuted: false; downloadsPlanned: 0; executionAuthorized: false; releaseReadiness: 'not-assessed' };
}
export interface ToolPreparationRequest { schemaVersion: 1; projectId: string; expectedObservationRevision: number }
export interface ToolPreparationApi { toolPreparationPlan(request: ToolPreparationRequest): Promise<unknown> }
// These callbacks adapt EXISTING frontend operation controllers. They must not
// become another native lifecycle or bypass their ordinary review/consent UI.
export interface ToolPreparationActions {
  showProjectRequirements(): void;
  refreshRegisteredTools(): void | Promise<void>;
  chooseRegisteredCopy(comparison: SelectAndroidToolchain): void | Promise<void>;
  chooseSource(role: AndroidToolSourceRole): void | Promise<void>;
  showSourceInspection(): void;
  showToolService(): void;
  showRecovery(): void;
  showXcodeChecks(): void;
  showXcodeInstructions(): void;
  showBuild(): void;
}
