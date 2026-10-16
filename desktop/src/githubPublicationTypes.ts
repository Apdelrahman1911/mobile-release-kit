// Renderer DATA only; the native connected document owns all authority.
export type PublicationKind = 'prepare' | 'publish' | 'pending' | 'reconcile';
export type PublicationReason = 'none' | 'target-changed' | 'source-changed' | 'caller-mismatch' | 'source-unsupported' | 'configuration-invalid' | 'response-invalid' | 'response-limit' | 'no-change' | 'branch-exists' | 'unauthorized' | 'forbidden' | 'not-found-or-inaccessible' | 'rate-limited' | 'network-unavailable' | 'tls-failed' | 'expired' | 'cancelled' | 'journal-unavailable' | 'unresolved' | 'ambiguous' | 'configuration-changed' | 'resources-unavailable' | 'runtime-unavailable' | 'unqualified' | 'publisher-unconfigured' | 'not-connected' | 'busy' | 'invalid-input' | 'cleanup-unknown' | 'consent-expired';
export type PublicationEffect = 'none' | 'not-sent' | 'potentially-applied' | 'draft-pr-observed' | 'unresolved' | 'branch-observed';
export type PublicationStep = 'tree' | 'commit' | 'branch' | 'pull';
export interface PublicationTarget { projectBinding: string; repository: string; accountId: string; repositoryId: string; base: string; toolingRepository: string; toolingSha: string; marker: string }
export interface PublicationPrepared { protocol: 'mrk-github-setup-publication/1'; target: PublicationTarget; baseCommit: string; baseTree: string; desiredTree: string; files: { path: string; before: string | null; after: string }[]; head: string; confirmation: string }
export interface PublicationSummary extends Omit<PublicationPrepared, 'head' | 'confirmation' | 'files'> { files: { path: string; before: { bytes: number; sha256: string } | null; after: { bytes: number; sha256: string } }[] }
export interface PublicationPending { summary: PublicationSummary; claimed: PublicationStep[]; confirmed: Partial<Record<PublicationStep, string>> }
export interface PublicationConsent { id: string; expiresAt: string; prepared: PublicationPrepared }
export interface PublicationStatus {
  schemaVersion: 1; revision: number; sessionId: string | null; available: boolean; reason: PublicationReason;
  operation: { id: string; kind: PublicationKind; phase: 'running' | 'stopping' | 'settled' | 'cleanup-unknown'; reason: PublicationReason; effect: PublicationEffect } | null;
  consent: PublicationConsent | null; pending: PublicationPending[]; pull: { number: string; url: string; commit: string } | null;
}
export interface PublicationApi {
  githubPublicationStatus(): Promise<PublicationStatus>;
  githubPublicationPrepare(args: { sessionId: string; expectedRevision: number; expectedConnectionRevision: number; base: string }): Promise<PublicationStatus>;
  githubPublicationPublish(args: { sessionId: string; expectedRevision: number; consentId: string; confirm: true }): Promise<PublicationStatus>;
  githubPublicationPending(args: { sessionId: string; expectedRevision: number; expectedConnectionRevision: number }): Promise<PublicationStatus>;
  githubPublicationReconcile(args: { sessionId: string; expectedRevision: number; marker: string }): Promise<PublicationStatus>;
  githubPublicationDiscard(args: { sessionId: string; expectedRevision: number; consentId: string }): Promise<PublicationStatus>;
  githubPublicationCancel(operationId: string): Promise<PublicationStatus>;
  subscribeGitHubPublication(onStatus: (status: PublicationStatus | null) => void): Promise<() => void>;
}
export interface PublicationView {
  mode: 'native' | 'preview' | 'unavailable'; status: PublicationStatus | null; base: string;
  originalTarget: { repository: string; accountId: string; repositoryId: string; base: string } | null;
  confirmed: boolean; pending: boolean; observing: boolean; cancelling: boolean; discarding: boolean; uncertain: boolean; error: PublicationReason | null;
}
