// Closed local-publication DATA. The existing History original owns all IO,
// consent, verification and finality; neither a path nor these phases permits retry.
import { connectionBounded as bounded, connectionKeys as keys, connectionNumericId as numericId } from './githubConnectionProtocol.ts';
import type { GitHubHistorySelection, GitHubHistoryStart } from './githubHistoryTypes.ts';

export const GITHUB_CANDIDATE_DOWNLOAD_CONSENT = 'github-candidate-primary-download-v1' as const;
export type GitHubCandidateDownloadStart = GitHubHistoryStart & {
  consentVersion: typeof GITHUB_CANDIDATE_DOWNLOAD_CONSENT; confirmed: true;
};
export interface GitHubCandidateDownloadEffect {
  relativePath: string; pendingPath: string;
  publication: 'not-entered' | 'entered' | 'refused' | 'published' | 'unknown';
  durability: 'not-entered' | 'entered' | 'durable' | 'unknown'; closed: boolean;
}
export function candidateDownloadNames(selection: GitHubHistorySelection): { relativePath: string; pendingPath: string; primary: string } | null {
  if (!numericId(selection.runId) || !Number.isInteger(selection.attempt) || selection.attempt < 1 || selection.attempt > 100
      || selection.stage !== 'candidate' || !['android', 'ios'].includes(selection.platform)) return null;
  const name = `candidate-${selection.runId}-attempt-${selection.attempt}-${selection.platform}`;
  return { relativePath: `release/downloads/${name}`, pendingPath: `release/downloads/.${name}.pending`,
    primary: selection.platform === 'android' ? 'app-release.aab' : 'app.ipa' };
}
export function candidateDownloadEffect(value: unknown, selection: GitHubHistorySelection): value is GitHubCandidateDownloadEffect {
  try {
    if (!bounded(value, 1024, 32, 2) || !keys(value, ['relativePath', 'pendingPath', 'publication', 'durability', 'closed'])) return false;
    const names = candidateDownloadNames(selection);
    return names !== null && value.relativePath === names.relativePath && value.pendingPath === names.pendingPath
      && typeof value.publication === 'string' && ['not-entered', 'entered', 'refused', 'published', 'unknown'].includes(value.publication)
      && typeof value.durability === 'string' && ['not-entered', 'entered', 'durable', 'unknown'].includes(value.durability)
      && typeof value.closed === 'boolean' && (value.publication === 'published' || value.durability === 'not-entered')
      && (!value.closed || !['entered', 'unknown'].includes(value.publication) && !['entered', 'unknown'].includes(value.durability));
  } catch { return false; }
}
export function candidateDownloadExported(value: GitHubCandidateDownloadEffect): boolean {
  return value.publication === 'published' && value.durability === 'durable' && value.closed;
}
export function candidateDownloadProgress(old: GitHubCandidateDownloadEffect | undefined, next: GitHubCandidateDownloadEffect | undefined): boolean {
  if (!old || !next) return old === next;
  if (old.relativePath !== next.relativePath || old.pendingPath !== next.pendingPath || old.closed && !next.closed) return false;
  const publication = old.publication === next.publication || old.publication === 'not-entered'
    || old.publication === 'entered' && ['published', 'refused', 'unknown'].includes(next.publication);
  const durability = old.durability === next.durability || old.durability === 'not-entered'
    || old.durability === 'entered' && ['durable', 'unknown'].includes(next.durability);
  return publication && durability;
}
