import type { OfflineCoreStatus, OfflinePreflightFinding, OfflinePreflightResult } from './offlinePreflightTypes.ts';

export type OfflinePreflightFindingFilter = 'all' | OfflineCoreStatus;

// Presentation only: filter the returned prefix, not the complete set counted by the core.
export function selectOfflinePreflightFindings(
  result: OfflinePreflightResult, filter: OfflinePreflightFindingFilter,
): { rows: readonly OfflinePreflightFinding[]; reported: number; visible: number; omitted: number } {
  const rows = filter === 'all' ? result.findings : result.findings.filter((finding) => finding.status === filter);
  const reported = filter === 'all' ? result.summary.total : result.summary.counts[filter];
  return { rows, reported, visible: rows.length, omitted: reported - rows.length };
}
