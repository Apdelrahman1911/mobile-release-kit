// Display-only binding of existing core requirements to an observed saved
// snapshot. Never sent to the network helper or used as remote write authority.
import { sameJson } from './catalog.ts';
import { validationFresh } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';
import { connectionInputSelection } from './githubConnectionProtocol.ts';
import type { GitHubInputSelection } from './githubConnectionTypes.ts';
import type { RequirementDescriptor } from './types.ts';

export type SavedGitHubInput = RequirementDescriptor & GitHubInputSelection & { kind: 'secret' | 'variable' };
export function savedGitHubInputs(session: ProjectSession | null): { observedAt: string; inputs: SavedGitHubInput[] } | null {
  if (!session || !session.snapshot || session.snapshotRequest !== null || session.snapshotError !== null ||
      session.snapshotPredatesSave || session.saveRecoveryRequired || session.sourceChanged ||
      session.validationRequest !== null || session.validationError !== null || !validationFresh(session) ||
      !session.validation?.valid || session.snapshot.config.state !== 'format-valid' ||
      !session.snapshot.config.data || !session.draft || !sameJson(session.draft, session.snapshot.config.data)) return null;
  const inputs: SavedGitHubInput[] = [];
  for (const row of session.validation.requirements) {
    // File/manual prerequisites are not GitHub environment fields. This view
    // labels that limit instead of treating a subset as a complete preflight.
    if (row.kind !== 'secret' && row.kind !== 'variable') continue;
    if (!connectionInputSelection({ stage: row.stage, name: row.name }) ||
        inputs.some((seen) => seen.stage === row.stage && seen.name === row.name)) return null;
    inputs.push({ ...row, alternatives: [...row.alternatives] } as SavedGitHubInput);
  }
  return { observedAt: session.snapshot.observedAt, inputs };
}
