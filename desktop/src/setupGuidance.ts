// Presentation only: these selectors never authorize a write or start an
// operation. Setup reuses the existing draft, save and version owners.
import { sameJson } from './catalog.ts';
import { preparedMatches } from './configEdit.ts';
import type { ConfigEditState } from './configEdit.ts';
import { normalEditResult } from './configEditProtocol.ts';
import { savedRevisionFresh } from './drafts.ts';
import type { ProjectSession } from './drafts.ts';

export function configurationSetupNeeded(session: ProjectSession | null, preview: boolean, saves: ConfigEditState): boolean {
  // A retained save may have changed files since the snapshot. Do not invent a
  // read/save ordering; generic guidance remains available without this label.
  const saveObserved = session !== null && (saves.attempt?.binding.projectId === session.project.id ||
    saves.recoveryProjects.some((owner) => owner.projectId === session.project.id) ||
    [saves.status?.active, saves.status?.lastTerminal, saves.buffered?.active, saves.buffered?.lastTerminal,
      saves.unknownEvidence].some((owner) => owner?.projectId === session.project.id));
  return !preview && session !== null && session.observedAt !== null &&
    session.snapshotRequest === null && session.snapshotError === null &&
    !session.snapshotPredatesSave && !session.sourceChanged && !session.saveRecoveryRequired && !saveObserved &&
    session.snapshot?.discovery.partial === false && session.snapshot.config.state === 'missing';
}

// Return only the original submitted revision, not a claim about current files.
// A terminal status alone (including a read-only foreign summary) is not a save.
export function savedSetupRevision(state: ConfigEditState, session: ProjectSession | null, selectedId: string | null): number | null {
  const attempt = state.attempt;
  const saved = session?.lastSave;
  const owner = attempt?.projection;
  if (state.mode !== 'native' || !state.initialized || !state.listening ||
      state.integrityFailed || state.generationLost || state.nativeBlocked || state.observationIssue || state.unknownEvidence ||
      !session || selectedId !== session.project.id || session.saveRecoveryRequired ||
      state.recoveryProjects.some((item) => item.projectId === session.project.id) ||
      !saved || saved.result !== 'saved' || !savedRevisionFresh(session) ||
      !attempt?.handled || !attempt.applyClaimed || !owner || !preparedMatches(attempt) ||
      attempt.binding.projectId !== selectedId || !state.status || owner.ownerGeneration !== state.status.windowGeneration ||
      state.status.active !== null || normalEditResult(owner) !== 'saved' ||
      attempt.submittedPlanToken === null || attempt.submittedPlanToken !== owner.prepared?.planToken ||
      saved.sessionId !== attempt.sessionId || saved.statusRevision !== attempt.projectionRevision ||
      saved.draftRevision !== attempt.binding.draftRevision || saved.baselineGeneration !== attempt.binding.baselineGeneration ||
      saved.resultingBaselineGeneration !== attempt.binding.baselineGeneration + 1 ||
      !sameJson(session.draft, attempt.binding.draft) || !sameJson(session.baseline, attempt.binding.draft)) return null;
  return saved.draftRevision;
}
