// Renderer context checks correlate saved settings only. They grant no paths,
// file bytes or native write authority, and never save a configuration draft.
import { sameJson } from './catalog.ts';
import { isDirty } from './drafts.ts';
import { metadataConfiguredChoices } from './metadataText.ts';
import type { MetadataConfiguredContext } from './metadataText.ts';
import type { ProjectSession } from './drafts.ts';

export interface ImageProjectBinding {
  projectId: string;
  configRevision: number;
  configBaselineGeneration: number;
  configObservationGeneration: number;
}
export interface ImageConfiguredContext extends MetadataConfiguredContext { assetType: string }
export function imageProjectBinding(project: ProjectSession | null): ImageProjectBinding | null {
  return project ? { projectId: project.project.id, configRevision: project.revision,
    configBaselineGeneration: project.baselineGeneration, configObservationGeneration: project.observationGeneration } : null;
}
export function imageConfiguredChoices(project: ProjectSession | null): MetadataConfiguredContext[] {
  // Reuse the saved-configuration locale roster. No guessed locale, image slot,
  // Store dimensions or draft-only platform can become a picker option.
  return metadataConfiguredChoices(project);
}
export function imageConfigReason(project: ProjectSession | null): string | null {
  if (!project) return 'Choose a native project, then save its metadata root and enabled locales.';
  if (project.saveRecoveryRequired) return 'A separate configuration transaction needs recovery. An image import cannot clear that block.';
  if (project.snapshotRequest !== null) return 'Wait for the original configuration observation before selecting images.';
  if (project.sourceChanged) return 'Reconcile the changed saved configuration before selecting images.';
  if (!project.baseline || project.snapshot?.config.state !== 'format-valid' && project.lastSave?.resultingBaselineGeneration !== project.baselineGeneration)
    return 'Save a format-valid release/mobile-release.json before selecting localized images.';
  if (isDirty(project) || !sameJson(project.draft, project.baseline))
    return 'Save or explicitly discard configuration changes first. Image import never implicitly saves settings.';
  if (!imageConfiguredChoices(project).length)
    return 'Enable a platform and add its listing locales in saved settings. No locale is guessed.';
  return null;
}
