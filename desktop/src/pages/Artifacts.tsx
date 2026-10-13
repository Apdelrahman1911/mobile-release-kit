import type { ArtifactInspectionController, ArtifactInspectionState } from '../artifactInspection.ts';
import { ArtifactInspection } from '../components/ArtifactInspection.tsx';
import type { HelpContent } from '../types.ts';
import type { LifecycleEvidenceController, LifecycleEvidenceView } from '../lifecycleEvidence.ts';
import { ReleaseEvidence } from '../components/ReleaseEvidence.tsx';
import { PageHeading } from '../components/Common.tsx';

export function Artifacts({ state, controller, inspectionState, inspectionController, projectName, onHelp }: {
  inspectionState:ArtifactInspectionState;inspectionController:ArtifactInspectionController;
  state: LifecycleEvidenceView; controller: LifecycleEvidenceController; projectName: string | null; onHelp: (help: HelpContent) => void;
}) {
  return <>
    <PageHeading eyebrow="ARTIFACTS" title="Understand your saved release evidence." description="The same selected-folder observation is shared with Releases and Recovery. Artifact declarations do not verify payload bytes." />
    <ArtifactInspection state={inspectionState} controller={inspectionController} projectName={projectName} onHelp={onHelp}/>
    <ReleaseEvidence state={state} controller={controller} projectName={projectName} onHelp={onHelp} />
  </>;
}
