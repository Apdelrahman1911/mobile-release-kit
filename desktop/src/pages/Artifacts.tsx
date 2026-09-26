import type { HelpContent } from '../types.ts';
import type { LifecycleEvidenceController, LifecycleEvidenceView } from '../lifecycleEvidence.ts';
import { ReleaseEvidence } from '../components/ReleaseEvidence.tsx';
import { PageHeading } from '../components/Common.tsx';

export function Artifacts({ state, controller, projectName, onHelp }: {
  state: LifecycleEvidenceView; controller: LifecycleEvidenceController; projectName: string | null; onHelp: (help: HelpContent) => void;
}) {
  return <>
    <PageHeading eyebrow="ARTIFACTS" title="Understand your saved release evidence." description="The same selected-folder observation is shared with Releases and Recovery. Artifact declarations do not verify payload bytes." />
    <ReleaseEvidence state={state} controller={controller} projectName={projectName} onHelp={onHelp} />
  </>;
}
