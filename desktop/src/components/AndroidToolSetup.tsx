import type { Ref } from 'react';
import type { AndroidBuildController, AndroidBuildState } from '../androidBuild.ts';
import type { HelpContent } from '../types.ts';
import { AndroidToolService, AndroidToolSources, AndroidToolRegistration,
  AndroidToolchainCatalog, AndroidToolSetupControls } from './AndroidBuild.tsx';
import { SectionHeading } from './Common.tsx';

export interface AndroidToolSetupProps {
  state: AndroidBuildState;
  controller: AndroidBuildController;
  onHelp?: (help: HelpContent) => void;
  sectionRef?: Ref<HTMLElement>;
}

/** Another view of the same app-owned controller, not another tool owner. */
export function AndroidToolSetup({ state, controller, onHelp, sectionRef }: AndroidToolSetupProps) {
  return <section className="card" aria-label="Set up build tools" tabIndex={-1} ref={sectionRef}>
    <SectionHeading title="Set up build tools"
      description="Use an existing protected copy first. Choose source folders only when you need to prepare another copy." />
    <p>These controls do not build or publish your app. Choosing folders, checking tools and approving a protected copy remain separate steps.</p>
    <AndroidToolchainCatalog state={state} controller={controller} onHelp={onHelp} />
    <div className="section-heading"><div><h3>Need another tool copy?</h3>
      <p>Choose the source folders, check the installed helper, then inspect and review the exact copy. Keep working installations unchanged.</p>
    </div></div>
    <AndroidToolSources state={state} controller={controller} onHelp={onHelp} />
    <AndroidToolService state={state} controller={controller} onHelp={onHelp} />
    <AndroidToolRegistration state={state} controller={controller} onHelp={onHelp} />
    <div className="button-row"><AndroidToolSetupControls state={state} controller={controller} /></div>
    <p className="save-note">An unfinished or unconfirmed action keeps its original status and cancellation controls. A selected tool copy is not a build or release-readiness result.</p>
  </section>;
}
