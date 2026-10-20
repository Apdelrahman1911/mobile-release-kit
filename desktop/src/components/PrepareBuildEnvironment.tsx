import type { AndroidToolSourceRole } from '../androidToolSources.ts';
import type { ToolAcquisitionController, ToolAcquisitionState } from '../toolAcquisitionController.ts';
import { stagedToolSourceGuidance, toolAcquisitionFailureGuidance } from '../toolAcquisitionGuidance.ts';
import type { ToolRequirementHint } from '../toolAcquisitionProtocol.ts';
import { DiscoveredToolSources } from './DiscoveredToolSources.tsx';
import { foundToolRoles, TOOL_DISCOVERY_HELP } from '../toolSourceDiscovery.ts';
import { PreparedToolSourceFolders } from './PreparedToolSourceFolders.tsx';
import { hasIncompleteSdk, MANUAL_ANDROID_SDK_STEPS, toolComponentLabel } from '../toolAcquisitionComponents.ts';

export interface PrepareBuildEnvironmentProps {
  state: ToolAcquisitionState;
  controller: ToolAcquisitionController;
  compact?: boolean;
  // Only the existing native picker/catalogue/registration UI. No cache path
  // becomes a SourceSnapshot, and no callback approves a protected copy.
  toolsBusy: boolean;
  chooseSource(role: AndroidToolSourceRole): void | Promise<void>;
  choosePreparedSource(role: AndroidToolSourceRole): void | Promise<void>;
  refreshCatalog(): void | Promise<void>;
  openRegistration(): void;
}
const hint = (value: ToolRequirementHint) => value.state === 'literal' ? value.value :
  value.state === 'unspecified' ? 'Exact native profile required' : 'Could not be read safely';

/** Controlled view: mounting, navigation and checkbox rendering do no work. */
export function PrepareBuildEnvironment({ state, controller, compact = false, toolsBusy, chooseSource, choosePreparedSource,
  refreshCatalog, openRegistration }: PrepareBuildEnvironmentProps) {
  const op = state.status?.operation;
  const active = op && op.phase !== 'terminal';
  const attention = !!state.issue || op?.phase === 'unknown';
  const retained = attention || !!active || state.pending !== null || state.requestPending || state.cancelPending ||
    controller.ownerReason() !== null;
  if (compact && !retained) return null;
  const consent = state.consent;
  // Peer owners can change during a parent render without changing this
  // controller's projection. Recheck admission; these methods perform no IO.
  const checkReason = controller.checkReason(), reviewReason = controller.reviewReason(), downloadReason = controller.downloadReason();
  const title = attention ? 'Tool preparation needs attention' : state.pending === 'inspect' || active && op.context.action === 'inspect'
    ? 'Checking required tools' : op?.phase === 'stopping' || state.cancelPending ? 'Stopping tool preparation' :
      active && op.phase !== 'awaiting-consent' ? 'Preparing tool sources' : consent ? 'Review the tool download' : 'Prepare the Android build environment';
  const originalControls = <div className="button-row">
    <button type="button" className="button secondary" disabled={!state.canRead} onClick={() => void controller.checkStatus()}>
      {state.reading ? 'Checking status…' : 'Check original status'}</button>
    {state.canCancel && <button type="button" className="button secondary" onClick={() => void controller.cancel()}>Cancel tool preparation</button>}
    {state.cancelSent && active && <span className="save-note">Cancellation requested. Waiting for the original operation to finish.</span>}
  </div>;
  const problem = attention ? 'Completion is unconfirmed. Keep the existing files and use the original status or cancel control. Do not repeat the download.' :
    op?.phase === 'terminal' && op.outcome !== 'complete' ?
      op.outcome === 'cancelled' ? 'Tool preparation was cancelled. Nothing has been registered.' :
        op.reason === 'context-changed' || op.reason === 'stale-intent' || op.reason === 'intent-expired'
          ? 'The saved project or this review changed. Check the current tools again; the old approval cannot be reused.' :
          toolAcquisitionFailureGuidance(op.reason).body : null;
  if (compact) return <section className={`notice ${attention ? 'notice-warning' : 'notice-info'}`} aria-label="Original tool preparation">
    <div><strong>{title}</strong>{problem && <p role="status">{problem}</p>}
      {state.historical && <p>This request belongs to an earlier project or review. Its original status and cancel control are kept here.</p>}
      {originalControls}</div>
  </section>;

  const requirements = state.inspection?.requirements.android;
  const reuseSelected = state.inspection?.protectedTools === 'reuse-selected';
  const parts = state.inspection?.components;
  const foundExisting = foundToolRoles(state.inspection?.discoveredSources).length > 0;
  const chosenComplete = !reuseSelected && !foundExisting && !!parts && parts.missing.length === 0;
  const report = op?.result?.kind === 'staged-tool-sources' ? op.result : null;
  const staged = report && stagedToolSourceGuidance(report, state.presentation);
  const busy = toolsBusy || retained;
  return <section className="card" aria-label="Prepare Android build environment" aria-busy={state.pending !== null || state.requestPending}>
    <div className="section-heading"><div><h2>{title}</h2><p>Reuse compatible tools first. Downloads are optional and always need your approval.</p></div></div>
    {problem && <p className="notice notice-warning" role="status">{problem}</p>}
    {!state.preparedFolders && !consent && !active && (!report || state.historical || state.presentation === 'stale') && <>
      <div className="button-row">
        <button type="button" className="button primary" disabled={checkReason !== null} onClick={() => void controller.inspect()}>
          {state.pending === 'inspect' ? 'Checking required tools…' : 'Check required tools'}</button>
        <button type="button" className="button secondary" onClick={openRegistration}>Use existing tools</button>
      </div>
      {checkReason && <p className="save-note">{checkReason}</p>}
    </>}
    {requirements && !report && <>
      <h3>{foundExisting ? 'Found existing tools' : reuseSelected || chosenComplete ? 'No tool download needed' : 'Required tool sources'}</h3>
      {foundExisting && !state.preparedFolders && <p>Matching components were found at a conventional location. Choose the existing folders below and check the remaining tools. The native picker is still required; no duplicate download or automatic selection is allowed.</p>}
      {reuseSelected && <p role="status">Your selected protected JDK, Android platform, build tools and Gradle match this project’s saved requirements. Keep using them unchanged. This check downloaded and installed nothing; builds still run their own checks.</p>}
      {chosenComplete && <p role="status">Your chosen JDK, Android SDK packages and Gradle match the supported profile. Nothing was downloaded. Inspect the selected tools next, then review and approve any protected copy.</p>}
      {!reuseSelected && parts && <dl className="environment-baseline">
        <dt>Keep unchanged</dt><dd>{parts.compatible.map(toolComponentLabel).join(', ') || 'No matching chosen sources'}</dd>
        <dt>Download only</dt><dd>{parts.missing.map(toolComponentLabel).join(', ') || 'Nothing'}</dd>
      </dl>}
      {!reuseSelected && parts && !foundExisting && hasIncompleteSdk(parts) && <p className="save-note">Only one SDK package is missing. The app will copy your checked matching package into a separate prepared SDK, then add only the missing package. Your existing SDK and other packages stay unchanged. You still inspect and approve the complete prepared folder.</p>}
      <p>The saved project’s source hints were checked without running its build scripts. This is not a build-readiness check.</p>
      <dl className="environment-baseline"><dt>Java JDK</dt><dd>{hint(requirements.jdk)}</dd>
        <dt>Android platform</dt><dd>{hint(requirements.sdkPlatform)}</dd>
        <dt>Android build tools</dt><dd>{hint(requirements.sdkBuildTools)}</dd>
        <dt>Gradle</dt><dd>{requirements.gradle.version ?? 'Could not be read safely'}</dd></dl>
      {!consent && !active && <>
        {chosenComplete && <button type="button" className="button primary" disabled={toolsBusy} onClick={openRegistration}>Inspect selected tools</button>}
        {!reuseSelected && !chosenComplete && <>
          <p>Already have these tools elsewhere? Choose them instead. This check covers the supported protected catalogue, your chosen folders and three fixed Mac locations, not every folder on this computer.</p>
          <button type="button" className="button primary" disabled={reviewReason !== null} onClick={() => void controller.reviewDownload()}>Review download</button>
          {reviewReason && <p className="save-note">{reviewReason}</p>}
        </>}
      </>}
    </>}
    {consent && <div className="notice notice-info"><div>
      <p>The app will reuse its checked cache first, then download only required pinned public sources. It will verify the archives and stage folders, copying a checked matching SDK package when needed to prepare a complete SDK. It will not register tools or replace existing installations.</p>
      <label><input type="checkbox" checked={consent.acknowledged} disabled={state.pending !== null || state.requestPending || state.cancelPending}
        onChange={(event) => controller.setAcknowledged(consent.operationId, consent.ownerGeneration, event.target.checked)} />{' '}
        I approve preparing these tools. I will inspect the prepared tools and separately approve any protected copy.</label>
      <div className="button-row"><button type="button" className="button primary" disabled={downloadReason !== null}
        onClick={() => void controller.download(consent.operationId, consent.ownerGeneration)}>Download required tools</button></div>
      {downloadReason && <p className="save-note">{downloadReason}</p>}
    </div></div>}
    {state.preparedFolders ? state.preparedFolders.existing ? <DiscoveredToolSources folders={state.preparedFolders} busy={busy}
      checkReason={checkReason} chooseFound={choosePreparedSource} chooseExisting={chooseSource} checkAgain={() => controller.inspect()} /> :
      <PreparedToolSourceFolders folders={state.preparedFolders} busy={busy}
      choosePrepared={choosePreparedSource} chooseExisting={chooseSource} openRegistration={openRegistration} /> :
      staged && <div className="notice notice-info" role="status"><div><strong>{staged.title}</strong><p>{staged.body}</p></div></div>}
    {originalControls}
    <details><summary>Existing tools &amp; manual setup</summary>
      <p>Keep your working JDK, Android SDK and Gradle installation. Choose the folders you already have, then use Check existing protected tools and Check required tools again. Refresh the saved project if requested. Inspect and approve the protected copy in Set up build tools below.</p>
      <div className="button-row"><button type="button" className="button secondary" disabled={busy} onClick={() => void refreshCatalog()}>Check existing protected tools</button>
        {(['jdk', 'sdk', 'gradle'] as const).map((role) => <button type="button" className="button secondary" key={role} disabled={busy}
          onClick={() => void chooseSource(role)}>Choose {role === 'jdk' ? 'JDK' : role === 'sdk' ? 'Android SDK' : 'Gradle'}</button>)}
        <button type="button" className="button secondary" onClick={openRegistration}>Open tool inspection &amp; approval</button></div>
      <p>For manual preparation, use the exact supported releases shown in the existing tool review. Do not upgrade a compatible installation, change global Java settings or run a project wrapper just to discover its version.</p>
      <p>A current, verified protected tool selection is reused without a download. A saved catalogue entry may need the existing Recover and Choose steps first. Downloads require a supported, separately enabled Mac build and a complete check of the supported catalogue and chosen folders. Only confirmed missing pieces are downloaded; present but incompatible or unreadable tools need manual review. Incompatible or dynamic requirements and unfinished operations use the manual route. Do not delete selections or working tools to bypass these checks.</p>
      <p>{TOOL_DISCOVERY_HELP}</p>
      <h3>Complete an Android SDK manually</h3>
      <ol>{MANUAL_ANDROID_SDK_STEPS.map((step) => <li key={step}>{step}</li>)}</ol>
      <p>The supported downloaded SDK contains API 35 revision 2 and Build-Tools 35.0.0 only. NDK, CMake, emulator, platform-tools and other versions are not installed by this action. A complete prepared SDK contains both required packages, reusing your checked package when only one was missing. If that source changes or cannot be copied safely, review the operation and use manual setup; no license acceptance is automated.</p>
      <p>Literal source hints are not Gradle’s resolved configuration. The native operation rechecks exact project sources and its pinned tool profile before any download. iOS/Xcode setup remains a separate check.</p>
      {report && <p>Staging folder identifier: <code>{report.cacheJob}</code>. A folder name is not an installation or completion receipt.</p>}
    </details>
  </section>;
}
