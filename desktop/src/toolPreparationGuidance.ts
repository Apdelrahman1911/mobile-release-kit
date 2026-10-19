// Presentation only. A guidance row is never a native tool lease, fresh probe,
// installation request or permission to continue another original operation.
import type { EnvironmentDiagnosticsState } from './environmentDiagnosticsController.ts';
import type { ToolPreparationPlan } from './toolPreparationTypes.ts';

export interface ToolPreparationGuidance { title: string; body: string; nextLabel: string | null; steps: string[] }

export function xcodePreparationSteps(pin: { version: string; build: string } | null): string[] {
  const expected = pin ? `Xcode ${pin.version}, build ${pin.build}` : 'the exact Xcode version and build shown in the current project requirements';
  return [
    `Look for an existing full ${expected} first. If it is genuinely missing, obtain that exact Apple release from Apple Developer Downloads (https://developer.apple.com/download/all/), not an automatic update to the newest Xcode. Command Line Tools alone are not enough.`,
    'Open the original Xcode and complete Apple’s first-launch setup, review and accept its license yourself, and install the iOS platform support your project needs. Keep the original installation; do not change global xcode-select settings to bypass the app’s checks.',
    'For a protected copy, finish other builds and quit Mobile Release Kit. Use only the signed Prepare Xcode.pkg companion verified for this app release and macOS version. Allow space for a second full logical Xcode copy plus the installer’s reserve, and review the administrator prompt yourself.',
    'On macOS 27, an older companion restricted to macOS 26 will not work. A working main app is not companion or iOS-build verification. If the matching verified companion is not available, request it; do not use an older installer or remover as a workaround.',
    'If preparation is interrupted or refused, preserve the original Xcode, protected copy and installer message. Reconcile the existing operation first; do not delete its files, relax permissions or repeat with a different package. Never run the app as root.',
    'Reopen the app and check again. Installer success or a matching version does not prove SDK, signing, archive or upload readiness; the normal native checks still apply.',
  ];
}

function androidPreparationSteps(plan: ToolPreparationPlan): string[] {
  const policy = plan.policy;
  const pinned = policy ? `${policy.jdkVendor} ${policy.jdk}, Gradle ${policy.gradle}, AGP ${policy.agp}, ${policy.sdkPlatform} and build-tools ${policy.sdkBuildTools}` : 'the exact JDK, Gradle, AGP and SDK profile shown by the current protected-tool policy';
  return [
    `Check registered tools first, then look for existing installations of ${pinned}. A missing selection is not proof that anything needs to be downloaded. Do not upgrade a compatible installation.`,
    'Use the existing Choose JDK, Choose Android SDK and Choose Gradle controls to pick local source folders. The picker and version labels alone do not verify their complete contents. Run Inspect selected tools and review every source before preparing a protected copy.',
    'If a required component is genuinely absent, obtain only the exact supported vendor release. Review any vendor license yourself. Do not execute a project’s Gradle wrapper to download it, accept an unverified URL or checksum, or use a Java workflow example as the protected-tool policy.',
    'Keep all existing installations and completed protected copies. Check the setup service, then use the existing explicit review and approval controls. If interrupted, read the original status and re-check what already exists before any new preparation.',
    'A reusable protected copy still needs the ordinary native checks when a build or signing operation starts. This check does not authorize that operation.',
  ];
}

export function toolPreparationGuidance(plan: ToolPreparationPlan): ToolPreparationGuidance {
  const steps = plan.platform === 'ios' ? xcodePreparationSteps(plan.xcode) : androidPreparationSteps(plan);
  const make = (title: string, body: string, nextLabel: string | null): ToolPreparationGuidance => ({ title, body, nextLabel, steps });
  switch (plan.action) {
    case 'use-selected-copy': return make('Use the tools you already have', 'The selected protected copy matches the current static requirements and supported profile. No download or upgrade is needed for this plan. The build will check those tools again.', 'Continue to build');
    case 'choose-registered-copy': return make('A matching protected copy already exists', 'Choose an existing copy rather than installing another. Selection is not build or signing authorization.', 'Choose existing tools');
    case 'refresh-registered-tools': return make('Check registered tools first', 'Refresh the protected-tool list before choosing source folders or considering a download.', 'Check registered tools');
    case 'choose-jdk': case 'choose-sdk': case 'choose-gradle': {
      const name = { 'choose-jdk': 'JDK', 'choose-sdk': 'Android SDK', 'choose-gradle': 'Gradle' }[plan.action];
      return make(`Choose an existing ${name}`, `No ${name} source is selected yet. Look for an existing matching installation first; this is not evidence that it is missing from your computer.`, `Choose ${name}`);
    }
    case 'inspect-sources': return make('Check the selected source folders', 'The folders have not yet passed a complete current inspection. Inspect them before approving a protected copy.', 'Inspect selected tools');
    case 'review-protected-copy': return make('Review the protected copy', 'The source review is complete. Review the exact copy and space requirements, then approve it in the existing tool-setup controls. Nothing has been installed by this check.', 'Review tool setup');
    case 'review-source-problem': return make('A selected tool needs attention', 'Read the specific inspection problem. Keep your existing installation; do not replace it or loosen permissions just to make a version check pass.', 'Review inspection');
    case 'check-tool-service': return make('Check the tool-setup service', 'The sources are inspected, but the original native setup service needs a current check before a protected copy can be prepared.', 'Review setup service');
    case 'register-tool-service': case 'open-tool-service-settings': return make('Tool setup needs your approval', 'Open the existing service controls and review the macOS approval yourself. A registration request is not proof that the service is enabled.', 'Review setup service');
    case 'reconcile-setup': return make('Finish checking the previous setup', 'An original operation or retained copy is unresolved. Keep the app and existing files. Read its status or use its recovery controls; do not install again.', 'Review previous setup');
    case 'wait-for-setup': return make('A tool operation is still running', 'Wait for the original operation, or use its existing cancel and status controls. Refreshing this plan cannot finish or replace it.', null);
    case 'check-xcode': return make('Check the Xcode you already have', `Use the local version check to compare both Xcode ${plan.xcode.version} and build ${plan.xcode.build}. Nothing is downloaded or licensed by the check.`, 'Check this computer');
    case 'inspect-xcode-copy': return make('Xcode’s version matches; more checks remain', 'The version check is not protected-copy, SDK, license, signing or archive verification. Review the supported layout and use the ordinary native build checks.', 'Review Xcode checks');
    case 'install-xcode-manually': return make('Review the required Xcode installation', `The supported lookup did not establish Xcode ${plan.xcode.version}, build ${plan.xcode.build}. Reuse that exact Apple release if it is already present; otherwise follow the manual steps.`, 'Review Xcode setup');
    case 'unsupported-host': return make('This tool setup is not available here', 'The native runtime or host profile is not qualified for this operation. Manual installation cannot override the host gate. Keep existing tools and use a supported app release and host.', null);
    default: return make('Review this project’s tool requirements', plan.reason === 'policy-mismatch'
      ? 'The source requirements do not match the app’s protected-tool profile. Do not change a project pin, downgrade it or update working tools automatically. Review the supported profile and use the project’s established manual build path if necessary.'
      : 'The saved source snapshot is incomplete, dynamic or unverified. Check the actual application module and literal tool requirements; no effective Gradle model or compatible installation has been inferred.', 'Review project requirements');
  }
}

// This adapter is already wired into the real Environment page. It consumes the
// existing retained diagnostics controller, not capability/catalogue fixtures.
// It never advertises "ready", even when a finite version check matches.
export function diagnosticToolGuidance(state: EnvironmentDiagnosticsState): ToolPreparationGuidance {
  const make = (title: string, body: string, nextLabel: string | null, steps: string[] = []): ToolPreparationGuidance => ({ title, body, nextLabel, steps });
  if (state.mode !== 'native') return make('Check tools in the desktop app', 'This view cannot inspect your computer. Example requirements are not installed-tool observations.', null);
  const observation = state.observation, projection = observation?.projection;
  const original = state.status?.active ?? state.attempt?.projection;
  if (state.nativeBlocked || state.integrityFailed || state.generationLost || state.unknownEvidence || original?.finality === 'unknown' || projection?.finality === 'unknown')
    return make('The previous tool check needs attention', 'Keep the app open and preserve the existing tools. Original native completion is unverified. Use the status and recovery controls below; do not install or start another check.', 'Read native status');
  if (state.status?.active || state.attempt && !state.attempt.projection || original?.finality === 'pending')
    return make('Checking this computer', 'The original check has not finished. Wait, or use its existing cancel and status controls. A returned version alone does not mean native work has settled.', 'Read native status');
  if (state.observationIssue || !state.initialized || !state.listening)
    return make('Reconnect to the current tool status', 'Read the original native status first. Earlier rows cannot be used to decide that an installation is missing or ready.', 'Read native status');
  if (!state.project?.hasDraft || state.selectionPending)
    return make('Select and configure your project first', 'The check needs the current project and its requirements. No installation has been inferred.', null);
  if (state.operation !== 'build') return make('Tool checks are for building', 'Choose the build task above to check local tools. Artifact validation has its own separate requirements.', null);
  if (!observation || observation.stale)
    return make('Start with the tools already on this computer', 'Check local tool versions first. This does not install, upgrade or replace anything, and a missing supported lookup is not a complete search of your computer.', 'Check this computer');
  const context = projection!.context, result = projection!.result, terminal = state.status?.lastTerminal;
  const current = state.project.projectId === context.projectId && state.project.draftRevision === context.draftRevision &&
    state.project.baselineGeneration === context.baselineGeneration && state.platform === context.platform && context.operation === 'build' &&
    terminal?.runId === projection!.runId && terminal.ownerGeneration === projection!.ownerGeneration &&
    state.status!.statusRevision >= observation.statusRevision;
  if (!current || projection!.phase !== 'settled' || projection!.finality !== 'settled' || projection!.reason !== 'none' ||
      !['complete', 'partial'].includes(projection!.outcome ?? '') || !result || result.context.projectId !== context.projectId ||
      result.context.draftRevision !== context.draftRevision || result.context.baselineGeneration !== context.baselineGeneration ||
      result.context.platform !== context.platform || !result.lifetime.complete || result.lifetime.fatal || !result.lifetime.contained ||
      !result.lifetime.inputClosed || !result.lifetime.handlersRestored || !result.lifetime.toolDescriptorsClosed || result.lifetime.stopObserved !== 'none')
    return make('A current tool result is still needed', 'The earlier check is incomplete or belongs to a different context. Review its status before drawing conclusions about installed tools.', 'Read native status');
  if (state.platform === 'ios') {
    const xcode = result.checks.find((check) => check.id === 'xcode');
    const pin = xcode?.baseline.kind === 'exact-pin' && xcode.baseline.version && xcode.baseline.build ? { version: xcode.baseline.version, build: xcode.baseline.build } : null;
    if (xcode?.state === 'completed' && xcode.reason === 'observed' && xcode.returnCode === 0 && pin && xcode.version === pin.version && xcode.build === pin.build)
      return make('Xcode’s version matches; more checks remain', `Observed Xcode ${pin.version}, build ${pin.build}. This does not verify its protected copy, iOS SDK, license, signing, archive or upload.`, 'Review Xcode setup', xcodePreparationSteps(pin));
    return make('Review your Xcode installation', pin ? `The check did not establish Xcode ${pin.version}, build ${pin.build}, in the supported layout. Look for that existing full installation before downloading anything.` : 'The check did not establish the current exact Xcode requirement. Review the current requirements and supported layout before changing your installation.', 'Review Xcode setup', xcodePreparationSteps(pin));
  }
  return make('Review the Android tools you already have', 'These are finite Git and Java version observations, not verification of the project’s JDK, Gradle or SDK. Check the registered protected tools next. A Java workflow reference is not the protected-tool policy, and a version match is not build or signing readiness.', 'Check registered tools');
}
