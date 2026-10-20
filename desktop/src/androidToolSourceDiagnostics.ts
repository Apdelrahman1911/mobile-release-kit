// Fixed explanations for an ORIGINAL joined inspection refusal. These messages
// never classify a tool as missing/compatible or approve a retry or installation.
import type { AndroidToolRegistrationProblem } from './androidToolRegistration.ts';

export type SourceInspectionProblem = Extract<AndroidToolRegistrationProblem,
  'jdk-source' | 'sdk-source' | 'gradle-source' | 'app-support-source'>;

export const sourceInspectionProblemText: Record<SourceInspectionProblem, string> = {
  'jdk-source': 'The source check stopped at the selected JDK.',
  'sdk-source': 'The source check stopped at the selected Android SDK.',
  'gradle-source': 'The source check stopped at the selected Gradle distribution.',
  'app-support-source': 'The source check stopped at the support tools supplied by this app.',
};

const continuation: Record<SourceInspectionProblem, string> = {
  'jdk-source': 'Keep your other tool folders. Check that this is the complete supported JDK .jdk bundle or its Contents/Home folder, not a different Java runtime. Use Browse for a different JDK only if needed, then Inspect selected sources again when the original status permits it. Do not change global Java settings or loosen permissions.',
  'sdk-source': 'Keep your working SDK. Check that you chose the SDK root containing both the required Android platform and build-tools versions. If a required package is missing, use Android Studio’s SDK Manager to add that exact supported package without upgrading the others. Review its license yourself. Then choose the complete SDK folder and Inspect selected sources again when the original status permits it.',
  'gradle-source': 'Keep your other tool folders. Choose a complete extracted Gradle distribution containing bin/gradle and lib, matching the project’s reviewed version; do not choose its ZIP or the project folder. Then Inspect selected sources again when the original status permits it. Do not run a project wrapper to discover or replace Gradle.',
  'app-support-source': 'Do not replace your JDK, SDK or Gradle to fix this app-support check. Use the matching signed app release or report this tool-setup error. Do not copy files from a Gradle cache into the app or loosen permissions. The app’s own support tools need their separate original verification.',
};

export function sourceInspectionContinuation(problem: AndroidToolRegistrationProblem, sameCurrentInspection: boolean): string | null {
  // This is only a display veto. The existing controller/native owners retain
  // every Browse, Inspect, protected-copy and build admission separately.
  if (!sameCurrentInspection || !Object.hasOwn(continuation, problem)) return null;
  return continuation[problem as SourceInspectionProblem];
}
