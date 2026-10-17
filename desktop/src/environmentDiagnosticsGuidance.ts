import type { EnvironmentSelectionDiagnostic } from './environmentDiagnosticsTypes.ts';

// Presentation of an already-admitted observation only. No paths from tool
// output, permission changes, tool selection or new checks originate here.
export function selectionDiagnosticGuidance(detail: EnvironmentSelectionDiagnostic): { location: string; problem: string; nextStep: string } {
  const locations: Record<EnvironmentSelectionDiagnostic['stage'], string> = {
    'selector-output': 'macOS developer selection', 'selection-path': 'selected developer location',
    root: 'system root', applications: 'Applications folder', application: 'selected Xcode app',
    contents: 'Xcode Contents folder', developer: 'Xcode Developer folder', library: 'system Library folder',
    'library-developer': 'system developer-tools folder', 'command-line-tools': 'Command Line Tools folder',
    alias: 'Xcode selection link',
  };
  const location = locations[detail.stage];
  const protectedSetup = 'Review Xcode prerequisites. If your release includes Prepare Xcode.pkg, use that companion after completing Apple Xcode setup to create the separate protected tool copy. Do not change system-folder permissions or run the app as administrator to bypass a refusal.';
  switch (detail.reason) {
    case 'directory-owner': case 'alias-owner':
      return { location, problem: 'The selected tool location does not meet the required ownership rules.', nextStep: protectedSetup };
    case 'directory-group-write': case 'directory-world-write':
      return { location, problem: 'Other accounts can change this part of the selected tool installation.', nextStep: protectedSetup };
    case 'namespace-missing':
      return { location, problem: 'A required part of the selected tool installation is missing.', nextStep: 'Install full Xcode from Apple and finish its normal first-launch setup. In Xcode Settings → Locations, review the selected Command Line Tools. Then check the supported layout in Xcode prerequisites.' };
    case 'namespace-inaccessible':
      return { location, problem: 'The app could not inspect this part of the selected tool installation.', nextStep: 'Check that the installation is available and review Xcode prerequisites. This observation does not prove that Xcode is absent; do not loosen permissions to force the check to pass.' };
    case 'project-overlap':
      return { location, problem: 'The selected developer tools overlap the mobile project folder.', nextStep: 'Use a project folder separate from the Xcode/tool installation. Selecting a project must not give its files authority to act as system tools.' };
    case 'identity-changed':
      return { location, problem: 'The Xcode selection changed while it was being checked.', nextStep: 'Let any Xcode installation or update finish. After this check has settled, run Check build tools again; this app will not adopt a replacement during an active operation.' };
    case 'stderr-present': case 'byte-shape': case 'line-shape': case 'utf8-invalid':
      return { location, problem: 'macOS returned a developer selection that the app could not interpret safely.', nextStep: 'Open Xcode and complete first-launch setup, then review Settings → Locations. Review Xcode prerequisites if the next settled check still cannot read the selection.' };
    default:
      return { location, problem: 'The selected developer location or Xcode link is outside the supported layout.', nextStep: 'Review Xcode prerequisites and the selection in Xcode Settings → Locations. A custom path or link does not override the app’s protected-tool checks.' };
  }
}
