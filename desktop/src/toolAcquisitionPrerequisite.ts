// Closed diagnostics from Document Prepare BEFORE native owner admission.
// A code alone never releases a request: the controller still waits for its
// original rejected Promise and an unchanged, fresh original status read.
export type ToolAcquisitionPrerequisite = 'catalogue' | 'saved-inputs';

export function toolAcquisitionPrerequisite(error: unknown): ToolAcquisitionPrerequisite | null {
  try {
    if (!error || typeof error !== 'object' || Array.isArray(error)) return null;
    const code = Object.getOwnPropertyDescriptor(error, 'code');
    if (!code || !Object.hasOwn(code, 'value')) return null;
    if (code.value === 'tool_acquisition_catalog_required') return 'catalogue';
    if (code.value === 'tool_acquisition_saved_inputs_required') return 'saved-inputs';
  } catch { /* An accessor, foreign error or lost response is not this hint. */ }
  return null;
}

export const TOOL_ACQUISITION_PREREQUISITE_TEXT: Readonly<Record<ToolAcquisitionPrerequisite, string>> = Object.freeze({
  catalogue: 'Check the protected tool catalogue after choosing folders. If it contains tools, use Recover and Choose for the matching installation. Then check required tools again. No tool preparation was started.',
  'saved-inputs': 'Read the saved project inputs after choosing tools, then check required tools again. Your folder choices are kept. No tool preparation was started.',
});
