// Exactly four fixed RAW commands and one status event. No preview, URL,
// filesystem path, command runner, installed-tool flag or capability fallback.
import { encodeToolAcquisitionRequest, TOOL_ACQUISITION_EVENT } from './toolAcquisitionProtocol.ts';
import type { ToolAcquisitionCommand, ToolAcquisitionContext, ToolAcquisitionIdentity, ToolAcquisitionStart } from './toolAcquisitionProtocol.ts';

export interface ToolAcquisitionApi {
  readonly mode: 'native';
  prepare(request: ToolAcquisitionContext): Promise<unknown>;
  start(request: ToolAcquisitionStart): Promise<unknown>;
  status(): Promise<unknown>;
  cancel(request: ToolAcquisitionIdentity): Promise<unknown>;
  subscribe(listener: (value: unknown) => void): Promise<() => void>;
}
type Invoke = (command: ToolAcquisitionCommand, body: Uint8Array) => Promise<unknown>;
type Listen = (event: typeof TOOL_ACQUISITION_EVENT, listener: (value: unknown) => void) => Promise<() => void>;

export function createToolAcquisitionApi(mode: string, invoke: Invoke, listen?: Listen): ToolAcquisitionApi | null {
  if (mode !== 'native' || !listen) return null;
  const call = (command: ToolAcquisitionCommand, input: unknown): Promise<unknown> => {
    const raw = encodeToolAcquisitionRequest(command, input);
    if (!raw) throw { code: 'ToolAcquisitionRequestInvalid', message: 'The tool request is invalid. Nothing was sent.', retryable: false };
    return invoke(command, raw);
  };
  return Object.freeze({ mode: 'native' as const,
    prepare: (input: ToolAcquisitionContext) => call('prepare_tool_acquisition', input),
    start: (input: ToolAcquisitionStart) => call('start_tool_acquisition', input),
    status: () => call('tool_acquisition_status', {}),
    cancel: (input: ToolAcquisitionIdentity) => call('cancel_tool_acquisition', input),
    subscribe: (listener: (value: unknown) => void) => listen(TOOL_ACQUISITION_EVENT, listener) });
}
