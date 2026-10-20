// Four fixed RAW commands. The parent supplies its existing window-scoped
// invoke/listener; no preview, HTTP, credential or native-state fallback.
import { APPLE_PROVISIONING_EVENT, encodeAppleProvisioningRequest } from './appleProvisioningProtocol.ts';
import type { AppleProvisioningCommand } from './appleProvisioningProtocol.ts';
import type { AppleProvisioningIdentity, PrepareAppleProvisioning, StartAppleProvisioning } from './appleProvisioningTypes.ts';

export interface AppleProvisioningApi {
  readonly mode: 'native';
  prepare(request: PrepareAppleProvisioning): Promise<unknown>;
  start(request: StartAppleProvisioning): Promise<unknown>;
  status(): Promise<unknown>;
  cancel(request: AppleProvisioningIdentity): Promise<unknown>;
  subscribe(listener: (status: unknown) => void): Promise<() => void>;
}
type Invoke = (command: AppleProvisioningCommand, body: Uint8Array) => Promise<unknown>;
type Listen = (event: typeof APPLE_PROVISIONING_EVENT, listener: (status: unknown) => void) => Promise<() => void>;
export function createAppleProvisioningApi(mode: string, invoke: Invoke, listen?: Listen): AppleProvisioningApi | null {
  if (mode !== 'native' || !listen) return null;
  const call = (command: AppleProvisioningCommand, value: unknown): Promise<unknown> => {
    const bytes = encodeAppleProvisioningRequest(command, value);
    if (!bytes) throw { code: 'apple_provisioning_invalid', message: 'The Apple setup request is invalid. Nothing was sent.', retryable: false };
    return invoke(command, bytes);
  };
  return Object.freeze({ mode: 'native' as const,
    prepare: (value: PrepareAppleProvisioning) => call('prepare_apple_provisioning', value),
    start: (value: StartAppleProvisioning) => call('start_apple_provisioning', value),
    status: () => call('apple_provisioning_status', {}),
    cancel: (value: AppleProvisioningIdentity) => call('cancel_apple_provisioning', value),
    subscribe: (listener: (status: unknown) => void) => listen(APPLE_PROVISIONING_EVENT, listener) });
}
