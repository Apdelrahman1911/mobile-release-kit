// Three-way transport absence remains absence, never a preview or HTTP fallback.
import { encodeRepositoryCreateRequest, REPOSITORY_CREATE_EVENT } from './githubRepositoryCreateProtocol.ts';
import type { RepositoryCreateCommand, RepositoryCreatePort } from './githubRepositoryCreateProtocol.ts';
export function createRepositoryCreatePort(mode: string,
  invoke: (command: RepositoryCreateCommand, raw: Uint8Array) => Promise<unknown>,
  listen: ((event: typeof REPOSITORY_CREATE_EVENT, callback: (value: unknown) => void) => Promise<() => void>) | null,
): RepositoryCreatePort | null {
  if (mode !== 'native' || !listen) return null;
  const call = (command: RepositoryCreateCommand, value: unknown): Promise<unknown> => {
    const raw = encodeRepositoryCreateRequest(command, value);
    if (!raw) throw { code: 'github_repository_create_refused_invalid_input', retryable: false };
    return invoke(command, raw);
  };
  return Object.freeze({ mode: 'native' as const,
    status: () => call('github_repository_create_status', {}),
    prepare: (a) => call('github_repository_create_prepare', a), create: (a) => call('github_repository_create_create', a),
    pending: (a) => call('github_repository_create_pending', a), reconcile: (a) => call('github_repository_create_reconcile', a),
    discard: (a) => call('github_repository_create_discard', a), cancel: (a) => call('github_repository_create_cancel', a),
    subscribe: (f) => listen(REPOSITORY_CREATE_EVENT, f),
  } satisfies RepositoryCreatePort);
}
