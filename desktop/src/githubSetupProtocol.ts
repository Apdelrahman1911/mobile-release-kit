// Closed, bounded transport admission, not configuration, credential or workflow
// policy. Never render templates, resolve refs, hash files or grant Apply here.
import type { ApiError, GitHubSetupHelp, GitHubSetupRequest, GitHubSetupResult, GitHubSuppliedSnapshot } from './types.ts';
import { ENVIRONMENTS, assurance, boundedJson, keys, oneOf, record, requirement, text } from './requirementProtocol.ts';

const encoder = new TextEncoder();

export const GITHUB_WORKFLOWS = [
  { id: 'preflight', path: '.github/workflows/mobile-preflight.yml' },
  { id: 'candidate', path: '.github/workflows/mobile-candidate.yml' },
  { id: 'external-testing', path: '.github/workflows/mobile-external-testing.yml' },
  { id: 'production-submit', path: '.github/workflows/mobile-production-submit.yml' },
] as const;
const GUIDANCE_IDS = ['source-authority', 'protected-environments', 'runner-policy', 'credentials', 'preflight-and-releases', 'scope'] as const;
const INPUT_IDS = ['toolingRepository', 'toolingSha', 'suppliedSnapshot'] as const;
const HELP_FIELDS = ['label', 'what', 'why', 'where', 'format', 'failure'] as const;
const LOWER_SHA256 = /^[0-9a-f]{64}$/;
// Only the returned wire coordinate is checked against the agreed grammar.
// User-input pin policy remains in the core; no local "valid pin" is produced.
const WIRE_REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9](?:[A-Za-z0-9._-]{0,98}[A-Za-z0-9])?$/;

function integer(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max;
}

function digest(value: unknown): value is string { return typeof value === 'string' && value.length === 64 && LOWER_SHA256.test(value); }

function snapshot(value: unknown): value is GitHubSuppliedSnapshot | null {
  if (value === null) return true;
  if (!keys(value, ['workflows']) || !Array.isArray(value.workflows) || value.workflows.length > 4) return false;
  const ids = new Set<string>();
  return value.workflows.every((entry) => {
    if (!record(entry) || !oneOf(entry.id, GITHUB_WORKFLOWS.map((workflow) => workflow.id)) || ids.has(entry.id)) return false;
    ids.add(entry.id);
    return entry.state === 'absent' ? keys(entry, ['id', 'state']) :
      keys(entry, ['id', 'state', 'byteLength', 'sha256']) && entry.state === 'present' &&
      integer(entry.byteLength, 1048576) && digest(entry.sha256);
  });
}

export function githubSetupRequestFits(value: unknown): value is GitHubSetupRequest {
  try {
    return boundedJson(value, 1024 * 1024, 20_000, 32) &&
      keys(value, ['draft', 'toolingRepository', 'toolingSha', 'suppliedSnapshot']) && record(value.draft) &&
      boundedJson(value.draft, 512 * 1024, 8000, 28) &&
      // Transport size/Unicode only. The core rejects malformed coordinates or
      // non-full pins, without a second renderer policy or normalization.
      text(value.toolingRepository, 140, false) && text(value.toolingSha, 40, false) && snapshot(value.suppliedSnapshot);
  } catch { return false; }
}

function facts(value: unknown): boolean {
  return keys(value, ['githubContacted', 'repositoryObserved', 'toolingRefResolved', 'templateCompatibility', 'comparisonBasis', 'snapshotProvided', 'applyAvailable']) &&
    value.githubContacted === false && value.repositoryObserved === false && value.toolingRefResolved === false &&
    value.templateCompatibility === 'unknown' && value.comparisonBasis === 'caller-supplied-digest-summary' &&
    typeof value.snapshotProvided === 'boolean' && value.applyAvailable === false;
}

function validation(value: unknown, valid: boolean): boolean {
  if (!keys(value, ['valid', 'state', 'issues', 'requirements', 'assurance']) || value.valid !== valid ||
      value.state !== (valid ? 'format-valid' : 'invalid') || !assurance(value.assurance) ||
      !Array.isArray(value.issues) || !Array.isArray(value.requirements)) return false;
  if (!valid) {
    const issue: unknown = value.issues[0];
    return value.requirements.length === 0 && value.issues.length === 1 && keys(issue, ['code', 'status', 'message', 'remediation']) &&
      issue.code === 'config.invalid' && issue.status === 'INVALID' &&
      issue.message === 'Configuration does not satisfy the shared core format/policy rules; review the draft and contextual field guidance.' &&
      issue.remediation === 'Correct the input and validate again; no changes were saved.';
  }
  const identities = new Set<string>();
  return value.issues.length === 0 && value.requirements.length <= 128 && value.requirements.every((item) => {
    if (!requirement(item)) return false;
    const identity = JSON.stringify([item.name, item.stage, item.platform]);
    if (identities.has(identity)) return false;
    identities.add(identity);
    return true;
  });
}

function settings(value: unknown): boolean {
  if (!keys(value, ['configPath', 'sourcePolicy', 'environments', 'guidanceIds']) || value.configPath !== 'release/mobile-release.json' ||
      !keys(value.sourcePolicy, ['candidateBranch', 'productionBranch', 'basis']) || value.sourcePolicy.basis !== 'configured-policy' ||
      !text(value.sourcePolicy.candidateBranch, 1024) || !text(value.sourcePolicy.productionBranch, 1024) ||
      !Array.isArray(value.environments) || value.environments.length !== ENVIRONMENTS.length ||
      !Array.isArray(value.guidanceIds) || value.guidanceIds.length !== GUIDANCE_IDS.length) return false;
  return value.environments.every((entry, index) => keys(entry, ['stage', 'name']) &&
    entry.stage === ENVIRONMENTS[index]?.stage && entry.name === ENVIRONMENTS[index]?.name) &&
    value.guidanceIds.every((id, index) => id === GUIDANCE_IDS[index]);
}

export function parseGitHubSetupResult(value: unknown): GitHubSetupResult | null {
  try {
    if (!boundedJson(value, 262144, 8000, 16) || !record(value) || value.schemaVersion !== 1 ||
        !assurance(value.assurance) || !facts(value.facts)) return null;
    if (value.state === 'invalid') {
      return keys(value, ['schemaVersion', 'state', 'validation', 'facts', 'assurance']) && validation(value.validation, false)
        ? value as unknown as GitHubSetupResult : null;
    }
    if (!keys(value, ['schemaVersion', 'state', 'validation', 'facts', 'assurance', 'templateSet', 'tooling', 'workflows', 'settings']) ||
        value.state !== 'proposed' || !validation(value.validation, true) || !settings(value.settings)) return null;
    const template = value.templateSet;
    if (!keys(template, ['coreVersion', 'resourceVersion', 'resourceSha256']) || !text(template.coreVersion, 32, true, true) ||
        !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(template.coreVersion) || template.resourceVersion !== 1 || !digest(template.resourceSha256)) return null;
    const tooling = value.tooling;
    if (!keys(tooling, ['repository', 'sha', 'schemaReference', 'state']) || !text(tooling.repository, 140, true, true) ||
        !WIRE_REPOSITORY.test(tooling.repository) || !text(tooling.sha, 40) || !/^[0-9a-f]{40}$/.test(tooling.sha) ||
        tooling.state !== 'format-only' || !text(tooling.schemaReference, 512) ||
        tooling.schemaReference !== `https://raw.githubusercontent.com/${tooling.repository}/${tooling.sha}/schemas/project.schema.json`) return null;
    if (!Array.isArray(value.workflows) || value.workflows.length !== GITHUB_WORKFLOWS.length) return null;
    let contentBytes = 0;
    if (!value.workflows.every((workflow, index) => {
      if (!keys(workflow, ['id', 'path', 'content', 'byteLength', 'sha256', 'comparison']) ||
          workflow.id !== GITHUB_WORKFLOWS[index]?.id || workflow.path !== GITHUB_WORKFLOWS[index]?.path ||
          !text(workflow.content, 16384) || !integer(workflow.byteLength, 16384) ||
          encoder.encode(workflow.content).byteLength !== workflow.byteLength || !digest(workflow.sha256) ||
          !oneOf(workflow.comparison, ['not-supplied', 'reported-absent', 'supplied-digest-match', 'supplied-digest-differs'])) return false;
      contentBytes += workflow.byteLength;
      return contentBytes <= 65536;
    })) return null;
    const result = value as unknown as GitHubSetupResult;
    if (result.state === 'proposed' && !result.facts.snapshotProvided && result.workflows.some((workflow) => workflow.comparison !== 'not-supplied')) return null;
    return result;
  } catch { return null; }
}

// Correlation checks only: compare echoed inputs and caller-supplied assertions.
// A matching digest is not a computed/authenticated file digest or a no-op plan.
export function githubSetupResultMatches(result: GitHubSetupResult, request: GitHubSetupRequest): boolean {
  if (result.facts.snapshotProvided !== (request.suppliedSnapshot !== null)) return false;
  if (result.state === 'invalid') return true;
  if (result.tooling.repository !== request.toolingRepository || result.tooling.sha !== request.toolingSha.toLowerCase()) return false;
  const source = request.draft.source;
  if (!record(source) || result.settings.sourcePolicy.candidateBranch !== source.candidateBranch ||
      result.settings.sourcePolicy.productionBranch !== source.productionBranch) return false;
  return result.workflows.every((workflow) => {
    const supplied = request.suppliedSnapshot?.workflows.find((entry) => entry.id === workflow.id);
    const expected = !supplied ? 'not-supplied' : supplied.state === 'absent' ? 'reported-absent' :
      supplied.byteLength === workflow.byteLength && supplied.sha256 === workflow.sha256 ? 'supplied-digest-match' : 'supplied-digest-differs';
    return workflow.comparison === expected;
  });
}

export function parseGitHubSetupHelp(value: unknown): GitHubSetupHelp | null {
  try {
    if (!boundedJson(value, 128 * 1024, 8000, 16) || !keys(value, ['schemaVersion', 'inputs', 'guidance']) || value.schemaVersion !== 1 ||
        !Array.isArray(value.inputs) || value.inputs.length !== INPUT_IDS.length ||
        !Array.isArray(value.guidance) || value.guidance.length !== GUIDANCE_IDS.length) return null;
    const bodies = (item: Record<string, unknown>) => HELP_FIELDS.every((key) => text(item[key], key === 'label' ? 96 : 1024, true, true));
    return value.inputs.every((item, index) => keys(item, ['id', 'requiredness', ...HELP_FIELDS]) &&
      item.id === INPUT_IDS[index] && item.requiredness === (index === 2 ? 'optional' : 'required') && bodies(item)) &&
      value.guidance.every((item, index) => keys(item, ['id', ...HELP_FIELDS]) && item.id === GUIDANCE_IDS[index] && bodies(item))
      ? value as unknown as GitHubSetupHelp : null;
  } catch { return null; }
}

export function parseCatalogGitHubSetup(value: unknown): GitHubSetupHelp | null {
  try {
    // Admit only the original envelope and the four explicit combinations of
    // its two optional guides. Neither independent guide grants Setup authority.
    const envelope = ['schemaVersion', 'schema', 'fields', 'credentials', 'metadata', 'githubSetup', 'assurance'];
    return (keys(value, envelope) || keys(value, [...envelope, 'credentialGuide']) ||
      keys(value, [...envelope, 'githubConnection']) || keys(value, [...envelope, 'credentialGuide', 'githubConnection'])) && value.schemaVersion === 1
      ? parseGitHubSetupHelp(value.githubSetup) : null;
  } catch { return null; }
}

export function githubSetupError(error: unknown): ApiError {
  let code: unknown;
  try {
    if (record(error)) {
      const descriptor = Object.getOwnPropertyDescriptor(error, 'code');
      if (descriptor && Object.hasOwn(descriptor, 'value')) code = descriptor.value;
    }
  } catch { /* Never inspect or echo a raw exception. */ }
  const messages: Record<string, string> = {
    invalid_params: 'The setup request was rejected. Review the draft, toolkit inputs and supplied comparison; nothing was applied.',
    invalid_request: 'The setup request exceeds the supported shape or size. No proposal was generated.',
    resource_unavailable: 'The shipped GitHub setup resource is unavailable or invalid. Restore the packaged core service; no proposal was generated.',
    proposal_output_limit: 'The complete proposal exceeds the supported output limit. No partial workflow preview was accepted.',
    PreviewOnly: 'Browser preview has no core workflow proposal service. No workflows were generated or applied.',
    NativeBridgeRequired: 'Open the installed desktop application. No native proposal service or browser fallback is available.',
    runtime_unavailable: 'The packaged core service is unavailable. Restore it and reload guidance before requesting a proposal.',
    shutting_down: 'The application is stopping its owned queries. No setup proposal was confirmed.',
    query_timeout: 'The passive setup query exceeded its deadline. No proposal was accepted.',
    cleanup_unknown: 'Original query cleanup is unconfirmed. Further native queries remain disabled; no setup was applied.',
    protocol_error: 'The core returned an invalid or incomplete response. No setup proposal was accepted.',
    GitHubSetupResponseInvalid: 'The service returned an inconsistent or unsupported setup response. No proposal was accepted.',
    GitHubSetupHelpUnavailable: 'Core GitHub setup guidance could not be admitted. Restore the packaged service; no substitute guidance is generated.',
  };
  if (typeof code === 'string' && Object.hasOwn(messages, code)) return { code, message: messages[code]!, retryable: false };
  return { code: 'GitHubSetupUnavailable', message: 'The desktop service did not return a usable setup response. No proposal, fallback or operation was confirmed.', retryable: false };
}
