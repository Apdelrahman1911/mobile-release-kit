// Closed comparison DATA only; actual signing material stays with the native owner.
import type { AndroidBuildContext, PrepareAndroidBuild } from './androidBuildTypes.ts';
export const AGENT_ANDROID_BUILD_SIGNED_CONSENT = 'agent-saved-android-local-sign-v1';
export const AGENT_ANDROID_CANDIDATE_CONSENT = 'agent-local-android-candidate-inputs-v1';
export function canonicalAndroidUploadFingerprint(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  if (/^[0-9A-Fa-f]{64}(?![\s\S])/.test(value)) return value.toLowerCase();
  if (/^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}(?![\s\S])/.test(value)) return value.replaceAll(':', '').toLowerCase();
  return null;
}
// Called only AFTER the existing complete native request/context parser.
export function signedAndroidAgentInput(input: PrepareAndroidBuild | AndroidBuildContext): boolean {
  return input.signing?.mode === 'local-upload-key' && input.action === undefined &&
    (input.operation === undefined || input.operation === 'android-build-sign') &&
    input.artifactValidation.mode === 'upload-signature' &&
    canonicalAndroidUploadFingerprint(input.artifactValidation.uploadCertificateSha256) !== null;
}
export function candidateAndroidAgentInput(input: PrepareAndroidBuild | AndroidBuildContext): boolean {
  return input.operation === 'android-candidate-inputs' && input.action === 'create' &&
    input.signing?.mode === 'local-upload-key' && input.artifactValidation.mode === 'upload-signature' &&
    canonicalAndroidUploadFingerprint(input.artifactValidation.uploadCertificateSha256) !== null;
}
export function agentAndroidBuildContext(input: AndroidBuildContext): boolean {
  return input.operation === 'android-candidate-inputs' ? candidateAndroidAgentInput(input) :
    input.operation === 'android-build-sign' ? signedAndroidAgentInput(input) :
    input.operation === 'android-build-inspect' && input.signing === undefined && input.action === undefined &&
      input.artifactValidation.mode === 'structure-and-version' && input.artifactValidation.uploadCertificateSha256 === null;
}
