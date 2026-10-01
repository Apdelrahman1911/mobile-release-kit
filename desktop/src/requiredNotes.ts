// Required-note transport DATA. Paths/digests never grant file/write authority.
// Private Load/Prepare DTOs are separate from routine native status by design.
import type { CoreEditOutcome, HelpContent, NativeEditReason } from './types.ts';

export const REQUIRED_NOTE_KINDS = ['android-build', 'android-default', 'ios-beta-review', 'ios-app-review', 'testflight-what-to-test'] as const;
export type RequiredNoteKind = (typeof REQUIRED_NOTE_KINDS)[number];
export type RequiredNoteContext = { kind: 'android-build' | 'android-default'; locale: string } |
  { kind: 'ios-beta-review' | 'ios-app-review' | 'testflight-what-to-test' };
export interface RequiredNoteDigest { byteLength: number; sha256: string }
export type RequiredNoteAssertion = { state: 'absent' } | ({ state: 'present' } & RequiredNoteDigest);
export type RequiredNoteOriginal = { state: 'absent' } | { state: 'present'; text: string };
export interface RequiredNoteBaseline {
  config: RequiredNoteDigest;
  version: RequiredNoteDigest | null;
  note: RequiredNoteAssertion;
  counterpart: RequiredNoteAssertion | null;
}
export interface RequiredNoteSelection {
  context: RequiredNoteContext;
  metadataRoot: string;
  destination: string;
  savedBuild: number | null;
  effective: { source: 'exact' | 'default' | 'missing'; valid: boolean } | null;
}
export type RequiredNoteIssueCode = 'notes.missing' | 'notes.utf8' | 'notes.editor-byte-limit' | 'notes.android-content' |
  'notes.android-length' | 'notes.android-policy' | 'notes.apple-empty' | 'notes.testflight-length' |
  'metadata.empty-text' | 'metadata.nul' | 'metadata.placeholder' | 'metadata.secret-pattern' | 'metadata.length';
export interface RequiredNoteValidation {
  schemaVersion: 1;
  kind: RequiredNoteKind;
  valid: boolean;
  state: 'format-valid' | 'invalid';
  rawByteCount: number | null;
  characterCount: number | null;
  characterLimit: number | null;
  outboundCharacterCount: number | null;
  editorByteLimit: number;
  issues: { code: RequiredNoteIssueCode; message: string }[];
}
// Direct, requested, selected-window response only; NEVER broadcast/store in history.
export interface RequiredNotesLoaded {
  schemaVersion: 1;
  type: 'required-notes-loaded';
  projectId: string;
  windowGeneration: string;
  selection: RequiredNoteSelection;
  baseline: RequiredNoteBaseline;
  original: RequiredNoteOriginal;
  validation: RequiredNoteValidation;
}
// The original owner must compare the supplied baseline with its own capture,
// then return this direct view. No renderer value may replace that capture.
export interface RequiredNotesPrepared {
  schemaVersion: 1;
  type: 'required-notes-prepared';
  projectId: string;
  windowGeneration: string;
  ownerGeneration: string;
  sessionId: string;
  revision: string;
  planToken: string;
  draftRevision: number;
  selection: RequiredNoteSelection;
  baseline: RequiredNoteBaseline;
  before: RequiredNoteOriginal;
  after: string;
  action: 'create' | 'replace' | 'preserve';
  createDirectories: string[];
  validation: RequiredNoteValidation;
}
// This exact shape is the ONLY permitted routine event/status/lastTerminal shape.
// There are deliberately no paths, text, digests, baseline, prepared view, or messages.
export interface RequiredNotesRoutineStatus {
  schemaVersion: 1;
  domain: 'required_notes';
  projectId: string;
  windowGeneration: string;
  ownerGeneration: string;
  sessionId: string;
  planToken: string | null;
  revision: string | null;
  context: RequiredNoteContext;
  draftRevision: number;
  statusRevision: number;
  phase: 'opening' | 'editing' | 'preparing' | 'reviewing' | 'applying' | 'finalizing' | 'final' | 'unknown';
  applySubmitted: boolean;
  coreOutcome: CoreEditOutcome | null;
  nativeReason: NativeEditReason;
  nativeFinality: 'pending' | 'settled' | 'unknown';
  lateSettled: boolean;
}
export interface RequiredNotesGuide {
  schemaVersion: 1;
  fields: (HelpContent & { id: RequiredNoteKind; audience: 'public-play' | 'apple-review' | 'testflight-testers' })[];
  actions: (HelpContent & { id: 'load' | 'validate' | 'review' | 'save' | 'import' | 'discard' })[];
}
export interface RequiredNotesScope {
  projectId: string;
  projectName: string;
  windowGeneration: string;
  configGeneration: number;
  serviceGeneration: number;
  context: RequiredNoteContext;
}
export interface RequiredNotesPrepareInput {
  projectId: string;
  context: RequiredNoteContext;
  expectedBaseline: RequiredNoteBaseline;
  text: string;
  draftRevision: number;
}
// A real native picker supplies this only after its original safe read/cleanup.
// No path, generic filename, shell argument, or credential asset role is accepted.
export type RequiredNotesImported = { schemaVersion: 1; type: 'required-notes-import'; state: 'cancelled' } |
  { schemaVersion: 1; type: 'required-notes-import'; state: 'selected'; kind: RequiredNoteKind; text: string; validation: RequiredNoteValidation };

export function requiredNoteByteLimit(kind: RequiredNoteKind): number {
  return kind === 'android-build' || kind === 'android-default' ? 2000 : kind === 'testflight-what-to-test' ? 65536 : 32768;
}
export function requiredNoteCharacterLimit(kind: RequiredNoteKind): number | null {
  return kind === 'android-build' || kind === 'android-default' ? 500 : kind === 'testflight-what-to-test' ? 4000 : null;
}
export function sameRequiredNoteContext(a: RequiredNoteContext, b: RequiredNoteContext): boolean {
  return a.kind === b.kind && ('locale' in a ? 'locale' in b && a.locale === b.locale : !('locale' in b));
}
