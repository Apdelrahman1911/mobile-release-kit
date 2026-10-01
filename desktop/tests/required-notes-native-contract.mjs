// Consume one actual Rust test serialization; no copied fixture, subprocess,
// native receipt, Store operation or relaxed frontend grammar is involved.
// Root runs this separately with the exact source-bound emitter output path.
import assert from 'node:assert/strict';
import { constants, openSync, fstatSync, readSync, closeSync } from 'node:fs';
import { parseRequiredNotesCapabilities, parseRequiredNotesImportStatus } from '../src/requiredNotesProtocol.ts';

assert.equal(process.argv.length, 3, 'Provide the bounded, source-bound Rust contract output file.');
const fd = openSync(process.argv[2], constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_CLOEXEC);
let output;
try {
  const before = fstatSync(fd);
  assert(before.isFile() && before.size <= 65536, 'Expected a regular bounded contract output.');
  const bytes = Buffer.alloc(65537);
  let used = 0;
  while (used < bytes.length) {
    const count = readSync(fd, bytes, used, bytes.length - used, null);
    if (count === 0) break;
    used += count;
  }
  const after = fstatSync(fd);
  assert(used <= 65536 && used === before.size && before.size === after.size && before.mtimeMs === after.mtimeMs,
    'Contract output changed or exceeded the bound.');
  output = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, used));
} finally { closeSync(fd); }
const marker = 'MRK_REQUIRED_NOTES_CONTRACT_V1 ';
const lines = output.split('\n').filter((line) => line.includes(marker));
assert.equal(lines.length, 1, 'Exactly one real Rust contract roster is required.');
const roster = JSON.parse(lines[0].slice(lines[0].indexOf(marker) + marker.length));
assert.deepEqual(Object.keys(roster).sort(), ['capabilities', 'imports', 'schemaVersion']);
assert.equal(roster.schemaVersion, 1);
assert.equal(roster.capabilities.length, 5);
assert.deepEqual(roster.capabilities.map((row) => {
  const parsed = parseRequiredNotesCapabilities(row);
  assert(parsed, 'Actual Rust capabilities must pass the unchanged strict frontend parser.');
  assert.deepEqual(parsed.read, parsed.edit); assert.deepEqual(parsed.edit, parsed.import);
  return parsed.read.reason;
}), ['none', 'unsupported_platform', 'runtime_unavailable', 'unqualified', 'document_unavailable']);
const expected = [
  ['pending-invalid-text', 'pending', null, 'none'],
  ['invalid-file', 'settled', 'refused', 'invalid_file'],
  ['changed-file', 'settled', 'refused', 'changed_file'],
  ['invalid-text', 'settled', 'refused', 'invalid_text'],
  ['unavailable', 'settled', 'refused', 'unavailable'],
  ['early-stop', 'settled', 'refused', 'io_error'],
  ['context-changed', 'settled', 'refused', 'context_changed'],
  ['late-stop', 'settled', 'refused', 'io_error'],
  ['native-cancel-model', 'settled', 'cancelled', 'cancelled'],
  ['unknown', 'unknown', null, 'cleanup_unknown'],
  ['selected-dto-only', 'settled', 'selected', 'none'],
];
assert.equal(roster.imports.length, expected.length);
assert.deepEqual(roster.imports.map((row) => {
  assert.deepEqual(Object.keys(row).sort(), ['case', 'status']);
  const parsed = parseRequiredNotesImportStatus(row.status);
  assert(parsed, 'Actual Rust import projection must pass the unchanged strict frontend parser.');
  return [row.case, parsed.phase, parsed.outcome, parsed.reason];
}), expected);
console.log('Required Notes Rust/frontend transport contract accepted: 5 capabilities, 11 statuses; not native qualification.');
