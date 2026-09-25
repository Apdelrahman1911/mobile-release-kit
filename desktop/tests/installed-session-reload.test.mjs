// Inert branch DATA only: no browser, native owner, release, credential or IPC.
// Execute the actual fixed observer body, not a handwritten equivalent.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

const source = readFileSync(new URL('../src-tauri/src/installed_shell_observation.rs', import.meta.url), 'utf8');
const matches = [...source.matchAll(/SessionStep::Reload=>r#"([\s\S]*?)"#\.into\(\),/gu)];
assert.equal(matches.length, 1, 'one actual installed-session Reload branch is required');
const script = `(() => { try { ${matches[0][1]} } catch { return { state: 'error' }; } })()`;

function fixture(button) {
  let reloads = 0;
  const progress = {};
  const window = { location: { reload() { reloads += 1; } } };
  const context = {
    window,
    panel: () => ({ querySelector(selector) { assert.equal(selector, '.session-progress'); return progress; } }),
    button(label, container) {
      assert.equal(label, 'Request cancel / discard this operation');
      assert.equal(container, progress);
      return button;
    },
  };
  return { window, reloads: () => reloads, run: () => runInNewContext(script, context, { timeout: 100 }) };
}

test('held unacknowledged Prepare keeps Cancel disabled while the original reload proceeds once', () => {
  const button = { disabled: true };
  const held = fixture(button);
  assert.equal(held.run().state, 'ready');
  assert.equal(held.reloads(), 1);
  const witness = held.window.__mrkInstalledSessionButton;
  assert.equal(witness.button, button);
  assert.equal(witness.label, 'loss-discard');
  assert.equal(button.disabled, true);
  assert.equal(held.run().state, 'error');
  assert.equal(held.reloads(), 1, 'the retained witness forbids a second reload');
  assert.equal(held.window.__mrkInstalledSessionButton, witness);

  for (const [value, state] of [[null, 'wait'], [{ disabled: false }, 'error']]) {
    const refused = fixture(value);
    assert.equal(refused.run().state, state);
    assert.equal(refused.reloads(), 0);
    assert.equal(Object.hasOwn(refused.window, '__mrkInstalledSessionButton'), false);
  }
});
