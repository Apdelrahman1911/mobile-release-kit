import React from 'react';
import {createRoot} from 'react-dom/client';
import {App} from '../../src/App.tsx';
import '../../src/styles.css';
import {calls, inflight, emit, finished, statusRows, nativeTick, subscriptionCounts} from './workspace-native-fixture.mjs';

let done = false, phase = 'mount', ticks = 0, deliveries = 0, failure = null;
const transitions = [];
const report = data => {
  if (done) return;
  done = true;
  window.webkit.messageHandlers.probe.postMessage({
    ...data, phase, ticks, deliveries, transitions, failure,
    bootstraps: calls.filter(name => name === 'app_info').length,
    helperCalls: calls.filter(name => /^(check_android_tool_service|request_android_tool_service_registration|open_android_tool_service_approval_settings)$/.test(name)),
  });
};
const problem = error => report({ok: false, message: String(error?.message ?? error).slice(0, 1_000)});
window.addEventListener('error', event => problem(event.error ?? event.message));
window.addEventListener('unhandledrejection', event => problem(event.reason));
class Boundary extends React.Component {
  state = {failed: false};
  static getDerivedStateFromError() { return {failed: true}; }
  componentDidCatch(error, info) {
    failure = {message: error.message, components: info.componentStack};
    problem(error);
  }
  render() { return this.state.failed ? React.createElement('p', null, 'FATAL') : this.props.children; }
}
// Match native event microtask checkpoints while normal-priority work is held
// behind an accumulated batch. Timer sleeps would let React drain that work
// and hide the original maximum-update-depth failure.
const turn = () => new Promise(resolve => {
  const channel = new MessageChannel();
  channel.port1.onmessage = () => { channel.port1.close(); channel.port2.close(); resolve(); };
  channel.port2.postMessage(null);
});
const settle = async () => { for (let i = 0; i < 20; i++) await turn(); };
const wait = async (ready, label) => {
  const end = performance.now() + 5_000;
  while (!ready()) {
    if (done) throw Error('Earlier failure');
    if (performance.now() > end) throw Error('Timed out: ' + label);
    await turn();
  }
};
const button = name => [...document.querySelectorAll('button')].find(node =>
  node.getAttribute('aria-label') === name || node.textContent.trim() === name ||
  name === 'Home' && node.textContent.trim() === 'Overview');
const click = async name => {
  phase = name;
  await wait(() => button(name) && !button(name).disabled, name);
  button(name).click();
  await settle();
};
const burst = async label => {
  phase = label;
  const rows = await statusRows();
  if (!subscriptionCounts()['config-edit-state'] || !subscriptionCounts()['asset-session-state']) throw Error('Native listeners were not ready');
  for (let i = 0; i < 300; i++) {
    deliveries += nativeTick(rows);
    ticks++;
    await Promise.resolve();
    if (done) return;
  }
  await settle();
  transitions.push(label);
};
const switchProject = id => {
  const select = document.querySelector('select[aria-label^="Switch project;"]');
  if (!select) throw Error('Project switcher missing');
  Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set.call(select, id);
  select.dispatchEvent(new Event('change', {bubbles: true}));
};
const commitMessage = () => [...document.querySelectorAll('textarea')].find(node => node.placeholder === 'Describe what changed');
const editMessage = value => {
  const input = commitMessage();
  if (!input) throw Error('Local Git draft is missing');
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, value);
  input.dispatchEvent(new Event('input', {bubbles: true}));
};
async function run() {
  createRoot(document.getElementById('root')).render(React.createElement(Boundary, null, React.createElement(App)));
  await wait(() => calls.includes('app_info') && button('Open another project folder') && !button('Open another project folder').disabled, 'initial connection');
  await settle();
  await burst('no-project-status-backlog');
  if (done) return;

  await click('Open another project folder');
  await click('GitHub');
  await wait(commitMessage, 'first project Git controller');
  editMessage('Keep project one draft');
  await settle();
  if (commitMessage().value !== 'Keep project one draft') throw Error('First project draft did not update');
  await burst('selected-project-status-backlog');
  if (done) return;

  await click('Open another project folder');
  await wait(() => commitMessage()?.value === '', 'second project Git controller');
  editMessage('Keep project two draft');
  await settle();
  switchProject('fixture-project-1');
  await wait(() => commitMessage()?.value === 'Keep project one draft', 'retained first project draft');
  // Two synchronous context intents must preserve the final selection too.
  switchProject('fixture-project-2');
  switchProject('fixture-project-1');
  await settle();
  if (commitMessage()?.value !== 'Keep project one draft') throw Error('Rapid ABA project selection lost or retargeted a draft');
  transitions.push('two-project-drafts-and-rapid-ABA');

  await click('Home');
  await click('Read saved version again');
  await click('Build tools');
  await click('Check installed service');
  await wait(() => inflight.length === 1, 'original helper check');
  let original = inflight.shift();
  const complete = async (call, state) => {
    const row = finished(call.row, state);
    emit(row); await turn(); call.resolve(structuredClone(row)); await settle();
  };
  await complete(original, 'requires-approval');
  const consent = document.querySelector('[aria-label="Android system service setup"] input[type="checkbox"]');
  if (!consent || consent.disabled) throw Error('Helper registration consent missing');
  consent.click(); await settle();
  await click('Request system-service registration');
  original = inflight.shift();
  if (!original) throw Error('Original registration request missing');
  await complete(original, 'requires-approval');
  await click('Open approval settings');
  original = inflight.shift();
  if (!original) throw Error('Original approval settings request missing');
  await complete(original, 'requires-approval');
  window.dispatchEvent(new Event('focus'));
  document.dispatchEvent(new Event('visibilitychange'));
  await burst('helper-approval-focus-return-backlog');
  if (done) return;
  await click('Check installed service');
  original = inflight.shift();
  if (!original) throw Error('Enabled helper check missing');
  await complete(original, 'enabled');
  await click('Home');
  report({ok: true, scope: 'real-macOS-WebKit-controlled-native-DATA', fatal: document.body.textContent.includes('FATAL'), preservedProjectDrafts: true});
}
run().catch(problem);
