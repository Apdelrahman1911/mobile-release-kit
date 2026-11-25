// Replaces Tauri only in the isolated WebKit regression bundle.
import './workspace-native-fixture.mjs';
export const isTauri = () => true;
export const invoke = (...args) => globalThis.fixtureInvoke(...args);
