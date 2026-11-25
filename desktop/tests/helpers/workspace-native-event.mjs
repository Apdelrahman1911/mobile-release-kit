import './workspace-native-fixture.mjs';
export const listen = (event, fn) => globalThis.fixtureListen(event, payload => fn({payload}));
