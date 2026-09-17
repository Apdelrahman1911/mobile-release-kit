// Fixed existing IPC in the real bundled document. No source pathname, permit,
// synthetic callback, status polling, new subscription, deadline or assessment.
(async function (request) {
  const call = (command, args = {}) => globalThis.__TAURI_INTERNALS__.invoke(command, args);
  switch (request.action) {
    case 'project':
      await call('choose_project');
      return;
    case 'jks': {
      await call('vault_open', { mode: 'session' });
      const context = await call('asset_context', { projectId: request.projectId,
        draft: {}, platform: 'android', stage: 'candidate', purpose: 'signing' });
      if (!context.context || !Number.isSafeInteger(context.context.revision)) throw new Error('SG1 context unavailable');
      await call('asset_choose', { contextRevision: context.context.revision,
        kind: 'android-keystore', replacement: null });
      return;
    }
    default:
      throw new Error('Not an SG1 action');
  }
})
