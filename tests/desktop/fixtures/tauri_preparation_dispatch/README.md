This fixture compiles the current `prepare_installation_quit` handler, original
window/body gates, and confirmation parser through the pinned Tauri command
macro. Tauri's MockRuntime dispatches a real Invoke; no Wry/WebKit window or
native maintenance owner is created. Only the final Document port is a fixture.

Run `python -m unittest tests.desktop.test_tauri_preparation_dispatch`. Cargo
uses cached dependencies offline, seeded from the app's current Cargo.lock.
`MRK_PART_TEST_ROOT` can select the temporary evidence directory. The suite proves
that a caller outside Tokio reaches the unchanged admission port once inside
Tauri's runtime, while the previous synchronous form fails its runtime check.
It also verifies original window/request rejection and refusal propagation.

This is dispatch integration evidence, not installed signing, SMAppService,
maintenance-memory, native cleanup, or ordinary app exit qualification.
