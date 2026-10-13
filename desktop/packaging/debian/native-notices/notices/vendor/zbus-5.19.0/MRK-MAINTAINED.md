# Maintained zbus 5.19.0 delta

Upstream crate SHA256:
`5db4be7c075cb421e4b7ee645541604239bd243ba7c357511f4ff3a74b555907`.
All 115 archive source files, including MIT LICENSE and original manifests/lock,
were copied byte-for-byte from the retained authenticated source before changes.
`MRK-UPSTREAM.json` records each original file and executable mode. The generated
registry `.cargo-ok` marker is not source and is omitted.

The additive Unix/Tokio `connection::OwnedConnectionAttempt` keeps one original
startup, raw call, socket control and actual reader join. It exposes neither an
ordinary Connection nor a MessageStream (which can convert back into Connection).
It uses the existing authentication, call/reply and ordered-stream implementation;
there is no new transport or codec. Local shutdown has no remote-success meaning.
Legacy Builder, Task Future/Drop, provider, proxy and encryption APIs are unchanged.

Modified upstream files: `Cargo.toml`, `src/lib.rs`,
`src/connection/{mod,builder}.rs` and `src/abstractions/executor.rs`.
New implementation: `src/connection/owned.rs`.
The opt-in `mrk-owned-test-support` feature adds only
`src/connection/owned/test_support.rs`: six finite memory-only actual-task/SDK
checks and two separately admitted Unix checks. It adds no dependency or work
on import. The app's debug Linux dev-dependency alone enables it; the crate
rejects unsupported/release feature combinations. Ordinary shipping graphs do
not enable it. These checks do not use the upstream default/provider suites or
their larger dev-dependency graph.

Application and standalone secret-service root manifests select one shared path
patch. Lock resolution and execution remain separately reviewed operations.
The checked-in upstream zbus lock and original manifest remain unchanged.

This delta does not qualify an endpoint/provider, implement pre-allocation frame
or FD limits, prove total memory bounds, or enable persistent/public key storage.
Native qualification remains OFF. Never run upstream provider/default suites as
a substitute for the reviewed finite lifecycle selectors and isolated fixtures.
