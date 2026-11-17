This small macOS-only fixture compiles the **whole production**
`vault_keyring_macos.rs` module and its tests. It uses real anonymous pipes and
the unchanged native crate's wire decoder. It does not extract or reimplement
the client functions. Unused application admission types are uninhabited, so
this fixture cannot grant memory, initialize a vault, launch a helper or claim
native settlement. No installed application or Keychain operation runs.

Use Rust 1.98.1, one compiler job, a private target directory and the local
aggregate memory supervisor (3 GiB maximum). Run from the repository root:

```sh
CARGO_TARGET_DIR=/path/to/private/target cargo +1.98.1 test --locked --offline --jobs 1 \
  --manifest-path tests/desktop/fixtures/vault_keyring_transport/Cargo.toml \
  --lib transport_tests:: -- --test-threads=1
```

The seven transport tests cover no GO, STOP before GO, one exact request and
retirement of both client request copies, a full nonblocking input pipe,
discarded stderr, fragmented failure
replies, nine response-binding/candidate-cell faults, three truncated streams,
trailing output, and a failed join after interruption. All values are fictional.
The existing client DATA tests can be run by omitting the `transport_tests::`
filter. Native receipts, peer identity, document admission, process finality,
Keychain denial and successful key delivery remain outside this fixture.
