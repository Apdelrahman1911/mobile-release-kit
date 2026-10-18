# macOS functional coverage (without GUI delivery gates)

GUI testing is now manual. Automated acceptance should test business operations,
original file effects, credentials, native boundaries and packaging—not require
particular accessibility roles, text-node shapes or picker gestures. Retiring a
GUI assertion does not turn its failed operation into a pass.

This source inventory was checked at `fa01d419` on 2026-10-18. The seven core
edit/recovery-engine/mobile-operation modules below passed **129 tests** locally
in a nonroot, networkless, read-only-source test boundary (zero failures/skips).
No new Rust, native or signed-app execution is claimed. The signed application
remains `fcb1aa46`. Its existing
`desktop-macos-components.yml` **app-contracts** run `39116453156/1` passed all
**74 selected Rust contracts on both macOS 26 architectures**, with zero failed
or ignored. That is real native compilation/contract evidence, not 74 installed
end-to-end operations. See [completion history](desktop-macos-completion.md).

## Small existing functional suites

Run these only in the existing coordinated test environment; do not discover
all historical native/packaging tests or enable every ignored test.

| Layer / existing entry | Meaningful coverage | Boundary of that evidence |
| --- | --- | --- |
| `desktop-ci.yml`: `cargo test --locked --lib --no-default-features` | Actual Rust protocol, owner, Document state, credential crypto/format, source binding and resource-budget code; target-specific Mac modules on Mac | Many owner/native ports are inert. No webview or production IPC invocation; compiling an installed profile is not executing it. |
| Components `app-contracts` | Fixed 74-test Store/History/Android/iOS/material roster, including the runtime descriptor-composition regression | No real credential enrollment, signing build, Store mutation or installed filesystem walk is established by its memory-only contracts. Reuse the existing pass unless affected code changes. |
| Components `local-keychain-contracts` | Fixed 102 app-library contracts: Keychain failure/finality, original history/Store material, candidate/recovery protocol ordering | Does not initialize a real login-Keychain item. `local-keychain` additionally builds the actual helper and runs seven native wire/lease tests, including real Darwin same-OFD lifetime tests. |
| Core edit adapters: `test_config_edit`, `test_github_workflow_edit`, `test_metadata_text_edit`, `test_release_version_edit` | Real capture/prepare/apply logic and exact payloads with inert lease/transaction seams; stale inputs, single-use plans, unrelated-content preservation | Not real disk transactions. Config regression includes the sorted Rust-wire draft and independent exact config/ignore payloads. |
| Core recovery: `test_saved_text_recovery_engine`, `test_project_recovery` | Actual engine routing and closed intent/consent/finality contracts with inert effects | Not restart recovery or a real filesystem rollback. |
| Core mobile operations: `test_android_build_operation`, `test_ios_archive` | Actual operation/engine objects: selected context, Start/stop, ordered results, original cleanup, signed/unsigned separation | File/process/tool/account boundaries are inert. No Gradle, Xcode, signing identity or remote account is consumed. |
| `npm --prefix desktop test` | Existing controller/protocol tests for config, credentials, GitHub, history, metadata, versions, Android/iOS and recovery | Tests controller/API coordination using test ports, not React rendering, native IPC, actual Keychain or authenticated service success. |

The focused core adapter/operation invocation, from the repository root, is:

```sh
PYTHONPATH=src:tests:tests/desktop python -B -m unittest \
  test_config_edit test_github_workflow_edit test_metadata_text_edit \
  test_release_version_edit test_saved_text_recovery_engine \
  test_project_recovery test_android_build_operation test_ios_archive
```

The standard Rust invocation is the existing command, not a new runner:

```sh
rustup run 1.98.1 cargo test --locked --no-default-features \
  --manifest-path desktop/src-tauri/Cargo.toml --lib
```

Use it on each affected supported Mac target. The embedded production shell
still needs its normal build; `development-runtime` compiles distinct conditional
code and may use a separate `cargo check`, not be treated as an identical build.

## What the Rust/backend tests actually exercise

- **Credentials:** `vault_format::tests` and `vault_crypto::tests` test real closed
  records, authenticated encryption/decryption, identity/nonce binding and
  tampering. `vault_keyring_macos::tests` tests provider/child finality and failure
  projection. `asset_session` tests preserve assignments, private material and
  document lifetimes. None substitutes for a successful real Keychain session.
- **Local project changes:** `edit_protocol`, `github_workflow_edit_protocol`,
  metadata/version protocols and `edit_owner` test actual native request and
  owner rules. `edit_owner::hosted_tests` contains real-child configuration,
  workflow, metadata and version transactions. These require
  `development-runtime`, explicit ignored-test selection and the existing
  admitted disposable fixture; most workflow/metadata/version hosted lanes are
  Linux-specific. Do not relabel that evidence as an installed Mac operation.
- **GitHub:** local workflow Apply is separate from commit/push/PR and repository
  settings/secret updates. `github_setup_protocol`, `github_publication_protocol`
  and their sessions test exact contexts, original consent and partial results;
  Python setup/publication tests cover the core route with bounded test ports.
  Passing local Apply never establishes authenticated remote publication.
- **Recovery/mobile:** `project_recovery_protocol`, `ios_archive_protocol`,
  `android_build_protocol` and `saved_command_owner` enforce original context,
  consent, phase order and known closes. Renderer request/permission contracts
  are distinct from actual execution through `shell.rs` → `DocumentBinding` →
  native owner → Python engine. A successful terminal DATA fixture is not that
  executed chain.

## Retain real effects; close only genuine remaining gaps

1. Keep the existing non-UI real-filesystem tests: `test_project_initialization`,
   `test_github_workflow_recovery`, and `test_saved_text_recovery`. The latter
   includes exact original-file rollback and joined restart-child cases; it must
   retain its reviewed nonroot Linux/macOS filesystem/process boundary. Never
   place its intentional interrupted child into an unbounded generic runner.
2. Coverage still needed beyond these suites: real Mac initialize/save/lock/
   reopen/replace/delete and genuine P0→P1 Keychain continuity. Preserve the
   existing non-UI wrapping-Keychain/direct-native scopes and their source/input
   admission; old supplier pins are not permission to use retired inputs.
   Desktop CI now explicitly selects the existing ARM-only ignored
   `vault_store::macos::tests::native_apfs_storage_lifecycle` in its own empty
   directory. This new route is not yet executed: it covers real storage effects,
   not Keychain, authenticated credential records or app restart.
3. Mobile execution still needs a real current Android build/sign/
   inspect and iOS archive/export/recovery through the installed backend with
   matching tools and controlled project inputs. Existing protocol or controller
   passes cannot replace those operations. They need not repeat GUI selectors
   or re-sign an unchanged application just to change test infrastructure.
4. Authenticated GitHub push/PR/settings/secrets and Store operations require
   explicit separate credentials/consent and service evidence. Keep ordinary
   local tests credential-free; do not turn a test run into a live mutation.
5. Keep Installer/signature/readback, interruption/Restore, removal and update
   tests independent of manual GUI acceptance. A source-reviewed correction,
   synthetic result or cancelled UI run proves none of their finality.

No new test owner, generalized collector or GUI-gating framework is needed.
