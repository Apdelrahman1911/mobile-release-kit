# Existing Mac contract roster: Remote CLI and prerequisite hints

Base: `6e93436154562a55d738166016b801866f2ac3ae`, after the accepted
P12 two-parent hook and Git observer hook. Apply only
`macos-remote-tools-roster-hooks-20261021.patch` to
`.github/workflows/desktop-macos-components.yml`.

This is a selector addition in the existing focused library subshell, not a
new job, runner, fixture, availability flag or execution permission. Shipping,
CLI and observer compilation, existing resource/time limits, default flags,
private fixture policy, IPC checks and the six-call P12/key component owner
with its original 90-second deadline remain unchanged.

## Exact source resolution

The patch contains all 25 full test names as literal Bash array entries. Each
has one `#[test]` declaration in its actual containing module at this base.
The private handoff manifest `.task-mac-remote-roster/manifest.json` records
each full name, source path/line/hash and the before/after workflow hashes.
Complete source-only workflow copies are in that directory's `before/` and
`after/` trees. No test binary was run to produce this proof.

| Actual module prefix | Added | Containing source |
|---|---:|---|
| `service_git_remote_protocol::tests` | 4 | `service_git_remote_protocol.rs` |
| `service_git_requests::remote_requests::tests` | 8 | `service_git_remote_requests_tests.rs` |
| `asset_session::agent_git_index::remote::tests` | 2 | `service_git_remote_document.rs` |
| `application_service::git_index::remote::tests` | 2 | `service_git_remote_application_tests.rs` |
| `installed_cli::git_index::remote_tests` | 4 | `installed_cli_git_remote_tests.rs` |
| `github_connection_session::fetch::tests` | 1 | `git_fetch_connection.rs` |
| `github_connection_session::push::tests` | 1 | `git_push_connection.rs` |
| `tool_acquisition_protocol::prerequisite::tests` | 1 | `tool_acquisition_prerequisite.rs` |
| `saved_command_owner::tool_acquisition::tests` | 1 | `saved_command_tool_acquisition.rs` |
| `saved_command_owner::android_catalog::frozen_row_data_tests` | 1 | `saved_command_android_catalog.rs` |

All selected tests are ordinary `cfg(test)`, with no `ignore` or special
native-observer feature. The Doc and Service parents additionally require
Linux or macOS, so both are present in the existing ordinary Mac library.
The module path declarations, not filenames alone, establish these names.

**Explicitly omitted and unrun on Mac:**
`saved_command_owner::android_catalog::tests::catalog_unknown_and_earlier_failure_retain_the_original_slot_without_a_build_session`.
Its containing module is gated by
`all(test, not(all(target_os="macos", target_pointer_width="64", any(target_arch="aarch64", target_arch="x86_64"))))`.
The compatible `frozen_row_data_tests` module is separate; it is not a
replacement implementation of that unsupported-target test.

## Counts and execution effects

The existing Cargo/libtest `--list` mechanism first requires exactly 25 listed
tests and exactly one full-name line for each addition. Listing executes no
test body. The original test invocation then takes the union of its existing
filters and the 25 names, under unchanged `--test-threads=1` and `pipefail`.
Its exact success count becomes **156 = 131 prior + 22 Remote + 3 Tools**.
The existing Fetch prefix already matches the new Fetch test after Remote
source integration; the explicit full-name filter does not run it twice.
There is no separate new test-body invocation or permissive zero-test pass.

Twenty Remote tests and all three Tools tests operate only on inert DATA,
in-memory originals or codecs. They open no runtime, invoke no native work,
and make no Git/provider/credential/process calls. The two Remote Service
tests use the existing exclusive `Fixture::new()` directory under the test
working directory, real private State Store operations, explicit service
stop/store close and removal of only that fresh fixture. They open no IPC
listener or ambient user store. Existing fixture policy already covers this
same type of filesystem effect.

## Verification boundary

Only source declaration/hash comparisons, scoped whitespace checks and
patch applicability are checked by this task. **No Cargo, libtest, native,
CLI, Git, provider, signing, CI or private fixture execution occurred.**
The added selectors remain pending Root's scheduled actual Mac run; no
runtime qualification or feature availability is inferred.
