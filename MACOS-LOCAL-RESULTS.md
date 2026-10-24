# Mac continuation results — 2026-10-24

## Source and scope

- Checkpoint: `af9a4f76be5c4ced9186fb9e2e80e302e3078d7d`.
- Fix: `148e7c6234a51a548e07bbc87095527e7beaa584`.
- Fix tree: `311234838b7a7d74b5f75a12c23e8f635b70156d`.
- Continuation branch: `codex/macos-git-read-continuation`.
- A separate clean clone was used. The owner's existing checkout was on a
  different branch with extensive deletions and a modified workflow; it was left
  untouched. No installation, removal, credential access, Store mutation or
  production publication was performed on the owner's Mac. `main` was not changed.

## Reproduced and corrected

An idle image display becomes `OtherEditActive` when a Git read is pending.
The actual shared `common_gate` already reports Busy for that pending read,
before the later Supervisor `can_exit` check. The image snapshot previously
called `DocumentBinding::bump` to publish this display change. That stopped the
same original Git ticket and invalidated its Document revision.

Before changing that behavior, the local Rust regression failed with:

```text
before: Starting, no error
after:  Stopping, cancelled, DocumentStop, go_claimed_at_boundary=false
```

The regression uses the real in-memory Document, Supervisor owner roster,
capability composition, Git ticket and image snapshot publisher. Its fixture is
below native qualification, starts no child, grants no registered source, and
keeps its receipt Pending. It proves the state/publication defect, not a signed
installed Git invocation or native cleanup success.

Image selection status now owns an independent monotonically increasing display
revision. It compares the entire bounded serialized status, covering capability,
active selection, last terminal and window generation. Identical reads keep the
same revision. Cached bytes are charged by retained capacity. Revision exhaustion
fails closed through the existing Document exhaustion path and returns an error;
it neither wraps nor fabricates settlement.

GitRead admission, current-source checks, cancellation, deadlines, stop precedence
and receipt handling are unchanged. The only Git/Supervisor additions are test
fixtures under `cfg(test)`. No runtime feature nomination was opened.

## Local verification

Host: ARM64, macOS 27.0 (26A428), Xcode 27.0 (27A266a), Node 24.12.0.
Homebrew Python 3.11.16 is available; the shell's earlier Python 3.9.6 observation
did not mean Python 3.11 was absent.

Rust 1.98.0 was installed, but the existing native build script explicitly
refuses it on ARM64. Rust 1.98.1 was installed alongside the existing toolchains,
without changing their default or rewriting the repository's 1.98.0 pin.

Passed against fix `148e7c62`:

- 28 focused Rust tests: image display/selection (including five new regressions),
  retained memory, image service state, GitRead failure provenance and repository
  summary. Tests cover display stability, real Document change/loss, explicit
  cancellation, shutdown invalidation, original pending finality and exhaustion.
- 117 existing frontend tests in `git-read-native.test.mjs`,
  `metadata-images.test.mjs`, `service-metadata-images.test.mjs`, and
  `service-metadata-images-prepare.test.mjs`.
- `npm run build` (includes TypeScript checking).
- `cargo +1.98.1 build --locked --features desktop-shell,custom-protocol
  --bin mobile-release-kit-desktop`, producing an ARM64 Mach-O executable.
- `git diff --check`.

Rust tests used `CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0`; the Desktop
build used `CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0`. This local build was
not launched, installed, distribution-signed, bundled with qualified runtime
inputs or notarized. Existing warning output was not treated as a reason for
unrelated refactoring. A test-only nested Document lock discovered after the
first fix run was corrected; the final regression group passed without a hang.

Local evidence is in the sibling directory whose name ends in
`-macos-20261024-evidence`, outside Git. It contains the before/after test logs,
focused test/build logs, and bounded Tool26 facts. Do not publish raw logs or
treat a diagnostic image as a user installer.

## Existing Tool26 result

Run `40099646335`, attempt 1, job `120888971939`, source `92b6e742...` finished
with failure at `2026-10-24T15:35:18Z`.

- Package signing, notarization and normal installation passed in their original
  scope, as already recorded in the checkpoint.
- Step 67 failed at `OpenProject`, reason `native-default-input`. Its native
  accessibility control projection reported `cannot-complete`; no button press
  returned successfully.
- `originalCallReturned=false`, `appReturncode=null`,
  `invocationFinality=unknown`, `fixturesPreserved=true`.
- Installed CLI, acquisition, key and backup checks were skipped. Service
  readiness was not established. This does not prove a new application service
  defect or a recurrence of the earlier payload-path defect.

No selector change, duplicate monitor or replacement run of that old source was
made. These original unknown-finality facts must remain unchanged.

## Current native verification and remaining delivery

The unchanged existing workflow was triggered by fast-forwarding only
`verify/desktop-macos-candidate` to the tested fix. No workflow was redesigned.

- Run: [40110783814](https://github.com/Apdelrahman1911/mobile-release-kit/actions/runs/40110783814),
  attempt 1, exact source `148e7c6234a51a548e07bbc87095527e7beaa584`.
- Git27 job: `120921867192`.
- Tool26 job: `120921867407`.
- At this report's creation, both jobs are in progress, not passed.
- Distribution signing remains in the existing `macos-developer-id` environment.

Consume those original results before launching replacements. Fix a demonstrated
application defect if a new result identifies one; do not relabel skipped or
unknown operations as successful or repair brittle UI selectors as a substitute.
Enable only features whose corresponding native behavior is actually established.

The ordinary signed/notarized 0.1.3 installer, real 0.1.2-to-0.1.3 update,
credential reopening and essential installed lifecycle remain outstanding.
The current run builds nonshipping observers and is not itself that delivery.
Use the existing ordinary/update packaging routes when their prerequisites are
met. Do not install, update or remove software on the owner's daily-use Mac
without the separately required explicit approval. Preserve all external,
provider, Intel and physical-device limitations from the original handoff.
