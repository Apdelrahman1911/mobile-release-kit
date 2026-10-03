# Existing-package Mac entry diagnostics

The dedicated `verify/desktop-macos-entry-diagnostic` branch runs **two independent
fresh macOS26 ARM64 jobs**, not the normal app test suite. Both authenticate and
install the same unmodified preview package from application source `53850a9`.
The workflow/harness source is recorded separately. No Rust/application rebuild,
Store operation, production credential, public release or application re-signing
is involved.

- **launchservices:** three small C/Objective-C compilation units; one public
  NSWorkspace launch of the ordinary outer entry. The controller keeps the
  returned original NSRunningApplication and requests termination only through
  that original. A bounded forceTerminate fallback belongs only to this
  unsandboxed diagnostic, not to normal-Quit acceptance.
- **direct_entry:** no native compilation or NSWorkspace. The existing core
  `run_owned` calls the fixed entry with no arguments once (15s work + unchanged
  3s cleanup allowance). Only its actual returned status or typed owner error is
  reported. There is no guessed PID, process scan, second launch or new owner.

A complete NSWorkspace diagnostic may retain **outer-only** public properties:
these properties are not reliable evidence of exec into the nested payload.
NSRunningApplication has no app exit-status API. The direct job's status belongs
only to its own original process, never to the other job or a historical XCTest.
A timeout is not evidence of successful startup. A red diagnostic job may still
contain valuable exact refusal evidence; a green job does not qualify the app.

Each native launch consumes its exclusive per-job `launch-attempted` marker;
this prevents repeats but is not an ownership/finality receipt. The adapter
preserves original source/package/Installer/readback bindings, finite command
results, closed numeric/boolean observations and first failures. Raw app and
Installer logs are not uploaded. Unknown state retains its associated outputs.
No protected installation is deleted, no shared services/caches are touched,
and task compiler outputs are removed only after their original use has settled.

The nine focused Python tests cover inert parser/source/workflow/no-clobber
contracts. They cannot qualify native Mac execution. Independent actual-diff
review and Root's explicit hosted dispatch/reconciliation remain required.
