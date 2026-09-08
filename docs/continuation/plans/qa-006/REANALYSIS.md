# QA-006 reanalysis — 2026-09-07

Read the original gate26 failure, both complete Ruby adapter suites, the common
native capture and platform adapters, CI consumers, package data declarations,
QA-001's original plan/review and Python fixture, and independent gate26 report.
Root verified all173 pending QA-003 source hashes/modes and user AGENTS; index empty.
Neither affected Ruby suite nor the shared runtime helper is changed by QA-003.

The native capture starts a private real process group, bounds both pipes and total
time, redacts child diagnostics on error, and KILLs the group on incomplete exit,
including after the leader was reaped. The wrapper validates fixed argv/modules,
scrubs Store authority and consumes output only after successful capture. Neither
the failed assertion nor synthetic investigation justifies weakening these paths.

The defective tests generate fresh shebang scripts, fork then publish a child PID,
use a3s real budget and assume every timeout reached the descendant/leader-exit
boundary. The shared native setup test and simple adapter timeout tests already
capture real waiter handles; they do not prove descendant readiness. Output-limit,
scrubbed-environment and fixed-bootstrap tests must remain unchanged and rerun.

Independent probes isolate pre-fork and post-fork/pre-record cases on both full
adapters. Root's own controlled pre-fork current! reproduction returned the expected
timeout, signaled/reaped its real leader, used no watchdog/fallback, then hit the
same ENOENT read. Initial root probe failed before execution due to an incorrect
relative require path; preserved R0 script/logs distinguish that harness mistake.
No precise historical startup-delay phase is established. No process-group escape
is established. Future fixture diagnostics must retain progress in failure output.

QA-001 delivered only the analogous Python gh fixture correction. QA-006 is a new
scoped finding for these two Ruby siblings, not a reopening/waiver of QA-001.
The all-confirmed denominator is now15 (9delivered/15=60.0%); original finding
delivery remains7/9=77.8%. QA-003 and final production readiness remain unfinished.

Plan scope: tests/helper plus required macOS CI test gate and its behavioral workflow
contract. No Ruby gem/pin/runtime dependency, package resource, schema, CLI, signed
artifact, Store evidence, public-release policy or credential authorization changes.
The existing QA-003 diff stays untouched in the main worktree; use a separately
owned main-based worktree and isolated verification destinations for this issue.

Process ownership is a key acceptance point: capture the actual spawn handle early,
never use process-name searches or historical PID files to authorize signaling;
observe death before any fallback. Prefer a private control pipe with EOF shutdown
for fixture descendants so fallback never signals a reaped/recyclable child PID.
Bound all fixture/driver/readiness waits and join every owned worker. A fallback
or watchdog intervention is failure evidence, never a production-pass substitute.
