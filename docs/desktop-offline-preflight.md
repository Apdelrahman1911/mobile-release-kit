# Saved offline checks (Android)

## Availability

**Run offline checks (Android)** is a staged implementation, not an enabled or
qualified desktop capability. Its native and runtime qualification gates remain
closed. Windows is unsupported. Browser-preview data and another operation's
test permission cannot enable it. Source preparation is not evidence that tests,
native process/window behavior, installed runtimes or clean-machine checks passed.

## Saved input and explicit consent

The operation uses only the saved `release/mobile-release.json` in the original
native-selected project. The configuration must be valid, enable Android, and
match the reviewed saved byte count and SHA-256. Those values compare inputs;
they are not filesystem custody or release evidence. A missing, changed, unsafe,
oversized, invalid or possibly sensitive configuration refuses before shared
preflight policy runs. Other project files remain live, non-atomic inputs.

Unsaved drafts, renderer-supplied commands, environments, paths, runtimes,
platforms and alternative configurations are not execution inputs. Save or
discard changes separately, refresh the saved baseline, and resolve pending or
unknown operations first. GitHub must be disconnected. Passive requests,
configuration/metadata edits, asset operations, evidence inspection and tool
diagnostics cannot overlap this operation.

Prepare creates one short-lived comparison intent; it does not inspect a
runtime, execute a tool, acquire the project or launch a child. Review the saved
input and check the explicit, initially unchecked acknowledgement for that
intent before Start. It expires after five minutes. Context changes, refresh,
navigation and consent dismissal invalidate the review; returning to the same
values does not restore it. Start consumes the intent before runtime admission,
including refused or lost-reply starts. It is never automatically retried.

## Trust boundary

**Core builds are disabled.** The service calls the existing shared core
preflight with offline mode, Android only, `run_builds=False`, no artifacts, no
credentials file, `credentials_from_env=False`, `require_tools=False` and no
signing lease, using one original invocation and cancellation owner. It does not
request toolkit signing, credential loading, artifact validation or Store work.

**Configured project checks are trusted arbitrary project code.** Offline mode
is not a sandbox, network isolation or a no-write promise. Saved commands can
invoke builds, contact services, access user resources or change files even
though toolkit-owned builds are disabled. Run checks only for a project and
saved commands you trust. Cancellation cannot undo those effects. Static checks
may stop shared policy before configured commands run; the desktop does not
bypass the existing core policy to force them.

## Cancellation, deadlines and results

Cancel requests STOP from the original operation. A request acknowledgement,
closed input pipe, core terminal frame or **Stopping** display is not proof that
the original child, readers, wait, closes and native tasks settled. A lost reply
must be reconciled with original native status, not another Start.

The native work endpoint is 1,800 seconds from Start entry, including admission.
Final settlement cannot extend beyond 1,810 seconds. The first lifecycle failure
or STOP shortens settlement to at most ten seconds from that first event; later
events and polling never renew it. Complete policy failures, missing requirements
and a completed nonzero project check are findings, not lifecycle failures.
Each command also receives the remaining whole-second allowance; below one
second no new command is dispatched.

Results remain provisional until the last actual original native join. At or
after an unsettled endpoint the operation is **Unknown**: no successful result
or reuse is permitted. Later positive closure may permit exiting, but does not
make the result trustworthy or re-enable the owner.

The UI projects fixed, redacted finding identifiers rather than raw reports,
paths, argv, output or exception text. It retains all nine core status categories,
shows at most the first 128 findings, and counts omitted findings. **Complete**
does not mean every finding passed. Neither successful checks nor a clean report
establish build, signing, Store, provenance or release readiness.

Traversal, reads, command capture and retained results have fixed, precharged
application limits. These limit toolkit-managed work, not arbitrary project
scripts or exact process memory. A limit refusal is not permission to skip the
remaining checks or present an incomplete report as successful.
