# Saved offline checks (Android)

## Availability

**Run offline checks (Android)** is selected only for the fixed installed Linux
x86_64 engineering build (`x86_64-unknown-linux-gnu`) with manifest anchor
`8ef2fefe057a1773acb8d5d514adc08c28baebc98d4178f448ad2b74be204d66`
and protocol anchor
`083e6afae3e329c4e0d81bad00dd0c9920f77491b38ce0d23aa602996f4c4bf5`.
Actual runtime admission additionally requires kernel `6.17.0-1022-azure`.
Other profiles, macOS and Windows remain unavailable. This is not portable Linux,
cross-platform or standalone-distribution qualification.

**Available** means the build permits Review and an explicit Run attempt, not
that the actual host or bundled runtime has passed admission. Status and Prepare
do not inspect the runtime or launch work. Start checks the original host,
payload and custody; a wrong kernel, missing or changed payload, or custody
failure refuses before project execution, without a fallback. Observation tokens,
browser-preview data and another operation's permission cannot enable execution.
Source preparation alone is not evidence that native behavior, installed runtimes
or clean-machine checks passed.

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
