# Project build-input recovery

This protocol owns only the project's temporary build inputs and selected
Android/iOS service-file replacements. It does **not** recover account signing
resources, recreate credentials, rebuild an application, contact a Store, or
retry an upload. Account recovery is described in [local signing](local-signing.md);
initialization has its separate [init recovery](init-recovery.md) protocol.

## Inspect without running the project

```sh
mobile-release build-inputs status --root /absolute/path/to/project
```

`--root` is required. A relative root is anchored to the current directory;
`..` and symbolic-link ancestry are refused rather than silently resolved. Use
the original project's physical path on a supported local Linux/macOS filesystem.
These commands do not load release configuration, discover the project, acquire
external/configured credentials, execute application/native tools, or access
Stores. Recovery does read bound private pending files to verify ownership
before conditional cleanup; those bytes are never printed.

Status obtains the nonblocking project-directory lock and reports bounded JSON:

| Status | Meaning | Exit |
|---|---|---:|
| `idle` | No pending build-input controls were found. | 0 |
| `busy` | A cooperating owner still holds the project lock. | 1 |
| `pending` | A validated original transaction needs reconciliation; includes its session and fixed role names. | 1 |
| `cleanup-only` | A validated terminal control permits metadata retirement only; includes its session. | 1 |
| `conflict` | Authority is incomplete, changed, unsupported or otherwise unsafe to use. Preserve it. | 1 |

Argument errors, filesystem failures and unresolved lifetime errors exit `2`.
Interruption exits `130`; it is not a successful recovery. An `idle` status does
not retrospectively prove that an earlier operation or its cleanup passed.

## Recover one exact original session

First let the original invocation finish and establish that its exact original
workers are idle. An unlocked project, an absent PID, elapsed time, or a command's
exit code alone does not establish producer finality.

If account signing recovery is necessary, complete the separate
`local-signing status/recover` procedure **before** project-input recovery, outside
the project lock. The build-input command never acquires or recovers the account
lease while holding the project lock. Account recovery alone does not settle
project service files or clear their pending state.

Use the exact lowercase 32-hex session reported by status:

```sh
mobile-release build-inputs recover --root /absolute/path/to/project \
  --session <32-lowercase-hex-session> \
  --confirm project-build-inputs-are-idle-and-restore-owned-state
```

The command revalidates the fixed original inventory, project/private directory
identities, target parents, retained objects, modes and content bindings under
the project lock. Normal recovery additionally requires original persisted
consumer quiescence. It attempts independent safe restoration without clobbering
intervening changes. Only exactly identified task-owned files can be removed.
There is no `--force`, arbitrary recovery path, PID takeover, clear-marker option,
recursive cleanup, or automatic retry of application work.

Successful recovery prints `{"status":"recovered","session":"..."}` (JSON key
order/spacing is not significant) and exits `0`. A repeated exact request with no
remaining pending state reports `absent`; this is a current no-state observation,
not a rewritten success record for a previously failed operation.

## Missing original-worker finality

`--manual` is only for a valid original filesystem inventory whose consumer
quiescence was not positively persisted. Both input and output must be interactive
terminals. While holding the project lock, the command shows recorded roles and
relative locations and requests this exact line:

```text
recheck <32-lowercase-hex-session> original-workers-are-idle
```

The original operator must independently establish that exact-worker fact before
confirming. If that is not possible, stop and preserve the state. Do not pipe a
confirmation into the command or treat a missing PID as proof. Manual confirmation
records a **new operator-confirmed recovery fact**; it does not change the old
containment result, manufacture native verification, or turn the old failure into
a pass. It cannot override missing/corrupt controls, changed backups, unknown
entries, conflicting targets, or no-clobber checks.

## Intervening edits and incomplete authority

Recovery never overwrites a foreign current service file. Its owner must first
preserve that independently identified file in a separate private location
**outside the reserved transaction namespace**, without replacing another file.
Do not alter retained controls/backups. Only after the intervening edit is safely
preserved and its destination has been deliberately freed may the supported
recovery command restore the still-bound original (or confirm original absence).
The owner may then deliberately reapply the saved edit as normal project work.

A changed/lost original backup or incomplete/unobserved preparation is not fixed
by selecting another session, editing JSON, removing a marker, or supplying
`--manual`. Preserve the private state and obtain technical review of the original
authority. This is bounded catchable-exit recovery, not an unattended power-loss
or hostile-same-user filesystem guarantee.

## Terminal metadata-only retirement

Private state uses `.mobile-release/build-inputs/` and the external terminal
control `.mobile-release/build-inputs-complete.json`, including reserved staging
names. New materialization refuses pending or terminal state. Never commit,
upload, log, or broadly delete these private entries: they may contain original
project files or credential material.

A valid terminal control is published only after the original target settlement
and consumer-dependent scratch cleanup. It authorizes removal of its **exact
remaining metadata inventory**, then the exact empty pending directory, then the
terminal control last. It **never reopens, re-compares, restores or rewrites current
application targets**. Legitimate edits made after target restoration must survive
terminal recovery. Unknown or changed residual entries remain conflicts.

If a terminal unlink takes effect but reports an error, the invocation remains
failed. A later `absent` result does not repair that historical evidence. Hard
termination cannot run cleanup; retain the required private evidence and original
ownership facts rather than inferring deletion authority from an empty directory
or a familiar filename.
