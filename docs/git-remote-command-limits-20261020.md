# Fetch: fixed original-W file limits (supporting slice)

This implements the accepted Fetch plan's narrow W-only effect. It **does not
enable Fetch**, create a remote credential issuer, nominate an installed Git,
or prove an aggregate disk bound by itself. The approved Fetch plan remains
`22efc84c92543d23092bb50f6ed1e8909250707dcee1e73c18ecbb09cc478544`.

## Same original, two fixed resources

`_git_remote_command_limits.apply_worker_limits` is private and has no caller
resource/limit/environment options. Only the original `_Worker` with the same
live W `_Context`, adopted map-v2 socket FD8, actual bootstrap identity/nonce,
null account slot and original acquisition may enter. Equal descriptor/map
DATA cannot replace those references. The same ordinary UID must still own the
socket; a root or changed-effective-user invocation refuses. This is not proof
of arbitrary Linux capability policy or installed executable admission.

The W attempt is consumed **before** any owner callback. The original context
checks currentness/deadline before and after every get/set; the same acquisition
validates the endpoint before and after. No new work or cleanup clock is made.
The outer GitRemote45/55 and first-failure endpoint must still be enforced by
the actual original operation when that native route is implemented; this leaf
does not derive authority from a numeric endpoint or start a new timer.

The finite order is: read inherited FSIZE and CORE; refuse malformed or stricter
FSIZE policy; set both soft/hard CORE to0, then FSIZE to32MiB; read back exact
CORE and FSIZE; rematch the same original. Both setters use the existing W
`_setup` effect ledger. There is no retry or restoration. Even a stricter soft
FSIZE limit is never raised for convenience. A late STOP, failed/unknown call,
unexpected return/readback or endpoint drift prevents target exec. An entered
attempt cannot be called again after any failure or successful return.

## Exact Root hook and ordinary behavior

`git-remote-command-limits-hooks-20261020.patch` changes only
`src/mobile_release/_command_process.py`, three added lines in two hunks:
the W's attempt bit and the fixed lazy call inside its existing GitRemote-only
branch. The call is **before** FD8's original inheritable setup, cwd/signals
and exec. CLOEXEC remains required during this new leaf's validation.

The old map-v1/ordinary C/A/W roles, standard descriptors, command APIs,
signal policy, exec rejection protocol, currentness, clocks, native effects,
original child waits, EOFs, group lifetime and close/retention paths are
unchanged. There is no new generic `setrlimit`, subprocess or FD endpoint.
Exceptions follow the original W/loader failure path; no setup receipt is
promoted to process, helper, C/A/W or network settlement.

The limit is inherited by the intended exec and descendants. It is **per-file**,
not an aggregate-disk or RSS quota. Full Fetch still requires the separately
source-selected single kept pack/index path, finite two-content-inode/80MiB
staging reservation and actual controlled exec roster; unexpected output must
fail/retain. The same private streaming pipe, stock fsck/connectivity/layout
checks, durable original `.keep` before publication, candidate ACK/CAS and all
original source/runtime/management/NativeUse joins remain pending work.

## Focused evidence

13 focused tests pass with the actual Worker constructor/run and `_setup`, but
**inert protocol/OS/resource return doubles only**. They cover fixed order,
same-original/role/map refusal, once-only entry/reentrancy, original clocks,
nonprivileged identity, stricter inherited policy, malformed constants/results,
unknown set return, STOP after each return, final descriptor drift and the real
hook's position before inheritance/exec. Ordinary map-v1 takes no limit call.

No real `getrlimit`/`setrlimit`, descriptor, child, signal change, Git, socket,
TLS, native ABI, credential, repository or provider operation is tested. The
existing channel fixture supplies only finite fake descriptor returns. Run
only `test_git_remote_command_limits` with the exact one-parent hook and
unchanged current native-map source on the package path (or after Root
integration). No unrelated lifecycle suite is required for this source packet.
