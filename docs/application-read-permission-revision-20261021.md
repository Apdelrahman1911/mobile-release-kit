# Original MAIN READ permission observation

Base: `164567583e4a05876983bb7b0b825e33dc1924f0`.
Scope: six existing source/test files and this guide, plus the detached
three-parent `application-read-permission-revision-hooks-20261021.patch`.
Cleanup independently reviewed the plan; Root authorized implementation and
is the distinct implementation reviewer. No Root source was edited here.

## Boundary and order

The previous MAIN Allow request carried only a project ID. A request delayed
until after Revoke could create a new Host ticket using the *new* epoch. The
original ticket protected the interval after admission, not this earlier gap.

Explicit Check now returns the original three status fields plus
`permissionRevision`, a canonical decimal-u64 **string**. The same Host
Control guard reads both status and its existing epoch. This is MAIN-only
DATA: ordinary service/installed-CLI/headless status remains exactly
`enabled`, `remainingMs`, and `projectIds`. Allow and Revoke replies also
remain that original three-field status. There is no new counter or grant.

MAIN Allow requires exactly `projectId` and `expectedPermissionRevision`.
Under the existing Control guard, `begin_allow` checks that original epoch
**before** the original location/complete-roster reservation, then performs
reservation and the original startup/ticket transition without unlocking.
Both original epoch advances remain (initial roster and startup). A stale
request cannot alter the roster, revoke a newer grant, or replace its ticket.
Revoke, native-state startup, registration/currentness changes, poison and
epoch exhaustion retain their original invalidation/fail-closed behavior.

No IO is added to that critical section. The existing source observation,
Edit stamp, native project/document/registration/input checks, startup and
one-hour deadlines, original prepare/finish ticket, listener/Store ownership,
shutdown joins and Unknown retention are unchanged. Native-state and
foreground headless startup do not receive this MAIN observation or a new
READ permission path. The main wrapper stores one scalar epoch and formats
at most 20 public digits; no retained Document field or memory limit changes.

The controller retains a stamp only from its actually returned explicit
Check, bound to the same port, native session, selected project and local
context epoch; native registration/input checks remain independent. Allow
consumes it before any listener/await and sends it
unchanged. Revoke, a new Check, context/reentry/ABA, failure or disposal cannot
refresh old consent. Allow never performs a hidden Check. Original pending
promises remain retained, including concurrent Revoke and late replies.

## Integration

Commit the eight owned paths listed by `.task-read-access-revision/frozen.json`;
apply the three-target patch once, never overwrite full after-images. Its
targets are the existing bridge, shell and installed CLI observer. The two
observer READ steps use a genuine explicit status observation before their
existing Allow; no native receipt, picker, qualification or clock is faked.
Root's separate LocalChecks observer `.access`/revision additions must be
preserved in the same file. Base shared/CLI DTOs, command names and ACLs are
unchanged. No new permission or endpoint is registered.

## Evidence and remaining qualification

* Existing focused Node group: **30 PASS**, zero failed/skipped/cancelled,
  372.982 ms. Four new lifecycle/strict-parser cases and meaningful existing
  cases cover old Check/late Allow across Revoke, one-use observation, no
  hidden refresh, parser reentry, ABA and exact bridge arguments.
* One whole composed strict noEmit: **PASS**, 16.158 s, actual caller joined.
  Nonroot, networkless, existing readonly dependency cache, 382 exact source
  files. Source/projection hashes were unchanged; only the owned projection,
  temporary dependency link and its empty HOME/TMP were removed.
* Four Rust source files parsed with rustfmt (no writes). This is **not** a
  typecheck or test execution. No Cargo, native, IPC, provider or CI run here.
* Four new Rust cases are **UNCOMPILED/UNRUN**: three use the original private
  fixture only for real directory identity and Host in-memory transitions;
  they do not enter a SourceBook, service, endpoint or grant publication. The
  fourth verifies MAIN lossless serialization without changing shared DTOs.
  The existing RAW grammar test is extended; old Host lifecycle cases now
  obtain a genuine same-Host Check before their original fixture Allow.

Exact new/affected selectors and full source/command/result hashes are in the
task manifest and `results/`. Positive native Allow/IPC/retirement behavior
still requires the existing applicable native tests; source review and Node
results do not supply that qualification.
