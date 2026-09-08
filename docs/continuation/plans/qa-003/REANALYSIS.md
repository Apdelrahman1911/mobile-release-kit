# QA-003 reanalysis after QA-002 delivery

Baseline main2beb37336fa8002b69f598fe431082606368310d/tree00f3acee00c994e6e81470cc76e42f1f2108fcdb,
version0.3.0; branchfix/qa-003-local-signing-lease. No implementation changes.
AGENTS.md unchanged/untracked. Original FINDING.md and original reproduction remain intact.

`reanalysis-current.py/.json` executes the actual current context/profile filesystem
with an explicit fictional CMS/native-keychain seam. It confirms all original overlap
effects, plus overwriting independently intervening default/search edits and an
activation timeout leaving a search reference to an already-deleted keychain.
All temporary inputs were removed; no native credential/keychain or Store call ran.

## Actual consumers and related contracts

- credentials.py:1085–1303 owns profile installation, default/search snapshots,
  P12 extraction/import, activation, body and cleanup. Root ownership is still
  per invocation, not a per-user shared lifetime. Flags follow native success,
  and cleanup restores saved state without a current-state comparison.
- credentials.py:1891–2067 materialize_build_inputs prepares per-invocation inputs
  and optionally enters this context; preflight.py:1022–1061 uses it across
  run_ios_build. Earlier private input materialization is separate from shared
  signing state; its inherited outer cleanup remains QA-004.
- ios.py:1042–1150 archives with manual signing and exports the single configured
  primary profile. No supported explicit per-invocation export-keychain selector
  is implemented. Removing global activation without a proved replacement would
  break supported Xcode export and is not a sound fix.
- Candidate and reusable preflight call this same CLI boundary on fresh hosted
  homes. Store/promotion/production/recovery validators do not enter it. No Store
  authorization, manifest, receipt, public schema or workflow identity needs change.
- QA-002 profile reader/source/capture/installer owners and DefaultCancellation
  must remain safe. Extending an outer lifetime requires actual borrowing into
  inner acquisitions; simply nesting a second default-only guard is insufficient.
- Existing signing tests and real-signal fixture model a constant search/default
  response. They must become stateful, including native creation/deletion effects,
  rather than weakening readback to accommodate their old assumptions.

## Independent platform/source research

`flock-platform-probe.json`: real Darwin directory and file flock both reject a
second independent open in the same process and another process; retry after
release succeeds. Exact fixture cleanup completed. This proves the intended
cooperating primitive locally, not arbitrary/network-filesystem or hostile-UID safety.

Public Apple Security source is pinned to
db15acbe6a7f257a859ad9a3bb86097bfe0679d9. Downloaded sources beside this record are
third-party research, not bundled product code or executed input:

- SecurityTool/macOS/keychain_create.c invokes SecKeychainCreate.
- OSX/libsecurity_keychain/lib/SecKeychain.cpp:103ff invokes StorageManager/create;
  StorageManager.cpp:507ff explicitly adds a created keychain to the search list
  where applicable and may set a missing default. Creation itself is a global
  mutation, BEFORE the toolkit's explicit list/default activation.
- keychain_delete.c calls SecKeychainDelete; StorageManager.cpp:999ff removes the
  keychain from saved search/default settings before deleting its database.
- keychain_list.c prints one unescaped quoted path per line. A shell/JSON parser
  is not a faithful parser for every possible filename; ambiguous paths must be
  rejected without global mutation, not silently reconstructed.
- StorageManager.cpp:326ff does not append a second -db to an existing -db suffix;
  outside Library/Keychains, the special legacy de-munging does not apply.

The first request for singular Keychain.cpp returned404 after successfully
downloading SecKeychain.cpp and StorageManager.cpp. The zero-byte unsuccessful
research output and command failure are preserved; no claim that it was reviewed.
The source directory shows plural Keychains.cpp instead. The confirmed native
side effects above are sufficient for the design and must be represented in tests.
These sources do not substitute for the owner's protected native export rehearsal.

## Required scope

Protect the complete shared signing-resource lifetime, not just file creation;
reject busy same-user entry before profile authentication/P12 native processing
or shared mutations; reconcile observed state, preserve unrelated edits, arm
mutation ownership before dispatch, retain private recovery information after
uncertainty, and never silently take over an abandoned session. Preserve all
QA-002 cancellation/authentication guarantees. QA-004's unchanged outer owner is
a separate next fix, not permission to leave new QA-003 resources unprotected.

## R2 reanalysis corrections and actual subprocess reproduction

R1 independent review requires changes; see PLAN-REVIEW-R1.md. Additional pinned
Apple source proves legitimate DB atomic inode replacement and source-derived .fl
sidecar lifetimes. StorageManager.shouldAddToSearchList119–134 currently permits
implicit create insertion only for login/System: nonce-path insertion remains a
conservative compatibility simulation, not an observed pinned-source guarantee.

reanalysis-process-descendants.py/.json executed both current runners with actual
fictional subprocesses and explicit startup synchronization before timeout. Both
returned their typed errors while an owned descendant continued updating its
heartbeat. Both children exited on exact scoped stop files and their absence was
confirmed before fixture cleanup. No native credential/Store command ran. The
17-second execution session completed; no owned worker or disposable input remains.
Darwin SDK inspection also confirms statvfs does not carry MNT_LOCAL; use a validated
fstatfs ABI, not a guessed statvfs flag, for local-filesystem admission.

R2 caller/ownership reconciliation (no implementation): full preflight also calls
its own prepareCommand/showBuildSettings/project checks before the later signed
context, so those synchronous command runners need the same owned-process boundary.
Default profile API paths during post-build artifact validation must borrow the
active outer guard too. Source display_name can print a per-keychain error without
changing the parent exit code; observation requires empty stderr as well as strict
complete stdout. Forked installer cleanup must not unlink a parent's active profile.
Never-owned reused profiles may be changed/deleted externally; such changes are
preserved/conflicts, not an impossible old-inode-restoration prerequisite for
clearing already-cleaned OWNED resources. R3 will make every control-file teardown
cut point explicitly resumable rather than treating ordinary interrupted cleanup
as unknown/corrupt input.
