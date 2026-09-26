# Desktop unsigned iOS archive

This slice is **not yet native-qualified or delivered**. Its normal execution
gate stays closed until independent implementation acceptance and genuine
installed Apple-silicon macOS verification. Linux renderer/DATA tests are not
Xcode or native cleanup evidence.

## What the screen does

Releases provides a separate **Create unsigned iOS archive** flow:

1. Select the registered source project.
2. Save the intended iOS configuration, then refresh its saved snapshot.
3. Read the saved version. Both original observations, their generations,
   byte counts, digests, version source, name and build must agree.
4. Review the saved Xcode container, shared scheme, build configuration, bundle
   ID, symbols policy and whether project preparation will execute.
5. Acknowledge project-code effects and explicitly start one unsigned archive.

Unsaved drafts are preserved but are not execution inputs. A save, new snapshot,
version observation, selection change or expired review cannot reuse old
consent. The five-minute consent deadline is not renewed by Status. A started
operation keeps its original Status and Cancel when navigating away from
Releases; the same completed result also appears in Artifacts.

Each important choice has contextual help describing what it means, where to
find it, its format, whether it is required, and how to recover from a failure.
Configuration/path-picking capabilities retain their own platform gates; this
archive slice does not claim to qualify new pickers or configuration editing.

## Deliberately limited result

The installed core performs its existing archive command and structural
identity/version/dSYM checks. Toolkit code requests **unsigned archive only**.
Full Xcode is required; the fixed selection uses `/Applications/Xcode.app`,
allows only the reviewed one-direct-sibling app alias, retains original
descriptors and refuses unqualified or changed tool/SDK layouts. No ambient
Python, `xcode-select` fallback, tool installation or license acceptance occurs.

Only native terminal finality can publish the bounded result. The output is
retained at `.mobile-release/desktop-ios-archive/<operation>/archive.xcarchive`
relative to that operation's source project. The inspection snapshot and
task-owned work have separate cleanup dispositions. A retained location is
historical DATA, not permission to reopen, adopt, delete or publish a current
file. Failed or cancelled operations can retain incomplete output.

This is **not** IPA export, signature/profile authentication, paired
IPA/archive validation, authenticated source provenance, Store testing,
promotion or release-readiness approval. No credentials or Store operation are
requested by the toolkit. Project build phases and preparation code still run
with the user's account access and may modify files or contact the network.
Only run trusted projects. Cancellation is not rollback.

## Ownership and verification boundary

The four dedicated Raw IPC commands are `prepare_ios_archive`,
`start_ios_archive`, `ios_archive_status` and `cancel_ios_archive`.
The renderer supplies saved comparisons and one-use consent, not tool paths,
commands, credentials, deadlines or native ownership. `IOSArchiveOwner` adapts
the existing `SavedCommandOwner` with independent iOS protocol/domain types.
The original document mutex guards admission; GO is released only after that
mutex is unlocked. Offline checks, Android builds, editors, credentials,
passive work and selection retain reciprocal admission gates.

The production work ceiling is 5,400 seconds including startup, with a finality
ceiling of 5,410 seconds shortened to first failure plus 10 seconds. Every
entered command role needs its original command-slot outcome/finality; an
aggregate dispatch Boolean alone cannot prove settlement. Unknown cleanup
remains retained and cannot become a new run or success after reconnecting.

Focused checks are in `tests/desktop/test_ios_archive.py`,
`desktop/src-tauri/src/ios_archive_protocol.rs`, the existing saved-command owner
tests, and `desktop/tests/ios-archive.test.mjs`. Inert fixtures exercise strict
DATA, saved-input retirement, one-use Start, inter-domain exclusion, bounded
frames, first-failure clocks and finality withholding. Genuine installed macOS
Xcode archive/failure/cancel/finality evidence is required separately. No
physical-Mac-only requirement has been established for this slice.

The separate engineering-only installed Mac observation uses the same original
application owners, a sealed document/owner-bound one-use token, and a shorter
300-second work / 310-second hard ceiling established at original Start. It
cannot change a shipping application's gate or accept renderer-supplied clocks.
Its finality case holds only the existing final observer; public completion and
conflicting work stay unavailable until that exact observer and watchdog join.
