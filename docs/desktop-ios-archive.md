# Desktop local iOS archive, signed export and recovery

This implementation is **not yet native-qualified or delivered**. The ordinary
Mac application's selected installed provider supports unsigned archive, signed
export and local recovery; those support bits are not successful native execution
or release-readiness evidence. Every Start independently admits its actual
runtime, tools, project and applicable private inputs. Linux renderer/DATA tests
are not Xcode, signing, account-restoration or native-cleanup evidence. Intel
requires the separately integrated and verified native provider, not profile DATA
alone. No Store upload or public release is part of these local flows.

## Unsigned archive

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

## Unsigned result and its limits

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

## Signed export

Choose **Sign and export IPA** in Releases. Save and refresh the iOS selection
and version, then use Credentials -> iOS -> Candidate / internal testing ->
Build / signing to select, assess, keep and assign the P12, its password and the
matching provisioning profile. Any required Firebase/project-read input belongs
to the same current context. Native file selection and contextual help are in the
application; no manual internal-folder placement is needed.

Review the exact saved signing policy and current assignments, acknowledge the
project-code effects, then start once. Native admission requires full Xcode and
its SDK plus the fixed security/codesign/openssl tools. The existing core validates
the selected signer/profile, creates the archive and IPA, restores its original
signing and material sessions, and checks the retained archive/IPA pair. Private
bytes stay in the original material loan and bounded private transport; they are
not renderer logs or command-line values. Changing an assignment, saved input or
project retires an unstarted review. Store readiness, provenance authentication,
symbol upload and release promotion are separate operations, not this result.

## Local recovery

Use **Local signing / build-input recovery**. Review and start an inspection
first; no saved configuration, version, Xcode or private input is required.
Recovery admits its own fixed security tool, not archive/signing tool authority.
Only the exact session offered by that same settled inspection can be reviewed
for ordinary account or project recovery. Account and project scopes do not hold
each other's locks. A new start consumes that inspection even if it is refused;
inspect again before another action. Busy/unknown owners must settle through
their original Status/Cancel. Conflicts are preserved; manual-required recovery
is explicitly unsupported here. No force cleanup or unrelated keychain reset is
offered, and a recovered account is not a new signed-release result.

## Ownership and verification boundary

The four dedicated Raw IPC commands are `prepare_ios_archive`,
`start_ios_archive`, `ios_archive_status` and `cancel_ios_archive`.
The renderer supplies saved comparisons and one-use consent, not tool paths,
commands, credentials, deadlines or native ownership. `IOSArchiveOwner` adapts
the existing `SavedCommandOwner` with independent iOS protocol/domain types.
The original document mutex guards admission; GO is released only after that
mutex is unlocked. Offline checks, Android builds, editors, credentials,
passive work and selection retain reciprocal admission gates.

Unsigned work is bounded by 5,400 seconds including startup, with finality at
5,410 seconds or first failure plus 10 seconds, whichever is earlier. Signed
work has the same 5,400-second ceiling, cleanup at 5,520 seconds and finality at
5,530 seconds. Recovery has 120-second work, 240-second cleanup and 250-second
finality ceilings. Signed/recovery cleanup and finality are shortened to first
failure plus 120/130 seconds, never renewed. Every entered command role needs
its original command-slot outcome/finality; an
aggregate dispatch Boolean alone cannot prove settlement. Unknown cleanup
remains retained and cannot become a new run or success after reconnecting.

Focused checks are in `tests/desktop/test_ios_archive.py`,
`desktop/src-tauri/src/ios_archive_protocol.rs`, the existing saved-command owner
tests, and `desktop/tests/ios-archive.test.mjs`. Inert fixtures exercise strict
DATA, saved-input retirement, one-use Start, inter-domain exclusion, bounded
frames, first-failure clocks and finality withholding. Genuine installed macOS
Xcode archive/failure/cancel/finality evidence, a valid signed export and paired
validation, and actual account-recovery/restoration evidence are required
separately. A valid signed export needs appropriate real signing inputs; a
synthetic refusal is not a successful export. No physical-Mac-only requirement
has been established for these local flows.

The separate engineering-only installed Mac observation uses the same original
application owners, a sealed document/owner-bound one-use token, and a shorter
300-second work / 310-second hard ceiling established at original Start. It
cannot change a shipping application's gate or accept renderer-supplied clocks.
Its finality case holds only the existing final observer; public completion and
conflicting work stay unavailable until that exact observer and watchdog join.
