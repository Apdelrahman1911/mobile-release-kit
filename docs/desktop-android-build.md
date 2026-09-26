# Saved Android build and inspection

**Implementation status:** the core service and guided Desktop controls are
implemented in preparation source, but execution remains disabled pending
runtime/toolchain custody and native platform qualification. This is not a
production-ready release feature. No availability flag is enabled by this document.

## What this action is for

The **Build Android app** flow in Releases is designed to build one
explicit Android application module and variant, then inspects one captured AAB
(Android App Bundle). It uses the existing Mobile Release Kit core rather than
running the CLI or parsing console output.

- **Saved configuration and version:** the action uses the files saved in the
  selected project, not unsaved form values. Review shows the same saved version
  used for the build and inspection. If either file changes, refresh and review
  again; old consent cannot authorize the changed files.
- **Application module:** this is the Gradle module containing the Android app,
  for example `:app`. It must be explicitly configured; the action does not guess
  between multiple apps. A variant such as `release` selects its bundle task.
- **Tools:** a separately approved JDK, Android SDK, Gradle and bundletool profile
  is required. An installed Java executable or a successful environment check
  alone does not qualify it. The first profile targets Linux GNU x86_64; macOS
  and Windows require their own implementation and native verification.
- **Optional upload-signature inspection:** **Also verify upload signature** is
  off by default. Turn it on before reviewing saved inputs to check signature
  integrity and compare the captured bundle's signer with the saved upload
  certificate SHA-256 fingerprint. The same protected JDK must also supply
  `jarsigner` and `keytool`; their presence alone does not qualify this mode.

## Which certificate fingerprint to save

For a Play-managed app, open **Play Console → App integrity → Upload key
certificate** and copy its SHA-256 fingerprint. This is the **upload** certificate,
not the **App signing key certificate** used by Play for distributed apps. Save
the public fingerprint in Android's upload-certificate field as exactly 64 hex
characters, without colons. Do not enter a keystore, private key or password.

The review displays that saved value, not an editable override. Changing the
inspection choice or saved inputs retires the previous review; acknowledge the
new review before starting. An already started build retains its original
choice and Status/Cancel controls.

## Local prerequisites and availability

Provide a compatible, user-installed **JDK and Android SDK**. Execution uses one
selected, protected Gradle distribution and the pinned bundletool, not whichever
wrapper, Java installation or cache happens to be found. The selected tools,
their dependencies and required native helpers must be admitted into the exact
protected profile. This action does **not** install/update an SDK or JDK,
download tools, accept licenses, or repair a partial installation.

Use **Environment Requirements** for setup guidance. **Tools** diagnostics only
observe Git, Java and Javac; they do not inspect the Android SDK, prove Gradle or
plugin/dependency readiness, or grant build authority. Keep these distinctions:

- **Missing:** a required item was not found in an admitted lookup.
- **Unselected:** an installation may exist but is not the selected profile.
- **Unsupported:** the host or installation shape is outside the implemented profile.
- **Not inspected:** there is no observation of that prerequisite.
- **Unqualified:** the runtime/toolchain/native gate is closed, even if tools exist.

A disabled action or closed qualification gate is **not evidence of a missing
SDK**. Installing another SDK cannot itself qualify this action.

## Review before starting

Building runs the project's Gradle scripts and plugins. Use only a project you
trust: those programs can change files, access same-user resources, start helpers
and make network requests. A private working directory is **not a sandbox**.

The toolkit does not request signing, read signing credentials, contact a Store,
or publish a release in this action. Project code may nevertheless sign the
bundle itself. Without the optional checkbox, its signature and signer are
explicitly **not inspected**. Offline checks remain a separate build-free action
and never implicitly start this build.

## Reading a result

Task completion, bundle structure, native application/version checks and release
readiness are different facts. Inspection may complete and report an invalid
bundle. Missing or unsuccessful native inspection cannot become a verified
application/version result.

With upload-signature inspection selected, the result separates **signature
integrity** from **matches saved upload certificate**. A match requires both
checks to pass on the same captured bytes. An unsigned, tampered or wrong-signer
bundle is a negative validation result even if the build and inspection finish.
Failed signature verification skips the signer comparison; it is not a match.
These checks do not establish that the saved upload certificate is enrolled in
Play or that the bundle is ready for Store submission. Results are shown only
after the original native operation and cleanup have settled.

The captured bundle may be incremental, reused or stale output. A zero-exit
Gradle task and a matching version do not establish that the bytes were produced
from the current source. Local size/hash/ABI observations are not authenticated
candidate evidence, approved signing identity, upload authority or promotion
history. Optional mapping and native-symbol outputs are outside this first slice.

## Cancellation, failures and retained files

Cancel requests that the original operation stop; it is not rollback. Completion
requires the original process, readers, tools, workspace, project and input owners
to settle. Until then, the application must keep showing the original status.

- A known task failure reports its observed exit outcome without exposing
  private compiler output. Never search an older output directory for a substitute.
- A changed input or artifact requires a new review after the original operation
  settles. There is no automatic retry of an ambiguous start.
- Unconfirmed cleanup remains **unknown** and blocks new execution; a result
  message or closed window cannot clear it.
- Task-private work is removed only using its original bounded ownership records.
  Unrelated project outputs and shared caches are never adopted for cleanup.
  Uncertain leftovers are retained and reported, not silently deleted.
- A complete local result intentionally retains its captured artifact. An
  incomplete retained artifact is not promoted into a successful result.

The UI keeps the original build's Status and Cancel controls available when
navigating elsewhere. Its result also appears in Artifacts without being promoted
to authenticated candidate evidence. A lost acknowledgement never automatically
repeats Start; unknown cleanup remains blocking. These controls and contextual
help do not replace actual runtime/toolchain and native platform qualification.

## Installed-native engineering candidate (source only)

The candidate appends four fixed GUI cases to the existing twenty:
a real Java-only AAB build and inspection, a deliberate Gradle failure, cancellation
after an observed active Gradle task, and consent-bound saved-version drift.
They use the existing installed shell, core engine and original Android owner;
they are not Tools/Offline tokens or a second build launcher.

The fixture selects a **file-only** protected Maven repository at
`gradle/repository`, including the authenticated AGP plugin marker and complete
transitive dependencies. Those files/directories count in the existing manifest,
custody and caps. Gradle offline mode is set before plugin resolution.
This fixture policy is not network isolation: `PrivateNetwork=no` is unchanged,
and trusted project code still has ordinary same-user effects.

JDK17 / Gradle8.14.5 / AGP8.9.2 / android-35 / build-tools35.0.0 /
bundletool1.18.3 is the **selected material tuple**, not a natively qualified
combination or a complete authenticated OS closure. Concrete reviewed material
selectors are absent (`SHELL_ANDROID_MATERIALS=None`); the compiled OS contract is
also absent. Missing bindings refuse before fixture creation or compilation.
There is no download, ambient-cache fallback, installer or guessed hash.

The source-only root publication branch now accepts bounded references to the
strict manifest, exact OS contract and complete source rows. It checks fresh
root-owned tool copies, exact membership/bytes/modes/links/attributes, publishes
the manifest last, and rechecks the same protected profile after its consumers
settle. Partial failures retain accounting and never authorize app launch or
cleanup of unrelated files. Its publication DATA is still absent; these source
contracts and mocked failure tests are not an installed or native success.

The saved-version refusal expects **zero Gradle/bundletool attempts**, not zero
core children or zero custody. It changes the consent-bound version bytes, not a
harmless wrapper comment, and does not claim native wrapper/property-policy
coverage. Generated AAB/cache/compiler-output bodies are not scanned or exported
by the fixture inventories; only25 original source controls and fixed generated
root metadata are accounted for after original Exit.

These four cases have not been executed or accepted as native evidence in this
source stage. They do not discharge W3000 expiry, private-JVM/property policy,
no-auto-install, or every native-helper obligation. Original consent300s,
W3000/H3010, `min(H,F+10)`, the shell45s/outer60s limits, aggregate caps and
original StopPost finality remain unchanged. Ordinary Android qualification flags
stay false. Normal activation and a no-grant normal-app smoke check require their
own later review and evidence; a local result is never freshness, signing,
release readiness or Store authority.
