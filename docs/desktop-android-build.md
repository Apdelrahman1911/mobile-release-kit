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
