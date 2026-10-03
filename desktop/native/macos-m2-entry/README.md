# Synthetic fixed-entry feasibility — not installed-product qualification

This experiment asks whether a tiny stable entry app can acquire the original
shared maintenance lock **before** `execve` enters a separate full payload
bundle, while preserving useful macOS app identity, activation and normal Quit.
It does not implement the production M2 ABI, installer, updater or uninstaller.

## Fixed scope

Only the reviewed `desktop-macos-m2-entry.yml` push route is admitted: this
repository's `verify/desktop-macos-m2-entry` branch, exact detached source,
GitHub-hosted macOS 26 ARM64, original unprivileged `runner` account. No manual
command, application or directory selector is provided. Root must admit the
actual source and execution separately before publishing that route.

The adapter creates one fresh, private, run-bound `/private/tmp/mrk-macos-m2-entry-*`
namespace. The names `Launch Mobile Release Kit.app` and `Mobile Release Kit.app`
are synthetic fixtures there, **not** the installed application. Compile-time
constants fix their paths, source, bundle IDs, UID/GID and original gate device
and inode. The test gate is runner-owned 0444, not a claim of production
root-owned path authentication. The entry links only system libSystem/dyld;
`otool` rejects extra linked images, RPATH, dynamic-loader environment commands,
routine commands and initializer sections before any launch observation.

## Three observations, using the same entry image

1. With the adapter's independently opened EX held, direct entry refuses before
   exec (75). The payload bundle does not yet exist.
2. Without EX, that entry's real `execve` encounters the still-missing payload
   (ENOENT, 76). A separate-open EX probe establishes the original SH remains
   held at the failed-exec diagnostic; source retains it until `_exit`. Only
   after the original owned command has returned does the adapter acquire EX.
3. After creating the signed, standalone AppKit payload, the observer makes
   exactly one `NSWorkspace` launch of the entry. New instance is requested and
   running-app substitution/prompting disabled. The payload validates its
   inherited original descriptor and preserved PID, marks that descriptor
   CLOEXEC, and never closes or unlocks it before process exit. The observer
   matches the original returned app reference to the payload's own PID, tests
   independent EX refusal while alive, requests normal Quit using **only that
   returned object**, observes its terminated property, then probes EX again.

The NSWorkspace callback is concurrent; a main-queue handoff and atomic body
counts separate callback observations from main-thread app state. Work has a
fixed 30-second deadline, cleanup the original absolute 45-second deadline;
late completion may identify the original for cleanup but never renew work or
erase failure. The existing pinned `run_owned` bounds compilers, codesign,
inspection, direct entry cases and observer. There are no custom process
controllers, PID lookups, process scans, force-termination or permission repair.
The work deadline is irreversibly checked after setup/before launch, immediately
after the event pump, after record IO and after the final native observation.
An iteration that began in time cannot accept work completed at/after30s;
`workDeadlineFailed` makes that refusal explicit even when a late callback can
still identify the original app for cleanup before the unchanged45s limit.

## What a successful observation does and does not mean

`_NSGetExecutablePath`, `NSBundle.mainBundle`, payload `NSRunningApplication`
and the originally returned LaunchServices app are recorded **separately**.
Payload executable/main-bundle identity, visible window and actual activation
must match; an activation request alone is not a pass. Each running-app
identity must resolve to one of the two fixed synthetic identities, but they
need not all be identical: the report preserves which one was actually seen.
Any failure or unknown identity keeps `feasibilityObserved=false`.

Normal Quit must reach both delegate callbacks with SH still held at
`applicationWillTerminate`. AppKit does not return through main for normal
termination. The returned `NSRunningApplication` is **not an owned NSTask**:
its terminated property exposes no exit status or all-descendant finality.
The report therefore requires `originalAppExitStatus=null` and
`allWorkerFinality="not-established-by-NSRunningApplication"`. Callback body
counts are not OS-thread-join receipts. None of these diagnostic JSON records
is a process-ownership capability. `installedProductQualified`, `tauriQualified`,
`credentialQualified` and `maintenanceAvailable` always remain false.

The original controller/entry calls use the existing owner return contract.
Known completed compiler/controller outputs and their own temp directory may
be removed after complete native observation; the app gets a **separate**
explicit `app-tmp`. Synthetic bundles, app temp, gate and diagnostic records
remain for disposable hosted-job retirement, especially if app state is
unknown. No shared caches are deleted. Only bounded normalized JSON (plus
bounded public-source compiler-error excerpts when applicable) is uploaded;
OS stderr is bounded and hashed, never exported as a transcript or used as a
success receipt. No project, signing input, Keychain, Store operation or release
is involved. Local DATA tests validate parser/refusal boundaries, not AppKit.

## Apple authority and remaining engineering limits

Apple's XNU `execve(2)` documents non-CLOEXEC descriptor, UID/GID and PID
preservation; successful exec does not return. `flock(2)` is advisory and the
original open description's lock must not be converted/unlocked through a
duplicate. Apple's `NSWorkspace.openApplication` documents a concurrent
completion containing the launched app reference. `Bundle.main` describes the
bundle containing the current executable, not LaunchServices registration.
`NSRunningApplication.terminate()` means a request was sent; its `isTerminated`
property is separate. `NSApplication.activate()` is not guaranteed activation;
`terminate(_:)` documents delegate cleanup rather than code after main's run.

These are authority for the narrow source design, not proof that LaunchServices
identity transfers across exec. Only the actual native result can resolve that
question. Neither this AppKit probe nor Linux DATA tests qualify Tauri,
credential-caller authentication, the production retained-entry layout, ten
runtime constructor joins, the vault helper, 3/8-FD child transfers, provider
re-entry, capacity accounting, update/remove or distribution.
