# macOS Specialist findings — 2026-11-17 (#17, #46, #64, #30)

Source checks only unless stated. Raw evidence stays private on the owner's
Mac. This page has no local paths, account data or private identifiers.

## #17 Git CLI journey: Finish refusal root cause (fixed in source, not yet installed-verified)

- Historical CI failure: whole-case deadline at `GitCli(Checked)`. The
  historical first error is still uncaptured. Repeated stdlib bytecode
  compilation in each helper interpreter is confirmed as a large cost, but it
  is not proven to have been the only historical cause.
- With the stdlib cache candidate on the installed runtime, all 8 CLI calls
  returned inside the unchanged 120 s case and every native Git stage
  completed. The observer then refused at `GitCli(Finish)`. That was not a
  deadline.
- Cause: the observer captures its fixture before OpenProject. When the
  disposable project folder is selected in the Open panel, macOS attaches its
  own `com.apple.macl` access tag to that root, which advances only the root's
  ctime. The Finish readback still required no xattrs and an unchanged ctime on
  the root. Retained installed evidence: every root that got past OpenProject
  carries the tag, with ctime 28–39 s after creation. The runs blocked before
  the selection have no xattr and an unchanged ctime.
- Fix `6dbd9543` (test observer only; the module is compiled only under
  `all(test, debug_assertions, …)`): the capture stays strictly untagged. At
  Finish, the root may differ only by exactly one bounded `com.apple.macl`,
  read with the existing strict native reader, plus a strictly later ctime.
  Roster, ACL, mode, owner, link count, size and mtime are unchanged. Any other
  xattr, or a ctime change without the tag, still refuses. The accepted root
  identity and tag digest are bound into `After` for every later readback. The
  rule is an inert DATA check executed by the compiled observer's
  `data-contracts`, which passed.
- Pending: the installed 120 s run with the fixed observer, the app's return
  and an independent readback. These need an owner-authenticated swap.

## #46 First runtime connection "unavailable" (unresolved; not reproduced)

- The observed text is produced only when the startup inspection itself
  returns `Native`. A failure in the later preparation step has a different
  message. The 0.1.4 code differs from the current code here only by the
  phase diagnostic.
- During the first launch of the fresh 0.1.4 install, macOS attached its
  standard `com.apple.macl` tag to the outer installed bundle about 1.2 s after
  the payload started. The same two-entry tag is on nearly every launched app
  bundle in `/Applications`. Never-launched bundles have none. The installation
  itself had finished 15 minutes earlier. The unified log names no writer.
- Correction (later the same day): calling this correlation "weak" was
  wrong. In a race emulation, the real native macl reader ran inside
  Book-like identity rechecks. 27.6–30.3% of single metadata changes that
  landed during the held-entry checks mapped to `Native`, and the rest to
  `Identity` (3 trials of 20,000 changes, clean launchd context). The real Book
  does more identity-only work while it holds the entry, so its ratio is lower
  and was not measured. The overlap is plausible, but it is not proven.
- A new, uniquely named ad-hoc bundle in `/Applications`, launched once through
  LaunchServices from a clean user LaunchAgent, got no tag. The real native
  reader admitted every cycle. The 0.1.4 tag landed on a root-owned,
  Developer ID-signed bundle. Creating it needs private-key use or root, so it
  was not reproduced. The probe was removed after its evidence was saved.
- Diagnostic loss fixed (`a7f046a7`): an app launched by LaunchServices has
  stdout and stderr on `/dev/null`, so the stderr step line from `1e7c4411` was
  discarded on ordinary first launches. The same fixed step code is now
  appended to the visible reason after the unchanged category sentence. The
  error code, retryability, category and finality are unchanged, and UI
  observers still match the category. `protected-application` is split into
  fixed sub-steps, and `protected-entry-attributes` isolates the outer-bundle
  macl window. This fixes the observability gap, not the runtime cause.
- The root cause is still unknown, and no retry or fix was added. Next evidence:
  one fresh install containing `a7f046a7` and the visible step on first launch.

## #64 Protected Xcode resolver and `/Applications` (boundary kept)

- The earlier proposal to relax `/Applications` is **withdrawn**. Stock
  `/Applications` (on this host: `root:admin 0775`, `sunlnk`, no ACL, no sticky
  bit) lets any process running as the logged-in admin user rename or replace
  entries without a password. Later steps run tools by path, so a swap after
  admission is detected only after use, not prevented. The refusal is a real
  boundary.
- The app's selection is correct. The protected copy at
  `/Library/MobileReleaseKitDeveloper/Xcode.app` is chosen whenever it is
  present. `/Applications` is used only when that copy is absent, and then it is
  refused. The Python and fastlane consumers apply the same predicate, and the UI
  already points users to the signed Prepare Xcode companion.
- On this host the protected copy is absent, so the refusal is the designed
  outcome. The remedy is an owner-run companion install, which the docs qualify
  on macOS 26 only. This host runs macOS 27.0.
- The companion's existing producer path is the `xcode-setup-companion`
  operation of the hosted installed-candidate workflow. It runs on a macOS 26
  runner, only on the `verify/desktop-macos-xcode-setup` branch (absent on the
  remote now), in the `macos-developer-id` environment. It signs with CI-held
  Developer ID Application/Installer P12s, notarizes with a CI notary API key
  and retains the package for 14 days. No such artifact exists: none of the
  1,514 repository artifacts is a companion.
- A local build cannot replace that step without source changes. The setup
  binary self-verifies against the exact pinned Developer ID leaf
  (`MRK_XCODE_SETUP_REQUIREMENT` from the reviewed signing profile), and the
  producer always notarizes. The pinned Developer ID Application identity and
  one Developer ID Installer identity are present and valid in the owner's
  keychain (read-only listing; no key access). Using them can prompt, and
  notarization is an account action.
- The companion has no OS ceiling: `mrk_platform` requires macOS 26 or later,
  and the package allows 26.0 or later. The app admits the protected copy by
  its root-protected chain alone, with no receipt. Host Xcode is 27.0 at about
  4.0 GB, and the data volume has about 13 GB free.
- Concrete next step (Lead/owner, in order):
  1. Push the reviewed head to the absent `verify/desktop-macos-xcode-setup`
     branch, no force.
  2. Dispatch `operation=xcode-setup-companion`,
     `target=aarch64-apple-darwin`.
  3. Download the artifact and check `pkgutil --check-signature` and
     `spctl -a -t install`.
  4. The owner runs `sudo /usr/sbin/installer -pkg "Prepare Xcode.pkg" -target /`.
     This is the macOS 27 qualification step.
  5. The Specialist re-runs the resolver read-only against
     `/Library/MobileReleaseKitDeveloper/Xcode.app`.

  No agent push, dispatch, signing or root step was taken.
- The 26.3 Xcode pin applies only to CLI `preflight` and to a desktop warning
  badge. The installed archive check and the companion accept any well-formed
  version, so host Xcode 27.0 is not an extra installed gate.
- `90f61a50` is a test-only fix. The structural test that pins this boundary had
  been failing at an outdated count since a managed-copy re-check was added, so
  its `/Applications` pins never ran. They run again now. Dropping the re-check
  or relaxing `0o7022` makes the test fail.
- Real-account Store and GitHub journeys were not run: they need accounts and
  owner approval.

## #30 Dependency recheck and IPC client review

- `cargo-audit 0.23.0`, offline, advisory DB `02e2517f`, `--no-yanked`. These
  categories are reported exactly. Zero vulnerabilities does **not** mean the app
  has no security defects.
  - App lock: 0 vulnerabilities (ctutils 0.4.4). 9 unmaintained. 3 unsound:
    tokio 1.48.0 (RUSTSEC-2026-0386), rustix 1.1.5 (RUSTSEC-2026-0486), glib
    0.18.5 (RUSTSEC-2024-0429). Yanked status was not checked.
  - `macos-android-register` and `macos-desktop-image` locks still pin
    vulnerable ctutils 0.4.2 (RUSTSEC-2026-0385). They belong to their owners
    and were not edited.
- The vendored `secret-service` and `zbus` crates' own lockfiles report
  advisories, but the app build does not use them. They are recorded for the
  next vendoring refresh.
- Android registration XPC client (`5066468f`, tests only):
  - An unconfigured signing profile leaves the peer requirement empty. The
    original gate then reports the service unavailable.
  - The client installs exactly one requirement before `resume`.
  - On this macOS, an ad-hoc peer answers when no requirement is set. Under the
    app's requirement template with synthetic identity values the same peer is
    refused (4102), and an empty requirement raises an exception.
- The vault helper is started from a fixed path with a cleared environment. The
  helper verifies its parent by exact cdhash. That side is helper-owned and was
  reviewed only.
- Still open: installed authentication, Keychain denial and peer checks. They
  need the owner.
