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
- **Correction (Lead review).** An earlier note here said a local build
  cannot replace that step without source changes. That was wrong: it treated
  "the hosted producer always notarizes" as if it meant "local compilation
  needs source changes". A local test build is possible from unchanged source:
  - The workflow compiles the setup with an ordinary
    `cargo build --locked --release --no-default-features --features
    macos-xcode-setup --target aarch64-apple-darwin --bin
    mrk-macos-xcode-setup`, before any credential is admitted.
  - `build.rs` derives `MRK_XCODE_SETUP_REQUIREMENT` from the real pinned
    SOURCE profile and certificates. Those are fixed inputs; a caller cannot
    choose them.
- That exact argv was run locally on committed `8bf29633`, exported with
  `git archive`:
  - Rust 1.98.1, Command Line Tools SDK 26.5, jobs 1, under the unchanged
    3 GiB group RSS cap. Peak was 3,094,298,624 B and the original return
    was 0.
  - It used a new private target and a clean user LaunchAgent. No
    `GITHUB_*`/`RUNNER_*` variable was set and no credential was used.
  - Artifact: arm64, minos 26.0, system libraries only, sha256
    `a9249c37…cf8a`.
  - The embedded requirement is byte-identical to the build.rs derivation:
    team, leaf SHA-1, Developer ID OIDs and identifier.
  - With only the linker's ad-hoc signature, verifying against that fixed
    requirement is refused, as expected. That refusal is not qualification.
- **Where notarization is enforced.** The setup consumer does not check
  notarization:
  - `xcode_self.m`, `macos_xcode_source.rs` and `macos_xcode_carrier.rs`
    check the signature against the fixed requirement (offline), root
    ancestry, the exact embedded hooks, and the receipt and BOM.
  - None of them checks notarization, a ticket or `spctl`.
  - The hosted `finalize-xcode-setup-package` step requires notary
    `Accepted` and staples the package. Its signature parser treats the
    post-staple `Notarization:` line as informational only.
  - So notarization is a distribution guarantee, not a consumer requirement.
- **Local test route.** The hosted packaging tool refuses local context by
  design: `admit()` requires the fixed runner checkout and the hosted
  ref/event. It was not used or spoofed. Instead, a local test recipe repeats
  the credential-free component and product steps:
  - It uses the public stager subcommands
    `prepare-xcode-setup-scripts/-carrier/-product`.
  - It uses the same `pkgbuild`, `bsdtar`, `xar` and `productbuild` argv.
  - It calls the stager's own audit functions, unchanged.
  - A dry run with the unsigned helper passed every audit. It is labelled
    not installable and has no signature.
- **Pending owner-only steps:**
  - codesign and productsign by Keychain reference to the pinned identities.
    These may prompt; no key is exported.
  - A `pkgutil` leaf check.
  - An owner-run `installer`.
  - The result is LOCAL: not notarized, not stapled and not
    hosted-qualified. Signing is not an account action; notarization would
    be, and is not part of the local route.
  - The recipe and its evidence are in the private evidence store
    (`issue64-specialist-20261117/local-test-finalization/`).
- The companion has no OS ceiling: `mrk_platform` requires macOS 26 or later,
  and the package allows 26.0 or later. The app admits the protected copy by
  its root-protected chain alone, with no receipt. Host Xcode is 27.0 at about
  4.0 GB, and the data volume has about 13 GB free.
- Next steps. There are two separate routes, and only the second one produces a
  qualified artifact:
  - **Local test route** (unqualified; enough for local acceptance on this Mac):
    1. The owner, while present, runs the reviewed private finalization recipe.
       It first re-checks the pinned source manifest, then signs with
       codesign/productsign through the Keychain, then runs the `pkgutil` leaf
       check.
    2. The owner runs `installer` on that LOCAL package.
    3. The Specialist re-runs the resolver read-only against
       `/Library/MobileReleaseKitDeveloper/Xcode.app`.

    The result is not notarized and not hosted-qualified. It must not be
    distributed.
  - **Hosted distribution route** (qualified; needed before any release claim):
    1. Push the reviewed head to the absent `verify/desktop-macos-xcode-setup`
       branch, no force.
    2. Dispatch `operation=xcode-setup-companion` with
       `target=aarch64-apple-darwin`.
    3. Download the artifact and check `pkgutil --check-signature` and
       `spctl -a -t install`.
    4. The owner installs it and the resolver is re-checked as above.

  No agent push, dispatch, signing or root step was taken on either route.
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
