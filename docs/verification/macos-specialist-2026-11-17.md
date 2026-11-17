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

## #46 First runtime connection "unavailable" (unresolved)

- During the first launch of the fresh 0.1.4 install, macOS attached
  `com.apple.macl` to the outer installed app bundle about 1.2 s after the
  payload process started. That is within the startup runtime inspection,
  which reads that bundle's tag and identity, ctime included. The unified log
  does not name the writer.
- A tag landing while the bundle is held maps to `Identity`, a different
  message from the one observed. It maps to the observed `Native` only inside
  the stat-stability window of one native read. This is a timed coincidence
  that also explains why no later start reproduces, but it is **not a proven
  cause**. No code was changed.

## #64 Protected Xcode resolver and `/Applications` (decision; no code change)

- Stock macOS `/Applications` is `root:admin 0775` with the Apple `sunlnk`
  flag. The native `metadata()` predicate (`mode & 0o7022 == 0`) and Python
  `_upload_protected` refuse it, so Xcode resolution fails on every standard
  Mac.
- Decision: this is a policy defect for this one fixed system ancestor. Admin
  group members can already sudo. The resolver already admits a user-owned
  `Xcode.app` alias there. Every lower component must still be root-owned and
  not group- or world-writable, and is held by FD with rechecks.
- Proposed narrow rule, pending owner/Lead approval because it relaxes an
  ownership check: accept only the held `/Applications` child of `/`, with
  exactly uid 0, gid admin, mode 0775, flags as held, empty ACL and no xattrs.
  All other ancestors keep the strict rule. Lead-owned #63 uses the same chain.
- Real-account Store/GitHub journeys remain blocked on accounts and owner
  approval.

## #30 Dependency recheck on `6dbd9543`

- cargo-audit 0.23.0 with a freshly fetched advisory DB (1,509 advisories,
  unchanged since 2026-11-16). App lock: 0 vulnerabilities. Unsound: tokio
  1.48.0 (RUSTSEC-2026-0386), rustix 1.1.5, glib 0.18.5. The
  `macos-android-register` and `macos-desktop-image` locks still pin vulnerable
  `ctutils 0.4.2`; those belong to their owners.
- The vendored `secret-service` and `zbus` crates' own lockfiles report
  ctutils/bytes/crossbeam-epoch advisories. Those locks are not used for the
  app build, which resolves them through the clean app lock. They are recorded
  for the next vendoring refresh.
- Installed security checks remain pending.
