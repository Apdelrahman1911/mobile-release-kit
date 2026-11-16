# Scoped macOS security review — 0.1.4 (#30)

Scope: the isolated `fix/macos-remaining-essential` source branch, based on
`c52b57a5`, reviewed 2026-11-16. This is not a release approval or a complete
cross-platform #30 sign-off. No credential, Keychain item, installer, installed
app, helper registration, repository setting or publishing workflow was changed.
Windows/Linux implementation review and signed installed acceptance are deferred.

## Findings and disposition

| Priority | Finding | Disposition |
|---|---|---|
| P1 | Application crypto graph locks vulnerable `ctutils 0.4.2` | Application `desktop/src-tauri/Cargo.lock` updated narrowly to `0.4.4`; no other package/version or manifest changed. |
| P1 coordination | `desktop/helpers/macos-desktop-image/Cargo.lock` and `desktop/helpers/macos-android-register/Cargo.lock` independently lock `ctutils 0.4.2` | Unchanged to avoid competing helper/image edits. Those graphs must be updated and checked by the owning/integrating agent before a release verdict. |
| P2 coordination | Exact `tokio = 1.48.0` pin has an I/O-safety advisory | Runtime/helper version coordination required. No direct `AsyncFd` use found in application source; no app exploit is established. Do not silently suppress the advisory. |
| P2 other target | Locked `rustix 1.1.5` has an xattr-buffer advisory; `glib 0.18.5` also has an unsoundness notice | `rustix` has no path in the actual macOS ARM UI dependency tree; its exact direct pins and GTK/glib are other-target work. No unrelated-platform upgrade was made. |
| P2 owner setting | Release issue records repository-level signing secrets | Environment protection/scoping needs owner settings work outside this task. No secret value was read or posted; no workflow trigger, environment or setting was changed. |

The crypto finding is [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html):
mask generation could introduce secret-dependent branches; the advisory's patched
range starts at 0.4.4. The actual ARM app graph includes the package through
`digest`/HMAC/SHA2 and Poly1305. Updating the main lock does **not** update the
independent shipping-image/helper locks, so the integrated release remains gated.
Functional tests do not prove constant-time execution; this uses the upstream
patch and its published verification.

[Tokio RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html)
concerns safe AsyncFd constructors accepting raw descriptor wrappers; patched
ranges include 1.51.6–1.51.x and >=1.53.3. A root manifest pin change would also
require coordinated helper/image lock updates and runtime/finality regression
checks. The issue is recorded rather than creating inconsistent locked graphs.

Reopened verification confirmed that the helper image manifests depend on the
app crate by path. A trial app-only exact pin update to 1.51.6 (and its required
tokio-macros 2.7.2) removes the Tokio notice from the app audit, but both untouched
helper image roots then fail `cargo metadata --locked` because their independent
locks still contain 1.48.0. The trial was withdrawn; the root manifest/lock are
restored to the committed versions, and no helper file was edited. The exact
two-file patch and audit are retained privately for a coordinated lock refresh.
The trial's own source-check supervisor was explicitly stopped and joined after
670.168s while compiling the unchanged catalogue; return -9 is **not a pass**.
Its updated Tokio dependency had checked, but the full app had not. Existing
full current-lock source-check receipts apply to the restored committed graph.
Do not merge the saved trial without updating and verifying both owned image
locks together. This is a real ownership/dependency gate, not a helper-free fix.

[Rustix RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html)
concerns zero-length xattr buffers being marked initialized, patched in 1.1.6.
The macOS ARM tree with `desktop-shell,custom-protocol` reports no dependency on
that version. The existing Linux/Windows exact pins are outside this Mac task.
Unmaintained dependencies and the GTK notice remain in the all-target lock scan.

## Source review

- CSP admits only packaged scripts/styles/fonts, self/data images and the IPC
  endpoints. It denies objects, frames, forms and base URL changes. The single
  capability is local `main`; its only generic core permissions are event
  listen/unlisten. It grants no generic shell, filesystem, opener or HTTP API.
- All 335 registered command names match their build declarations, generated
  handler list and explicit custom capability grants. This is a complete surface
  inventory, not proof of every native implementation. Hand review followed
  app capabilities/project queries, document loss/navigation, credential inputs,
  vault codec/keyring transport and fixed helper admission paths.
- `shell.rs::trusted_document` restricts scheme/host, normalized root path,
  credentials, port, query and fragment. Navigation and content-process loss
  feed the existing original document owner. `bridge.rs` passive/project queries
  pass that original binding; grants and confirmations remain native decisions.
- Credential `Fields` is write-only, has no production Debug/Deserialize/readback,
  and wipes its owned strings on drop. Vault payloads use bounded authenticated
  encryption and zeroizing key buffers. This does not claim erasure of OS or
  renderer copies. Credential and project source values were fictional fixtures.
- Root/project custody retains filesystem identities, no-follow descriptors,
  explicit revisions and finite original operations. The #17 ancestor fix keeps
  project/candidate flags strict; #65 preserves changed journals and first errors.
- Read-only helper review found fixed signing requirements installed on the
  original XPC connection before resume, fixed service/protocol roles, bounded
  wire frames, and code/runtime/UID checks. No arbitrary path/process capability
  is supplied by decoded wire data. Decoder tests are not live peer qualification.
- The packaged entitlement file is empty. Source inspection of signing steps
  found private umasks and secret inputs supplied through job environments.
  Neither a signing job nor an installer was run. Repository-level secret policy
  remains an owner setting gate, as already noted by #30.

## Audit and test evidence

- `npm 11.6.2 audit --omit=dev`: zero reported production vulnerabilities.
- RustSec `cargo-audit 0.23.0`, official ARM binary verified against release SHA256
  `84101204e5b8013c9a8d7251766aebdef3e7fa1a3ef040cde44d65b48b8c4056`.
  Advisory DB commit `02e2517f457a359fc6d3440ea4560c8ea188fee8`, 1,509 advisories.
- Main lock before: one vulnerability (`ctutils`), nine unmaintained notices,
  three unsoundness notices and a yanked `yoke-derive` warning. Registry yanked
  queries also timed out; that initial result is retained separately.
- Main lock after: zero vulnerabilities, nine unmaintained and three unsoundness
  notices, using the fetched DB with `--no-fetch --no-yanked`. Yanked status was
  deliberately not rechecked; this is not an all-warning clean result.
- Independent native/vault-helper/GitHub-seal locks: zero vulnerability notices;
  Android-registration and desktop-image locks: the same ctutils vulnerability.
- 91 credential/metadata/secret-input tests: 90 pass; one distinct case-alias
  fixture skips on case-insensitive APFS. The hardlink test now uses a genuinely
  distinct name, so it no longer deletes its canonical fixture on APFS.
- Seven actual native-independent query/maintenance wire tests pass. They use
  only closed data/decoder functions; no helper connection or lifecycle runs.
- Targeted frontend security/credential/capability tests pass, and the prior
  complete frontend suite passes. The patched ctutils package checks with
  Rust 1.98.1, one job, under a separate 512 MiB compiler cap.
- An attempt to run dependency unit tests directly via the application package
  was refused by Cargo because dependency dev tests are outside the workspace;
  it is not reported as a passing test. Full current-lock and installed-cli source
  checks subsequently pass with Rust 1.98.1, one job, peak RSS below 3 GiB.
- Reopened credential regressions: 91 tests, 90 pass and one distinct case-alias
  skip on APFS; all 67 focused frontend credential tests pass. These checks do
  not prove a previously observed native security exploit was reproduced.

## Additional Store boundary findings (#64)

The Python fixed CLT provider rejected system-protection flags accepted by the
existing native policy. It now matches that exact mask and compares observed,
held and named flags on every check; permissions, identities and executable
selection remain strict. Four flag regressions and 188 provider/source/owner
tests pass with inert provider/native outcomes, not live peer qualification.

The real protected Xcode resolver refuses this host's root-owned 0775
`/Applications` ancestor in `local_store_execute.py::_upload_protected`.
This is an actual host-protection gate, not evidence that tool help or a leaf
hash grants safe pathname execution. No group-write allowance, chmod, installer
or helper change was made. Coordinate native tool-selection/installation policy
and protected-host qualification with the #47–#49 owner before Store acceptance.

## Integration gates

Coordinate the two affected helper/image locks and the pinned Tokio runtime with
#47–#49 owners. Repeat dependency and source/installed checks on the eventual
integrated commit. Live peer-authentication negatives, Keychain denial/lock,
installer privilege/signature checks, helper approval/shutdown, and signed
installed path protection remain separate acceptance evidence. No installed
security verdict is inferred from static review, data fixtures or compilation.
