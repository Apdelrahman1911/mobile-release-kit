# Reopened essential macOS verification

No claim is made that all ten original assigned issues are fully resolved.
Diagnostics, source checks and adjacent fixes are evidence for their specific
boundaries, not substitutes for reproducing the original failures. All changes
remain on `fix/macos-remaining-essential`; no installed app, helper, real project,
release, workflow, other agent's branch or account was changed.

| Issue | Original reported problem fixed? | Root cause eliminated? | Original failure reproduced and verified absent? | Evidence and remaining gate | Status |
|---|---|---|---|---|---|
| #45 | Not established | Original cause unknown; a separate unsafe error-boundary accessor was fixed | No. Historical `ac506bb3` and current frontend both survive the controlled approval journey | Sixteen mounted-React scenarios; real macOS 27 WKWebView DOM/effects approval→settings→focus→enabled journey on both trees returns 0 without a fatal boundary. Native helper DATA is controlled; no fresh OS helper registration/approval occurred | **Unresolved original incident** |
| #46 | No | No failing native predicate or first-launch race identified | No original first-connection failure reproduced | Two phase-diagnostic Rust tests and full source checks prove diagnostics preserve the failure, not that Native inspection succeeds on first launch. An independently built executable cannot satisfy the fixed installed-payload identity proof | **Unresolved** |
| #17 | Historical Checked timeout not fixed | Historical pending call unknown; separate Darwin ancestor-flags initialization cause was eliminated | Initialization refusal reproduced/fixed; historical `GitCli(Checked)` deadline not reproduced after a fix | 660 Git core/worker tests: 656 pass, four explicit skips. Exact original job log recovered and hash matched; its timings show the case deadline was nearly exhausted before Checked, without an original pending-call return. Eleven installed groups remain open | **Unresolved original timeout** |
| #65 | Verified for five core write domains; not installed app state/shutdown | No corruption found in the exercised cases. A stale-journal error-classification defect was fixed | Actual disposable writers were killed and fresh processes recovered whole old/new files | Twenty SIGKILL/recovery cases across metadata text, version, images, Android identity and iOS identity; two additional abrupt-exit cases. Original process finality precedes recovery and cleanup. Installed GUI restart, shutdown and power-loss acceptance remain open | **Partially resolved / verified** |
| #66 | Only the measured quadratic path-comparison bottleneck | That algorithmic cause was eliminated; no app-wide performance cause established | Old/new algorithm directly compared; original installed performance acceptance not completed | Reproducible 512-path benchmark, 10,000 controller cycles and 100 real WKWebView mount/navigation/unmount cycles. No whole-app idle/startup/one-hour measurement or agreed device budgets | **Partially resolved** |
| #30 | App crypto dependency patched; review not signed off | Crypto cause patched in app lock. Tokio requires a coordinated app/helper lock refresh; an incompatible app-only trial was withdrawn | Dependency audit identifies affected versions; no app exploit reproduced or claimed | Credential, wire and frontend security checks; scoped source report. Independent helper crypto locks, Tokio synchronization, installed peer qualification and accepted-risk/release review remain gates | **Partially resolved** |
| #50 | Intended refusal now has actionable guidance; granted installed status not proven | The recorded unavailable response is the explicit read-access gate, not evidence of a CLI crash | Formatter behavior verified; installed grant→status success not reproduced here | Three actual shared Rust formatter tests, 58 frontend access tests and installed-cli source check. No authority check was bypassed | **Partially resolved** |
| #62 | Android source/version/identity fixture journeys work; full installed journey not proven | No original Android failure isolated; fixture missing module selection corrected | Fresh offline Gradle debug build succeeds after actual version and identity transactions; APK package/version verified | Prior 180 tests plus 75 fixture/identity regressions; whole build tree monitored and retired. Installed tool acquisition/registration, UI and signed/account/device paths remain open | **Partially verified** |
| #63 | Unsigned iOS source/version/identity fixture journeys work; full installed journey not proven | No original iOS failure isolated; fixture uses the editor's conventional xcconfig policy | Fresh simulator compile and unsigned Debug archive pass after actual version and identity transactions; core inspector accepts new bundle ID/version | Prior 63 tests plus 75 fixture/identity regressions. Installed tool binding, signing, physical-device and account paths remain open | **Partially verified** |
| #64 | CLT provider flag mismatch fixed; Store acceptance incomplete | Exact Python/native flag-policy mismatch reproduced and eliminated; protected Xcode host refusal remains | Source policy regression is covered; no Store-account journey claimed | 136 network-denied provider contracts, 52 source/owner, 52 preparation/recovery and 51 frontend tests pass. A 92-test host set has 90 passes, one filesystem skip and one real protected Xcode ancestry refusal. No accounts, Store mutations or relaxed writable-ancestor policy | **Partially resolved** |

## New original-boundary evidence

The #45 retained owner log contains no original React exception; the historical
boundary discarded it. The controlled macOS test now exercises real React
effects and DOM, rather than only a static render. Both the historical and
current tree pass. This is explicit non-reproduction, not a verified fix for
the old incident, and it does not depend on the owner remembering missing text.
The historical core was then used directly: capability/version payloads match
current responses, with only the snapshot timestamp differing. The historical
and current App also pass with the real installed-profile description fields
and bundled runtime mode during unavailable initialization. These remain
controlled DATA cases, not actual OS helper approval or a verified incident fix.
Two additional probes attempted helper approval before runtime reload, with
and without selecting a project. Both stop at an unavailable helper control
and return 1 with `fatal: null`; neither reaches helper approval or reproduces
the incident. These are incomplete ordering probes, not passing approval tests
and not product crash regressions. No guard was bypassed to force that path.
The reachable historical sequence (unavailable focus return → explicit reload →
project selection → approval journey) then returns 0 without a fatal boundary.

For #17, the recovered original job log is 86,817 bytes and SHA-256
`3d7ee0d62851b4ea90536b95be53f436a7496c6d1f1df79397f516ab15163708`,
matching the reported original evidence. Its recorded read wait is 20.062240s,
Prepare 29.020745s and terminal/Apply observation 35.279288s; Checked is still
pending at the case deadline after another 5.675875s. This narrows profiling
to earlier work and the final pending calls. It does not prove those calls
returned or justify extending the deadline. The source trace preserves that
distinction. No artifact containing a more precise original failing call is
available from that run.

## Why original acceptance remains incomplete

The original #65/#66 acceptance issues require a qualified #57 installed
candidate. The original Native inspection and Git observation also require
the fixed protected installed identity. Building/installing another candidate,
resetting helper approval, altering the installed app and changing workflows
are explicitly excluded from this task. No test-only identity bypass was added.
Source/test binaries and disposable project operations remain permitted and
are reported separately. Store and signed mobile journeys additionally need
credentials/accounts/devices that were neither supplied nor accessed here.

These are concrete experiment boundaries, not assertions that an unknown bug
is fixed. No issue is closed and no release readiness is claimed.

## Reopened work checklist and commits

All items below are completed experiments/reviewable changes; they are not
claims that the corresponding original issue is closed.

| Issue | Follow-up commit | Completed work | Outstanding verification |
|---|---|---|---|
| #45 | `d36d49b2` | Historical/current React matrix, actual macOS WKWebView approval journey, historical-core and installed-profile cases | Original failure and actual clean helper-approval boundary |
| #46 | `eef946ee` | Native startup/protected-payload path traced; helper wait rejected as unsupported | Original failing native predicate and first-launch success |
| #17 | `109e597d` | Exact original job log/hash recovered and step timings analyzed | Pending call/root cause and installed Git groups |
| #65 | `d902dbf3` | Twelve new actual SIGKILL/recovery cases; 57-test recovery regression group passes | Installed GUI/app state, shutdown and power-loss boundaries |
| #66 | `f8720a3e` | 100 actual WKWebView mount/navigation/unmount cycles retire subscriptions and DOM | Installed startup/idle/large-project/one-hour measurements and budgets |
| #30 | `dd5ff4d0` | 90/91 credential and 67 frontend checks; exact helper-lock dependency confirmed | Coordinated crypto/Tokio locks and installed/security-review acceptance; incompatible trial withdrawn |
| #50 | `39408f3d` | Exact original response traced; three Rust and 30 focused frontend tests pass again | Installed explicit grant → successful status → revoke/expiry |
| #62 | `f3c55ec1` | Actual version+identity edit → fresh APK, package/version verified; 75 tests pass | Installed protected tool/helper and complete UI/signed journeys |
| #63 | `855d4e35` | Actual version+identity edit → simulator build and unsigned archive/core inspection; 75 tests pass | Installed and signed/device/account journeys |
| #64 | `dc523f32` | Python/native protection rules compared; 69/70 Store checks pass with one skip; real positive host qualification remains failed | Protected Xcode execution and approved account-backed readbacks |

The source files under `desktop/src`, `desktop/src-tauri` and `src` are identical
to the previously fully source-checked `2e8f6c1d` tree. New tracked implementation
in this reopened pass is test infrastructure and disposable fixture coverage;
no additional production fix is represented as a remedy for an unreproduced
original incident. The per-issue earlier commits and their exact scope remain
listed in `macos-essential-progress.md`.

Final shared verification passes all 100 tests in 27.584s, including the actual
crash/recovery matrix and both buildable version/identity fixtures. Machine-
readable numeric receipts and output hashes are in
`macos-essential-reopened-checks.json`; overlapping suites are not summed as
unique tests. The failed Store host qualification and withdrawn compiler trial
are retained explicitly.
