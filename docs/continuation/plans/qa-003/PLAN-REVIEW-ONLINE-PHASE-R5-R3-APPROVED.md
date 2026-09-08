# QA-003 independent online-phase amendment review R5-R3

**Verdict: APPROVED, for the revised plan only.** The narrow amendment restores
supported online diagnostic independence without authorizing work after fatal
lifetime uncertainty. No current implementation, whole-diff, full-suite or
production-readiness approval is implied.

## Exact reviewed authority

Final `PLAN-ONLINE-PHASE-R5-R3.md` SHA256:
`e35548e88988cd14cc9a8f2aa01bce2b2ba96360ccf39171cdc02fa941c75b2a`.

The initially submitted hash
`376eb263d532cf6b7d89b66691ed72be995b76f0af8beca00ff71022160f0a8e`
needed the ADC correction described below; it is **not** the approved version.
All non-overridden approved R5-R2/R4/R3/R2 obligations remain applicable.

Baseline HEAD `2beb37336fa8002b69f598fe431082606368310d`, tree
`00f3acee00c994e6e81470cc76e42f1f2108fcdb`, version 0.3.0, branch
`fix/qa-003-local-signing-lease`. The working tree contains partial R5-R2 and
previous QA-003 implementation. The online amendment was not implemented at
review close. Review-time file hashes are recorded in the companion evidence
JSON; this is not a final immutable implementation inventory.

## Independent review basis

Re-read the original QA-003 overlap finding and relevant R1 implementation
review/lifetime scope; the complete revised amendment; the approved R5-R2 phase
contract and R3 caller map. Inspected current doctor/preflight phases, fatal
runner conversions, credential requirements/resolution/material validators,
query-specific blockers, environment wrapper, Store online adapter, fixed
Fastlane online lanes/readback consumers, CLI run-build suppression, report
status computation, original online test assertions and relevant integration/
credential/troubleshooting documentation.

The 88-test development log was inspected, not independently rerun in this
review. It reports four errors, not a passing check. The errors are consistent
with the blanket report gates suppressing supported diagnostics/query behavior;
a successful online ownership query must remain possible for an unverified
identity while the overall report stays failing.

## Initial contradiction and reviewed correction

Initial step 2 required inventory gating before private Store-material
validation, but one of the four preserved regressions requires
`credential-material.google-adc` MISSING. Actual candidate Store inventory
already emits `credential.candidate.android.google_application_credentials`
MISSING when only WIF provider/account declarations exist. Consequently the
proposed earlier gate would skip the only producer of that material diagnostic.

Independent probe `plan-review-online-prerequisites-r5-r3.py/json` executes the
actual inventory, query-blocker and Android absence-diagnostic helpers on a
fictional project. It observes both distinct codes and proves the inventory
blocker would skip the original material diagnostic. No native validator,
credentials, keychain, Store or background process is used.

The revised step 2 explicitly shares the pure missing-ADC prerequisite diagnosis
between online preflight and the Store material validator. It does not open/read
files, create scratch or execute native commands; mixed-platform missing ADC can
therefore stop before P8 validation while preserving the existing diagnostic.
The test list now requires this exact case and side-effect-free helper behavior.
This resolves the original contradiction without weakening the earlier gate or
invoking private validation merely to produce an absence message.

## Why the final amendment is sound

1. **Different phases have different prerequisites.** Build signing, symbol and
   review completeness are not authorization requirements for the existing
   non-publishing Store ownership/track/group/build-uniqueness query. The helper
   can retain those failing findings while checking the query's actual version,
   enabled platform, explicit blocked identity, destination and Store credential
   requirements. `unverified` differs from explicitly `blocked`; no query result
   edits configuration or upgrades an identity to approved automatically.
2. **Fatal uncertainty is not an independent diagnostic.** Fatal ProcessError
   escapes doctor/material/runner conversion before ordinary CredentialError
   handling. Query-specific inventory/material failures still stop private/API
   phases. The amendment does not relax offline/signing first-failure gates or
   permit a secondary cleanup exception to advance a phase. An unhandled
   expected/unexpected failure is not permission to continue with an empty list
   or fabricated successful material result.
3. **The online branch cannot fall through to builds.** Separate return flow
   must hold even for direct internal `run_builds=True`; no project checks,
   effective Gradle/Xcode identities, signing materialization or build runner.
   Existing CLI suppression (`cli.py:453-466`) is defense in depth, not the
   helper's only protection. Store-purpose credential filtering excludes build
   signing and project-read capability; inherited ambient capabilities remain
   scrubbed before the actual Store adapter.
4. **Store scope is unchanged.** The fixed Android lane
   (`fastlane/Fastfile:1767-1805`) inserts its inspection edit, reads tracks/
   bundles/tester assignment, writes readback and deletes without commit. The
   fixed iOS lane (`2057-2079`) reads app/group/build state. The amendment does
   not introduce uploads, promotions, metadata writes, submission, retries,
   source adoption or public release. Existing request/network ambiguity limits
   of those adapters are not being newly certified by this plan review.
5. **A query PASS is not toolkit readiness.** Original failing report findings
   remain; `Report.ok` still derives from all failing statuses. The final tests
   must verify failing report/CLI result after an otherwise successful ownership
   query, not merely the presence of its PASS finding. Missing version,
   blocked/disabled selection and missing destinations stop before private
   validation or a Store request with an actionable prerequisite SKIP.

## Mandatory validation and remaining scope

Preserve all four original cases and the negative development log. Add the
revised pure ADC/mixed-platform case, ordinary unrelated doctor failure with
query PASS/overall FAIL, and no application/build/signing work for online mode.
Exercise blocked/missing/disabled/version/credential/material ordering. Fatal
injections must include both uncontained groups and contained but incomplete
cleanup through actual public online callers, plus secondary cleanup masking
that cannot execute another validator/platform/Store command. Use real control
flow and sentinels rather than only text assertions or exceptions tested in
isolation. Existing per-R5-row and real-descendant regressions remain mandatory.

The changed helper's static behavior must be verified without reading a private
file simply to diagnose absence. A malformed present ADC still needs its existing
private-path/structural validation before use; the pure helper cannot turn mere
presence into authorization. No duplicated contradictory prerequisite findings
or fake success should be added to make the old assertions pass.

Only the explicitly described preflight/shared prerequisite helper, focused tests
and relevant docs are authorized by this amendment. Distinct complete actual-
diff review, R6's native-active matrix and the frozen full project gates remain
required. QA-004/QA-005, remaining original findings and the fresh complete audit
are not closed. This review performs no live Store or real signing rehearsal.

## Execution and cleanup evidence

Executed (exit 0):

```sh
.mobile-release/remediation/MRK-002/venv/bin/python -I -S -B \
  .mobile-release/remediation/QA-003/plan-review-online-prerequisites-r5-r3.py
```

This is a plan contradiction/helper-flow probe, **not** a passing implementation
regression. `git diff --check` also exited 0 as an interim whitespace check, not
final verification. The companion evidence records exact source/result hashes.

Reviewer changed only ignored QA-003 report/probe/evidence files. Synthetic
resources were removed after observation; no reviewer build/background worker
remains. Source, tests, public docs, index/refs and user AGENTS.md were untouched.
AGENTS SHA256 remains
`7a520b569d674ad637be886c400f88d38c294b36f925595ca1f3b479526757eb`.
