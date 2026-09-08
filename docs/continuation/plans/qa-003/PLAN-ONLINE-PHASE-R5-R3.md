# QA-003 R5-R3 — preserve independent online-preflight diagnostics

Proposed narrow amendment to approved R5-R2 section D. No implementation of
this amendment has begun. All other R5-R2/R4/R3 requirements remain in force.

## Reanalysis and concrete regression

The R5 development run (`development-r5-targeted-r1.log`) executed 88 tests with
four errors. Blanket `_preflight` checks of `not report.ok` now return before
online credential inventory, ADC diagnostics and the supported non-publishing
identity query. Existing `test_cli_and_build.py` tests at 1284–1464, the
`_online_query_blockers` consumer and the documented unverified-identity
integration journey establish that these are regressions, not obsolete tests.

An ordinary completed doctor finding (unverified identity, missing signing
certificate/symbols/review metadata, unavailable build tool) is not an unsafe
command lifetime and is not necessarily a prerequisite of the Store ownership
query. The report must retain that failure; it must not use it to suppress an
independent query which can help resolve the configuration. In contrast, a
structured fatal ProcessError (including contained but cleanup-incomplete) must
abort every mode before any further private/native/application/Store work.

## Exact changes

1. Keep initial and project-check fail-fast report gates for offline/signing
   modes. Online never runs application checks, effective identity builds,
   materializes signing inputs or builds, even if its internal `run_builds`
   argument is true. An invalid/disabled platform selection stops before private
   validation and reports the existing online prerequisite SKIP.
2. Online still resolves explicit Store credentials and collects candidate-stage
   Store credential inventory despite unrelated nonfatal doctor/metadata results.
   Collect a pure static Store-material prerequisite diagnostic too: absent
   Android ADC must retain `credential-material.google-adc` MISSING even though
   the inventory also reports missing Google credentials. Factor that existing
   diagnostic into a small credentials helper shared with `validate_store_material`;
   it does not open/read a file, create scratch or dispatch a native process.
   The validator itself may fail fast on this prerequisite before P8/native work.
   Before private Store-material validation, evaluate `_online_query_blockers`
   against that inventory, selected platforms, explicit blocked identities and
   required query destinations. No complete version source means no query or
   private validation. Add a clear Store prerequisite SKIP without losing the
   original failing findings and pure missing-ADC material diagnostic. Missing/
   invalid query credentials are not sent to a native validator or Store request.
3. If those query-specific prerequisites pass, run `validate_store_material` to
   retain useful ADC/P8 diagnostics, even when unrelated build/metadata findings
   fail. Re-evaluate blockers including material findings before calling the
   online runner. Keep `identityStatus=unverified` eligible for the query;
   `identityStatus=blocked` remains ineligible. A query PASS cannot turn the
   overall report PASS while unresolved findings remain.
4. Preserve fatal ProcessError through the online materialization/runner wrapper
   before broad CredentialError conversion. Ordinary failed private-material
   findings prevent all Store requests. The outer public preflight lifetime FAIL
   and no-session/real-session recovery guidance remain authoritative. A
   secondary cleanup exception cannot permit a later command. No retries or
   automatic adoption of Store state are introduced.
5. Keep offline/signing early gates, first-failure command/platform semantics,
   committed release inputs, exact credential scrubbing and Store separation.
   No changes to schemas, workflows, Store lanes or provenance; QA-005's source
   authority fix is separate and remains required.

Implementation may isolate the existing online branch in a private helper to
make the phase separation explicit, rather than spreading exceptions to all
gates. Only `preflight.py`, the shared pure credentials prerequisite helper,
focused regression tests and relevant docs change.

## Tests, risks, security and recovery

- Preserve all four original failing cases and their negative log.
- Test ordinary unrelated doctor failures allow the correctly scoped query but
  retain failing report/exit status, with no application/build/signing command.
- Test blocked/disabled/missing identity, missing version, credentials and failed
  material prevent the query; inventory and material ordering are asserted.
- Test missing ADC in mixed-platform online mode retains its original diagnostic
  while both P8 validation and Store calls remain unexecuted. Assert the shared
  prerequisite helper is static/side-effect-free, not a new secret-file reader.
- Inject fatal errors (both group-uncertain and contained/cleanup-incomplete)
  into actual public online preflight's doctor/Store validator/runner boundaries;
  assert no subsequent validator, second platform, application or Store command.
- Keep offline/signing fail-fast tests at every R5 table row and actual descendant
  tests. Do not replace useful behavior checks with text-only security assertions.
- Document the distinction between unrelated diagnostic failure and unsafe
  lifetime failure. Non-publishing Android uses only its existing disposable edit
  query; no new persistent Store operation is authorized or exercised in tests.

Compatibility: restores the existing supported online workflow while making
query prerequisites earlier/more explicit. The report retains all collected
failures; there is no readiness override. Main risk is accidentally treating an
unsafe cleanup result as an ordinary unrelated doctor finding or widening query
authority; tests must prove neither. Recovery semantics, manual public-release
boundary and existing local-signing journal authority do not change.

## Acceptance

Require independent amendment approval before editing. Run targeted tests,
complete the R5 table and actual-worker regressions and mandatory R6 matrix,
then distinct whole-diff implementation review and frozen complete gates.
Development passes are not final verification, delivery or READY.
