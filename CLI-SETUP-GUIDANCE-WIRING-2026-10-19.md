# Saved CLI setup-guidance projection

This is a redacted projection of the **same completed passive snapshot** already
published by `ApplicationService`. It does not discover a project, run checks,
read credentials, contact a provider, save settings, or authorize an operation.
The existing Desktop, project read grant, stale fence, original store and native
snapshot-ticket checks remain unchanged.

## Exact integration

Apply `CLI-SETUP-GUIDANCE-WIRING-2026-10-19.patch` to Root's current integration;
it changes only these five Root-owned files:

1. `service_protocol.rs`: optional/default/omitted-when-absent
   `SavedObservation.setupAnalysis`; standard serde strict typed decoding with
   an unsupported-optional fallback to `None`; same-config/partial normalization
   when decoding an existing bounded response.
2. `application_service.rs`: project `snapshot.setupAnalysis` only after the
   existing required saved fields pass; compare the redacted projection in the
   existing no-op dedup; normalize optional persisted context on load. Existing
   base/store failure semantics are unchanged. Includes two original-store tests.
3. `installed_cli.rs`: existing `observe --json` includes the optional codes;
   human output reports saved requirement states, not a passed check. Missing
   or stale guidance is unavailable. No new command or permission. Includes one
   presentation/old-schema test; static capabilities retain the same commands.
4. `installed_cli_main.rs` and `lib.rs`: declare `service_setup_guidance` in both
   graphs. The module imports only the existing DATA configuration enum, serde
   and serde_json, not Desktop/Document/EditOwner or native helpers.

The additive module `desktop/src-tauri/src/service_setup_guidance.rs` retains
only:

```text
schemaVersion, configurationState, discoveryPartial, platforms,
requirements[{id, stage, state}]
```

All fields other than booleans/schema are closed enums. There is no arbitrary
summary, field name, reference/path, application ID, credential, account, source
text or limit-message output. The source's known schema, canonical finite
platform/requirement roster, stage/state codes and no-effects/static assurance
are checked without recomputing any requirement. `configured` means a setting
was present; `detected` means a static hint. Neither is readiness or consent.

The existing source response is bounded. The projector borrows strings and
checks fixed shallow containers and per-string bounds before invoking the
existing serde encoder for the tighter 16KiB source bound; no generic traversal
or filesystem/process interface was introduced. Source wording is not matched.
Only finite enum vectors survive. Stored/wire optional decoding stays within
the existing original namespace/response byte limits.

Absent, unsupported, malformed or mismatched optional guidance becomes `None`.
It cannot become an empty/completed checklist or hide malformed required
configuration, revision, count, registration, store or response fields. On a
host restart, an otherwise valid remembered projection remains **stale** with
its original saved observation; aliases and grants are not restored.

## Evidence and queued checks

Author checks: new Rust module formatter/parser and five patched Root copies
syntax-parse; packet applies to current Root; whitespace checks. These are not
compilation, test execution, native qualification, or installed delivery.

Eight focused Rust tests are authored and **await Root's actual graph batch**:

- `service_setup_guidance::tests` (5): enum-only redaction/round-trip, absent and
  mismatched input, closed unique roster/stages, effects/bounds refusal, optional
  old/malformed/duplicate-member decoding without hiding base-field failures.
- `application_service::tests::optional_setup_guidance_uses_original_store_redaction_and_dedup`:
  existing real store, no-analysis to analysis, ignored-text no-op, changed code,
  framed response, mismatched optional context, optional refusal, base refusal.
- `application_service::tests::setup_guidance_restart_is_stale_and_optional_damage_does_not_hide_base_damage`:
  original store close/reopen, new alias/grant required, stale to fresh, actual
  CAS with optional corruption versus a required base-count failure.
- `installed_cli::tests::setup_guidance_cli_is_optional_saved_data_and_stale_is_unavailable`:
  current/stale/missing display and backward-compatible omitted field.

Reuse the unchanged shared Python/TS setup-analysis author evidence; this packet
does not alter that algorithm. Root should compile the exact full Rust graph,
run the eight tests plus its retained service regression group, and compile the
thin CLI. No own Cargo run, runtime, native/provider or private-data operation
was performed for this source packet.
