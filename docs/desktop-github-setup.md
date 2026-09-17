# Desktop GitHub setup proposals

This is an **in-memory proposal**, not completed GitHub setup. It works through
the passive core service in a qualified development runtime; the production
runtime remains disabled. Connect, Apply, secret provisioning and dispatch are
not implemented or enabled by a successful preview.

## Guided UI

The GitHub page explains the toolkit repository coordinate and full commit SHA
before submission. Help comes from `catalog.githubSetup`, independently of a
valid project draft or toolkit pin. Each input explains what/why/where/format,
requiredness and incorrect-value consequences. The toolkit repository is not
the user's application repository. The full SHA pins generated caller text;
its existence and compatibility have **not** been checked with GitHub.

With a valid draft and pin, the service proposes these four fixed files:

| ID | Proposed path |
| --- | --- |
| `preflight` | `.github/workflows/mobile-preflight.yml` |
| `candidate` | `.github/workflows/mobile-candidate.yml` |
| `external-testing` | `.github/workflows/mobile-external-testing.yml` |
| `production-submit` | `.github/workflows/mobile-production-submit.yml` |

All previews are read-only: **nothing applied; GitHub not contacted**. Changing
the selected project, draft/baseline, or proposal inputs invalidates old results.
A late response cannot restore an earlier proposal. Missing runtime/help is
reported honestly; a bridge failure never activates browser examples or a
JavaScript workflow generator.

The environment checklist reuses core credential requirements and configured
source policy. It contains names and guidance, never credential values or a
claim that GitHub secrets, reviewers, protection or runners were inspected.
Local `_PATH` alternatives are not additional GitHub secret names. Candidate
build inputs remain separate from external-testing/production credentials.

## Closed core contract

Method: `github.setup.propose`. Required parameters are exactly:

```text
{draft, toolingRepository, toolingSha, suppliedSnapshot}
```

`draft` is a JSON object, at most 512 KiB. `toolingRepository` follows the existing
CLI's ASCII `OWNER/REPO` rules (at most 140 characters). `toolingSha` is exactly
40 hexadecimal characters and is normalized to lowercase. No URL, token,
arbitrary template, repository root, revision, Apply flag or command is accepted.

`suppliedSnapshot` must be explicitly null, or `{workflows:[...]}` containing at
most four unique fixed IDs. Each assertion is exactly `{id,state:"absent"}` or
`{id,state:"present",byteLength,sha256}`. Length is an integer from 0 to 1 MiB;
SHA-256 is lowercase hexadecimal. These are caller assertions, **not** a
filesystem/GitHub observation. Omitted IDs are not supplied, not absent.

Invalid configuration returns only `schemaVersion`, `state:"invalid"`, bounded
redacted `validation`, `facts`, and `assurance`; no proposal is invented.
A valid result adds `templateSet`, normalized `tooling`, the four `workflows`
and `settings`, with `state:"proposed"`. Workflow records contain only fixed ID,
path, complete text, UTF-8 byte length, SHA-256 and one comparison:
`not-supplied`, `reported-absent`, `supplied-digest-match`, or
`supplied-digest-differs`. A digest match grants no overwrite/no-op authority.

Each caller is at most 16 KiB; all callers at most 64 KiB. The complete result
is at most 256 KiB, depth 16 and 8,000 nodes. Unknown shapes and overflows reject
rather than truncate source or silently omit requirements. The UI admits a
closed bounded result, not an unchecked TypeScript type assertion.

## Policy and authority

The CLI and passive service share the pure pin/render leaf
`mobile_release.workflow_payloads`. The four canonical templates remain in
`templates/workflows`. Their exact-byte package mirror is
`mobile_release/api/data/github-setup-v1.json`; parity tests prevent silent
divergence. No environment-selected template, YAML execution, remote fetch or
CLI invocation is used by the passive service. CLI template selection and its
existing file transaction remain separate and unchanged.

`schemaReference` is informational, never fetched or written to configuration.
Template resource identity is not remote compatibility or installed-runtime
provenance. All proposal facts retain `githubContacted:false`,
`repositoryObserved:false`, `toolingRefResolved:false`, `applyAvailable:false`
and unknown release readiness. A proposal does not initialize metadata,
configuration or `.gitignore`.

Actual setup still needs authenticated repository identity, fresh file/remote
observations, a reviewed diff, stale-state refusal, retained operation ownership,
explicit confirmation, protected PR delivery and partial-failure reconciliation.
Runner eligibility and protected-environment administration must precede future
activation. This proposal is never a token or shortcut for those operations.
