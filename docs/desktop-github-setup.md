# Desktop GitHub previews and local workflow review

The passive service produces an **in-memory proposal**, not completed GitHub
setup. A separate local workflow edit path can review and install only four
fixed caller files, through its own sealed native profile, independently of
configuration editing. The normal installed Linux connection is **prepared
source; installed workflow verification is pending**. Global edit flags remain
false, and other profiles remain closed. Source implementation or inert renderer
checks are not qualification. The full Desktop remains incomplete; no standalone
readiness or general installer qualification is claimed.

Connect, remote GitHub setup, secret provisioning and dispatch remain
unimplemented. Neither a preview nor local caller installation enables them.

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

All passive previews are read-only: **nothing applied by the preview; GitHub
not contacted**. The separate local-operation panel reports actual native
installation outcomes and does not inherit this preview's no-write statement. Changing
the selected project, draft/baseline, or proposal inputs invalidates old results.
A late response cannot restore an earlier proposal. Missing runtime/help is
reported honestly; a bridge failure never activates browser examples or a
JavaScript workflow generator.

The environment checklist reuses core credential requirements and configured
source policy. It contains names and guidance, never credential values or a
claim that GitHub secrets, reviewers, protection or runners were inspected.
Local `_PATH` alternatives are not additional GitHub secret names. Candidate
build inputs remain separate from external-testing/production credentials.

**Open Credentials & Signing**, beside **Review project settings**, opens the
separate local-input guides and current native availability/scope. Navigation
selects no file and enters no private value; use those private controls only when
available. Local session assets are not GitHub secrets, and this page never
uploads assets or provisions secrets. Local caller installation still requires
its own fresh native review and explicit confirmation.

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

Remote setup still needs authenticated repository identity, fresh remote
observations, protected PR delivery and partial-failure reconciliation. Runner
eligibility and protected-environment administration must precede future
activation. This passive proposal is never a token or shortcut for local or
remote operations.

## Separate local workflow edit

**Review local workflow files** requests a fresh native observation of the
selected, native-registered project, not the passive preview or its optional
digest assertions. The original owner validates the frozen in-memory draft,
calls the shared proposal generator with no supplied snapshot, and freezes the
generated bytes once. The draft need not be saved first and is never saved,
marked clean, reset or adopted as a new configuration baseline by this feature.

In the supported native profile, select a project, prepare/adopt an in-memory
draft in Project settings, and enter the toolkit repository and full commit on
GitHub. Choose **Review local workflow files**, inspect all four paths and open
their complete text, then open the separate confirmation. **Keep reviewing**
sends no Apply or Close. Acknowledging the review enables **Apply reviewed local
files** (or **Confirm unchanged plan**). Wait for the original outcome and
native settlement; a preview or accepted command is not installation success.

The complete plan is exactly the four paths above. Each destination must be
observed absent (`create`), equal the complete generated caller (`preserve`), or
be an exact rendering of the **current bundled canonical template** with a
different toolkit repository/full commit (`update`). Updating repins that local
caller; it does not resolve, authenticate or establish compatibility of either
remote commit. A changed comment, newline, job, permission, repeated pin or
unrecognized older template refuses the **entire bundle with no Apply token**.
There is no arbitrary YAML merge, force, subset or overwrite option. Keep custom
callers intact and reconcile them separately before requesting a fresh review.
Unsafe, unreadable, oversized or changed observations are failures, not absence.

The native review shows all four fixed paths, create/preserve/update actions, complete
generated text and display diff, generated and observed lengths/SHA-256, any
missing directories, normalized toolkit pin and shipped-template identity.
Hash displays are consistency facts, not renderer-computed file authority.
Only a recognized canonical update exposes its complete original text, with
every removed and added line shown; this is a full-file comparison, not a
minimal diff. Unrecognized existing YAML and absolute project roots are never exposed. Conflict
summaries contain only up to four observed fixed IDs and their lengths/hashes.
Observation failure may show a reason alone; missing observations are never
invented. A conflict must still await original native settlement.

Explicit confirmation submits that one original plan. The one-use claim occurs
before invocation. The native owner rechecks the original root, ancestors,
files/absences and registered binding without re-rendering, rebasing or capturing
a replacement revision. Updates independently reload the fixed bundled resource,
compare its captured SHA-256 and match both frozen old/new bytes before staging.
Original raw file/parent facts are rechecked before replacing originals; a
same-byte later write does not silently become the reviewed original. Four preserves require the same confirmation/recheck,
then return verified unchanged with no journal, not fabricated write success.

Persistent product writes are restricted to absent or recognized canonical fixed
caller leaves and missing `.github` / `.github/workflows` directories. New directories use 0755;
new files request 0644 subject to inherited umask. Updates retain original modes
and use the existing exclusive backup/install/rollback path; committed cleanup
may remove only authenticated backups from that original validated plan. Preserved originals are not
rewritten or chmodded. Existing transaction controls remain bounded and private;
ordinary settled success leaves no journal. Configuration, `.gitignore`, unknown
workflow siblings, metadata, assets, `.git`, the index and Git commits are not
modified. No credentials are collected, no GitHub API is called and no workflow
or release is executed.

## Ownership, stale review and outcomes

Configuration and workflow edits share **one global native edit owner**. A
domain-filtered status with no local active row is not proof that this owner is
idle: `other_edit_active` disables admission while the other domain owns it.
The renderer also claims its local attempt synchronously, preventing competing
configuration/workflow Open calls before the first native status event. Native
global exclusion remains authoritative.

The frontend subscribes before its initial status read, coalesces concurrent
reads, validates closed bounded DTOs and retains monotone original status.
Workflow commands and `github-workflow-edit-status` events use an explicit
`github_workflows` domain; configuration and passive proposal decoders cannot
accept them as save or Apply authority. The five commands are:

```text
github_workflow_edit_open({projectId})
github_workflow_edit_prepare({sessionId,revision,draft,toolingRepository,toolingSha,draftRevision,baselineGeneration})
github_workflow_edit_apply({sessionId,planToken})
github_workflow_edit_close({sessionId})
github_workflow_edit_status({})
```

Renderer-supplied paths, file content, expected digests, snapshots, force flags,
registered root identities and credentials are not Prepare inputs. The private
native/core protocol is distinct (`mrk-github-workflows/1`); it is not a generic
shell or filesystem bridge. Configuration child frames remain unchanged.

Selection, draft/baseline, toolkit pin, service/runtime and document generation
changes synchronously retire pre-Apply authority; a late response cannot restore
it. Changing passive comparison assertions does not influence native authority.
After Apply submission, newer inputs are kept and the original operation's
outcome remains visible, even if a later opposite-domain status replaces the
shared last-terminal slot. Native document replacement revokes control; an
original submitted outcome may be observed, never reattached as a new token.

An invocation reply, core receipt or child exit alone is not success. Ordinary
installation needs the original prepared revision and submitted plan, final
native settlement with no native reason/late settlement, settled core resources
with no reason, and either `committed` + `clean` for actual creates/updates or `unchanged`
with `not_created` for four exact preserves. Known commit with failed/late cleanup
is not normal success. Rolled back, recovery required and unknown outcomes are
shown distinctly, with effect, journal, core-resource and native-finality facts.

This is recoverable multi-file installation, **not instantaneous four-file
atomicity**. Cancellation can be too late; it is not evidence that changes were
undone. A lost reply or duplicate click never resends Open, Prepare or Apply:
only the original owner is observed. Close keeps the draft and retires authority;
it is separate from discarding in-memory draft data.

Recovery is limited to one original in-session rollback or committed-cleanup
attempt. Recovery-required and unknown outcomes retain evidence and block
further edits. Do not delete/reset journals or retry Apply. Persisted recovery,
resume and general recovery buttons are not implemented by this feature.

The prepared installed route uses Linux x86_64 GNU strong native registration,
the unchanged A35507734308/1 payload, and the existing exact
`6.17.0-1022-azure` platform/custody profile. Configuration and workflow runtime
slots are separately tagged through inspection, transfer, preparation, one-use
claim and consuming settlement; they cannot borrow each other's authority.
Canonical updates extend the existing core/protocol; they do not introduce an
alternate transaction owner, template source, bootstrap or UI controller, or
broaden the platform/permission admission.

Installed acceptance still requires the existing normal-shell check plus its
four observer cases. The `workflow-apply` case must prove four fresh originals:
preserve-one/create-three, changed-pin canonical update review followed by
explicit Close **without Apply**, all-preserve Apply, and Quit with a pending
all-preserve review. Required counts are Open4/Prepare4/Apply2/Close1, with no configuration mutation. Post-exit
inventories must prove three exact new callers, unchanged original identities
and sentinels, configuration absence, no journal, and unchanged runtime. Native
request bindings and visible UI reads must separately prove the retained unsaved
draft; a disk inventory cannot establish that in-memory state.
The changed-pin installed case proves update preview/discard, not a replacement
commit or rollback. Separate real Linux filesystem cases exercise mixed canonical
update/create/preserve, original-mode retention and original backup cleanup, plus
failure after the first actual replacement and complete rollback. They use the
production typed lease/transaction inside the reviewed execution boundary;
inert contract tests cannot substitute for them. Customized callers retain the
existing adapter and genuine hosted newline-conflict no-token checks.
These changed-source checks have not yet been executed or independently accepted.
Historical changed-pin-refusal receipts cannot prove canonical-update behavior.
Historical headless run35273521622/1, configuration fixtures, pure UI tests,
compilation and browser previews are not installed workflow evidence.
Mac/Windows workflow writes and remote setup remain outside this slice.
