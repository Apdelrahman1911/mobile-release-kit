# Decisions, publication boundary, and information not transferred

## Latest decisions, not inferred completion

| Subject | Latest decision | Consequence |
| --- | --- | --- |
| MRK-001–007, QA-001, QA-002 | Delivered through protected main | 9/16 currently confirmed findings delivered |
| QA-003 tree `387856e…` | **APPROVED_IMPLEMENTATION_ONLY**; original decision SHA `3c0e80e7b619aac64fa25fafb93fc4e1144f2695f4c7b682d96467e1e9012def` | Whole final verification remains failed/incomplete; rebase/refreeze after prerequisites |
| QA-006 R6 | **INCOMPLETE_VERIFICATION**; review original SHA `01241105f6944e76174c5ff61f24bd3a7122e9a839ea2b3c35195af4f859b162` | No full implementation acceptance or delivery |
| Verifier fixture-base R2 | Changes required: original-parent after-effect finality | Keep its genuine failure and complete positive profiles |
| Verifier fixture-base R3 | **APPROVED_PLAN_ONLY**, decision SHA `bc7dcb38d276893f7c75566471f1ca795eea2303176ef6c0ee510a973fa38873` | Paused two-file draft still incomplete/unreviewed/untested |
| Native inheritance result | **RECONCILED_FAILURE_NO_RETRY_AUTHORITY**, decision SHA `4a327f4eaee55d60c41a4ec2181e2b3d5521e4d1ce925a7947c70347f077ec4b` | 3 narrow passes, 1 failed, 7 unexecuted; original unknown state retained |
| Scalar clock result | **RECONCILED_CURRENT_HOST_HELPER_CLOCK_MISMATCH_NO_FOLLOWUP_AUTHORITY**, decision SHA `ea2f609dc4741a650bec62a6ff048f166873b01d9c221e56c8b99f4e7ade4262` | Current mismatch confirmed; historical missing Ruby cause not established |
| Clock correction R1 + supplement | **APPROVED_PLAN_ONLY**, decision SHA `44e060cd4c9bac8fbfe20fd942c2c967429ded6a0cba68a40397509f2a9fe880` | Implementation has not started; no corrected-code execution grant |
| Handoff export plan | **APPROVED_PLAN_ONLY**, distinct reviewer; original decision SHA `ce228a9e15adc8a830e9ef2ae39e6df6af5b73249b0058d34164a6e9cb33d089` | Assemble only sanitized handoff branch; distinct final content review required |

The old R18 status “clock plan under review” is superseded by its final independent
approval. The author's previous “implementation in progress” is superseded by a
safe **paused/incomplete/unreviewed** checkpoint. No product issue was newly fixed,
verified or delivered merely by publishing this information.

The original task-management goal already included the fresh complete audit and
feature report, but its API status was obsolete `blocked` with no resume operation.
That bookkeeping state is not completion. It is thread-local, not a repository
resource. The substantive user requirements are preserved in WORKFLOW.md.

## Reference chronology and safe adaptation

`plans/` deliberately retains proposed/rejected/superseded amendments so the next
agent does not repeat their mistakes. Current controlling documents are named in
QA006-CHECKPOINT.md and the independent reviews. In particular:

- QA-003 includes accepted lifetime/descriptor/caller/matrix/fatal-recovery/profile
  identity amendments through R9/R5. Its latest approval names the exact 55-path
  tree. Early approvals or development passes do not replace the later final gate.
- QA-006 product R6 inherits earlier fixture/ownership/cleanup requirements;
  unexecuted entered tests were not eliminated by a later pre-entry pass.
- Verifier `FIXTURE-BASE-PLAN-R4-R3` inherits R2 seed/editable/member contracts and
  separate `VERIFIER-CORRECTION-PLAN-R4-*` requirements. Similar filenames are not
  interchangeable. The two original oracle sources are included.
- Clock correction R1 includes its supplement and explicit old-BASE mutant fix,
  not just a one-line getter replacement.

Public exports replace personal/local paths with `/ORIGINAL_REPOSITORY`,
`/ORIGINAL_QA006_SOURCE`, `/ORIGINAL_QA006_WORKSPACE`, `/ORIGINAL_HOME`, or
`/ORIGINAL_SYSTEM_TEMP`. These are explanatory placeholders, **not roots to create**.
All reference hashes before and after transformation are separate. Historical
line references can shift with formatting; inspect the actual source.

The two selector fixture exports additionally remove actual identity/status fields.
They preserve useful structure/source inventory, not approved exact runnable fixtures.
The approved original-host requirement to keep fixtures byte-identical still holds
for the originals. A new-host replacement requires an explicit reviewed amendment,
fresh synthetic bindings and complete tests; simply changing hashes is not a fix.

## Explicit exclusion/custody ledger

| Excluded material | Why / custody / successor action |
| --- | --- |
| Original untracked user `AGENTS.md` | User-owned and not staged. Preserved in original worktree. Relevant working rules summarized in WORKFLOW.md; inspect any instructions present in new checkout. |
| Raw `.mobile-release/` run logs, receipts, manifests, attestations, control/ownership/acceptance JSON | Repository instructions prohibit committing local evidence. Retained privately on original machine; portable summaries and source-attribution hashes do not claim raw evidence availability/authenticity. |
| Credentials, keychains, signing assets, real Store/tester/reviewer data | Never read/export to make the handoff; not needed for synthetic verification. Obtain external prerequisites through protected owner-managed channels only. |
| Signed IPA/AAB/archive/dSYM and other binary/build outputs | Not repository inputs and not needed for source continuation. No binary artifact is included in this handoff. |
| Active/consumed grants, original absolute deadlines, process IDs, uid/device/inode capabilities | Non-transferable. Old identities cannot authorize execution, signal, cleanup or adoption on another host. Re-establish exact safe new environment in a reviewed plan. |
| Five verifier current29 JSON inputs | Raw configuration/discovery/ownership/bootstrap records deliberately excluded. Read source schemas/plans and create fresh scoped inputs after approval; do not invent PASS receipts. |
| Historical failed scratch, caches, 53 retained historical venvs/toolchains | Remain in original custody; not portable deliverables or proven junk. No cleanup/retirement authority follows from exclusion. |
| Optional failed archive and xattr records | Failure retained locally and summarized. Do not claim archive success, retry, reader/deletion/retirement approval. |
| Third-party interpreter/gem/wheel/SDK/cache payloads | Do not vendor or republish them. Repository lockfiles and retained member-derived plans identify versions/pins; reacquire safely and validate on the new host. |
| Old raw process observation that was already missing | Explicitly UNKNOWN; no claim that export can recover or authenticate it. |
| Entire chat/tool transcript and obsolete progress history | Not public repository content. Current reconciled decisions, failed outcomes, plan chronology, original findings, source snapshots and remaining obligations are retained instead. |

If a particular later decision truly requires an excluded raw record, request
that specific **sanitized** evidence through an appropriate private channel or
reproduce the requirement safely under a new plan. Record the limitation; do not
pretend the hash supplies the missing proof. This is not permission to rerun old
consumed experiments or erase their failed outcomes.

## Public branch and successor instructions

This branch is `handoff/2026-09-08`, based on protected main `2beb373…`. It adds no
active product behavior. No PR, merge, tag, release, workflow dispatch or Store
mutation is part of publishing it. The required main-only push CI does not run
just because this branch exists; absent CI is not a green check.

Use the exact clone branch in CONTINUE_HERE.md. The publication response gives
the actual pushed commit; verify it with the remote and inspect the diff. Main
is intentionally not advanced with unverified issue code. Future normal issue
deliveries still require distinct review, complete tests, protected PR and main CI.

The final feature report is deliberately **not** generated here. It is conditional
on the new comprehensive audit passing after all confirmed blockers are corrected.
This handoff does not make that readiness claim.
