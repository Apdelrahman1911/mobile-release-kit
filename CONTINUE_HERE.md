# Mobile Release Kit: start here before continuing

**Handoff checkpoint: 2026-09-08. NOT READY.**

This branch preserves unfinished work for another agent. It is **not a release,
an integrated fix, or proof that the pending tests passed**. Product files on
this branch remain at main commit
`2beb37336fa8002b69f598fe431082606368310d` (version `0.3.0`).

## Read in this order

1. [Status, exact snapshots, and resume instructions](docs/continuation/README.md).
2. [All 16 findings and delivery status](docs/continuation/FINDINGS.md).
3. [Required working procedure and final audit/report](docs/continuation/WORKFLOW.md).
4. [Current QA-006 implementation and verification checkpoint](docs/continuation/QA006-CHECKPOINT.md).
5. [Every known paused-verifier concern and unfinished obligation](docs/continuation/QA006-VERIFIER-TODOS.md).
6. [Historical results, failures, and required verification](docs/continuation/VERIFICATION.md).
7. [Decisions, exclusions, and non-transferable evidence](docs/continuation/DECISIONS.md).

Then read the relevant original finding, plans, review, and actual implementation
before changing that issue. Do not start by running the blanket native test suite
on a shared machine: the open QA-007 process-ownership finding matters.

**Delivered:** MRK-001 through MRK-007, QA-001, QA-002: **9/16 (56.25%)** of
currently confirmed findings. This is a delivery count, not overall effort or
production readiness. **Remaining:** QA-006 → QA-007 → QA-003 → QA-004 → QA-005 →
MRK-008 → MRK-009, then a completely fresh full audit, any further remediation,
and only after justified READY a separate comprehensive technical feature report.

Two independent, unapplied source patches preserve QA-003 (55 paths) and QA-006
(7 paths). Do not apply them on top of each other or count them as delivered.
Local verification-helper drafts are retained as **inert, sanitized reference
text**, not runnable tools. Their old host bindings and approvals do not transfer.

Clone this branch explicitly; cloning default `main` will not include this handoff:

```bash
git clone --branch handoff/2026-09-08 \
  https://github.com/Apdelrahman1911/mobile-release-kit.git
cd mobile-release-kit
cat CONTINUE_HERE.md
```

No Store mutation, signing, public release, PR merge, or protection bypass is
authorized by this handoff. Stop/join only your own workers; preserve other tasks,
user changes, and required deliverables. Never commit secrets or raw local evidence.
