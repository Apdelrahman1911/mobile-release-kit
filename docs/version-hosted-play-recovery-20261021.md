# Optional encrypted recovery of a known hosted Play edit

2026-10-21. Source implementation of the Root-approved plan
`2cfe654513fd40f8693db624aa614c5d4bad4c4b064982109899eda5bde29e67`.
Versions reviewed the plan; a different reviewer must review this implementation.
No protected secret was provisioned and no GitHub/Google/native operation ran.

## Supported boundary

This closes only the loss of a **known edit ID after a joined, unconfirmed
DELETE**, when the original hosted reservation explicitly opted into encryption
and acknowledged its capsule before exiting. It does not recover an unknown
insert response, an unjoined child, unknown scratch cleanup, an old capsule-less
fence, or runner loss before the capsule CAS/readback. No expiry/404/missing-edit
inference, automatic retry, recreation, counter reset or inventory reuse exists.

The existing journal `release/.mrk-version-ci-state-v1.json`, protected counter
branch, selected repository App token, finite source reader and owned child
remain the owners. This is not another storage service or an allocation action.
The existing Ruby reader's ensure already attempts one bounded DELETE; a
second live-attempt retry would not provide durable recovery and was not added.

## External setup and explicit entry

In the existing protected `mobile-candidate` environment, an operator must
separately provide:

* **New dedicated secret** `MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_BASE64`:
  canonical base64 of exactly 32 independently random bytes. Never reuse the
  Google/P8/GitHub/HMAC key. This packet neither generates nor configures it.
* Nonsecret variable `MOBILE_RELEASE_PLAY_EDIT_RECOVERY_KEY_VERSION`: 1–64 ASCII
  letters/digits/`_.-`, starting with a letter/digit.
* The same selected `MOBILE_RELEASE_PLAY_SERVICE_ACCOUNT_JSON_BASE64`, enrolled
  `MOBILE_RELEASE_VERSION_AUTHORITY`, and existing dedicated repository-scoped
  App credentials (Administration read, Contents write, Actions read).

Both recovery values absent preserves non-opt-in reservation behavior. A
partial/malformed opt-in refuses before any Play call. Only Android/paired
reservation receives the new values; ordinary candidates and iOS-only
reservation do not. Retain the **original** key/version and Google account/key
identity while a capsule is pending; no key ring or automatic rotation exists.

After a known failure has retained an unclaimed capsule, use the existing
generated **Mobile candidate** workflow with:

```
operation: recover-play-edit
platform: android | both   # exact original request's enabled platforms
confirmation: recover-play-edit:<original candidate UUID>:<original Play attempt UUID>
```

Read those public selectors from the exact pending `playQuery`; never supply
an edit ID. Leave all existing recovery/Desktop inputs empty. The same
`reserve_version` caller and `version_reserve` protected job select the fixed
entry `python -P -m mobile_release.version_hosted_play_recovery cleanup`.
It is intentionally not a general local CLI: actual GitHub workflow admission,
repository/run/source checks and protected inputs are required. Cleanup gets
Google plus the new recovery selection and dedicated GitHub token, **no P8 or
counter policy**, including for an originally paired request. No application
command, build, upload, WIF/ambient ADC fallback or additional job is introduced.

## Private envelope and exact original lifetime

Maintained Ruby OpenSSL AES-256-GCM uses one CSPRNG 96-bit nonce and full 128-bit
tag per single seal. Plaintext is at most 2 KiB; the closed capsule is at most
4 KiB. Plaintext contains only the retained edit ID, package and selected Google
identity, not a credential or raw provider body. It is parsed only after GCM
authentication. The fixed verifier/deleter never prints plaintext, key or
provider errors; no private ID/key enters argv, Git names/messages, Actions
outputs or artifacts. Clearing a Ruby string is not claimed as heap erasure.

Canonical AAD binds format/purpose/key version, the full enrolled authority
(including actual repository ID/name and project), local project ID, candidate,
full request digest, original Play attempt, full original source binding,
context digest and identity revision. Cleanup re-reads actual original commit,
config and version blobs through the existing bounded Git reader. It neither
resets current HEAD nor substitutes a caller-provided source/identity. A changed
repository name/identity fails closed rather than silently rebinding a capsule.

The hosted-only private frame adapter requires the original strict insert-200
response and matching ID, exact request paths/ordering, actual completed child,
unchanged material and **both** original scratch closures. Existing best-effort
`_retain_play_id` DATA is insufficient. Only then can the live `_play_original`
and consumed `Capture` append the opaque capsule through one existing CAS plus
commit-pinned full readback. That branch terminates reservation without any
ledger-number PUT or current-inventory publication. Unknown/late output cannot
become a recovery capsule.

Explicit cleanup then follows one retained coordinator:

1. Load the actual full pending row and verify original source/authority.
2. Run the fixed Ruby **verify** child, with no SDK load/token/network. Require
   actual return, both scratch closures, unchanged material and exact capsule
   comparison. Wrong key/tag/account/version does not consume a claim.
3. Retain the original coordinator; write a fresh one-use cleanup claim using
   the exact predecessor blob and full readback. A conflict/lost ACK cannot send.
4. Recheck repository/protection/journal, then run **delete** with the same
   capsule/key. Ruby decrypts again, then uses the existing real SDK/HTTP owner:
   one token POST followed by one DELETE, no invented insert/sequence. The
   original before-wire latch prevents retries, refresh and redirects.
5. Only 204 with an empty body, actual child/scratch settlement and current same
   claim permits the final CAS/readback to remove the Play fence. No allocation
   is performed. Any intervening journal change is a conflict, not a merge.

A failed/late/unknown DELETE or lost final ACK keeps the claim spent. No retry
of that capsule is admitted. A later read can discover a committed clear, but
absence of a provider edit is never a cleanup receipt. Invalid/expired Google
authentication after claim can also leave a spent attempt; preclaim verification
authenticates the ciphertext/account selection, not provider access.

## Journal compatibility, confidentiality and limits

Envelope v1/v2 canonical reads and non-opt-in writes remain unchanged. Only
explicit capsule retention introduces v3; its `playQuery.recovery` is a required
nullable closed `{capsule, claim}` field. Load performs no migration. Claim and
clear have separate exact original checks around the existing CAS primitive;
loaded DATA never populates `_play_original`, calls `choose`, remints a
candidate or relaxes normal `_store`/KEEP authority. Every allocation/checkpoint/
pending row stays identical. The accepted iOS-only progress exception preserves
the **entire** v3 Play record/capsule/claim and original candidate/enrollment.
Old-blob CAS cannot overwrite an intervening iOS write.

Ciphertext and its bounded metadata may persist permanently in **public Git
history**. Confidentiality depends on secrecy of the dedicated key; there is
no forward secrecy or history deletion. Later key compromise can expose old
IDs. Key loss/version/account mismatch leaves recovery unavailable. Workflows
holding the key are trusted; encryption is not native/provider settlement.
Administrator rollback without an independently newer anchor remains outside
the existing journal guarantee. Do not truncate/reset a journal to recover.

The existing 128 KiB/4096-node journal preparse/prospective-write cap and private
2 MiB Play frame cap are unchanged (the capsule fits inside them). Google input
remains at most 16 KiB; verifier/DELETE output is at most 1024 bytes each. The
coordinator has at most two children/four scratch scopes, not an unbounded pool.

| Action | Fixed upper bound / timing |
| --- | --- |
| Ordinary iOS reservation | Existing 37 GitHub calls / 5 journal writes, unchanged |
| Android/paired reservation incl. failed-delete capsule | Existing 44 GitHub / 12 Git / 7 journal writes, no increase |
| Explicit cleanup | 24 GitHub / 12 Git / 2 journal writes; no ledger PUT |
| Concrete cleanup schedule | At most 21 GitHub (attempt 1, journal load 7, source commit 1, three ref/ancestry pairs 6, claim/final PUT+readback 4, fresh repository/protection 2); 9 Git including original CA reads |
| Provider cleanup | One token POST + one DELETE, never inventory/insert/commit |
| Original clock | One 60s source endpoint; verifier ≤5s **inside** it; original child cleanup tail ≤3s |

Opt-in inventory and cleanup DELETE stop child work eight seconds before the
parent endpoint; that includes the existing up-to-three-second child tail.
At most five seconds remains after a fully used tail, not a renewed eight-second
CAS clock or a guarantee remote IO will finish. Actual counter checks precede
each wire/command; insufficient time, STOP or any late return fails closed.

## Exact delivery and evidence

Base: `413cf8fd6166ff927976331f984764cc41bc7b99` (accepted iOS exception included).
Owned seven paths: this guide, `version-hosted-play-recovery-hooks-20261021.patch`,
`src/mobile_release/version_hosted_play_recovery.py`,
`fastlane/play_edit_recovery.rb`,
`tests/unit/test_version_hosted_play_recovery.py`,
`tests/workflow/test_play_edit_recovery.rb`,
`tests/workflow/test_play_edit_recovery_yaml.rb`.

The **unapplied** patch has exactly eight targets: `version_hosted.py`,
`version_hosted_store.py`, `workflow.py` under `src/mobile_release/`;
`fastlane/android_store_versions.rb`; `.github/workflows/reusable-candidate.yml`;
`templates/workflows/mobile-candidate.yml`; `pyproject.toml`;
`tests/workflow/test_version_hosted_yaml.rb`. The last target only adjusts old
workflow expectations for the explicit new operation/last step. Packaging adds
the new Ruby helper **and its existing reader dependency**; no dependency install.
Complete before/post copies and exact pins remain in `.task-play-recovery/`.

Actual nonroot, clean HOME/TMP, networkless focused evidence:

* `python-v1`: 58 PASS (47 affected + initial 11 new), 2.778s; `python-v2`:
  final 13 new PASS, 1.066s. After adding actual paired Context and parsed TOML
  admission assertions, that one changed grouped test passed in 0.050s
  (`python-v3`). Thus 60 distinct Python tests covered, not 72 distinct tests.
* `ruby-v3`: 15 runs / 222 assertions PASS (6 new + 9 existing), 0.057969s.
  Real OpenSSL and private fixture files; existing SDK/HTTP doubles only.
* `workflow-v1`: 8 runs / 167 assertions PASS (3 new + 5 existing), 0.109051s;
  YAML parsed only, no run block/secret/workflow executed.

Python tests use actual Journal/Material/source transitions with explicitly
inert Git/HTTP/child outcomes and Popen forbidden; the affected suite also tests
the existing actual private scratch owner. They cover strict known insert vs.
unknown/malformed/late/close, preclaim verification, lost/stale CAS, no remint,
spent claims/sole DELETE, v1/v2 preservation, full v3 iOS preservation, fixed
admission and packaging. Ruby exercises GCM nonce/tag/AAD/key/account refusal,
token→sole DELETE, 204 versus 404/refusal/late output and default-frame behavior.

All actual callers returned. Successful final Python/Ruby projections were
hash/inode rematched and removed with empty HOME/TMP. Earlier failed projections
and logs are preserved: first Ruby run exposed a nil optional-env check, fixed;
second exposed a nested Minitest stub collision, fixed only in the test. Neither
was a provider run. Local runtimes were Python 3.12.3 and Ruby 3.2.3/OpenSSL
3.0.13 on Linux. Workflow-pinned Python 3.11/Ruby 3.3.12, real maintained SDK
integration, protected-secret setup and actual provider/CAS execution remain
**unexecuted/unqualified**. No native availability or production flag changed.
