# Restored key: historical certificate comparison

Base: `420db551a18925d759994548ef747fdff995e139`.
Plan: independently accepted by Versions; actual review assigned to SetupUI.

## User-visible scope

After an encrypted backup is restored as a **NEW record**, the user can select
that current record, check existing certificates, and explicitly continue a
matching earlier certificate request. The continuation is GET-only comparison.
It does not resolve an earlier Unknown, grant another certificate request,
restore an old keySaved receipt, assign signing material, or clear the account
fence that can still block P12 setup.

Ordinary fresh certificate/P12 reuse without old key-preparation history was
already supported when the account journal is clear. This change fixes only
the historical request selection/reconciliation path. It changes no runtime
availability flag or Apple trust policy.

## Original authority and ordering

* History still comes from the original joined INITIAL account snapshot and
  existing combined-32/32KiB projection. Cross-reference rows additionally
  match both CSR and full-SPKI hashes from this operation's verified key.
  The actual publisher requires the same returned key ACK, worker/source/
  native/private retirement and completed clock, not public Facts alone.
* Account, service project, registered root and full signing target remain
  matched. The earlier display name is only the existing explicit local choice.
* Prior selection accepts a different **valid** old full reference only in
  CertificateReconcile. The original row/reference/receipt remains unchanged.
* The new operation still loads/checks the current stored key and runs the
  existing PKCS8/CSR/signature/SPKI verifier. Native `key_ack` and Python
  `current_key` compare **both** prior hashes before the first provider GET.
  The final volatile certificate association repeats that comparison.
* CertificateCreate's exact current key-preparation relation and all original
  one-send, pending, stop, cleanup and P12 account-fence rules are unchanged.
  No journal schema, alias, CAS, new owner, transport or public wire is added.

## Packet and Root integration

Owned existing leaves (plus this guide and the hook patch):

* `desktop/src-tauri/src/apple_provisioning_certificate_protocol.rs`
* `desktop/src-tauri/src/apple_provisioning_certificate_recovery_selection.rs`
* `desktop/src-tauri/src/saved_command_apple_certificate.rs`
* `desktop/src/components/AppleDistributionCertificateSetup.tsx`
* `desktop/tests/apple-distribution-certificate-setup.test.mjs`
* `src/mobile_release/_desktop_apple_certificate_protocol.py`
* `src/mobile_release/_desktop_apple_certificate_worker.py`
* `tests/unit/test_desktop_apple_certificate.py`

Apply `apple-restored-certificate-reconcile-hooks-20261021.patch` separately
to the three existing parent paths: `saved_command_apple_provisioning.rs`,
`saved_command_apple_provisioning_native.rs` and
`saved_command_apple_provisioning_tests.rs` in `desktop/src-tauri/src/`.
The hook adds one private returned-ACK comparison, changes the two original
prior/history call sites and adds an inert test of the actual State factor.
It does not modify original writer or retirement behavior.

## Evidence and limits

Author lane: `.task-restored-reconcile/` contains logs, exact before/after
parent copies, tested-source hashes and freeze metadata. All test processes
returned; the task-only dependency link and disposable capsule were removed.

* **20 unique Python cases passed cumulatively**: certificate module's 19
  cases plus the existing P12 unresolved-account test. The full focused run
  passed 18 and exposed wrong exit-code assertions in two new refusal cases;
  those assertions were corrected to the actual returned terminal semantics
  and only those two cases were rerun (PASS). The first invocation also had a
  task-capsule working-directory error; it is not counted as passing evidence.
* **25 certificate frontend Node tests PASS**, no skips, 501.530349 ms. This
  includes the new actual-controller restored-record continuation regression.
* **Whole frontend TypeScript PASS**, using existing dependencies, no install.
* Six changed Rust files parsed with rustfmt. **No Rust tests or compile run**.

Tests ran as UID 65534 in a network namespace with an empty environment and
inert original worker/controller fixtures. No real key, certificate, provider,
backup, Keychain, NativeUse, Mac runtime or availability was qualified.

Four new Rust selectors for Root's existing test graph (unrun):

* `apple_provisioning_protocol::certificate_recovery::tests::restored_key_history_compares_both_hashes_without_rewriting_old_rows_or_key_saved`
* `apple_provisioning_protocol::certificate_recovery::tests::restored_key_hashes_cannot_disclose_foreign_project_root_or_target`
* `apple_provisioning_protocol::certificate_recovery::tests::restored_prior_stays_reconcile_only_and_both_key_hashes_are_rechecked`
* `saved_command_owner::apple_provisioning::tests::certificate_history_requires_original_entered_returned_key_ack_not_completed_data`

The positive Rust ACK test exercises only the actual route factor; it does
not manufacture a loan, completed native session, or private-retirement proof.
