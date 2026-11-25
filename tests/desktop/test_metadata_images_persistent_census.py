"""SOURCE-only image census contracts; no application/native module is imported.

These checks bind the focused Rust DATA visitors to the actual session and
allocation path. They are not executed/native vault or image qualification.
Execution belongs to the lead's exact-source, serialized test route.
"""
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUST = ROOT / "desktop" / "src-tauri" / "src"
LINUX = 'all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")'
MAC = 'all(target_os = "macos", target_arch = "aarch64")'


def between(source, first, last):
    if first not in source or last not in source.split(first, 1)[1]:
        raise AssertionError(f"missing source boundary: {first!r} / {last!r}")
    return source.split(first, 1)[1].split(last, 1)[0]


def method(source, name):
    # Census methods use this exact impl indentation; inner block endings are
    # more deeply indented. Deliberately a source contract, not a Rust parser.
    return between(source, "fn " + name + "(", "\n        }")


class ImagePersistentCensusSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = (RUST / "asset_session_images.rs").read_text(encoding="utf-8")
        cls.session = (RUST / "asset_session.rs").read_text(encoding="utf-8")
        cls.vault = (RUST / "asset_session_vault.rs").read_text(encoding="utf-8")
        cls.mac_store = (RUST / "vault_store_macos.rs").read_text(encoding="utf-8")
        cls.production = cls.image.split("    #[cfg(all(test, debug_assertions))]", 1)[0]

    def test_both_supported_profiles_visit_the_persistent_session_and_every_loan(self):
        before_module = self.production.split("mod persistent_memory {", 1)[0]
        self.assertIn(f"#[cfg(any({LINUX},\n    {MAC}))]", before_module)
        document = method(self.production, "document")
        for call in ("self.records(&state.records)?", "self.assignments(&state.assignments)?",
                     "self.context(context)?", "self.vault_session(session)?"):
            self.assertIn(call, document)
        session = method(self.production, "vault_session")
        self.assertEqual(session.count("value.data_bytes()"), 1)
        self.assertIn("self.vault_store(value.store())?", session)
        self.assertIn("self.vault_key(key)?", session)
        self.assertIn("for loan in value.bound.iter().flatten()", session)
        self.assertIn("self.loan_backings(&loan.context, &loan.payload, &loan.store, &loan.key)?", session)
        self.assertNotIn(".filter(", session)
        loan = method(self.production, "loan_backings")
        for call in ("self.context(context)?", "self.payload(payload)?",
                     "self.vault_store(store)?", "self.vault_key(key)"):
            self.assertIn(call, loan)
        for owned in ("BOUND_LOAN_BYTES", "size_of::<vault::BoundLoan>", "Box::new"):
            self.assertNotIn(owned, session + loan)
        wrapper = between(self.image, "\nfn persistent_bytes(", "\nfn raw_allowance_from_persistent(")
        self.assertIn("persistent_memory::persistent_bytes(state)", wrapper)
        self.assertIn(LINUX, wrapper)
        self.assertIn(MAC, wrapper)
        self.assertIn("Err(Reason::UnsupportedPlatform)", wrapper)

    def test_identity_capacity_and_store_refusal_do_not_refund_unknown_backing(self):
        self.assertIn("const BOUND_ROOTS: usize = 8;", self.production)
        self.assertIn("const IDENTITIES: usize = 3 * RECORD_LIMIT + 6 * BOUND_ROOTS + 3;", self.production)
        self.assertIn("const BOUND_LOAN_LIMIT: usize = 8;", self.vault)
        self.assertIn("value.bound.len() != BOUND_ROOTS", method(self.production, "vault_session"))
        self.assertIn("values.len() > RECORD_LIMIT", method(self.production, "records"))
        identity = method(self.production, "insert<T>") if "fn insert<T>(" in self.production else ""
        # Generic method extraction has the same source delimiter but no hidden
        # language import or compiled substitute for the actual implementation.
        self.assertIn("Arc::as_ptr(value) as usize", identity)
        self.assertIn("self.used == self.ids.len()", identity)
        self.assertIn("Err(Reason::Capacity)", identity)
        store = method(self.production, "vault_store")
        self.assertLess(store.index("self.seen.insert(value)?"), store.index("value.try_lock()"))
        for clause in ("map_err(|_| Reason::Busy)", "book.not_started()", "book.operation_quiescent()", "book.settled()",
                       "Problem::CleanupUnknown", "Cleanup::Unknown", "Err(Reason::CleanupUnknown)",
                       "self.arc::<Mutex<crate::vault_store::StoreBook>>()?",
                       "self.heap::<crate::vault_store::StoreBook>(book.retained_bytes())"):
            self.assertIn(clause, store)
        self.assertNotIn(".lock()", store)
        self.assertNotIn("unwrap_or", store)
        mac_retained = between(self.mac_store, "pub(crate) fn retained_bytes(&self) -> Option<usize> {\n        let acl", "\n    fn fail(")
        self.assertIn("if !acl.quiescent() { return None; }", mac_retained)
        self.assertIn("MaterialOrigin::Stored(source) => self.heap::<crate::vault_crypto::StoredBytes>(source.bytes.retained_bytes().ok())", self.production)
        self.assertIn("self.origin(&source.origin)", method(self.production, "material"))

    def test_allowance_limits_and_original_retirement_order_stay_closed(self):
        allowance = between(self.image, "\nfn raw_allowance_from_persistent(", "\nfn selected_items(")
        self.assertIn("SESSION_BYTES.checked_sub(bytes)", allowance)
        self.assertIn("remaining.min(wire::BATCH_LIMIT)", allowance)
        self.assertIn(".filter(|limit| *limit > 0).ok_or(Reason::Capacity)", allowance)
        self.assertIn("raw_allowance_from_persistent(persistent_bytes(state)?)", allowance)
        for line in ("const NATIVE_IMAGE_CONTROL_RESERVE: usize = 128 * 1024;",
                     "const SOURCE_IMAGE_CONTROL_RESERVE: usize = 512 * 1024;",
                     "const PROJECTION_CONTROL_RESERVE: usize = 256 * 1024;",
                     "const GUI_CONTROL_RESERVE: usize = 128 * 1024;",
                     "const DOCUMENT_CONTROL_RESERVE: usize = 3 * 1024 * 1024;"):
            self.assertIn(line, self.image)
        self.assertIn("const SESSION_BYTES: usize = 64 * 1024 * 1024;", self.session)
        self.assertIn("const RECORD_LIMIT: usize = 32;", self.session)
        selection = self.image.split("pub(crate) fn metadata_images_selection_start(", 1)[1]
        self.assertLess(selection.index("idle(&state)"), selection.index("raw_allowance(&state)"))
        self.assertLess(selection.index("raw_allowance(&state)"), selection.index("self.install(&mut state"))
        install = self.session.split("fn install(&self, state:", 1)[1]
        self.assertIn("if !slot.operation.images() && !slot.operation.installation() { vault::attach_asset_slot(state, &mut slot)?; }", install)
        self.assertIn("let old_slot = state.slot.take().map(Box::new);", install)
        run_job = self.session.split("async fn run_job(", 1)[1]
        self.assertLess(run_job.index("owner.release_retirement()"), run_job.index("execute_job(&document, &owner, job)"))
        wire = (RUST / "metadata_images_edit_protocol.rs").read_text(encoding="utf-8")
        for pattern in (r"const MAX_FILES: usize = 10;", r"const FILE_LIMIT: usize = 10 \* 1024 \* 1024;", r"const BATCH_LIMIT: usize = 24 \* 1024 \* 1024;"):
            self.assertRegex(wire, pattern)

    def test_store_bearing_regressions_are_linux_only_not_mac_native_fixtures(self):
        tests = between(self.image, "    #[cfg(all(test, debug_assertions))]\n    mod tests {", "\nfn persistent_bytes(")
        common, linux = tests.split("        mod linux_store_data {", 1)
        self.assertTrue(common.rstrip().endswith(f"#[cfg({LINUX})]"))
        # Comments can name the forbidden constructor to explain why the guard
        # exists; no executable common test body may call it or make an owner.
        common_code = re.sub(r"//[^\n]*", "", common)
        for call in ("StoreBook::new(", "empty_state(", "DocumentBinding::", "OriginalWork::", "Session::", "loan_backings("):
            self.assertNotIn(call, common_code)
        for name in ("image_loan_only_backing_reduces_old_credit_and_reaches_one_byte_boundary",
                     "image_current_records_and_loan_roots_deduplicate_but_equal_originals_do_not",
                     "image_store_mutex_and_arc_are_charged_and_contention_or_poison_refuses"):
            self.assertIn("fn " + name + "(", linux)
        self.assertIn("census.document(&state)", linux)
        self.assertIn("old_roots(&mut measured)", linux)
        self.assertIn("census.loan_backings(&context, &payload, &store, &key)", linux)
        self.assertIn("omitted_loan_credit - loan_bytes", linux)
        self.assertIn("raw_allowance_from_persistent(edge.bytes), Ok(1)", linux)


if __name__ == "__main__":
    unittest.main()
