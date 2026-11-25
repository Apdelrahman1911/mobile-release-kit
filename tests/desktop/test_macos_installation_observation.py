"""Installation observer parser/control-flow DATA; never Mac/native evidence.

No application owner is imported, process started, installed file opened or
fixture prepared. All receipt-shaped objects below are explicit test DATA.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import re
from subprocess import CompletedProcess
import sys
import unittest

ROOT = Path(__file__).absolute().parents[2]
PATH = ROOT / "desktop" / "tools" / "macos_aqua_qualification.py"
SPEC = importlib.util.spec_from_file_location("_mrk_installation_observer_data", PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
BINDING = M.Binding("a" * 40, "123", "1")
CASE = "installation-inspection"


def captured(value):
    return M.MARKER + json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def example():
    return M.expected_result(BINDING, CASE)


def changed(value, path, replacement):
    result = deepcopy(value)
    destination = result
    for key in path[:-1]:
        destination = destination[key]
    destination[path[-1]] = replacement
    return result


class InertFixtures:
    """Only the public invocation-boundary DATA used by run_cases."""
    def __init__(self):
        self.cases = (CASE,)
        self.inflight = self.last_returned = False
        self.before = []
        self.reads = []
        self.stage = None

    def before_call(self, case):
        self.before.append(case)

    def readback(self, case):
        if self.inflight or not self.last_returned:
            raise AssertionError("test readback lacks original returned-call DATA")
        self.reads.append(case)
        return {"inertTestOnly": True}


class InstallationObservationDataTests(unittest.TestCase):
    def assert_refused(self, value):
        with self.assertRaises(M.Refused):
            M.parse_result(captured(value), b"", BINDING, CASE)

    def test_one_closed_scope_keeps_defaults_and_disjoint_namespaces(self):
        self.assertEqual(M.selected_cases(), ("first-save", "noop-stale", "picker-loss", "save-loss"))
        self.assertEqual(M.selected_cases(CASE), (CASE,))
        self.assertEqual(M.argument_scope(["--scope", CASE]), CASE)
        self.assertEqual(M.case_timeout(CASE), 95)
        roots = {BINDING.root(), BINDING.root(project_fields=True), BINDING.root(vault_helper=True),
                 BINDING.root(installation_inspection=True)}
        self.assertEqual(len(roots), 4)
        self.assertEqual(str(BINDING.root(installation_inspection=True)),
                         "/private/tmp/mrk-macos-aqua-" + "a" * 40 + "-123-1-installation-inspection")
        for kwargs in ({"installation_inspection": 1}, {"installation_inspection": "true"},
                       {"installation_inspection": True, "project_fields": True},
                       {"installation_inspection": True, "vault_helper": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(M.Refused):
                BINDING.root(**kwargs)
        for args in ([CASE], ["--scope", CASE, "--path", "/tmp/other"], ["--scope", CASE, "--timeout", "999"],
                     ["--scope", CASE, "--scope", CASE], ["--scope", "installation"]):
            with self.subTest(args=args), self.assertRaises(M.Refused):
                M.argument_scope(args)
        self.assertEqual(M.fixture_data(CASE, False), M.fixture_data(CASE, True))

    def test_actual_bounded_counts_are_not_treated_as_operation_ids_or_fixture_defaults(self):
        value = example()
        inspection = value["installationInspection"]
        inspection["cancelled"]["firstRead"] = {"verifiedFiles": 37, "verifiedBytes": 8092}
        inspection["matching"]["firstRead"] = {"verifiedFiles": 2, "verifiedBytes": 30}
        inspection["matching"]["status"]["assessment"].update(files=2000, bytes=50 * 1024 * 1024)
        for revision, (name, kind) in zip((11, 19, 28, 35),
                (("cancelled", "start"), ("cancelled", "status"), ("matching", "start"), ("matching", "status"))):
            inspection[name][kind]["statusRevision"] = revision
        self.assertEqual(M.parse_result(captured(value), b"", BINDING, CASE), value)
        self.assertIsNone(value["native"]["projectOpenInput"])
        self.assertIsNone(value["native"]["projectOpenBinding"])
        self.assertIsNone(value["native"]["projectCompletionSelection"])
        self.assertFalse(value["native"]["selectedPathMatched"])
        self.assertFalse(value["shippingBinaryQualified"])
        self.assertFalse(value["distributionQualified"])
        self.assertLess(len(captured(value)), M.JSON_LIMIT)

    def test_missing_actual_objects_and_unknown_fields_are_never_filled(self):
        base = example()
        for path in (("installationInspection",), ("installationInspection", "cancelled"),
                     ("installationInspection", "matching"), ("installationInspection", "normalQuit"),
                     ("installationInspection", "cancelled", "firstRead"),
                     ("installationInspection", "matching", "firstRead"),
                     ("installationInspection", "cancelled", "originals"),
                     ("installationInspection", "matching", "originals"),
                     ("installationInspection", "matching", "status", "assessment")):
            with self.subTest(path=path):
                self.assert_refused(changed(base, path, None))
                value = deepcopy(base)
                target = value
                for key in path[:-1]:
                    target = target[key]
                del target[path[-1]]
                self.assert_refused(value)
        for path in (("installationInspection",), ("installationInspection", "matching"),
                     ("installationInspection", "cancelled", "firstRead"),
                     ("installationInspection", "matching", "originals"),
                     ("installationInspection", "matching", "status", "assessment")):
            value = deepcopy(base)
            target = value
            for key in path:
                target = target[key]
            target["unrecognized"] = True
            self.assert_refused(value)

    def test_ids_status_types_and_monotonic_original_revisions_cannot_be_swapped(self):
        base = example()
        for name, expected_id in (("cancelled", 1), ("matching", 2)):
            for kind in ("start", "status"):
                path = ("installationInspection", name, kind)
                for identifier in (True, False, 0, "1", 3, 3 - expected_id):
                    self.assert_refused(changed(base, path + ("operationId",), identifier))
                for revision in (True, 0, -1, 2**32 - 1, "3", 1.5):
                    self.assert_refused(changed(base, path + ("statusRevision",), revision))
                for field, value in (("schemaVersion", True), ("available", 1), ("canStart", 0)):
                    self.assert_refused(changed(base, path + (field,), value))
        for name, kind, revision in (("cancelled", "status", 1), ("matching", "start", 3),
                                     ("matching", "status", 4), ("matching", "start", 2)):
            self.assert_refused(changed(base, ("installationInspection", name, kind, "statusRevision"), revision))
        swapped = deepcopy(base)
        record = swapped["installationInspection"]
        record["cancelled"], record["matching"] = record["matching"], record["cancelled"]
        self.assert_refused(swapped)

    def test_first_read_and_matching_payload_bounds_and_fixed_assurance_are_required(self):
        base = example()
        for name in ("cancelled", "matching"):
            for field, values in (("verifiedFiles", (True, 0, 2049, "1")),
                                  ("verifiedBytes", (True, 0, 512 * 1024 * 1024 + 1, "7"))):
                for value in values:
                    self.assert_refused(changed(base, ("installationInspection", name, "firstRead", field), value))
        for field, values in (("files", (True, 0, 2049, "3")),
                              ("bytes", (True, 0, 512 * 1024 * 1024 + 1, "19")),
                              ("assurance", (None, "installed", "verified")),
                              ("maintenance", (None, "available"))):
            for value in values:
                self.assert_refused(changed(base, ("installationInspection", "matching", "status", "assessment", field), value))
        for field, value in (("verifiedFiles", 4), ("verifiedBytes", 20)):
            self.assert_refused(changed(base, ("installationInspection", "matching", "firstRead", field), value))

    def test_cancellation_requires_actual_first_read_exact_stop_and_known_refusal(self):
        base = example()
        for field, values in (("phase", ("observed", "checking", "stopping", "unknown")),
                              ("reason", ("none", "deadline", "cleanup-unknown")),
                              ("settlement", ("pending", "unknown", "late-known")),
                              ("assessment", ({"files": 3, "bytes": 19},))):
            for value in values:
                self.assert_refused(changed(base, ("installationInspection", "cancelled", "status", field), value))
        for field in ("cancelRequestedOnce", "cancelReturned"):
            self.assert_refused(changed(base, ("installationInspection", "cancelled", field), False))
            self.assert_refused(changed(base, ("installationInspection", "matching", field), True))
        self.assert_refused(changed(base, ("installationInspection", "cancelled", "originals", "stopped"), False))

    def test_each_real_join_disposal_finality_and_prequit_nonstopped_matching_is_required(self):
        base = example()
        for name in ("cancelled", "matching"):
            for field in ("normalCoordinatorJoined", "normalChildJoined", "nativeSettled", "storageDisposed", "resourcesSettled"):
                for value in (False, None, 1):
                    self.assert_refused(changed(base, ("installationInspection", name, "originals", field), value))
        self.assert_refused(changed(base, ("installationInspection", "matching", "originals", "stopped"), True))
        for field, value in (("reason", "cancelled"), ("settlement", "late-known"),
                             ("settlement", "unknown"), ("phase", "refused")):
            self.assert_refused(changed(base, ("installationInspection", "matching", "status", field), value))
        for field, value in (("operationId", 2), ("operationId", True), ("inspectionId", 1),
                             ("noProjectFinality", False), ("noProjectFinality", 1)):
            self.assert_refused(changed(base, ("installationInspection", "normalQuit", field), value))
        for path in (("originalRelayJoined",), ("actualExit",), ("native", "originalDocumentAndQuitSettled")):
            self.assert_refused(changed(base, path, False))

    def test_project_replay_or_shipping_qualification_cannot_satisfy_no_project_case(self):
        base = example()
        project = M.expected_result(BINDING, "noop-stale")
        for field in ("projectOpenInput", "projectOpenBinding", "projectCompletionSelection", "panelAttachments", "controlReturns"):
            self.assert_refused(changed(base, ("native", field), project["native"][field]))
        for path in (("native", "selectedPathMatched"), ("native", "projectCancelSettled"),
                     ("installationInspection", "projectSelected"), ("shippingBinaryQualified",), ("distributionQualified",)):
            self.assert_refused(changed(base, path, True))
        self.assert_refused(changed(base, ("saveSessions",), project["saveSessions"]))
        self.assert_refused(changed(base, ("case",), "noop-stale"))
        with self.assertRaises(M.Refused):
            M.parse_result(captured(base), b"", BINDING, "noop-stale")
        for path in (("installationInspection", "limits", "readOnly"), ("syntheticFileReadback",)):
            self.assert_refused(changed(base, path, False))

    def test_fixed_original_invocation_keeps_clean_environment_95s_and_return_before_readback(self):
        fixtures, calls, emitted = InertFixtures(), [], []
        def owned(argv, **options):
            self.assertTrue(fixtures.inflight)
            self.assertEqual(fixtures.reads, [])
            calls.append((argv[:], options))
            return CompletedProcess(argv, 0, captured(example()), b"")
        result = M.run_cases(BINDING, fixtures, owned, 501, "runner", emitted.append, CASE)
        self.assertEqual(result, ())
        self.assertEqual(len(calls), 1)
        argv, options = calls[0]
        self.assertEqual(argv, [M.EXECUTABLE, CASE])
        self.assertEqual(options["cwd"], BINDING.root(installation_inspection=True) / "state" / CASE)
        self.assertEqual(options["timeout"], 95)
        self.assertIs(options["capture"], True)
        self.assertIs(options["text"], False)
        self.assertEqual(options["output_limit"], M.OUTPUT_LIMIT)
        self.assertEqual(options["environ"], M.app_environment(options["cwd"], 501, "runner"))
        self.assertFalse({"GITHUB_TOKEN", "GH_TOKEN", "PYTHONPATH", "PYTHONHOME", "DYLD_LIBRARY_PATH"} & options["environ"].keys())
        self.assertEqual(fixtures.before, [CASE])
        self.assertEqual(fixtures.reads, [CASE])
        self.assertEqual(emitted[0]["observer"], example())
        self.assertFalse(fixtures.inflight)
        self.assertTrue(fixtures.last_returned)

    def test_original_exception_or_nonzero_never_becomes_an_executed_pass(self):
        original = RuntimeError("inert original exception")
        fixtures = InertFixtures()
        def interrupted(argv, **options):
            raise original
        with self.assertRaises(RuntimeError) as raised:
            M.run_cases(BINDING, fixtures, interrupted, 501, "runner", lambda _: self.fail("unexpected emission"), CASE)
        self.assertIs(raised.exception, original)
        self.assertTrue(fixtures.inflight)
        self.assertFalse(fixtures.last_returned)
        self.assertEqual(fixtures.reads, [])
        for result_kind in ("nonzero", "missing", "failed", "foreign"):
            fixtures = InertFixtures()
            def returned(argv, **options):
                body = captured(example())
                if result_kind == "missing":
                    body = b""
                if result_kind == "failed":
                    body += b"MRK_MACOS_AQUA_FAILURE_REASON=installation-status-contract\n"
                return CompletedProcess(argv if result_kind != "foreign" else [M.EXECUTABLE, "noop-stale"],
                                        2 if result_kind == "nonzero" else 0, body, b"")
            with self.subTest(result=result_kind), self.assertRaises(M.Refused):
                M.run_cases(BINDING, fixtures, returned, 501, "runner", lambda _: self.fail("unexpected emission"), CASE)
            self.assertEqual(fixtures.reads, [])
            self.assertEqual(fixtures.before, [CASE])

    def test_new_failure_labels_and_quit_diagnostics_are_closed_case_bound_data(self):
        for step in ("StartCancelled", "WaitFirstRead", "Cancel", "WaitCancelled", "StartMatching", "WaitMatching"):
            token = "Installation(" + step + ")"
            self.assertEqual(M.failure_step(("MRK_MACOS_AQUA_FAILURE_STEP=" + token + "\n").encode(), b""), token)
        for reason in ("installation-request-contract", "installation-status-contract", "installation-first-read-contract",
                       "installation-original-contract", "installation-finality-contract"):
            self.assertEqual(M.failure_reason(("MRK_MACOS_AQUA_FAILURE_REASON=" + reason + "\n").encode(), b""), reason)
        self.assertIsNone(M._open_sample_kind(CASE, 1, allow_files=True))
        native = {"step": "Quit", "entered": True, "returned": True}
        panel = {"step": "Quit", "id": 3, "kind": "quit"}
        action = {"step": "Quit", "id": 3, "action": "quit-confirm", "domain": "objc-exception", "site": "quit-confirm", "error": "io"}
        self.assertEqual(M._native_action_context(action, native, panel, case=CASE), action)
        for identifier in (1, 2, 4, True):
            self.assertIsNone(M._native_action_context({**action, "id": identifier}, native, {**panel, "id": identifier}, case=CASE))
        self.assertIsNone(M._native_action_context(action, native, panel, case="noop-stale"))
        self.assertIsNone(M._result_location(("installationInspection", "private-file-name")))
        self.assertEqual(M._result_location(("installationInspection", "matching", "originals", "storageDisposed")),
                         "installationInspection.matching.originals.storageDisposed")

    def test_fixture_native_readback_releases_record_then_revalidates_original_and_deadline(self):
        source = (ROOT / "desktop/src-tauri/src/installed_shell_observation_macos_installation.rs").read_text()
        parent = (ROOT / "desktop/src-tauri/src/installed_shell_observation_macos.rs").read_text()
        matching = source.split("Step::WaitMatching => {", 1)[1].split("Step::StartCancelled | Step::StartMatching", 1)[0]
        self.assertLess(matching.index("FixtureData::capture(&r.fixture)"), matching.index("drop(r);"))
        self.assertLess(matching.index("drop(r);"), matching.index("fixture.verify()"))
        self.assertLess(matching.index("fixture.verify()"), matching.index("self.record()"))
        resumed = matching.split("self.record()", 1)[1]
        for gate in ("self.timely()", "self.case != Case::Installation", "r.step != OuterStep::Installation(Step::WaitMatching)",
                     "!no_project(&r)", "!fixture.matches(&r.fixture)", "row.same(&cancelled)",
                     "Arc::ptr_eq(&active.observation, &observation)", "active.complete(first, facts).same(&completed)"):
            self.assertIn(gate, resumed)
            self.assertLess(resumed.index(gate), resumed.index("record.active.take()"))
        self.assertLess(resumed.index("record.active.take()"), resumed.index("r.file_readback = true;"))
        self.assertNotIn("r.fixture.verify(", source)
        self.assertIn("expected.verify(false)", source)
        self.assertIn("fixture.ios.is_none() && fixture.project_fields.is_none()", source)
        self.assertIn("fixture.config.is_none() && fixture.release.is_none()", source)
        finish = parent.split("fn finish(&self) -> Option<Value> {", 1)[1].split("fn phase(", 1)[0]
        final_read = finish.split("let installation_readback = if self.case == Case::Installation {", 1)[1]
        self.assertLess(final_read.index("FinalReadback::capture(&r)"), final_read.index("drop(r);"))
        self.assertLess(final_read.index("drop(r);"), final_read.index("expected.verify()"))
        reacquired = final_read.split("expected.verify()", 1)[1]
        self.assertLess(reacquired.index("self.record()"), reacquired.index("self.timely()"))
        self.assertLess(reacquired.index("self.timely()"), reacquired.index("installation_readback.as_ref()?.matches(&r)"))
        self.assertIn("} else if r.fixture.verify(", finish)
        self.assertIn("record.normal_quit == self.normal_quit", source)

    def test_source_uses_start_bound_counts_dedicated_finality_and_existing_relay_only(self):
        source = (ROOT / "desktop/src-tauri/src/installed_shell_observation_macos_installation.rs").read_text()
        parent = (ROOT / "desktop/src-tauri/src/installed_shell_observation_macos.rs").read_text()
        asset = (ROOT / "desktop/src-tauri/src/asset_session.rs").read_text()
        edits = (ROOT / "desktop/src-tauri/src/edit_owner.rs").read_text()
        limits = (ROOT / "desktop/src-tauri/src/macos_install_record.rs").read_text()
        self.assertIn("const FILE_LIMIT: usize = 2048;", limits)
        self.assertIn("const PAYLOAD_LIMIT: u64 = 512 * 1024 * 1024;", limits)
        self.assertIn("document.inspect_installation_observed(cancelled)", source)
        self.assertEqual(source.count("observation.first_read()"), 1)
        self.assertIn("let raw_first = observation.first_read();", source)
        self.assertIn("FirstRead::snapshot(raw_first)", source)
        snapshot = source.split("let raw_first = observation.first_read();", 1)[1]
        self.assertLess(snapshot.index("FirstRead::snapshot(raw_first)"), snapshot.index("self.record()"))
        self.assertIn("let first_tick = FirstRead::snapshot(None);", source)
        self.assertIn("let next_tick = FirstRead::snapshot(Some((1, 7)));", source)
        self.assertIn("FirstRead::snapshot(Some(bad)).is_ok()", source)
        self.assertIn("Arc::ptr_eq(&active.observation, &observation)", source)
        self.assertIn("document.cancel_installation(id)", source)
        self.assertIn("document.installation_observer_facts(id)", source)
        self.assertIn("active.cancel_requested = true;", source)
        self.assertLess(source.index("active.cancel_requested = true;"), source.index("document.cancel_installation(id)"))
        self.assertIn("record.cancelled = Some(completed); r.step = OuterStep::Installation(Step::StartMatching)", source)
        self.assertIn("record.matching = Some(completed);", source)
        self.assertIn("pub(super) fn data_checks() -> bool", source)
        self.assertNotIn("#[test]", source)
        self.assertNotRegex(source, r"(?:thread::spawn|tokio::spawn|Command::|std::process::|sleep\(|Instant::now\()")
        self.assertIn("drop(r); self.installation_tick(&state.document, step); return;", parent)
        # Capture the original before either real inspection. Matching and Exit
        # must consume that identity, never refresh it after normal shutdown.
        capture = asset.split("fn installed_macos_installation(&self) -> Option<InstallationWitness> {", 1)[1].split(
            "fn installed_macos_installation_final(", 1)[0]
        for gate in ("!live(&state)", "state.next_operation != 0", "state.slot.is_some()", "state.quit.is_some()",
                     "!self.inner.bridge.edits.can_exit()", "roster.generation == 1 && roster.roots.is_empty()",
                     "document: Arc::downgrade(&self.inner)", "edit: self.inner.bridge.edits.installed_macos_document()?"):
            self.assertIn(gate, capture)
        start = source.split("if matches!(step, Step::StartCancelled | Step::StartMatching) {", 1)[1].split("let (id, observation) = {", 1)[0]
        self.assertIn("if cancelled { record.cancelled.is_some() || record.witness.is_some() }", start)
        self.assertIn("else { record.witness.is_none() || !record.cancelled.as_ref().is_some_and(|row| row.valid(true)) }", start)
        self.assertIn("if cancelled {\n                let Some(witness) = document.installed_macos_installation()", start)
        self.assertEqual(source.count("document.installed_macos_installation()"), 1)
        self.assertEqual(source.count("record.witness ="), 1)
        self.assertIn("pub(super) fn witness(&self) -> Option<Arc<InstalledMacInstallationWitness>> { self.witness.clone() }", source)
        published = start.index("record.witness = Some(Arc::new(witness));")
        publication = start.split("let Some(witness) = document.installed_macos_installation()", 1)[1].split(
            "record.witness = Some(Arc::new(witness));", 1)[0]
        for gate in ("self.record()", "self.timely()", "r.step != OuterStep::Installation(step)", "!no_project(&r)",
                     "record.active.is_some()", "record.normal_quit", "record.cancelled.is_some()",
                     "record.matching.is_some()", "record.witness.is_some()"):
            self.assertIn(gate, publication)
        self.assertLess(publication.index("self.record()"), publication.index("record.witness.is_some()"))
        self.assertLess(start.index("document.installed_macos_installation()"), published)
        self.assertLess(published, start.index("document.inspect_installation_observed(cancelled)"))
        self.assertIn("record.witness = Some(Arc::new(witness));\n            }\n            if !self.timely()", start)
        finality = asset.split("fn installed_macos_installation_final(", 1)[1].split("fn installed_macos_final(", 1)[0]
        self.assertIn("witness: &InstallationWitness", finality)
        self.assertIn("!same_document(&self.inner, &witness.document)", finality)
        self.assertIn("self.inner.bridge.edits.installed_macos_document_live(&witness.edit)", finality)
        self.assertNotIn(".installed_macos_document()", finality)
        for gate in ("inspection_id.checked_add(1) != Some(quit_id)", "!quiet(&state) || !state.stopping || !state.quit_accepted",
                     "!state.lifetime.original_bound() || state.lost_observed", "state.next_operation != quit_id || quit.id != quit_id",
                     "!assets_can_exit_locked(&state) || !state.evidence.revoked", "slot.owner.id != inspection_id",
                     "!work.settled()", "JoinReceipt::Returned && book.handle.is_none()", "book.not_started()",
                     "completed(&self.inner, quit, NativeResponse::Accept, false, true)", "!self.inner.bridge.edits.disabled()",
                     "self.inner.bridge.supervisor.can_exit() && self.inner.bridge.edits.can_exit()"):
            self.assertIn(gate, finality)
        fresh = edits.split("fn document(inner: &Arc<Inner>, r: &Registry) -> Option<DocumentWitness> {", 1)[1].split("fn same_document(", 1)[0]
        self.assertIn("healthy(inner, r) && !r.document_lost && !r.stopping", fresh)
        exit_route = parent.split("let installation_finality = if self.case == Case::Installation {", 1)[1].split("} else { None };", 1)[0]
        self.assertLess(exit_route.index("self.record()"), exit_route.index("installation_check::Record::witness"))
        self.assertLess(exit_route.index("installation_check::Record::witness"), exit_route.index("drop(r);"))
        self.assertLess(exit_route.index("drop(r);"), exit_route.index("document.installed_macos_installation_final("))
        self.assertIn("Some(witness.as_ref().is_some_and(|witness|", exit_route)
        self.assertNotIn(".installed_macos_installation()", exit_route)
        self.assertIn("document.installed_macos_installation_final(installation_check::QUIT_ID, installation_check::MATCHING_ID, witness)", exit_route)
        self.assertIn("installation_finality.unwrap_or_else(|| document.installed_macos_final(", parent)
        self.assertIn("|| !installation_check::data_checks()", parent)
        self.assertIn("crate::installation::assert_installation_inspection_wire_contract();", parent)
        self.assertIn("crate::asset_session::assert_installation_owner_contracts();", parent)
        self.assertIn('directory(&root,uid,0o700,&[installation_check::NAME,"state"])', parent)
        self.assertIn("Step::ReadEnvironment => if self.case == Case::Installation", parent)
        reasons = re.findall(r'"([a-z][a-z0-9_-]+)"', parent.split("const FAILURE_REASONS:", 1)[1].split("];", 1)[0])
        self.assertEqual(len(reasons), len(set(reasons)))
        self.assertLess(len(reasons), 255)


if __name__ == "__main__":
    unittest.main()
