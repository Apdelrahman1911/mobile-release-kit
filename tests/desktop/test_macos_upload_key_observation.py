"""Finite upload-key observer DATA, not native generation/Keychain evidence.

Imports the complete current Aqua parser and its new fixed helper. No core
process owner, subprocess, native user lookup, private file or key is accessed.
The metadata port below is synthetic; it does not qualify real FD custody.
"""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import stat
from subprocess import CompletedProcess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).absolute().parents[2]
PATH = ROOT / "desktop/tools/macos_aqua_qualification.py"
SPEC = importlib.util.spec_from_file_location("_mrk_upload_key_observer_data", PATH)
M = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = M
SPEC.loader.exec_module(M)
U = M.UPLOAD
BINDING = M.Binding("a" * 40, "123", "1")
CASE, BEFORE, AFTER = U.CASES


def producer():
    """Explicit receipt-shaped test DATA, never a native candidate."""
    return {key: key not in ("cleanupUnknown", "privateDisposed") for key in U.PRODUCER_FLAGS}


def positive():
    false = {"nativeUseRetained", "privateRetained", "stopped", "clockFailed", "documentUnknown"}
    return {**{key: key not in false for key in U.SAMPLE_FLAGS}, "operationId": 5,
            "checkpoint": "none", "producer": producer(), "retainedProducer": None}


def stopped(case=BEFORE):
    data = positive()
    data.update({key: False for key in U.SAMPLE_FLAGS})
    data.update({key: True for key in ("reserved", "nativeUseRetained", "privateRetained", "stopped",
                                      "clockFailed", "unassigned", "documentUnknown")})
    if case == BEFORE:
        data.update(checkpoint="before-go", producer={key: key == "ready" for key in U.PRODUCER_FLAGS})
        data["retainedProducer"] = deepcopy(data["producer"])
    else:
        data.update(checkpoint="after-new-before-journal", authenticatedNew=True, producer=producer())
        current = {key: False for key in U.PRODUCER_FLAGS}
        current.update(cleanupUnknown=True, inspectorStarted=True, acquisitionStarted=True)
        data["retainedProducer"] = current
    return {"source": "original-upload-key-sample", "observationOnly": True,
            "exitOrDisposalPermission": False, "repeatedCreateRefused": True, "sample": data}


def report(*, missing=False, initialized=True):
    old = M._expected_vault_helper(M.VAULT_HELPER_CASES[0], negative=not initialized)
    return {"mechanism": "same-original-upload-key-v1", "normalGenerationEnabled": False,
            "execution": "not-executed-prerequisite" if missing else "executed",
            "testResult": "not-executed" if missing else "positive", "initializeHelper": old["initializeHelper"],
            "storage": old["storage"], "generated": None if missing else positive(),
            "repeatedCreateRefused": not missing, "authenticatedReopenReadback": not missing,
            "originalCount": 5 if missing else 9, "allOriginalsSettled": True, "finalDocumentEmpty": True,
            "automaticallyAssigned": False, "backupCreated": False, "releaseSigningQualified": False,
            "physicalMacEvidence": False, "privateContentsExported": False,
            "rowRetirement": "disposable-hosted-account-only"}


def result_frame(case=CASE, **kwargs):
    value = M.expected_result(BINDING, case)
    value["vaultHelper"] = report(**kwargs)
    return value


def captured(value):
    return M.MARKER + json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def failure_frame(case=BEFORE):
    context = {"pending": None, "nativeHandler": None, "lastPanel": None,
               "snapshotSource": "record", "uploadKey": stopped(case)}
    return (b"MRK_MACOS_AQUA_FAILURE_STEP=UploadKey(Running)\n"
            b"MRK_MACOS_AQUA_FAILURE_REASON=upload-key-expected-retention\n"
            b"MRK_MACOS_AQUA_FAILURE_CONTEXT="
            + json.dumps(context, separators=(",", ":")).encode("ascii") + b"\nMRK_MACOS_AQUA=failed\n")


class InertInvocation:
    """Only the existing run_cases public boundary; never an actual owner."""
    def __init__(self, case):
        self.cases = (case,)
        self.inflight = self.last_returned = False
        self.before, self.reads = [], []

    def before_call(self, case):
        self.before.append(case)

    def readback(self, case):
        self.reads.append(case)
        raise AssertionError("unexpected private readback")


class MetadataPort:
    """Finite synthetic metadata slots, no FDs, filesystem or private bytes."""
    uid, gid = 501, 20

    def __init__(self, *, generated=True, initialized=True):
        self.cases, self.inflight, self.last_returned = (CASE,), False, True
        self.vault_completed, self.reads, self.opened, self.closed, self.active = set(), [], [], [], set()
        self.before = []
        self.fail_close = set()
        self.first_close_error = None
        self.close_errors = 0
        self.meta, self.entries = {}, {}
        self.next_id = 1
        self.vault_namespace = self.directory()
        parent = self.directory()
        self.vault_parents = {CASE: parent}
        self.entries[self.vault_namespace][CASE] = parent
        self.app = self.directory()
        self.entries[parent]["dev.mobile-release-kit.desktop"] = self.app
        self.vault = self.directory()
        self.entries[self.app]["credential-vault-v1"] = self.vault
        for name, size in (("vault-lock", 0), ("initialization-reservation", 48)):
            self.file(self.vault, name, size)
        if initialized:
            self.file(self.vault, "vault-header", 104)
        if generated:
            self.file(self.vault, "record-" + "b" * 32, 4096)
            self.fence = self.file(self.app, "service-v1.reservation", len(b"MRK service root v1\n") + 16)
            self.service = self.directory()
            self.entries[self.app]["service-v1"] = self.service
            reservation = len(b"MRK application references v1\nprojects\ncredential-references\nversion-allocations\n")
            for name, size in (("owner.lock", 0), ("reservation", reservation), ("projects.state", 1024),
                               ("credential-references.state", 2048), ("version-allocations.state", 52)):
                self.file(self.service, name, size)

    def directory(self):
        value = self.next_id
        self.next_id += 1
        self.meta[value] = (7, value, stat.S_IFDIR | 0o700, self.uid, self.gid, 2, 0, 1, 1)
        self.entries[value] = {}
        return value

    def file(self, parent, name, size):
        value = self.next_id
        self.next_id += 1
        self.meta[value] = (7, value, stat.S_IFREG | 0o600, self.uid, self.gid, 1, size, 1, 1)
        self.entries[parent][name] = value
        return value

    def _upload_signature(self, value):
        return self.meta[value]

    def _upload_named_signature(self, parent, name):
        return self.meta[self.entries[parent][name]]

    def _upload_names(self, parent):
        return tuple(self.entries[parent])

    def _roster(self, parent, names, reason):
        U.need(set(self.entries[parent]) == set(names), reason)

    def _named(self, parent, name, value, mode):
        U.need(self.entries[parent][name] == value and self.meta[value][2] == stat.S_IFDIR | mode)

    def _open(self, name, parent, *, directory=False):
        value = self.entries[parent][name]
        U.need(stat.S_ISDIR(self.meta[value][2]) == directory)
        self.opened.append((parent, name, value))
        U.need(value not in self.active)
        self.active.add(value)
        return value

    def _close(self, value):
        U.need(value in self.active)
        self.active.remove(value)
        self.closed.append(value)
        if value in self.fail_close:
            self.close_errors += 1
            if self.first_close_error is None:
                self.first_close_error = OSError("synthetic close unknown")
            return False
        return True

    # Use the actual existing finite-close context logic, not a new policy.
    _temporary = M.Fixtures._temporary

    def _vault_namespace_current(self):
        U.need(self.vault_completed == {CASE})

    def readback(self, case):
        self.reads.append(case)
        return {"syntheticMetadataOnly": True}

    def before_call(self, case):
        self.before.append(case)


class UploadKeyObservationTests(unittest.TestCase):
    def assert_refused(self, fn, *args, **kwargs):
        with self.assertRaises((ValueError, M.Refused)):
            fn(*args, **kwargs)

    def test_scopes_are_independent_closed_invocations_with_fixed_outer_bounds(self):
        for case in U.CASES:
            self.assertEqual(M.entry_arguments(["--scope", case]), (case, M.ARM_TARGET))
            self.assertEqual(M.selected_cases(case), (case,))
            self.assertEqual(M.case_timeout(case), 495)
        for args in (["--scope", "upload-key-all"], ["--scope", CASE, "--timeout", "999"],
                     ["--scope", CASE, BEFORE], ["--scope", CASE, "--keytool", "/usr/bin/keytool"]):
            self.assert_refused(M.entry_arguments, args)
        self.assertEqual(M.case_timeout(M.VAULT_HELPER_CASES[0]), 135)

    def test_each_case_has_distinct_project_and_native_state_parents(self):
        roots = [BINDING.root(upload_key=c) for c in U.CASES]
        state = [U.fixture_path(BINDING, "/Users/inert", c) for c in U.CASES]
        self.assertEqual(len(set(roots)), 3)
        self.assertEqual(len({p.parent.parent for p in state}), 3)
        for case, root in zip(U.CASES, state):
            self.assertEqual(root.parent.name, case)
            self.assertEqual(root.name, "dev.mobile-release-kit.desktop")
        for home in ("/", "/Users/../inert", "/Users//inert", "/Users/inert/", "relative", "/Users/\x00inert"):
            self.assert_refused(U.fixture_path, BINDING, home, CASE)
        self.assert_refused(BINDING.root, vault_helper=True, upload_key=CASE)

    def test_project_config_is_existing_saved_data_not_generated_fixture_output(self):
        for case in U.CASES:
            before, before_dirs = M.fixture_data(case, False)
            after, after_dirs = M.fixture_data(case, True)
            self.assertEqual(before, after)
            self.assertEqual(before_dirs, after_dirs)
            self.assertEqual(before["release/mobile-release.json"], M.CONFIG)
            self.assertFalse(any("jks" in name or "password" in name for name in before))

    def test_positive_requires_every_original_generation_and_disposal_axis(self):
        self.assertIs(U.positive(positive())["clockRetired"], True)
        for key in U.SAMPLE_FLAGS:
            value = positive()
            value[key] = not value[key]
            self.assert_refused(U.positive, value)
        for key in U.PRODUCER_FLAGS:
            value = positive()
            value["producer"][key] = not value["producer"][key]
            self.assert_refused(U.positive, value)
        value = positive()
        value["retainedProducer"] = producer()
        self.assert_refused(U.positive, value)

    def test_report_is_not_generic_status_and_cannot_supply_private_data(self):
        for value in (None, {}, {"phase": "idle"}, {"records": 1}):
            self.assert_refused(U.positive, value)
        for field, replacement in (("operationId", True), ("operationId", 6), ("unassigned", 1),
                                   ("checkpoint", "done"), ("producer", None)):
            value = positive()
            value[field] = replacement
            self.assert_refused(U.positive, value)
        for name in ("password", "privateKey", "jks", "path", "recoveryCode"):
            value = positive()
            value[name] = "not-a-secret-test-data"
            self.assert_refused(U.positive, value)

    def test_stops_preserve_retained_unknowns_and_never_become_positive(self):
        for case in (BEFORE, AFTER):
            value = stopped(case)
            self.assertIs(U.retained_stop(value, case), value)
            self.assertFalse(value["sample"]["coordinatorJoined"])
            self.assertFalse(value["sample"]["childJoined"])
            self.assertTrue(value["sample"]["documentUnknown"])
            self.assert_refused(U.positive, value["sample"])
            for key in ("exitOrDisposalPermission", "observationOnly", "repeatedCreateRefused"):
                changed = deepcopy(value)
                changed[key] = not changed[key]
                self.assert_refused(U.retained_stop, changed, case)
        self.assertTrue(stopped(AFTER)["sample"]["retainedProducer"]["cleanupUnknown"])
        self.assertFalse(stopped(AFTER)["sample"]["producer"]["cleanupUnknown"])

    def test_stop_before_go_refuses_send_or_new_and_after_new_requires_real_boundary(self):
        for key in ("goClaimed", "goSent", "candidate"):
            value = stopped()
            value["sample"]["producer"][key] = True
            self.assert_refused(U.retained_stop, value, BEFORE)
        for key in ("authenticatedNew", "reserved", "nativeUseRetained", "privateRetained"):
            value = stopped(AFTER)
            value["sample"][key] = False
            self.assert_refused(U.retained_stop, value, AFTER)
        self.assert_refused(U.retained_stop, stopped(BEFORE), AFTER)
        self.assert_refused(U.retained_stop, stopped(AFTER), BEFORE)

    def test_complete_existing_parser_requires_current_exact_upload_report(self):
        value = result_frame()
        self.assertEqual(M.parse_result(captured(value), b"", BINDING, CASE), value)
        self.assert_refused(M.parse_result, captured(M.expected_result(BINDING, CASE)), b"", BINDING, CASE)
        for field in ("normalGenerationEnabled", "automaticallyAssigned", "backupCreated", "releaseSigningQualified",
                      "physicalMacEvidence", "privateContentsExported"):
            changed = deepcopy(value)
            changed["vaultHelper"][field] = True
            self.assert_refused(M.parse_result, captured(changed), b"", BINDING, CASE)
        for storage in ({"reservation": [1, 1], "header": [True, True], "durability": [True, True]},
                        {"reservation": [True, True], "header": [True, False], "durability": [True, True]}):
            changed = deepcopy(value)
            changed["vaultHelper"]["storage"] = storage
            self.assert_refused(M.parse_result, captured(changed), b"", BINDING, CASE)

    def test_missing_prerequisite_is_not_a_generation_pass(self):
        for initialized in (True, False):
            value = result_frame(missing=True, initialized=initialized)
            self.assertEqual(M.parse_result(captured(value), b"", BINDING, CASE), value)
            self.assert_refused(U.positive, value["vaultHelper"]["generated"])
        self.assert_refused(U.report, report(), BEFORE)
        self.assert_refused(U.report, report(), AFTER)

    def test_failure_reducer_keeps_closed_case_reason_and_diagnostic_only_contract(self):
        for case in (BEFORE, AFTER):
            raw = failure_frame(case)
            self.assertEqual(M.failure_context(raw, b"", case)["uploadKey"], stopped(case))
            self.assert_refused(M.parse_result, raw, b"", BINDING, case)
            self.assertIsNone(M.failure_context(raw, b"", CASE))
            self.assertIsNone(M.failure_context(raw.replace(b"UploadKey(Running)", b"Vault(Initialized)"), b"", case))

    def test_original_exception_never_clears_inflight_or_invokes_private_readback(self):
        fixture = InertInvocation(BEFORE)
        error = TimeoutError("synthetic original invocation timeout")
        calls = []
        def refused(argv, **kwargs):
            calls.append((argv, kwargs))
            raise error
        with patch.object(U, "readback", side_effect=AssertionError("private readback after unknown")):
            with self.assertRaises(TimeoutError) as raised:
                M.run_cases(BINDING, fixture, refused, 501, "inert", lambda _: None, BEFORE)
        self.assertIs(raised.exception, error)
        self.assertTrue(fixture.inflight)
        self.assertFalse(fixture.last_returned)
        self.assertEqual(fixture.before, [BEFORE])
        self.assertEqual(fixture.reads, [])
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], [M.EXECUTABLE, BEFORE])
        self.assertEqual(calls[0][1]["timeout"], 495)

    def test_completed_failure_remains_failure_without_retry_or_private_readback(self):
        fixture = InertInvocation(AFTER)
        calls = []
        def failed(argv, **kwargs):
            calls.append(argv)
            return CompletedProcess(argv, 1, failure_frame(AFTER), b"")
        with patch.object(U, "readback", side_effect=AssertionError("private readback after failure")):
            self.assert_refused(M.run_cases, BINDING, fixture, failed, 501, "inert", lambda _: None, AFTER)
        self.assertFalse(fixture.inflight)
        self.assertTrue(fixture.last_returned)
        self.assertEqual(len(calls), 1)
        self.assertEqual(fixture.reads, [])
        self.assertEqual(fixture.inner_failure_context["uploadKey"], stopped(AFTER))

    def test_complete_inert_invocation_uses_full_parser_and_metadata_readback_once(self):
        fixture, calls, emitted = MetadataPort(), [], []
        def returned(argv, **kwargs):
            calls.append(argv)
            self.assertEqual(kwargs["timeout"], 495)
            return CompletedProcess(argv, 0, captured(result_frame()), b"")
        self.assertEqual(M.run_cases(BINDING, fixture, returned, 501, "inert", emitted.append, CASE), ())
        self.assertEqual(calls, [[M.EXECUTABLE, CASE]])
        self.assertEqual(fixture.before, [CASE])
        self.assertEqual(fixture.reads, [CASE])
        self.assertEqual(len(emitted), 1)
        self.assertFalse(emitted[0]["observer"]["vaultHelper"]["normalGenerationEnabled"])

    def test_result_shaped_foreign_return_cannot_supply_original_finality(self):
        fixture = InertInvocation(CASE)
        def foreign(argv, **kwargs):
            return {"args": argv, "returncode": 0, "stdout": captured(result_frame()), "stderr": b""}
        self.assert_refused(M.run_cases, BINDING, fixture, foreign, 501, "inert", lambda _: None, CASE)
        self.assertTrue(fixture.inflight)
        self.assertFalse(fixture.last_returned)
        self.assertEqual(fixture.reads, [])

    def test_vault_roster_allows_one_new_record_and_no_recovery_fences_or_alias_names(self):
        names = ("vault-lock", "initialization-reservation", "vault-header", "record-" + "b" * 32)
        self.assertEqual(len(U.private_roster(names, initialized=True, generated=True, host_started=True)), 4)
        for changed in (names + ("candidate",), names[:-1], names + ("record-" + "c" * 32,),
                        (*names[:-1], "record-" + "0" * 32), (*names[:-1], "record-" + "B" * 32),
                        (*names[:-1], "../record-" + "b" * 32), names + (names[0],)):
            self.assert_refused(U.private_roster, changed, initialized=True, generated=True, host_started=True)
        self.assert_refused(U.private_roster, names, initialized=1, generated=True, host_started=True)
        self.assert_refused(U.private_roster, names, initialized=True, generated=True, host_started=False)

    def test_full_metadata_readback_has_exact_names_and_no_contents(self):
        fixture = MetadataPort()
        result = U.readback(fixture, CASE, report())
        self.assertTrue(result["uploadKeyOutput"]["newEncryptedRecordPresent"])
        self.assertTrue(result["uploadKeyOutput"]["referenceNamespacePresent"])
        self.assertFalse(result["uploadKeyOutput"]["privateContentsExported"])
        self.assertEqual(fixture.vault_completed, {CASE})
        self.assertEqual(fixture.active, set())
        self.assertEqual(len(fixture.closed), len(fixture.opened))
        self.assert_refused(U.readback, fixture, CASE, report())

    def test_metadata_bounds_mode_alias_and_unknown_close_never_complete(self):
        for kind in ("root-fence-size", "root-fence-device", "namespace-fence-size", "mode", "alias", "pending", "close"):
            fixture = MetadataPort()
            if kind == "root-fence-size":
                original = fixture.meta[fixture.fence]
                fixture.meta[fixture.fence] = (*original[:6], 79, *original[7:])
            elif kind == "root-fence-device":
                original = fixture.meta[fixture.fence]
                fixture.meta[fixture.fence] = (8, *original[1:])
            elif kind == "namespace-fence-size":
                record = fixture.entries[fixture.service]["reservation"]
                original = fixture.meta[record]
                fixture.meta[record] = (*original[:6], 35, *original[7:])
            elif kind == "mode":
                record = fixture.entries[fixture.vault]["record-" + "b" * 32]
                original = fixture.meta[record]
                fixture.meta[record] = (*original[:2], stat.S_IFREG | 0o644, *original[3:])
            elif kind == "alias":
                records = fixture.entries[fixture.vault]
                record = records["record-" + "b" * 32]
                original = fixture.meta[record]
                fixture.meta[record] = (*fixture.meta[records["vault-header"]][:2], *original[2:])
            elif kind == "pending":
                fixture.file(fixture.service, "credential-references.intent", 1)
            else:
                fixture.fail_close.add(fixture.entries[fixture.service]["projects.state"])
            with self.assertRaises((ValueError, OSError)):
                U.readback(fixture, CASE, report())
            self.assertEqual(fixture.vault_completed, set(), kind)
            self.assertEqual(fixture.active, set(), kind)
            self.assertEqual(len(fixture.closed), len(fixture.opened), kind)

    def test_readback_refuses_before_original_return_and_known_no_tools_has_no_host(self):
        for inflight, returned in ((True, False), (True, True), (False, False)):
            fixture = MetadataPort()
            fixture.inflight, fixture.last_returned = inflight, returned
            self.assert_refused(U.readback, fixture, CASE, report())
            self.assertEqual(fixture.opened, [])
            self.assertEqual(fixture.reads, [])
        fixture = MetadataPort(generated=False)
        value = U.readback(fixture, CASE, report(missing=True))
        self.assertFalse(value["uploadKeyOutput"]["newEncryptedRecordPresent"])
        self.assertFalse(value["uploadKeyOutput"]["referenceNamespacePresent"])

    def test_same_parent_fence_stays_held_and_late_replacement_is_not_completed(self):
        fixture = MetadataPort()
        named = fixture._named
        visits = []
        def changed(parent, name, value, mode):
            named(parent, name, value, mode)
            if value == fixture.service:
                self.assertIn(fixture.fence, fixture.active)
                visits.append(value)
                if len(visits) == 2:
                    old = fixture.meta[fixture.fence]
                    fixture.meta[fixture.fence] = (old[0], old[1] + 100, *old[2:])
        fixture._named = changed
        self.assert_refused(U.readback, fixture, CASE, report())
        self.assertEqual(len(visits), 2)
        self.assertEqual(fixture.vault_completed, set())
        self.assertEqual(fixture.active, set())
        self.assertEqual(len(fixture.opened), len(fixture.closed))


if __name__ == "__main__":
    unittest.main()
