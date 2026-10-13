"""Focused DATA/custody tests; never install, sign, mount or invoke Cargo.

Native fixture execution remains a separate Mac-only original in the dedicated
route. These tests exercise genuine adapter and existing Operation methods with
small owned files, not a replacement owner or a synthetic native-pass receipt.
"""
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load_tool(name, leaf):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / leaf)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE = load_tool("mrk_app_absence_test_adapter", "macos_app_absence_fixture.py")
HELPER = load_tool("mrk_app_absence_test_operation", "macos_android_helper_package.py")
NOW = 1_000_000_000


def state():
    return {"started": NOW, "observed": NOW, "workSeconds": 10, "hardSeconds": 20,
            "pendingRoot": None, "mount": None, "outputs": [], "roots": []}


def call_row(role, **changes):
    return dict({"role": role, "returncode": 0, "returned": True, "capturesSettled": True}, **changes)


def inert_operation(phase=None):
    return SimpleNamespace(app_absence=state(), app_absence_api=HELPER,
        phase=phase or FIXTURE.PREPARE, errors=[], calls=[], stager_io_pending=None,
        package_settled=lambda: True)


@contextlib.contextmanager
def file_operation():
    """Real descriptor registry/read/close, without the native owner's entry."""
    with tempfile.TemporaryDirectory(prefix="mrk-app-absence-data-") as directory:
        op = HELPER.Operation.__new__(HELPER.Operation)
        op.work = Path(directory)
        op.work_entry = op.source_entry = None
        op.entries, op.errors, op.calls = [], [], []
        op.entry_registry, op.directories = {}, {}
        op.app_absence, op.app_absence_api = state(), HELPER
        op.stager_io_pending = None
        try:
            fd = os.open(directory, HELPER.READ_FLAGS | os.O_DIRECTORY)
            op.work_entry = op.register(fd, "work-root", "directory")
            op.work_entry["identity"] = HELPER.directory_identity(os.fstat(fd))
            yield op
        finally:
            for entry in reversed(op.entries):
                op.close(entry)
            if op.errors or any(not entry["closed"] for entry in op.entries):
                raise AssertionError("fixture original closes not known")


def cargo_rows(checkout, target_root, target):
    package = checkout / "desktop/src-tauri"
    rows = []
    for name, source, kind, executable in (
            (FIXTURE.FIXTURE_EXECUTABLE, "src/bin/macos_install.rs", ["bin"],
             str(target_root / target / "release" / FIXTURE.FIXTURE_EXECUTABLE)),
            ("mobile_release_desktop", "src/lib.rs", ["lib"], None)):
        rows.append({"reason": "compiler-artifact",
            "package_id": "path+" + package.as_uri() + "#mobile-release-kit-desktop@0.1.1",
            "manifest_path": str(package / "Cargo.toml"),
            "features": ["macos-installed-app-absence-fixture"],
            "target": {"name": name, "kind": kind, "crate_types": kind,
                       "src_path": str(package / source), "edition": "2021"},
            "profile": {"test": False, "debug_assertions": False, "opt_level": "3"},
            "executable": executable, "fresh": False,
            "filenames": [executable] if executable else [str(target_root / "libmobile_release_desktop.rlib")]})
    return rows + [{"reason": "build-finished", "success": True}]


def encoded_rows(rows):
    return b"".join(json.dumps(row, separators=(",", ":")).encode("ascii") + b"\n" for row in rows)


def phase_value(phase):
    binding = {"fixtureSource": "1" * 40, "productSource": "1" * 40,
        "runId": "123", "runAttempt": "1", "target": FIXTURE.TARGETS[0]}
    binding.update({key: "2" * 64 for key in FIXTURE.BINDING_FIELDS if key not in binding})
    value = dict(binding, schemaVersion=1, kind="app-absence-phase-observation", phase=phase,
        baselineSha256="3" * 64, recordSha256=("3" if phase == "baseline" else "4") * 64,
        proof={key: True for key in FIXTURE.PROOFS[phase]}, originalOuterExitRequired=True,
        systemServiceExitClaimed=False, productReady=False)
    op = inert_operation()
    op.app_absence.update(nativeBinding=binding, baselineSha256="3" * 64)
    return op, value


def marker(value):
    return b"MRK_MACOS_APP_ABSENCE_RESULT=" + json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


class MacAppAbsenceFixtureData(unittest.TestCase):
    def test_fixed_bindings_layout_and_stricter_script_quote(self):
        FIXTURE.fixed_binding_and_layout_data_checks()
        FIXTURE.ownership_and_finality_data_checks()
        quote = FIXTURE.script_quote({"core.zip": {"size": 1024}}, 1024)
        self.assertLess(quote, FIXTURE.PRODUCT_LIMIT)
        # The abstract six-file DATA ceiling does not widen the actual route's
        # unchanged 512-MiB archive readers. Numeric quote: no large allocation.
        rows = [{"name": name, "bytes": 100, "sha256": "5" * 64, "mode": 0o444, "links": 1}
                for name in FIXTURE.CARRIER_NAMES]
        for row in rows:
            if row["name"] in FIXTURE.PHASE_NAMES:
                row["bytes"] = FIXTURE.PRODUCT_LIMIT + 1
        self.assertEqual(FIXTURE.transport_layout_data(rows)["fixtureBytes"], FIXTURE.PRODUCT_LIMIT + 1)
        with self.assertRaisesRegex(ValueError, "app-absence-fixture-ineligible"):
            FIXTURE.script_quote({"core.zip": {"size": FIXTURE.PRODUCT_LIMIT}}, 1024)
        binding = {"fixtureSource": "1" * 40, "productSource": "1" * 40,
            "runId": "123", "runAttempt": "1", "target": FIXTURE.TARGETS[0]}
        for changes in ({"productSource": "2" * 40}, {"runId": "0123"},
                        {"runAttempt": True}, {"target": "linux"}, {"extra": "path"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                FIXTURE.binding_data(dict(binding, **changes))

    def test_cargo_selection_is_same_source_exact_graph_and_terminal(self):
        checkout, target_root = Path("/owned/checkout"), Path("/owned/target")
        for target in FIXTURE.TARGETS:
            rows = cargo_rows(checkout, target_root, target)
            expected = target_root / target / "release" / FIXTURE.FIXTURE_EXECUTABLE
            self.assertEqual(FIXTURE.artifact_data(encoded_rows(rows), checkout, target_root, target), expected)
            mutations = []
            for where, key, value in ((0, "features", ["macos-installed-entry"]),
                                      (0, "executable", "/unrelated/fixture"),
                                      (0, "package_id", "path+file:///other#mobile-release-kit-desktop@0.1.1"),
                                      (2, "success", False)):
                changed = copy.deepcopy(rows); changed[where][key] = value; mutations.append(changed)
            changed = copy.deepcopy(rows); changed[0]["profile"]["test"] = True; mutations.append(changed)
            changed = copy.deepcopy(rows); changed[0]["target"]["src_path"] = "/other/bin.rs"; mutations.append(changed)
            mutations.extend((rows[:-1], rows + [rows[-1]], [rows[-1]] + rows[:-1], rows[:1] + rows))
            extra = copy.deepcopy(rows[0]); extra["target"]["name"] = "unrequested"
            mutations.append(rows[:-1] + [extra, rows[-1]])
            for changed in mutations:
                with self.subTest(target=target, changed=changed), self.assertRaises(ValueError):
                    FIXTURE.artifact_data(encoded_rows(changed), checkout, target_root, target)
            for body in (encoded_rows(rows).rstrip(b"\n"),
                         encoded_rows(rows).replace(b'"success":true', b'"success":true,"success":true')):
                with self.assertRaises(ValueError):
                    FIXTURE.artifact_data(body, checkout, target_root, target)

    def test_phase_marker_is_unique_complete_bound_and_pending_outer_exit(self):
        for phase in FIXTURE.PROOFS:
            op, value = phase_value(phase)
            line = marker(value)
            for stdout, stderr in ((line, b""), (b"", b"installer: " + line)):
                result = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
                self.assertEqual(FIXTURE.phase_observation(op, result, phase), value)
            for stdout, stderr, code in ((line + line, b"", 0), (line, line, 0),
                    (line.rstrip(b"\n"), b"", 0), (b"", b"", 0),
                    (b"bad\x01: " + line, b"", 0), (b"bad" + line, b"", 0),
                    (line, b"", 1), (line, b"", None), (line, b"", False)):
                with self.subTest(phase=phase, code=code), self.assertRaises(ValueError):
                    FIXTURE.phase_observation(op, SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr), phase)
            changes = ({"runId": "124"}, {"productReady": True}, {"systemServiceExitClaimed": True},
                       {"originalOuterExitRequired": False}, {"schemaVersion": True},
                       {"privatePath": "/private/fixture"}, {"baselineSha256": "6" * 64})
            for change in changes:
                with self.subTest(phase=phase, change=change), self.assertRaises(ValueError):
                    FIXTURE.phase_observation(op, SimpleNamespace(returncode=0, stdout=marker(dict(value, **change)), stderr=b""), phase)
            bad = copy.deepcopy(value); bad["proof"][next(iter(bad["proof"]))] = 1
            with self.assertRaises(ValueError):
                FIXTURE.phase_observation(op, SimpleNamespace(returncode=0, stdout=marker(bad), stderr=b""), phase)
            duplicate = line.replace(b'"schemaVersion":1', b'"schemaVersion":1,"schemaVersion":1')
            with self.assertRaises(ValueError):
                FIXTURE.phase_observation(op, SimpleNamespace(returncode=0, stdout=duplicate, stderr=b""), phase)

    def test_original_order_failure_pending_and_original_deadlines(self):
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW):
            self.assertEqual(FIXTURE.PREPARE_ROLES[:3],
                ("app-absence-build", "app-absence-data-tests", "app-absence-adhoc"))
            op = inert_operation()
            FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[0])
            op.calls.append(call_row(FIXTURE.PREPARE_ROLES[0]))
            FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[1])
            for change in ({"returncode": 1}, {"returncode": None}, {"returncode": False},
                           {"returned": False}, {"capturesSettled": False}):
                op.calls[:] = [call_row(FIXTURE.PREPARE_ROLES[0]), call_row(FIXTURE.PREPARE_ROLES[1], **change)]
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "exact-original-order"):
                    FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[2])
            op.calls[:] = [call_row(role) for role in FIXTURE.PREPARE_ROLES[:2]]
            op.errors.append({"stage": "previous"})
            with self.assertRaises(ValueError):
                FIXTURE.dispatch(op, FIXTURE.PREPARE_ROLES[2])
            op = inert_operation(FIXTURE.RESTORE)
            op.calls.append(call_row(FIXTURE.RESTORE_ROLES[0]))
            FIXTURE.dispatch(op, "app-absence-withdraw")
            self.assertEqual(op.app_absence["pendingRoot"], "app-absence-withdraw")
            self.assertFalse(FIXTURE.finish_ready(op))
            op.calls.append(call_row("app-absence-withdraw", capturesSettled=False))
            with self.assertRaises(ValueError):
                FIXTURE.returned(op, "app-absence-withdraw")
            self.assertEqual(op.app_absence["pendingRoot"], "app-absence-withdraw")
            op.calls[-1]["capturesSettled"] = True
            FIXTURE.returned(op, "app-absence-withdraw")
            self.assertTrue(FIXTURE.finish_ready(op))
            op.app_absence["mount"] = {"entered": True, "detached": False}
            self.assertFalse(FIXTURE.finish_ready(op))
            op.app_absence["mount"]["detached"] = True
            self.assertTrue(FIXTURE.finish_ready(op))
            op = inert_operation()
            def failed_io():
                raise OSError("fixture synthetic read failure")
            with self.assertRaises(OSError):
                FIXTURE.io(op, "read", failed_io)
            self.assertEqual(op.stager_io_pending, "app-absence-read")
            self.assertFalse(FIXTURE.finish_ready(op))
        op = inert_operation()
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW + 10_000_000_000):
            with self.assertRaisesRegex(ValueError, "original-deadline"):
                FIXTURE.clock(op)
            self.assertEqual(FIXTURE.clock(op, work=False), NOW + 10_000_000_000)
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW + 20_000_000_000):
            with self.assertRaisesRegex(ValueError, "original-deadline"):
                FIXTURE.clock(op, work=False)
        op = inert_operation()
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW - 1):
            with self.assertRaises(ValueError):
                FIXTURE.clock(op)
        op = inert_operation()
        with patch.object(FIXTURE.time, "monotonic_ns", side_effect=(NOW, NOW + 10_000_000_000)):
            with self.assertRaisesRegex(ValueError, "original-deadline"):
                FIXTURE.io(op, "post", lambda: b"complete bytes alone are not finality")
        self.assertEqual(op.stager_io_pending, "app-absence-post")

    def test_copy_has_real_original_post_exclusive_destination_and_consumed_close(self):
        with patch.object(FIXTURE.time, "monotonic_ns", return_value=NOW), file_operation() as op:
            body = b"small credential-free fixture\n"
            source = FIXTURE.output(op, op.work_entry, "source", body)
            expected = hashlib.sha256(body).hexdigest()
            self.assertEqual(FIXTURE.original_hash(op, source), expected)
            target = FIXTURE.copy(op, source, op.work_entry, "copied", 1024)
            self.assertEqual(op.read(target), body)
            self.assertEqual(stat.S_IMODE(os.fstat(target["fd"]).st_mode), 0o444)
            self.assertEqual(len(op.app_absence["outputs"]), 2)
            FIXTURE.post(op)
            with self.assertRaises(FileExistsError):
                FIXTURE.copy(op, source, op.work_entry, "copied", 1024)
            self.assertEqual(op.read(target), body)
            with self.assertRaisesRegex(ValueError, "copy-bound"):
                FIXTURE.copy(op, source, op.work_entry, "oversize", len(body) - 1)
            self.assertFalse((op.work / "oversize").exists())
            # Name replacement cannot be laundered through an unchanged open FD.
            os.rename("source", "withdrawn", src_dir_fd=op.work_entry["fd"], dst_dir_fd=op.work_entry["fd"])
            replacement = FIXTURE.output(op, op.work_entry, "source", body)
            self.assertNotEqual(replacement["identity"][1], source["identity"][1])
            with self.assertRaisesRegex(ValueError, "original-post"):
                FIXTURE.original_hash(op, source)
            op.close(target)
            self.assertIsNone(target["fd"])
            self.assertTrue(target["closed"])
            with self.assertRaisesRegex(ValueError, "original-closed"):
                FIXTURE.original_hash(op, target)
            op.close(target)  # Consumed originals never close a reused numeric FD.
            self.assertEqual(op.read(replacement), body)

    def test_native_data_result_requires_all_six_exact_names_and_genuine_zero(self):
        names = tuple("installer::worker::app_absence_fixture::tests::" + name for name in (
            "fixed_transport_and_same_source_bindings",
            "initial_fresh_install_and_same_gate_not_name_only",
            "output_quote_and_original_exit_finality_are_separate",
            "actual_restore_requires_new_app_and_exact_initial_history",
            "exclusive_rename_metadata_and_record_bounds_are_not_identity_reset",
            "phase_observations_are_pending_outer_exit_and_keep_private_fields_private"))
        self.assertEqual(FIXTURE.NATIVE_DATA_TESTS, names)
        lines = [b"running 6 tests"] + [("test " + name + " ... ok").encode("ascii") for name in reversed(names)]
        lines.append(b"test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.125s")
        stdout = b"\n".join(lines) + b"\n"
        stderr = b"   Compiling credential-free fixture\n"
        result = SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)
        value = FIXTURE.native_data_tests_result(result)
        self.assertEqual(set(value["methodNames"]), set(names))
        self.assertEqual((value["testCount"], value["passed"], value["failed"], value["ignored"], value["filteredCount"]), (6, 6, 0, 0, 4))
        self.assertEqual(value["stdoutSha256"], hashlib.sha256(stdout).hexdigest())
        self.assertEqual(value["stderrSha256"], hashlib.sha256(stderr).hexdigest())
        self.assertIs(value["productReady"], False)
        changed = []
        changed.append(b"\n".join(lines[:1] + lines[2:]) + b"\n")
        changed.append(b"\n".join(lines[:2] + [lines[1]] + lines[3:]) + b"\n")
        changed.extend((stdout + lines[1] + b"\n", stdout + lines[-1] + b"\n", stdout.rstrip(b"\n"),
            stdout.replace(b" ... ok", b" ... FAILED", 1), stdout.replace(b" ... ok", b" ... ignored", 1),
            stdout.replace(names[0].encode(), b"installer::worker::app_absence_fixture::tests::unexpected"),
            stdout.replace(b"running 6 tests", b"running 5 tests"),
            stdout.replace(b"0 ignored", b"1 ignored"), stdout.replace(b"0 failed", b"1 failed"),
            stdout.replace(b"0.125s", b"nans"), stdout.replace(b"0.125s", b"1440.001s")))
        for index, body in enumerate(changed):
            with self.subTest(index=index), self.assertRaises(ValueError):
                FIXTURE.native_data_tests_result(SimpleNamespace(returncode=0, stdout=body, stderr=stderr))
        with self.assertRaisesRegex(ValueError, "data-tests-original"):
            FIXTURE.native_data_tests_result(SimpleNamespace(returncode=0, stdout=stdout,
                stderr=b"x" * (4 * FIXTURE.MIB - len(stdout) + 1)))
        for code in (False, True, None, 1, -1):
            with self.subTest(code=code), self.assertRaises(ValueError):
                FIXTURE.native_data_tests_result(SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr))

    def test_baseline_identity_matches_held_parent_not_assumed_wheel_group(self):
        # Filesystem ports are inert DATA here: the separate real stager parent
        # admission protects the system path. This checks the adapter's binding
        # to that admitted original, not a claim of root filesystem qualification.
        op, observed = phase_value("baseline")
        native = op.app_absence["nativeBinding"]
        op.app_absence["binding"] = {key: native[key] for key in
            ("fixtureSource", "productSource", "runId", "runAttempt", "target")}
        parent = {"device": 9, "inode": 10, "mode": stat.S_IFDIR | 0o755, "uid": 0, "gid": 80}
        private = {"device": 9, "inode": 11, "mode": stat.S_IFDIR | 0o700, "uid": 0, "gid": 0}
        value = {"schemaVersion": 1, "kind": "app-absence-baseline", "binding": native,
            "rootNonce": "7" * 32, "parentIdentity": parent, "privateIdentity": private,
            "siblingCensusSha256": "8" * 64, "siblingCount": 1, "rootAbsent": True,
            "transportState": "pending-original-exit"}
        def identity_stat(row):
            return SimpleNamespace(st_dev=row["device"], st_ino=row["inode"],
                st_mode=row["mode"], st_uid=row["uid"], st_gid=row["gid"])
        def read(candidate, *, parent_after=None):
            body = json.dumps(candidate, separators=(",", ":")).encode("ascii") + b"\n"
            before = SimpleNamespace(st_dev=9, st_ino=12, st_mode=stat.S_IFREG | 0o444,
                st_nlink=1, st_uid=0, st_gid=0, st_size=len(body), st_mtime_ns=1, st_ctime_ns=2)
            events = []
            @contextlib.contextmanager
            def channel(_root):
                events.append("entered")
                try:
                    yield 73, "MobileReleaseKit"
                finally:
                    events.append("closed")
            op.stager = SimpleNamespace(INSTALL_ROOT="inert-system-path", installer_channel_parent=channel,
                read_at=lambda fd, name, limit: (body, before),
                maintenance_json=lambda data, limit: HELPER.tool_json(data))
            with patch.object(FIXTURE.os, "stat", return_value=before), \
                    patch.object(FIXTURE.os, "fstat", side_effect=(identity_stat(parent), identity_stat(parent_after or parent))):
                try:
                    result = FIXTURE.baseline_read(op, hashlib.sha256(body).hexdigest())
                finally:
                    self.assertEqual(events, ["entered", "closed"])
            self.assertEqual(set(result), {"bytes", "sha256", "identity"})
            self.assertEqual(result["bytes"], len(body))
            return result
        self.assertEqual(read(value)["identity"][1], 12)
        for key, field, replacement in (("parentIdentity", "gid", 0), ("parentIdentity", "inode", 13),
                ("privateIdentity", "gid", 80), ("privateIdentity", "mode", stat.S_IFDIR | 0o755),
                ("privateIdentity", "device", 14), ("privateIdentity", "uid", 501)):
            candidate = copy.deepcopy(value); candidate[key][field] = replacement
            with self.subTest(key=key, field=field), self.assertRaises(ValueError):
                read(candidate)
        with self.assertRaisesRegex(ValueError, "baseline-original-post"):
            read(value, parent_after=dict(parent, inode=13))
