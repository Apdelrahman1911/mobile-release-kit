"""Inert thin-router contracts, not native observations or coverage receipts.

Load the actual router through a closed import hook. Its only project-shaped
dependencies are the fakes below; file operations touch private temporary roots.
No production, process-owner, native fixture, or test-suite module is imported.
"""
from __future__ import annotations

import builtins
import gzip
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import zlib
from pathlib import Path
from types import ModuleType, SimpleNamespace


SOURCE = Path(__file__).with_name("local_signing_layered_fixture.py")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(_canonical(value) + b"\n")


class _InertRouter:
    """One source-loaded router with no shared module monkeypatches."""

    def __init__(self, root, *, all_kinds=False):
        self.root = root
        self.output = root / "output"
        self.output.mkdir(mode=0o700)
        self.package = root / "inert-package"
        self.package_files = {"inert-package": "unchanged"}
        self.definitions = {"inert-definitions": "unchanged"}
        self.now, self.deadline = 10.0, 50.0
        self.busy = self.returned = False
        self.current = None
        self.events, self.removals = [], []
        self.helper_action = self.validation_action = self.read_action = None
        self.row_fsync_action = self.final_fsync_action = self.remove_action = None
        candidates = (
            SimpleNamespace(identifier="p0001", kind="primitive", name="A/inert-component"),
            SimpleNamespace(identifier="s0001", kind="semantic", name="H/full-context"),
            SimpleNamespace(identifier="g0001", kind="regression", name="G/inert-original"),
        )
        self.items = {item.identifier: item for item in (candidates if all_kinds else candidates[1:2])}
        self.ids = tuple(self.items)
        self.definition = {"inertOnly": True, "caseIds": list(self.ids)}
        self.catalog = SimpleNamespace(
            PRIMITIVE_NAMES=("inert-component",),
            PRIMITIVE_FAILURES={"writer-failures": (), "reader-failures": (), "remover-failures": ()},
            expected_ids=lambda _os: self.ids,
            shard_ids=lambda _os, _shard: self.ids,
            definition=lambda _os: self.definition,
            case=lambda identifier, _os: self.items[identifier],
            regression_parts=lambda item, _os: self.parts(item),
            coverage=lambda _os, ids: {"inertOnly": True, "caseIds": list(ids)},
        )
        contract = SimpleNamespace(
            require=self.require, before_deadline=self.before_deadline,
            layered_catalog=lambda: self.catalog, strict_json=json.loads,
            canonical=_canonical, digest=lambda value: hashlib.sha256(_canonical(value)).hexdigest(),
            validate_layered_record=self.validate, MAX_EXPANDED_RESULTS=2 * 1024**2,
            MAX_RESULTS_BYTES=2 * 1024**2,
            package_manifest=lambda _package, **_kw: self.package_files,
            definitions_manifest=lambda _root, **_kw: self.definitions,
        )
        fixture = SimpleNamespace(PHASE_DEADLINE=self.deadline, ROOT=root, read_fixture_file=self.read)
        primitive = SimpleNamespace(
            COMPONENT_NAMES=self.catalog.PRIMITIVE_NAMES, _WRITER_FAILURES=(),
            _READER_FAILURES=(), _REMOVER_FAILURES=(),
            run_component=lambda parent, name: self.helper(parent, "primitive", "A/" + name),
        )
        workflow = SimpleNamespace(
            local_signing_matrix_contract=contract, local_signing_persistent_fixture=fixture,
            local_signing_matrix_diagnostic=SimpleNamespace(mark=lambda *_args: None),
            local_signing_primitive_fixture=primitive,
            local_signing_semantic_fixture=SimpleNamespace(
                run_case=lambda parent, name: self.helper(parent, "semantic", name)),
            local_signing_regression_fixture=SimpleNamespace(
                run_case=lambda parent, name: self.helper(parent, "regression", name)),
        )

        def remove(parent):
            self.removals.append((parent, self.rows(final=False), tuple(self.events)))
            self.events.append(("remove", self.current))
            if self.remove_action is not None:
                self.remove_action(parent)
            else:
                shutil.rmtree(parent)

        remove.avoids_symlink_attacks = shutil.rmtree.avoids_symlink_attacks
        substitutions = {
            "workflow": workflow,
            "unit.local_signing_workspace": SimpleNamespace(assert_native_cases_idle=self.idle),
            "os": SimpleNamespace(getuid=os.getuid, scandir=os.scandir, open=os.open,
                                  O_NOFOLLOW=os.O_NOFOLLOW, O_CLOEXEC=os.O_CLOEXEC, fsync=self.fsync),
            "shutil": SimpleNamespace(rmtree=remove),
            "time": SimpleNamespace(monotonic=lambda: self.now),
        }

        def inert_import(name, globals=None, locals=None, fromlist=(), level=0):
            if not level and name in substitutions:
                return substitutions[name]
            if not level and name in {"__future__", "gzip", "stat", "itertools"}:
                return builtins.__import__(name, globals, locals, fromlist, level)
            raise AssertionError("thin-router test refuses non-inert import: " + name)

        self.router = ModuleType("inert_layered_router")
        self.router.__file__ = str(SOURCE)
        self.router.__dict__["__builtins__"] = {**vars(builtins), "__import__": inert_import}
        exec(compile(SOURCE.read_text(), str(SOURCE), "exec"), self.router.__dict__)

    @staticmethod
    def require(condition, message):
        if not condition:
            raise ValueError("signing matrix: " + message)

    def before_deadline(self, deadline):
        if self.now >= deadline:
            raise TimeoutError("inert original deadline expired")

    def idle(self):
        self.require(not self.busy, "inert original finality unavailable")

    @staticmethod
    def parts(item):
        return ("G/inert-healthy-contribution",) if item.kind == "semantic" else ()

    @staticmethod
    def observation(item):
        return {"inertOnly": True, "kind": item.kind, "name": item.name}

    def helper(self, parent, kind, name):
        item, = (item for item in self.items.values() if (item.kind, item.name) == (kind, name))
        self.current = item.identifier
        self.events.append(("helper", self.current))
        _private_json(parent / "held.json", self.observation(item))
        if self.helper_action is not None:
            self.helper_action(parent)
        return self.observation(item)

    def read(self, path, *, limit):
        self.events.append(("read", self.current))
        if self.read_action is not None:
            self.read_action(path)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as stream:
            original = os.fstat(stream.fileno())
            data = stream.read(limit + 1)
        self.require(len(data) <= limit, "inert evidence read bound")
        return data, original

    def validate(self, row, operating_system):
        self.events.append(("validate", self.current))
        item = self.items[self.current]
        self.require(operating_system == "ubuntu-24.04" and row == {
            "schemaVersion": 2, "caseId": item.identifier, "kind": item.kind, "name": item.name,
            "observation": self.observation(item), "evidence": {"held.json": self.observation(item)},
            "regressionParts": list(self.parts(item)),
        }, "inert typed row differs")
        return self.validation_action(row) if self.validation_action is not None else item.identifier

    @staticmethod
    def matches(descriptor, path):
        try:
            value = path.lstat()
        except FileNotFoundError:
            return False
        actual = os.fstat(descriptor)
        return (actual.st_dev, actual.st_ino) == (value.st_dev, value.st_ino)

    def fsync(self, descriptor):
        os.fsync(descriptor)
        if self.matches(descriptor, self.output / "results.jsonl.gz"):
            self.events.append(("fsync-results", self.current))
            action, self.row_fsync_action = self.row_fsync_action, None
            if action is not None:
                action(self.parent)
        elif self.matches(descriptor, self.output / "matrix-result.json"):
            action, self.final_fsync_action = self.final_fsync_action, None
            if action is not None:
                action()

    @property
    def parent(self):
        return self.output / ("case-" + self.ids[0])

    def rows(self, *, final=True):
        data = (self.output / "results.jsonl.gz").read_bytes()
        expanded = gzip.decompress(data) if final else zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(data)
        self.require(not expanded or expanded.endswith(b"\n"), "inert row was not fully flushed")
        return [json.loads(line) for line in expanded.splitlines()]

    def run(self):
        self.router.run_phase(self.output, "inert-shard", {"os": "ubuntu-24.04"}, self.package,
                              self.package_files, self.definitions, deadline=self.deadline)
        self.returned = True


class LayeredRouterTests(unittest.TestCase):
    def failed(self, rig, error, message):
        with self.assertRaisesRegex(error, message):
            rig.run()
        self.assertFalse(rig.returned)
        self.assertFalse((rig.output / "matrix-result.json").exists())

    def test_each_original_dispatch_validates_and_fsyncs_complete_row_before_removal(self):
        with tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
            rig = _InertRouter(Path(temporary), all_kinds=True)
            rig.run()
            self.assertTrue(rig.returned)
            self.assertEqual([row["caseId"] for row in rig.rows()], list(rig.ids))
            self.assertEqual(len(rig.removals), len(rig.ids))
            for number, (parent, rows, events) in enumerate(rig.removals, 1):
                identifier = rig.ids[number - 1]
                self.assertEqual([row["caseId"] for row in rows], list(rig.ids[:number]))
                self.assertEqual(events[-2:], (("validate", identifier), ("fsync-results", identifier)))
                self.assertFalse(parent.exists())
            result = json.loads((rig.output / "matrix-result.json").read_bytes())
            self.assertEqual(result["executedCaseIds"], list(rig.ids))
            self.assertTrue(result["allExactChildrenReapedAndGroupsAbsent"])
            self.assertTrue(result["allCasePathsRemoved"])
            for name in ("catalog.json", "results.jsonl.gz", "matrix-result.json"):
                self.assertEqual((rig.output / name).lstat().st_mode & 0o777, 0o600)

    def test_helper_and_alias_rejection_preserve_original_evidence_without_coverage(self):
        for fault in ("helper", "alias-exception", "alias-identity"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
                rig = _InertRouter(Path(temporary))

                def reject(_value):
                    raise ValueError("inert helper or alias refused")

                if fault == "helper":
                    rig.helper_action = reject
                elif fault == "alias-exception":
                    rig.validation_action = reject
                else:
                    rig.validation_action = lambda _row: "foreign-alias"
                self.failed(rig, ValueError, "refused|original result differs")
                self.assertTrue((rig.parent / "held.json").is_file())
                self.assertEqual(rig.rows(), [])
                self.assertEqual(rig.removals, [])

    def test_cleanup_error_or_unremoved_path_retains_durable_row_without_phase_success(self):
        for fault in ("raises", "path-remains"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
                rig = _InertRouter(Path(temporary))

                def refuse(_parent):
                    if fault == "raises":
                        raise OSError("inert cleanup failure")

                rig.remove_action = refuse
                self.failed(rig, OSError if fault == "raises" else ValueError,
                            "cleanup failure" if fault == "raises" else "path remains")
                self.assertTrue((rig.parent / "held.json").is_file())
                self.assertEqual([row["caseId"] for row in rig.rows()], list(rig.ids))
                self.assertEqual(len(rig.removals), 1)

    def test_early_finality_mode_nlink_replaced_read_and_deadline_deny_removal(self):
        faults = {
            "finality": (ValueError, "original finality unavailable"),
            "mode": (ValueError, "evidence file state"),
            "nlink": (ValueError, "evidence file state"),
            "read-identity": (ValueError, "changed before original read"),
            "deadline": (TimeoutError, "original deadline expired"),
        }
        for fault, (error, message) in faults.items():
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
                rig = _InertRouter(Path(temporary))

                def change(parent):
                    if fault == "finality":
                        rig.busy = True
                    elif fault == "mode":
                        (parent / "held.json").chmod(0o644)
                    elif fault == "nlink":
                        os.link(parent / "held.json", rig.root / "retained-link.json")
                    elif fault == "deadline":
                        rig.now = rig.deadline

                def replace_read(path):
                    data = json.loads(path.read_bytes())
                    path.rename(rig.root / "retained-before-read.json")
                    _private_json(path, data)

                rig.helper_action = change
                if fault == "read-identity":
                    rig.read_action = replace_read
                self.failed(rig, error, message)
                self.assertTrue((rig.parent / "held.json").is_file())
                self.assertEqual(rig.rows(), [])
                self.assertEqual(rig.removals, [])
                if fault == "read-identity":
                    self.assertTrue((rig.root / "retained-before-read.json").is_file())

    def test_post_fsync_finality_parent_file_inventory_and_deadline_gate_disposal(self):
        faults = {
            "finality": (ValueError, "original finality unavailable"),
            "parent-identity": (ValueError, "case parent changed"),
            "file-identity": (ValueError, "evidence inode changed"),
            "inventory": (ValueError, "retained evidence changed"),
            "deadline": (TimeoutError, "original deadline expired"),
            "hardened-removal": (ValueError, "descriptor-relative layered removal unavailable"),
        }
        for fault, (error, message) in faults.items():
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
                rig = _InertRouter(Path(temporary))
                retained = rig.parent

                def change(parent):
                    nonlocal retained
                    if fault == "finality":
                        rig.busy = True
                    elif fault == "parent-identity":
                        retained = rig.root / "retained-original-case"
                        parent.rename(retained)
                        parent.mkdir(mode=0o700)
                    elif fault == "file-identity":
                        (parent / "held.json").chmod(0o400)
                    elif fault == "inventory":
                        _private_json(parent / "extra.json", {"inertOnly": True})
                    elif fault == "deadline":
                        rig.now = rig.deadline
                    else:
                        rig.router.shutil.rmtree.avoids_symlink_attacks = False

                rig.row_fsync_action = change
                self.failed(rig, error, message)
                self.assertTrue((retained / "held.json").is_file())
                self.assertEqual([row["caseId"] for row in rig.rows()], list(rig.ids))
                self.assertEqual(rig.removals, [])

    def test_post_removal_finality_or_deadline_withholds_final_record(self):
        for fault in ("finality", "deadline"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
                rig = _InertRouter(Path(temporary))

                def finish_then_expire(parent):
                    shutil.rmtree(parent)
                    if fault == "finality":
                        rig.busy = True
                    else:
                        rig.now = rig.deadline

                rig.remove_action = finish_then_expire
                self.failed(rig, ValueError if fault == "finality" else TimeoutError,
                            "original finality unavailable" if fault == "finality" else "original deadline expired")
                self.assertFalse(rig.parent.exists())
                self.assertEqual([row["caseId"] for row in rig.rows()], list(rig.ids))

    def test_final_publication_deadline_error_propagates_instead_of_returning_success(self):
        with tempfile.TemporaryDirectory(prefix="mrk-layered-router-inert-") as temporary:
            rig = _InertRouter(Path(temporary))
            rig.final_fsync_action = lambda: setattr(rig, "now", rig.deadline)
            with self.assertRaisesRegex(TimeoutError, "original deadline expired"):
                rig.run()
            self.assertFalse(rig.returned)
            self.assertFalse(rig.parent.exists())
            self.assertEqual([row["caseId"] for row in rig.rows()], list(rig.ids))
            # A retained final-write artifact is evidence, NOT an owner return,
            # capture/footer/finality receipt or authority to claim coverage.
            self.assertTrue((rig.output / "matrix-result.json").is_file())
