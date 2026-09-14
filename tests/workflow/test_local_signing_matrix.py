"""Adversarial matrix data contracts and finite-entrypoint admission tests."""
from __future__ import annotations

import copy
import gzip
import io
import json
import linecache
import os
import stat
import sys
import tempfile
import time
import traceback
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import mobile_release

from . import local_signing_matrix_contract as contract
from . import local_signing_persistent_fixture as fixture
from . import run_local_signing_matrix as runner
from .workflow_harness import load_workflow


def event(number):
    return {"index": number, "operation": "write", "slot": "<ROOT>/session-<TOKEN>/state.pending",
            "origin": "mobile_release.local_signing:_write", "phase": "recovery", "occurrence": number,
            "details": {}, "succeeded": True}


class ObservedScan:
    """Count actual lazy filesystem reads and fail if the caller over-consumes."""
    def __init__(self, scan, limit, *, read_error=False, close_error=False):
        self.scan, self.limit = scan, limit
        self.read_error, self.close_error = read_error, close_error
        self.count, self.closed = 0, False

    def __enter__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        if self.count >= self.limit:
            raise AssertionError("directory enumerated past its rejection bound")
        if self.read_error and self.count == 1:
            raise OSError("injected directory read failure")
        value = next(self.scan)
        self.count += 1
        return value

    def __exit__(self, *_):
        self.scan.close()
        self.closed = True
        if self.close_error:
            raise OSError("injected directory close failure")


class MatrixContractTests(unittest.TestCase):
    def setUp(self):
        self.scope = {"kind": "github", "repository": "example/mobile-release-kit", "commit": "1" * 40,
                      "runId": "1234", "attempt": 3, "job": "test-signing-matrix", "os": "ubuntu-24.04"}
        self.package, self.definitions = contract.digest("production"), contract.digest("test definitions")
        self.original = {"events": [event(number) for number in range(1, 129)], "lines": ["production:1"]}
        self.recovery = {"groups": {}}
        self.cases = fixture.matrix_cases(self.original, self.recovery)
        self.expected = list(self.cases)

    def candidates(self):
        result = []
        for operating_system in contract.OPERATING_SYSTEMS:
            for shard in range(contract.SHARDS):
                scope = {**self.scope, "os": operating_system, "attempt": 1}
                selected = [case for case in self.expected if contract.shard_for(case) == shard]
                run = {"executedCaseIds": selected, "inventorySha256": contract.digest(operating_system),
                       "packageSha256": self.package, "definitionsSha256": self.definitions,
                       "resultsSha256": contract.digest((operating_system, shard)),
                       "allExactChildrenReapedAndGroupsAbsent": True, "allCasePathsRemoved": True}
                proof = {"schemaVersion": 1, "scope": scope, "shard": shard, "expectedCaseIds": self.expected[:],
                         "expectedSha256": contract.digest(self.expected), "source": copy.deepcopy(run), "wheel": copy.deepcopy(run)}
                result.append((contract.artifact_name(scope, shard), proof))
        return result

    def reduce(self, candidates):
        return contract.reconcile(candidates, self.scope, self.package, self.definitions)

    def test_partition_is_disjoint_complete_and_stable_across_hash_order_and_global_indices(self):
        shuffled = copy.deepcopy(self.original)
        shuffled["events"].reverse()
        for index, item in enumerate(shuffled["events"], 9000):
            item["index"] = index
        other = fixture.matrix_cases(shuffled, self.recovery)
        self.assertEqual(list(other), self.expected)
        self.assertEqual(fixture.matrix_inventory_digest(self.cases, self.original, self.recovery),
                         fixture.matrix_inventory_digest(other, shuffled, self.recovery))
        union = set()
        for shard in range(contract.SHARDS):
            selected = {case for case in self.expected if contract.shard_for(case) == shard}
            self.assertTrue(selected)
            self.assertFalse(union.intersection(selected))
            union.update(selected)
        self.assertEqual(union, set(self.expected))
        changed = copy.deepcopy(self.original)
        changed["events"][0]["succeeded"] = False
        changed["events"][0]["error"] = "OSError"
        changed["events"][0]["details"]["flags"] = 256
        changed_cases = fixture.matrix_cases(changed, self.recovery)
        self.assertEqual(list(changed_cases), self.expected)
        self.assertNotEqual(fixture.matrix_inventory_digest(changed_cases, changed, self.recovery),
                            fixture.matrix_inventory_digest(self.cases, self.original, self.recovery))

    def test_complete_two_os_source_wheel_union_accepts_older_successful_cells_after_partial_rerun(self):
        candidates = self.candidates()
        rerun = copy.deepcopy(candidates[0][1])
        rerun["scope"]["attempt"] = 3
        candidates.append((contract.artifact_name(rerun["scope"], rerun["shard"]), rerun))
        result = self.reduce(iter(candidates))  # Stream downloaded proofs, including older attempts.
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["producingAttempts"]["ubuntu-24.04/0"], 3)
        self.assertEqual(result["producingAttempts"]["macos-26/0"], 1)
        for operating_system in contract.OPERATING_SYSTEMS:
            for mode in ("source", "wheel"):
                self.assertEqual(result["operatingSystems"][operating_system][mode]["cases"], len(self.expected))

    def test_one_cell_can_locally_pass_an_omitted_case_but_the_actual_cross_cell_reducer_rejects_it(self):
        candidates = self.candidates()
        name, proof = candidates[0]
        missing = proof["source"]["executedCaseIds"][0]
        proof["expectedCaseIds"].remove(missing)
        proof["expectedSha256"] = contract.digest(proof["expectedCaseIds"])
        for mode in ("source", "wheel"):
            proof[mode]["executedCaseIds"].remove(missing)
        # This is the old design's real logical counterexample, not an expected
        # local failure masquerading as proof that aggregate success is enough.
        contract.validate_proof(proof, name, self.scope, self.package, self.definitions)
        with self.assertRaisesRegex(ValueError, "cross-cell expected inventory"):
            self.reduce(candidates)

    def test_missing_duplicate_extra_wrong_scope_and_invalid_later_proofs_never_fall_back(self):
        for change in ("missing", "duplicate", "wrong-name", "repository", "commit", "runId", "job", "future-attempt",
                       "package", "definitions", "inventory", "omitted-source", "omitted-wheel", "duplicate-ID", "extra-ID",
                       "wrong-shard", "empty", "bool-version", "bool-attempt", "bool-shard", "unknown-field", "cleanup"):
            with self.subTest(change=change):
                candidates = self.candidates()
                name, proof = candidates[0]
                if change == "missing": candidates.pop()
                elif change == "duplicate": candidates.append(copy.deepcopy(candidates[0]))
                elif change == "wrong-name": candidates[0] = (name + "-other", proof)
                elif change in ("repository", "commit", "runId", "job"): proof["scope"][change] = "wrong"
                elif change == "future-attempt": proof["scope"]["attempt"] = 4
                elif change in ("package", "definitions", "inventory"):
                    key = {"package": "packageSha256", "definitions": "definitionsSha256", "inventory": "inventorySha256"}[change]
                    proof["source"][key] = "f" * 64
                elif change.startswith("omitted-"): proof[change.removeprefix("omitted-")]["executedCaseIds"].pop()
                elif change == "duplicate-ID": proof["source"]["executedCaseIds"].append(proof["source"]["executedCaseIds"][0])
                elif change == "extra-ID": proof["wheel"]["executedCaseIds"] = sorted([*proof["wheel"]["executedCaseIds"], "f" * 64])
                elif change == "wrong-shard": proof["shard"] = 1
                elif change == "empty": proof["expectedCaseIds"] = []
                elif change == "bool-version": proof["schemaVersion"] = True
                elif change == "bool-attempt": proof["scope"]["attempt"] = True
                elif change == "bool-shard": proof["shard"] = False
                elif change == "unknown-field": proof["forcePass"] = True
                elif change == "cleanup": proof["source"]["allExactChildrenReapedAndGroupsAbsent"] = False
                with self.assertRaises(ValueError): self.reduce(candidates)
        candidates = self.candidates()
        invalid_newer = copy.deepcopy(candidates[0][1])
        invalid_newer["scope"]["attempt"] = 3
        invalid_newer["source"]["executedCaseIds"].pop()
        candidates.append((contract.artifact_name(invalid_newer["scope"], 0), invalid_newer))
        with self.assertRaisesRegex(ValueError, "omitted"):
            self.reduce(candidates)

    def test_bounded_strict_json_and_unmerged_artifact_identity_are_required(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-proof-") as directory:
            root = Path(directory)
            name, proof = self.candidates()[0]
            artifact = root / name
            artifact.mkdir()
            path = artifact / "proof.json"
            for content in (b'{"scope":{},"scope":{}}', b'{"number":NaN}', b'{"incomplete":', b'\xff'):
                path.write_bytes(content)
                with self.assertRaises((ValueError, UnicodeError)): contract.read_proof(path)
            path.write_bytes(b" " * (contract.MAX_PROOF_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "size bound"): contract.read_proof(path)
            path.write_bytes(contract.canonical(proof))
            self.assertEqual(list(contract.proof_paths(root)), [(name, path)])
            self.assertEqual(contract.read_proof(path), proof)
            (artifact / "extra.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "extra files"): list(contract.proof_paths(root))
            (artifact / "extra.json").unlink()
            path.unlink()
            path.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "regular"): contract.read_proof(path)
        with self.assertRaisesRegex(ValueError, "missing"): self.reduce([])

    def test_proof_directory_scan_is_actually_bounded_before_excess_entries_are_consumed(self):
        real_scandir = os.scandir
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-scanning-") as temporary:
            for count in (0, contract.MAX_PROOFS, contract.MAX_PROOFS + 7):
                with self.subTest(count=count):
                    root = Path(temporary) / str(count)
                    root.mkdir()
                    for index in range(count):
                        artifact = root / f"local-signing-matrix-proof-macos-26-0-attempt-{index + 1}"
                        artifact.mkdir()
                        (artifact / "proof.json").write_text("{}")
                    scans = []

                    def scan(path):
                        observed = ObservedScan(real_scandir(path), contract.MAX_PROOFS + 1 if path == root else 2)
                        scans.append(observed)
                        return observed

                    with patch.object(contract.os, "scandir", side_effect=scan), patch.object(
                        os, "listdir", side_effect=AssertionError("eager listdir is not a bounded scan")
                    ):
                        if count == contract.MAX_PROOFS:
                            paths = list(contract.proof_paths(root))
                            self.assertEqual(len(paths), count)
                            self.assertEqual(paths, sorted(paths))
                        else:
                            with self.assertRaisesRegex(ValueError, "missing or excessive"):
                                list(contract.proof_paths(root))
                    self.assertEqual(scans[0].count, min(count, contract.MAX_PROOFS + 1))
                    self.assertTrue(all(scan.closed for scan in scans))
                    self.assertEqual(len(scans), 1 + count if count == contract.MAX_PROOFS else 1)
                    for observed in scans:
                        with self.assertRaises(StopIteration): next(observed.scan)

            root = Path(temporary) / "inner"
            root.mkdir()
            artifact = root / "local-signing-matrix-proof-macos-26-0-attempt-1"
            artifact.mkdir()
            for name in ["proof.json", *[f"extra-{index}" for index in range(7)]]:
                (artifact / name).write_text("{}")
            scans = []
            with patch.object(contract.os, "scandir", side_effect=scan), patch.object(
                os, "listdir", side_effect=AssertionError("eager listdir is not a bounded scan")
            ), self.assertRaisesRegex(ValueError, "extra files"):
                list(contract.proof_paths(root))
            self.assertEqual([observed.count for observed in scans], [1, 2])
            self.assertTrue(all(observed.closed for observed in scans))

    def test_proof_scanner_errors_close_actual_handles_and_cannot_accept_truncated_entries(self):
        real_scandir = os.scandir
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-scan-errors-") as temporary:
            root = Path(temporary)
            artifact = root / "local-signing-matrix-proof-macos-26-0-attempt-1"
            artifact.mkdir()
            (artifact / "proof.json").write_text("{}")
            for level in (root, artifact):
                for error in ("read", "close"):
                    with self.subTest(level=level.name, error=error):
                        scans = []

                        def scan(path):
                            observed = ObservedScan(real_scandir(path), contract.MAX_PROOFS + 1 if path == root else 2,
                                                    read_error=path == level and error == "read",
                                                    close_error=path == level and error == "close")
                            scans.append(observed)
                            return observed

                        with patch.object(contract.os, "scandir", side_effect=scan), self.assertRaisesRegex(
                            OSError, f"directory {error} failure"
                        ):
                            list(contract.proof_paths(root))
                        self.assertTrue(all(observed.closed for observed in scans))
                        for observed in scans:
                            with self.assertRaises(StopIteration): next(observed.scan)

    def test_actual_reached_cut_not_requested_id_is_the_execution_authority(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-actual-") as directory:
            root = Path(directory)
            item = event(1)
            case_id = contract.logical_case_id("original", item, "before")
            record = {"caseId": case_id, "seed": "original", "outcome": {"automatic": "recovered", "manual": None},
                      "results": {"original-cut": {"event": item, "edge": "before"}, "final-automatic": {}}}
            def write(records):
                with gzip.open(root / "results.jsonl.gz", "wb") as stream:
                    for value in records: stream.write(contract.canonical(value) + b"\n")
            write([record])
            self.assertRegex(runner.validate_actual_results(root, [case_id]), r"^[0-9a-f]{64}$")
            for variant in ("wrong-cut", "duplicate", "missing", "missing-recovery"):
                bad = copy.deepcopy(record)
                if variant == "wrong-cut": bad["results"]["original-cut"]["event"]["occurrence"] += 1
                if variant == "missing-recovery": bad["results"].pop("final-automatic")
                write([] if variant == "missing" else [bad, bad] if variant == "duplicate" else [bad])
                with self.assertRaises(ValueError): runner.validate_actual_results(root, [case_id])

    def test_original_c_prefix_reducer_requires_actual_positive_bytes_and_exact_read_inode(self):
        item = {**event(1), "operation": "command-fence/PENDING_WRITE", "origin": "original-custodian"}
        case_id = contract.logical_case_id("original", item, "partial")
        observation = {"nonce": "1" * 32, "commandSequence": 1, "ordinal": 4, "operation": "PENDING_WRITE",
            "edge": "PARTIAL", "outcome": "OK", "written": 2, "total": 8, "syncFlags": 0,
            "creationIdentity": [1, 2, 1000, 1000, stat.S_IFREG | 0o600, 1], "operandHex": b"test".hex(),
            "originalWorker": True, "actualReadHex": b"te".hex(),
            "originalFileState": [1, 2, stat.S_IFREG | 0o600, 1, 1000, 1000, 2, 17, 19],
            "finalAbsentBeforeAndAfter": True, "originalReadClosed": True}
        def validate(value):
            record = {"caseId": case_id, "seed": "original", "outcome": {"automatic": "recovered", "manual": None},
                "results": {"original-cut": {"event": item, "edge": "partial", "originalCFenceObservation": value},
                            "final-automatic": {}}}
            return contract.validate_actual_results(gzip.compress(contract.canonical(record) + b"\n"), [case_id])
        self.assertRegex(validate(observation), r"^[0-9a-f]{64}$")
        changes = ({"written": 0, "actualReadHex": ""}, {"written": -1}, {"written": True}, {"total": 9.0},
                   {"total": 4097}, {"operandHex": "not-hex!"}, {"actualReadHex": "ffff"}, {"syncFlags": True},
                   {"nonce": "x" * 32}, {"commandSequence": True}, {"ordinal": 0}, {"outcome": "PENDING"},
                   {"originalReadClosed": 1}, {"extra": True}, {"creationIdentity": [1, 3, 1000, 1000, stat.S_IFREG | 0o600, 1]},
                   {"originalFileState": [1, 2, stat.S_IFREG | 0o600, True, 1000, 1000, 2, 17, 19]},
                   {"originalFileState": [1, 2, stat.S_IFREG | 0o600, 1, 1000, 1000, 3, 17, 19]})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate({**observation, **change})
        absent = dict(observation)
        absent.pop("originalFileState")
        with self.assertRaises(ValueError):
            validate(absent)

    def test_ci_scope_and_invalid_selection_do_not_silently_become_local_or_partial_success(self):
        metadata = {key: value for key, value in self.scope.items() if key != "os"}
        self.assertEqual(contract.scope_from_metadata(metadata, "ubuntu-24.04", producer=True), self.scope)
        for field in metadata:
            missing = dict(metadata)
            missing.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                contract.scope_from_metadata(missing, "ubuntu-24.04", producer=True)
        for changes in ({"attempt": True}, {"job": "test"}, {"kind": "local"}, {"runId": None},
                        {"commit": "1" * 39}, {"unlisted": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                contract.scope_from_metadata({**metadata, **changes}, "ubuntu-24.04", producer=True)
        reduced = contract.scope_from_metadata({**metadata, "job": "test"}, "ubuntu-24.04", producer=False)
        self.assertEqual(reduced, self.scope)
        with redirect_stderr(io.StringIO()):
            for arguments in (("--shard", "-1"), ("--shard", "16"), ("--shard", "true"),
                              ("--shard", "1", "--all"), ("--phase", "other"),
                              ("--phase", "source", "--reduce", "/data")):
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                    runner.main([*arguments, "--output", "/unreached", "--os", "ubuntu-24.04"])

    def test_ci_requires_fixed_full_matrix_both_imports_and_mandatory_unmerged_proofs(self):
        workflow = load_workflow(runner.ROOT / ".github/workflows/ci.yml")
        job, aggregate = workflow["jobs"]["test-signing-matrix"], workflow["jobs"]["test"]
        self.assertEqual(job["strategy"]["matrix"], {"os": list(contract.OPERATING_SYSTEMS), "shard": list(range(contract.SHARDS))})
        self.assertEqual(job["strategy"]["max-parallel"], 4)
        self.assertIs(job["strategy"]["fail-fast"], False)
        self.assertEqual(job["timeout-minutes"], 60)
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertNotIn("env", job)
        self.assertNotIn("environment", job)
        self.assertNotIn("outputs", job)
        self.assertEqual(job["if"], "${{ github.event_name != 'workflow_dispatch' || (inputs.verification_target != 'macos' && inputs.verification_target != 'signing-adapter') }}")
        self.assertNotIn("continue-on-error", job)
        commands = [step["run"] for step in job["steps"] if "run" in step]
        self.assertEqual(len(commands), 3)  # Hosted guard, Linux provider preparation, fixed controller.
        owner = next(command for command in commands if "verify_ci.py" in command)
        self.assertIn("sudo -n env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin PYTHONSAFEPATH=1", owner)
        self.assertIn("--scope signing-matrix", owner)
        for metadata in ("--repository", "--commit", "--run-id", "--run-attempt", "--job", "--shard"):
            self.assertIn(metadata, owner)
        for command in commands:
            self.assertNotIn("run_local_signing_matrix.py", command)
            self.assertNotIn("pip wheel", command)
            self.assertNotIn("Popen", command)
        self.assertEqual(aggregate["needs"], ["test-linux", "test-native-profiles", "test-signing-matrix"])
        self.assertIn('"$MATRIX_RESULT" == success', aggregate["steps"][0]["run"])
        uploads = [step for step in job["steps"] if "local-signing-matrix-proof-" in step.get("with", {}).get("name", "")]
        self.assertEqual(len(uploads), 1)
        self.assertNotIn("if", uploads[0])
        self.assertEqual(uploads[0]["with"]["if-no-files-found"], "error")
        self.assertIn("${{ github.run_attempt }}", uploads[0]["with"]["name"])
        self.assertNotIn("overwrite", uploads[0]["with"])
        downloads = [step for step in aggregate["steps"] if "actions/download-artifact@" in step.get("uses", "")]
        self.assertEqual(len(downloads), 1)
        self.assertEqual(downloads[0]["with"], {"pattern": "local-signing-matrix-proof-*", "path": "${{ runner.temp }}/signing-matrix-proofs",
                                               "merge-multiple": False, "digest-mismatch": "error"})
        reducers = [step for step in aggregate["steps"] if "--reduce" in step.get("run", "")]
        self.assertEqual(len(reducers), 1)
        self.assertNotIn("--local-reduction", reducers[0]["run"])
        for step in aggregate["steps"]:
            self.assertNotIn("if", step)
            self.assertNotIn("continue-on-error", step)


class MatrixPhaseAdmissionTests(unittest.TestCase):
    """No process, fixture dispatch or production import in these recorders."""

    def test_explicit_ci_and_local_routes_require_complete_disjoint_metadata(self):
        valid = SimpleNamespace(local=False, repository="example/mobile-release-kit", commit="1" * 40,
                                run_id="1234", run_attempt=1, job="test-signing-matrix")
        for key in ("repository", "commit", "run_id", "run_attempt", "job"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "complete explicit"):
                runner.explicit_metadata(SimpleNamespace(**{**vars(valid), key: None}))
        with self.assertRaisesRegex(ValueError, "partial CI"):
            runner.explicit_metadata(SimpleNamespace(**{**vars(valid), "local": True}))
        local = SimpleNamespace(local=True, repository=None, commit=None, run_id=None, run_attempt=None, job=None)
        self.assertEqual(runner.explicit_metadata(local), {"kind": "local", "repository": None,
                         "commit": None, "runId": None, "attempt": 1, "job": "local"})

    def test_phase_rejects_runtime_deadline_and_root_changes_before_import_or_creation(self):
        flags = SimpleNamespace(**{name: 1 for name in ("isolated", "ignore_environment", "no_user_site",
                                                       "no_site", "safe_path", "dont_write_bytecode")})
        args = SimpleNamespace(deadline=20.0, phase="source", package_root=Path("/not-the-fixed-package"),
                               output=Path("/not-created"), shard=0, local_reduction=False)
        with patch.object(runner, "sys", SimpleNamespace(flags=flags)), \
                patch.object(runner, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaisesRegex(ValueError, "fixed phase roots"):
                runner.phase(args, {})
            for cutoff in (None, 9.0, 10.0, 431.0, float("nan"), float("inf")):
                with self.subTest(cutoff=cutoff), self.assertRaisesRegex(ValueError, "original phase deadline"):
                    runner.phase(SimpleNamespace(**{**vars(args), "deadline": cutoff}), {})
            flags.no_site = 0
            with self.assertRaisesRegex(ValueError, "isolated no-site"):
                runner.phase(args, {})

    def test_definitions_bind_every_controller_and_provider_file_not_only_python_helpers(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-definitions-") as temporary:
            root = Path(temporary)
            for directory in (root / "tests", root / ".github/scripts", root / ".github/workflows"):
                directory.mkdir(parents=True)
            for number in range(10):
                (root / "tests" / f"test_{number}.py").write_text("# inert definition\n")
            (root / ".github/workflows/ci.yml").write_text("# inert workflow\n")
            (root / "pyproject.toml").write_text("# inert packaging\n")
            helper = root / ".github/scripts/verifier-data.txt"
            helper.write_text("fixed admitted provider data\n")
            first = contract.definitions_manifest(root)
            self.assertIn(".github/scripts/verifier-data.txt", first)
            helper.write_text("changed provider data\n")
            self.assertNotEqual(contract.digest(first), contract.digest(contract.definitions_manifest(root)))
            helper.unlink()
            helper.symlink_to(root / "pyproject.toml")
            with self.assertRaisesRegex(ValueError, "invalid test definition"):
                contract.definitions_manifest(root)
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 20.0)), \
                    self.assertRaisesRegex(ValueError, "cutoff expired"):
                contract.package_manifest(root, deadline=20.0)

    def test_create_only_record_cannot_overwrite_prior_proof_or_follow_a_link(self):
        with tempfile.TemporaryDirectory(prefix="mrk-matrix-write-") as temporary:
            root = Path(temporary)
            path = root / "proof.json"
            runner.write_record(path, {"diagnostic": True})
            content = path.read_bytes()
            with self.assertRaises(FileExistsError): runner.write_record(path, {"replaced": True})
            self.assertEqual(path.read_bytes(), content)
            linked = root / "linked.json"
            linked.symlink_to(path)
            with self.assertRaises(FileExistsError): runner.write_record(linked, {"replaced": True})
            self.assertEqual(path.read_bytes(), content)


class SigningAdapterAdmissionTests(unittest.TestCase):
    """Closed-scope DATA checks; no test method, subprocess or native dispatch."""

    def metadata(self):
        return {"kind": "github", "repository": "example/mobile-release-kit", "commit": "1" * 40,
                "runId": "1234", "attempt": 1, "job": "test-signing-adapter"}

    def test_literal_inventory_and_metadata_never_expand_the_matrix_reducer(self):
        self.assertEqual(contract.adapter_test_ids(runner.ROOT), contract.ADAPTER_TEST_IDS)
        self.assertEqual(len(contract.ADAPTER_TEST_IDS), 4)
        value = self.metadata()
        scope = contract.adapter_scope_from_metadata(value, "ubuntu-24.04")
        self.assertEqual(scope["schema"], "mrk-signing-adapter-scope-v1")
        for changes in ({"job": "test-signing-matrix"}, {"kind": "local"}, {"attempt": True},
                        {"runId": None}, {"repository": None}, {"commit": "wrong"}, {"extra": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                contract.adapter_scope_from_metadata({**value, **changes}, "ubuntu-24.04")
        for producer in (False, True):
            with self.assertRaises(ValueError):
                contract.scope_from_metadata(value, "ubuntu-24.04", producer=producer)

    def test_adapter_cli_rejects_shard_reducer_local_and_incomplete_scope_before_dispatch(self):
        base = ["--adapter-phase", "source", "--output", "/not-created", "--os", "ubuntu-24.04",
                "--repository", "example/mobile-release-kit", "--commit", "1" * 40,
                "--run-id", "1234", "--run-attempt", "1", "--job", "test-signing-adapter"]
        with patch.object(runner, "adapter_phase") as dispatch, \
                patch.object(runner, "operating_system", return_value="ubuntu-24.04"), redirect_stderr(io.StringIO()):
            for extra in (["--shard", "0"], ["--reduce", "/other"], ["--local"], ["--local-reduction"]):
                with self.subTest(extra=extra), self.assertRaises((ValueError, SystemExit)):
                    runner.main(base + extra)
            with self.assertRaises(ValueError):
                runner.main(base[:-2])  # Missing job never implies local.
            dispatch.assert_not_called()

    def test_adapter_deadline_runtime_and_fixed_roots_precede_product_loading(self):
        flags = SimpleNamespace(**{name: 1 for name in ("isolated", "ignore_environment", "no_user_site",
                                                       "no_site", "safe_path", "dont_write_bytecode")})
        args = SimpleNamespace(deadline=20.0, adapter_phase="source", package_root=Path("/not-the-fixed-package"),
                               output=Path("/not-created"))
        with patch.object(runner, "sys", SimpleNamespace(flags=flags)), \
                patch.object(runner, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            with self.assertRaisesRegex(ValueError, "fixed adapter roots"):
                runner.adapter_phase(args, {})
            for cutoff in (None, True, 10.0, 431.0, float("nan")):
                with self.subTest(cutoff=cutoff), self.assertRaisesRegex(ValueError, "original adapter deadline"):
                    runner.adapter_phase(SimpleNamespace(**{**vars(args), "deadline": cutoff}), {})
            flags.no_site = 0
            with self.assertRaisesRegex(ValueError, "isolated no-site"):
                runner.adapter_phase(args, {})


class SigningAdapterDiagnosticTests(unittest.TestCase):
    """Actual exception/callback projection, with no native or child dispatch."""

    def context_and_task(self, *, foreign=False):
        trusted = "/fixed/source/tests/unit/test_local_signing_persistent.py"
        filename = "/PRIVATE/other/tests/unit/test_local_signing_persistent.py" if foreign else trusted
        namespace = {}
        exec(compile("def fail():\n    raise ValueError('PRIVATE_MESSAGE /PRIVATE/case/path')\n", filename, "exec"), namespace)
        context = ("source", contract.ADAPTER_TEST_IDS[0], ((trusted, "tests/unit/test_local_signing_persistent.py"),))
        return context, namespace["fail"]

    def test_projector_uses_only_exact_precomputed_frames_and_never_private_text_or_source_reads(self):
        for foreign in (False, True):
            context, task = self.context_and_task(foreign=foreign)
            try:
                task()
            except ValueError:
                error = sys.exc_info()
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(Path, "resolve", side_effect=AssertionError("no diagnostic path resolution")), \
                    patch.object(Path, "stat", side_effect=AssertionError("no diagnostic filesystem read")), \
                    patch.object(traceback, "extract_tb", side_effect=AssertionError("no formatted traceback")), \
                    patch.object(linecache, "getline", side_effect=AssertionError("no diagnostic source read")):
                record = contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0)
            self.assertEqual(record["category"], "value-error")
            self.assertEqual(record["locations"], [] if foreign else [
                {"file": "tests/unit/test_local_signing_persistent.py", "line": 2}])
            self.assertNotIn("PRIVATE", contract.canonical(record).decode())

    def test_suppressed_cyclic_links_use_builtin_data_and_share_the_original_frame_budget(self):
        class PrivateError(Exception):
            def __getattribute__(self, name):
                raise AssertionError("exception attributes must not be consulted")
            def __str__(self):
                raise AssertionError("exception text must not be formatted")
        context, _task = self.context_and_task()
        namespace = {"PrivateError": PrivateError}
        source = ("def deep(n):\n"
                  "    if n: return deep(n - 1)\n"
                  "    raise ValueError('PRIVATE deeply nested error')\n"
                  "def fail(n):\n"
                  "    try: deep(n)\n"
                  "    except ValueError:\n"
                  "        raise PrivateError('PRIVATE suppressed error') from None\n")
        exec(compile(source, context[2][0][0], "exec"), namespace)
        for depth in (1, 100):
            try:
                namespace["fail"](depth)
            except PrivateError:
                error = sys.exc_info()
            original = BaseException.__dict__["__context__"].__get__(error[1], BaseException)
            # Real built-in cyclic links, not a custom graph supplied to the projector.
            original.__cause__ = error[1]
            visited = []
            locations = contract._adapter_locations
            def counted(frame, source_map, budget, maximum):
                before = budget[0]
                result = locations(frame, source_map, budget, maximum)
                visited.append(before - budget[0])
                return result
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), \
                    patch.object(contract, "_adapter_locations", new=counted), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("no source reads")), \
                    patch.object(linecache, "getline", side_effect=AssertionError("no source lines")):
                first = contract.adapter_command_first(context, original)
                record = contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0,
                                                          command_first=first, command_reserved=16)
            self.assertEqual(record["category"], "exception")
            self.assertEqual([row["via"] for row in record["related"]], [["command-first"], ["context"]])
            self.assertLessEqual(sum(visited), 64)
            if depth == 100:
                self.assertEqual(sum(visited), 64)
            self.assertTrue(all(len(row["locations"]) <= 2 for row in record["related"]))
            self.assertLessEqual(len(contract.ADAPTER_FAILURE_PREFIX) + len(contract.canonical(record)) + 1, 2048)
            self.assertNotIn("PRIVATE", contract.canonical(record).decode())
        # Even a long real exception chain contributes no more than three links.
        chain = [ValueError() for _ in range(12)]
        for left, right in zip(chain, chain[1:]):
            left.__context__ = right
        with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
            record = contract.adapter_failure_record(context, "worker", "error", (ValueError, chain[0], None), deadline=20.0)
        self.assertEqual([row["via"] for row in record["related"]], [["context"] * count for count in (1, 2, 3)])

    def test_original_command_recorder_runs_once_first_and_diagnostic_claim_is_absorbing(self):
        owner = runner.case_owner
        context, task = self.context_and_task()
        try:
            task()
        except ValueError as caught:
            first_error = caught
        for mode in ("observed", "projection-error", "original-error", "busy", "foreign-pid", "other-role"):
            with self.subTest(mode=mode):
                calls, projections = [], []
                first = OSError("PRIVATE original recorder failure")
                slot = {"pid": 7, "context": context, "lock": owner.threading.Lock(), "claimed": False, "first": None}
                command = SimpleNamespace(pid=8 if mode == "foreign-pid" else 7,
                                          role="C" if mode == "other-role" else "O", primary=None)
                def actual(instance, error, **kwargs):
                    calls.append((instance, error, kwargs))
                    if mode == "original-error":
                        raise first
                    if instance.primary is None:
                        instance.primary = error
                    return "actual-result"
                def project(scope, error):
                    self.assertTrue(slot["claimed"])
                    self.assertIs(command.primary, error)
                    projections.append((scope, error))
                    value = contract.adapter_command_first(scope, error)
                    if mode == "projection-error":
                        raise RuntimeError("PRIVATE diagnostic failure")
                    return value
                if mode == "busy":
                    slot["lock"].acquire()
                try:
                    with patch.multiple(owner, _ADAPTER_WORKER_DIAGNOSTIC=slot,
                                        os=SimpleNamespace(getpid=lambda: 7), adapter_command_first=project):
                        recorded = owner.adapter_command_recorder(actual)
                        if mode == "original-error":
                            with self.assertRaises(OSError) as caught:
                                recorded(command, first_error, unknown=True)
                            self.assertIs(caught.exception, first)
                        else:
                            self.assertEqual(recorded(command, first_error, unknown=True), "actual-result")
                            self.assertEqual(recorded(command, first_error, unknown=False), "actual-result")
                            self.assertEqual(recorded(command, TypeError("PRIVATE later error")), "actual-result")
                finally:
                    if mode == "busy":
                        slot["lock"].release()
                self.assertEqual(calls[0], (command, first_error, {"unknown": True}))
                self.assertEqual(len(calls), 1 if mode == "original-error" else 3)
                self.assertEqual(len(projections), int(mode in {"observed", "projection-error"}))
                self.assertEqual(slot["claimed"], mode in {"observed", "projection-error"})
                self.assertEqual(slot["first"] is not None, mode == "observed")
        with patch.object(owner, "_ADAPTER_WORKER_DIAGNOSTIC", None):
            self.assertIs(owner.adapter_command_recorder(actual), actual)

    def test_worker_reserved_budget_survives_missing_inflight_and_failed_command_projection(self):
        owner = runner.case_owner
        context, _task = self.context_and_task()
        namespace = {}
        exec(compile("def deep(n):\n    if n: return deep(n - 1)\n    raise ValueError('PRIVATE')\n",
                     context[2][0][0], "exec"), namespace)
        try:
            namespace["deep"](100)
        except ValueError:
            error = sys.exc_info()
        for mode in ("inflight", "failed", "later"):
            with self.subTest(mode=mode):
                visits, records = [], []
                slot = {"context": context, "pid": 7, "lock": owner.threading.Lock(),
                        "claimed": False, "first": None, "reserved": 16}
                command = SimpleNamespace(pid=7, role="O", primary=None)
                locations = contract._adapter_locations
                def counted(frame, source_map, budget, maximum):
                    before = budget[0]
                    result = locations(frame, source_map, budget, maximum)
                    visits.append(before - budget[0])
                    return result
                def root_record():
                    self.assertIsNone(slot["first"])
                    records.append(contract.adapter_failure_record(context, "worker", "error", error, deadline=20.0,
                        command_first=slot["first"], command_reserved=slot["reserved"]))
                def actual(instance, caught):
                    instance.primary = caught
                def project(scope, caught):
                    value = contract.adapter_command_first(scope, caught)  # Consumes 16 real frames BEFORE failure.
                    if mode == "inflight":
                        root_record()  # Same scalar boundary as a concurrent worker failure; no test thread.
                    if mode == "failed":
                        raise RuntimeError("PRIVATE after partial diagnostic work")
                    return value
                with patch.multiple(owner, _ADAPTER_WORKER_DIAGNOSTIC=slot,
                                    os=SimpleNamespace(getpid=lambda: 7), adapter_command_first=project), \
                        patch.object(contract, "_adapter_locations", new=counted), \
                        patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)):
                    recorded = owner.adapter_command_recorder(actual)
                    if mode == "later":
                        root_record()  # Unclaimed is not permission to spend the reserved 16 again.
                    recorded(command, error[1])
                    if mode == "failed":
                        root_record()
                self.assertEqual(sum(visits), 64)
                self.assertEqual(len(records), 1)
                self.assertNotIn("related", records[0])

    def test_case_failure_scalars_use_original_terminal_observations_without_new_waits_or_reads(self):
        owner = runner.case_owner
        context, _task = self.context_and_task()
        for terminal in (b"EXPIRED -9\n", b"SETTLED 91\n", None):
            with self.subTest(terminal=terminal):
                events, records = [], iter((b"ARMED 42\n", terminal, b""))
                original = ValueError("PRIVATE missing terminal")
                class Wait:
                    pid, status, unknown, retired = 41, None, False, False
                    def fork(self):
                        events.append("original-fork")
                        return self.pid
                    def wait(self):
                        events.append("original-wait")
                        self.retired, self.status = True, 0
                        return self.status
                handles = SimpleNamespace(errors=[], pipe=lambda _name: None, get=lambda _name: 10,
                                          close=lambda _name: None, close_except=lambda: None)
                def receive(_descriptor, data, _deadline):
                    record = next(records)
                    if record is None:
                        raise original
                    data.extend(record)
                    return bool(record)
                def converted(status):
                    events.append(("existing-conversion", status))
                    return 0
                native = SimpleNamespace(getpid=lambda: 7, getpgrp=lambda: 8,
                    waitstatus_to_exitcode=converted, killpg=lambda *_: events.append("original-group-stop"))
                with patch.multiple(owner, os=native, OriginalWait=Wait, Handles=lambda: handles,
                                    receive=receive, send=lambda *_: None, absent=lambda *_args, **_kwargs: True,
                                    time=SimpleNamespace(monotonic=lambda: 10.0, sleep=lambda _seconds: None),
                                    threading=SimpleNamespace(active_count=lambda: 1),
                                    ADAPTER_DIAGNOSTIC_CONTEXT=context, ADAPTER_CASE_FAILURE=None), \
                        patch.object(Path, "read_bytes", side_effect=AssertionError("no post-failure reads")):
                    with self.assertRaises((AssertionError, ValueError)) as caught:
                        owner.run_worker(Path("/not-created"), "inert", lambda: None, write_json=lambda *_: None)
                    case = owner.adapter_case_failure(context)
                    self.assertIsNone(owner.adapter_case_failure((context[0], context[1], context[2])))
                self.assertEqual(events.count("original-wait"), 1)
                if terminal is None:
                    self.assertIs(caught.exception, original)
                    self.assertEqual(case, (0, None, None, False, None))
                    self.assertNotIn(("existing-conversion", 0), events)
                else:
                    self.assertEqual(case, (0, -9 if terminal.startswith(b"EXPIRED") else 91, 0, True,
                                            terminal.startswith(b"EXPIRED")))
                    self.assertEqual(events.count(("existing-conversion", 0)), 1)

    def test_trace_filter_preserves_production_inventory_across_nonproduction_callbacks_and_generator_resumes(self):
        production = {"__name__": "mobile_release.local_signing"}
        helper = {"__name__": "inert_helper"}
        exec(compile("def leaf(value):\n    return value + 1\n"
                     "def produce(helper):\n    for value in range(3):\n        yield from helper(value, leaf)\n"
                     "def entry(helper):\n    return list(produce(helper))\n", "<inert-production>", "exec"), production)
        exec(compile("def helper(value, callback):\n    yield callback(value)\n    yield callback(value + 10)\n"
                     "def invoke(entry):\n    return entry(helper)\n", "<inert-helper>", "exec"), helper)
        old_lines, old_nonproduction, new_nonproduction = set(), [], []
        def old(frame, event, _arg):
            module = frame.f_globals.get("__name__")
            if event == "line":
                if module in fixture.PRODUCTION:
                    old_lines.add(module + ":" + frame.f_code.co_name + ":" + str(frame.f_lineno))
                elif module == "inert_helper":
                    old_nonproduction.append(frame.f_lineno)
            return old
        previous = sys.gettrace()
        try:
            sys.settrace(old)
            expected = helper["invoke"](production["entry"])
        finally:
            sys.settrace(previous)
        trace = object.__new__(fixture.Trace)
        trace.lines, trace.inventory = set(), True
        actual = fixture.Trace._trace_lines
        def observed(self, frame, event, arg):
            if event == "line" and frame.f_globals.get("__name__") == "inert_helper":
                new_nonproduction.append(frame.f_lineno)
            return actual(self, frame, event, arg)
        with patch.object(fixture.Trace, "_trace_lines", new=observed), \
                patch.object(runner.case_owner, "ADAPTER_DIAGNOSTIC_CONTEXT", None):
            with trace.installed():
                value = helper["invoke"](production["entry"])
        self.assertEqual(value, expected)
        self.assertIs(sys.gettrace(), previous)
        self.assertTrue(old_lines and old_nonproduction)
        self.assertFalse(new_nonproduction)
        self.assertEqual(trace.lines, old_lines)

    def test_actual_result_first_subtest_failure_survives_teardown_skip_and_diagnostic_write_failure(self):
        context, task = self.context_and_task()
        try:
            task()
        except ValueError:
            error = sys.exc_info()
        for broken in (False, True):
            stream = io.StringIO()
            sink = SimpleNamespace(write=lambda _text: (_ for _ in ()).throw(OSError("PRIVATE writer error"))) if broken else stream
            test = unittest.FunctionTestCase(lambda: None)
            test.id = lambda: context[1]
            result = runner.SigningAdapterResult(context[0], 20.0, context[2])
            with patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), redirect_stderr(sink):
                result.startTest(test)
                self.assertIs(runner.case_owner.ADAPTER_DIAGNOSTIC_CONTEXT, result.context)
                runner.case_owner.ADAPTER_CASE_FAILURE = (result.context, (0, None, None, False, None))
                result.addSubTest(test, test, error)
                first = result.first_failure
                result.addError(test, error)  # A later teardown failure must not replace it.
                result.addSkip(test, "PRIVATE skip reason")
                result.stopTest(test)
            self.assertIs(result.first_failure, first)
            self.assertEqual(first, (context[1], "error"))
            self.assertTrue(result.failed and result.shouldStop)
            self.assertFalse(result.wasSuccessful())
            self.assertIsNone(runner.case_owner.ADAPTER_DIAGNOSTIC_CONTEXT)
            if broken:
                self.assertEqual(stream.getvalue(), "")
            else:
                lines = stream.getvalue().splitlines()
                self.assertEqual(len(lines), 1)
                record = json.loads(lines[0].removeprefix(contract.ADAPTER_FAILURE_PREFIX))
                self.assertEqual((record["testId"], record["layer"], record["outcome"]), (context[1], "unittest", "error"))
                self.assertEqual(record["case"], {"expectedExit": 0, "workerExit": None, "anchorExit": None,
                                                  "terminalParsed": False, "anchorExpired": None})
                self.assertNotIn("PRIVATE", lines[0])

    def test_worker_observation_is_disabled_by_default_and_writer_failure_keeps_exit_and_private_evidence(self):
        owner = runner.case_owner
        context, task = self.context_and_task()
        class Exited(BaseException):
            pass
        for mode in ("disabled", "enabled", "writer-error"):
            with self.subTest(mode=mode):
                calls, output = [], io.StringIO()
                sink = SimpleNamespace(write=lambda _text: (_ for _ in ()).throw(OSError("PRIVATE writer error"))) \
                    if mode == "writer-error" else output
                handles = SimpleNamespace(errors=[], close_except=lambda *_: calls.append("close-all"),
                    close=lambda name: calls.append(("close", name)), get=lambda _name: 123)
                native = SimpleNamespace(getppid=lambda: 7, getpgrp=lambda: 8,
                    _exit=lambda code: (_ for _ in ()).throw(Exited(code)))
                def receive(_fd, buffer, _deadline):
                    buffer.extend(b"RUN\n")
                    return True
                with patch.multiple(owner, os=native, receive=receive, send=lambda *_: None,
                                    remaining=lambda _deadline: 1, CASE_DEADLINE=None,
                                    ADAPTER_DIAGNOSTIC_CONTEXT=None if mode == "disabled" else context), \
                        patch.object(contract, "time", SimpleNamespace(monotonic=lambda: 10.0)), redirect_stderr(sink), \
                        self.assertRaises(Exited) as caught:
                    owner._worker(handles, 7, 8, Path("/not-created"), "synthetic", task, 20.0,
                        lambda path, _value: calls.append(("private-write", path.name)))
                self.assertEqual(caught.exception.args, (owner.WORKER_ERROR,))
                self.assertEqual(calls.count(("private-write", "synthetic-error.json")), 1)
                self.assertEqual(calls[-1], "close-all")
                self.assertNotIn("PRIVATE", output.getvalue())
                self.assertEqual(output.getvalue().count(contract.ADAPTER_FAILURE_PREFIX), int(mode == "enabled"))


if __name__ == "__main__":
    unittest.main()
