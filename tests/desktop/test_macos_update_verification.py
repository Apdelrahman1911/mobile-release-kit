"""Focused pure DATA and original-I/O tests, never Installer/native tools."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).absolute().parents[2]

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "desktop/tools" / filename)
    module = importlib.util.module_from_spec(spec)
    prior = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if prior is None: sys.modules.pop(name, None)
        else: sys.modules[name] = prior
    return module

DATA = load("_mrk_update_test_data", "macos_update_verification.py")
STAGER = load("_mrk_update_test_stager", "stage_macos_installed.py")
HELPER = load("_mrk_update_test_helper", "macos_android_helper_package.py")


def nomination():
    policy = {"schemaVersion": 1, "kind": "mrk-macos-developer-id-code-policy-v1", "teamIdentifier": "TEAM000001",
              "leafCertificateSha1": "1" * 40, "leafCertificateSha256": "2" * 64, "hardenedRuntime": True, "entitlements": "empty"}
    policy_hash = DATA.sha(json.dumps(policy, separators=(",", ":")).encode("ascii"))
    result = {"schemaVersion": 1, "mode": "configured", "targets": {}}
    for target, arch in zip(DATA.TARGETS, ("arm64", "x86_64")):
        member = lambda name, digest: {"name": name, "bytes": 100, "sha256": digest * 64}
        image = member("MobileReleaseKit.dmg", "1")
        row = {"source": "a" * 40, "runId": "123", "runAttempt": "1", "jobId": "456", "artifactId": "789",
               "artifactBytes": 200, "artifactSha256": "2" * 64, "members": [image], "image": image,
               "package": member("Install.pkg", "3"), "descriptor": member("producer.json", "4"),
               "signature": member("producer.sig", "5"), "inventory": member("install-inventory.json", "6"),
               "release": {"profile": "fixed-macos26-" + arch + "-maintenance-v2", "packageIdentifier": STAGER.PACKAGE_ID,
                   "bundleIdentifier": STAGER.BUNDLE_ID, "packageVersion": "0.1.1", "release": "macos26-" + arch + "-desktop-01",
                   "sourceCommit": "a" * 40, "protocolSha256": STAGER.CURRENT_PROTOCOL, "runtimeManifestSha256": "7" * 64,
                   "inventorySha256": "6" * 64, "signingPolicySha256": policy_hash, "packageSha256": "3" * 64},
               "signingPolicy": {"sha256": policy_hash, "policy": policy}, "qualificationEvidenceSha256": "8" * 64}
        row["resources"] = {"reviewed": True, **DATA.resource_quote_data(row)}
        result["targets"][target] = row
    return result


def nested_nomination():
    source = nomination()
    for row in source["targets"].values():
        row["members"] = [{"name": name, "bytes": len(name.encode()), "sha256": DATA.sha(name.encode())}
                          for name in DATA.ARTIFACT_PATHS]
        row["image"] = row["members"][0]
        row["resources"] = {"reviewed": True, **DATA.resource_quote_data(row)}
    return source


class UpdateDataTests(unittest.TestCase):
    def test_closed_nomination_requires_real_independent_qualified_source(self):
        source = nomination()
        for target in DATA.TARGETS:
            self.assertEqual(DATA.nomination_data(source, target, STAGER), source["targets"][target])
        with self.assertRaisesRegex(ValueError, "unconfigured"):
            DATA.nomination_data({"schemaVersion": 1, "mode": "unconfigured"}, DATA.TARGETS[0], STAGER)
        for key, value in (("source", "a" * 39), ("artifactId", "0"), ("artifactBytes", True),
                           ("qualificationEvidenceSha256", "0" * 64), ("resources", {"reviewed": False}),
                           ("package", {"name": "../Install.pkg", "bytes": 100, "sha256": "3" * 64})):
            bad = copy.deepcopy(source); bad["targets"][DATA.TARGETS[0]][key] = value
            with self.assertRaises((ValueError, STAGER.Refused)): DATA.nomination_data(bad, DATA.TARGETS[0], STAGER)
        bad = copy.deepcopy(source); bad["targets"][DATA.TARGETS[0]]["members"] *= 2
        with self.assertRaises(ValueError): DATA.nomination_data(bad, DATA.TARGETS[0], STAGER)
        self.assertEqual(DATA.REPOSITORY, "Apdelrahman1911/mobile-release-kit")
        source = nested_nomination()
        for target in DATA.TARGETS:
            self.assertEqual(DATA.nomination_data(source, target, STAGER), source["targets"][target])
            for fault in ("missing", "extra", "duplicate", "flat", "prefix", "traversal", "case", "separator", "removal", "hash"):
                bad = copy.deepcopy(source); row = bad["targets"][target]
                if fault == "missing": row["members"].pop()
                elif fault == "extra": row["members"].append(dict(row["members"][0], name="extra.txt"))
                elif fault == "duplicate": row["members"][-1] = dict(row["members"][0])
                elif fault in ("flat", "prefix", "traversal", "case", "separator"):
                    row["members"][0]["name"] = {"flat": "MobileReleaseKit.dmg", "prefix": "other/MobileReleaseKit.dmg",
                        "traversal": "preview/../MobileReleaseKit.dmg", "case": "Preview/MobileReleaseKit.dmg",
                        "separator": "preview\\MobileReleaseKit.dmg"}[fault]
                elif fault == "removal": row["image"] = row["members"][3]
                else: row["members"][1]["sha256"] = "0" * 64
                with self.subTest(target=target, artifact=fault), self.assertRaises((ValueError, STAGER.Refused)):
                    DATA.nomination_data(bad, target, STAGER)
        # The mounted package parser never acquires the new artifact path grant.
        with self.assertRaises(ValueError): DATA.member_data(source["targets"][DATA.TARGETS[0]]["image"])

    def test_complete_artifact_originals_keep_nested_namespaces_and_post(self):
        # Real existing descriptor-bound owner IO, hashes, POST and consuming
        # closes. No original process, mount, signing or Installer is started.
        for fault in (None, "flat", "missing", "extra-root", "extra-child", "case", "hash-install", "hash-removal",
                      "symlink-file", "symlink-directory", "hardlink", "post-replace", "post-extra", "post-directory"):
            with self.subTest(artifact=fault), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                selected = (nomination() if fault == "flat" else nested_nomination())["targets"][DATA.TARGETS[0]]
                download = root / "update-predecessor"; download.mkdir(mode=0o700)
                for row in selected["members"]:
                    path = download / row["name"]; path.parent.mkdir(parents=True, exist_ok=True)
                    body = row["name"].encode()
                    path.write_bytes(body); path.chmod(0o644)
                    row["bytes"], row["sha256"] = len(body), DATA.sha(body)
                leaf = download / selected["image"]["name"]
                if fault == "missing": (download / "remove-preview/REMOVE.md").unlink()
                elif fault == "extra-root": (download / "extra").write_bytes(b"inert")
                elif fault == "extra-child": (download / "preview/extra").write_bytes(b"inert")
                elif fault == "case": (download / "Preview").mkdir()
                elif fault in ("hash-install", "hash-removal"):
                    altered = leaf if fault == "hash-install" else download / "remove-preview/REMOVE.md"
                    altered.write_bytes(b"X" * altered.stat().st_size)
                elif fault == "symlink-file":
                    target = root / "other"; target.write_bytes(leaf.read_bytes()); leaf.unlink(); leaf.symlink_to(target)
                elif fault == "symlink-directory":
                    (download / "preview").rename(root / "other"); (download / "preview").symlink_to(root / "other")
                elif fault == "hardlink": os.link(leaf, root / "other")
                op = HELPER.Operation.__new__(HELPER.Operation)
                op.entries = []; op.entry_registry = {}; op.errors = []; op.directories = {}
                op.app_absence = None; op.update = {}; op.work = root; op.source_entry = None; op.phase = DATA.PHASE
                op.package_sources = []; op.package_outputs = []; op.package_roots = []; op.package_clock = lambda: 1
                try:
                    op.work_entry = op.register(os.open(root, HELPER.READ_FLAGS | os.O_DIRECTORY), "work", "directory")
                    op.work_entry["identity"] = HELPER.directory_identity(os.fstat(op.work_entry["fd"]))
                    if fault in (None, "flat", "post-replace", "post-extra", "post-directory"):
                        image = DATA.artifact_inputs(op, selected)
                        self.assertEqual(op.read(image), selected["image"]["name"].encode())
                        self.assertEqual(len(op.package_outputs), 1 if fault == "flat" else 6)
                        self.assertEqual(len(op.package_roots), 1 if fault == "flat" else 3)
                        self.assertEqual(len(op.entries), 3 if fault == "flat" else 10)  # Includes the existing work FD.
                        op.package_post()
                        if fault == "post-replace":
                            replacement = root / "new"; replacement.write_bytes(leaf.read_bytes()); replacement.chmod(0o644); replacement.replace(leaf)
                        elif fault == "post-extra": (download / "remove-preview/new").write_bytes(b"inert")
                        elif fault == "post-directory":
                            (download / "preview").rename(root / "old"); (download / "preview").mkdir()
                        if fault and fault.startswith("post-"):
                            with self.assertRaises(HELPER.Refused): op.package_post()
                    else:
                        with self.assertRaises((ValueError, OSError)): DATA.artifact_inputs(op, selected)
                finally:
                    for entry in reversed(op.entries): op.close(entry)
                self.assertTrue(all(entry["closed"] for entry in op.entries)); self.assertEqual(op.errors, [])

    def test_two_generation_shared_bound_and_resource_quote_are_not_per_generation(self):
        limit = 512 * 1024 * 1024
        self.assertEqual(DATA.aggregate_data([(1, limit - 12), (1, 10)], 4, limit, 2),
                         {"declaredFiles": 4, "declaredBytes": limit})
        for counts in ([(1, limit - 11), (1, 10)], [(2, 1), (1, 1)], [(True, 1), (1, 1)]):
            with self.assertRaises(ValueError): DATA.aggregate_data(counts, 4, limit, 2)
        row = nomination()["targets"][DATA.TARGETS[0]]
        self.assertEqual(DATA.resource_quote_data(row), {"additionalDiskBytes": 300 + limit + 4 * 1024**2,
            "rawPayloadBytes": 6 * limit + 80 * 1024**2, "maximumOriginals": 96})
        row["resources"]["rawPayloadBytes"] -= 1
        source = nomination(); source["targets"][DATA.TARGETS[0]] = row
        with self.assertRaisesRegex(ValueError, "too-small"): DATA.nomination_data(source, DATA.TARGETS[0], STAGER)

    def test_pair_requires_exact_real_policy_lineage_and_distinct_current_release(self):
        # Genuine producer/release parsers; the inventory-byte reducer is an
        # explicit fixed DATA port here, separately exercised by full stager
        # current/retained reader groups. No fabricated native qualification.
        for target in DATA.TARGETS:
            old = nomination()["targets"][target]
            newer = {**old["release"], "sourceCommit": "b" * 40, "packageVersion": "0.2.1",
                     "release": old["release"]["release"] + "-next", "packageSha256": "9" * 64}
            descriptor = {"schemaVersion": 2, "kind": "mrk-macos-install-producer-v2",
                "domain": "MobileReleaseKit-package-producer-v2", "target": target,
                "releaseSet": {"schemaVersion": 2, "current": newer, "acceptedPredecessors": [old["release"]]},
                "signingPolicies": [old["signingPolicy"]]}
            stager = SimpleNamespace(maintenance_producer_data=STAGER.maintenance_producer_data,
                BuildSelection=STAGER.BuildSelection, MAX_FILES=STAGER.MAX_FILES, MAX_BYTES=STAGER.MAX_BYTES,
                MAINTENANCE_GATE_BYTES=STAGER.MAINTENANCE_GATE_BYTES, REGISTRATION_GATE_BYTES=STAGER.REGISTRATION_GATE_BYTES,
                observation_inventory_bytes=mock.Mock(return_value={"file": {"size": 1}}))
            result = DATA.pair_data(stager, old, STAGER.canonical(descriptor), b"old", b"new", old_metadata=1, new_metadata=1)
            self.assertEqual(result["declaredFiles"], 4)
            self.assertEqual(stager.observation_inventory_bytes.call_count, 2)
            self.assertEqual([call.kwargs["selection"].release for call in stager.observation_inventory_bytes.call_args_list],
                             [old["release"]["release"], newer["release"]])
            for field in ("sourceCommit", "packageVersion", "release", "packageSha256"):
                bad = copy.deepcopy(descriptor); bad["releaseSet"]["current"][field] = old["release"][field]
                with self.assertRaises((ValueError, STAGER.Refused)):
                    DATA.pair_data(stager, old, STAGER.canonical(bad), b"old", b"new", old_metadata=1, new_metadata=1)
            for predecessors, policies in (([], descriptor["signingPolicies"]),
                    ([{**old["release"], "sourceCommit": "f" * 40}], descriptor["signingPolicies"]), ([old["release"]], [])):
                bad = copy.deepcopy(descriptor); bad["releaseSet"]["acceptedPredecessors"] = predecessors; bad["signingPolicies"] = policies
                with self.assertRaises((ValueError, STAGER.Refused)):
                    DATA.pair_data(stager, old, STAGER.canonical(bad), b"old", b"new", old_metadata=1, new_metadata=1)

    def test_census_preserves_baseline_and_adds_only_one_request(self):
        a, b = "a" * 32, "b" * 32
        old = {a: {"sha256": "1" * 64, "identity": [1], "bytes": 10}}
        new = {**old, b: {"sha256": "2" * 64, "identity": [2], "bytes": 11}}
        self.assertEqual(DATA.census_data({}, old), a)
        self.assertEqual(DATA.census_data(old, new, baseline=a), b)
        for before, after in (({}, new), (old, old), (old, {**new, "c" * 32: {}}),
                              (old, {**new, a: {"sha256": "f" * 64}})):
            with self.assertRaises(ValueError): DATA.census_data(before, after, baseline=a)

    def test_fixed_original_dispatch_clock_and_finality_do_not_accept_unknown(self):
        rows = [{"role": role, "entered": True, "returned": True, "capturesSettled": True, "returncode": 0} for role in DATA.ROLES]
        self.assertTrue(DATA.phase_credit(rows, phase=DATA.PHASE))
        for key, value in (("returncode", False), ("returncode", 1), ("returned", False), ("capturesSettled", None)):
            bad = copy.deepcopy(rows); bad[1][key] = value
            with self.assertRaises(ValueError): DATA.phase_credit(bad, phase=DATA.PHASE)
        op = SimpleNamespace(phase=DATA.PHASE, calls=[], work=Path("/inert/work"), mount_device=None,
                             update={"nomination": nomination()["targets"][DATA.TARGETS[0]]}, package_settled=lambda: True,
                             mount_entered=False, installer_entered=False, mount_known=False, mount_detached=False)
        attach = ["/usr/bin/hdiutil", "attach", "/inert/work/update-predecessor/MobileReleaseKit.dmg", "-readonly", "-nobrowse",
                  "-noautoopen", "-mountpoint", "/inert/work/package-mount", "-plist"]
        DATA.dispatch(op, DATA.ROLES[0], attach); self.assertTrue(op.mount_entered)
        with self.assertRaises(ValueError): DATA.dispatch(op, DATA.ROLES[0], attach + ["-owners", "off"])
        op.update["nomination"] = nested_nomination()["targets"][DATA.TARGETS[0]]
        nested_attach = list(attach); nested_attach[2] = "/inert/work/update-predecessor/preview/MobileReleaseKit.dmg"
        DATA.dispatch(op, DATA.ROLES[0], nested_attach)
        for bad in (attach, [*nested_attach[:2], "/inert/work/update-predecessor/remove-preview/MobileReleaseKit-Remove.dmg", *nested_attach[3:]]):
            with self.assertRaises(ValueError): DATA.dispatch(op, DATA.ROLES[0], bad)
        op.calls = rows[:1]
        with self.assertRaises(ValueError): DATA.dispatch(op, DATA.ROLES[1], [])
        now = 100
        op.update = {"start": 10, "observed": 10, "workEnd": 100, "hardEnd": 200}
        op.update_api = SimpleNamespace(time=SimpleNamespace(monotonic_ns=lambda: now))
        with self.assertRaises(ValueError): DATA.clock(op)
        self.assertEqual(DATA.clock(op, work=False), 100)
        self.assertEqual(HELPER.package_timeout_data(1, 420_000_000_001, 123, phase=DATA.PHASE, role=DATA.ROLES[1]), 123)
        with self.assertRaises(HELPER.Refused): HELPER.package_timeout_data(418_000_000_000, 420_000_000_000, 123, phase=DATA.PHASE, role=DATA.ROLES[1])

    def test_stager_unknown_blocks_future_dispatch_and_retains_first_failure(self):
        op = SimpleNamespace(package_settled=lambda: True, package_clock=lambda: 1, stager_io_pending=None, errors=[])
        error = RuntimeError("inert primary")
        def failed(): raise error
        with self.assertRaises(RuntimeError) as caught: DATA.io(op, "baseline-readback", failed)
        self.assertIs(caught.exception, error)
        self.assertEqual(op.stager_io_pending, "update-baseline-readback")
        self.assertEqual(op.errors, [{"stage": "update-io", "operation": "baseline-readback", "type": "CompletionUnknown"}])

    def test_source_original_reader_rejects_duplicate_and_same_size_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / DATA.NOMINATION
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{"schemaVersion":1,"mode":"unconfigured"}\n'); path.chmod(0o644)
            self.assertEqual(DATA.source_document(root), {"schemaVersion": 1, "mode": "unconfigured"})
            path.write_bytes(b'{"mode":1,"mode":2}')
            with self.assertRaisesRegex(ValueError, "duplicate"): DATA.source_document(root)
            first = b'{"schemaVersion":1,"mode":"unconfigured"}\n'
            path.write_bytes(first)
            actual = DATA.os.pread; calls = 0
            def changed(fd, size, offset):
                nonlocal calls
                value = actual(fd, size, offset); calls += 1
                if calls == 1: path.write_bytes(first.replace(b'1', b'2', 1))
                return value
            with mock.patch.object(DATA.os, "pread", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "post"): DATA.source_document(root)


    def test_real_sentinel_originals_reject_replacement_without_reading_other_user_data(self):
        # Only the logical filesystem root is redirected into this test's own
        # tiny tree. Every descendant permission, inode, link, byte, FD and
        # consuming close is genuine; account/console admission has its own case.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "home/Library/Application Support").mkdir(parents=True)
            actual_open, actual_stat = os.open, os.stat
            def open_root(name, flags, *args, **kwargs):
                return actual_open(root if name == "/" and kwargs.get("dir_fd") is None else name, flags, *args, **kwargs)
            def stat_root(name, *args, **kwargs):
                return actual_stat(root if name == "/" and kwargs.get("dir_fd") is None else name, *args, **kwargs)
            operation = HELPER.Operation.__new__(HELPER.Operation)
            operation.entries = []; operation.entry_registry = {}; operation.errors = []
            operation.app_absence = None
            operation.update = {"sentinelEntries": []}
            operation.update_api = HELPER
            operation.environment = {"MRK_MACOS_GUI_HOME": "/home", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
            operation.package_clock = lambda: 1
            try:
                with mock.patch.object(DATA.os, "open", side_effect=open_root), mock.patch.object(DATA.os, "stat", side_effect=stat_root), \
                     mock.patch.object(DATA, "gui_home_data", return_value="/home"):
                    expected = DATA.sentinel_open(operation, True, None)
                    DATA.sentinel_post(operation, expected)
                    self.assertEqual(DATA.sentinel_open(operation, False, expected), expected)
                    with self.assertRaises(FileExistsError): DATA.sentinel_open(operation, True, None)
                    leaf = root / "home/Library/Application Support" / DATA.IDENTIFIER / "mrk-update-preservation-123-1.txt"
                    self.assertEqual(leaf.read_bytes(), DATA.SENTINEL)
                    leaf.unlink(); leaf.write_bytes(DATA.SENTINEL); leaf.chmod(0o600)
                    with self.assertRaisesRegex(ValueError, "original-post"): DATA.sentinel_post(operation, expected)
                    with self.assertRaisesRegex(ValueError, "original-changed"): DATA.sentinel_open(operation, False, expected)
            finally:
                for entry in reversed(operation.entries): operation.close(entry)
            self.assertTrue(all(entry["closed"] for entry in operation.entries))
            self.assertEqual(operation.errors, [])

    def test_gui_home_requires_the_actual_console_account_not_sanitized_home(self):
        account = SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="runner", pw_dir="/actual/home")
        with mock.patch.object(DATA.os, "getuid", return_value=501), mock.patch.object(DATA.os, "geteuid", return_value=501), \
             mock.patch.object(DATA.os, "getgid", return_value=20), mock.patch.object(DATA.os, "getegid", return_value=20), \
             mock.patch.object(DATA.os, "stat", return_value=SimpleNamespace(st_uid=501)), \
             mock.patch.object(DATA.pwd, "getpwuid", return_value=account):
            self.assertEqual(DATA.gui_home_data({"MRK_MACOS_GUI_HOME": "/actual/home", "HOME": "/private/task"}), "/actual/home")
            for value in (None, "/Users/runner", "/private/task"):
                with self.assertRaises(ValueError): DATA.gui_home_data({"MRK_MACOS_GUI_HOME": value})


if __name__ == "__main__":
    unittest.main()
