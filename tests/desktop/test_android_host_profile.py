"""Command-free DATA contracts; only task-owned synthetic filesystem inputs.

The bounded readlink test is a read-only native filesystem API check, not a
product native test, host observation, compiler/tool invocation or qualification.
"""
import ast
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

SOURCE = Path(__file__).resolve().parents[2]


def load(name):
    spec = importlib.util.spec_from_file_location("_profile_test_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


P = load("observe_android_host_profile")
L = load("ubuntu_publication_lifecycle")
M = load("android_material_preparation")
H = load("android_hosted_data")
C = load("ci_ubuntu_publication")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def binding(name, raw=b"abc"):
    return {"path": name, "selectedPath": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "identity": [1, 2, stat.S_IFREG | 0o644, 1, len(raw), 3, 4], "links": [], "ancestry": {}}


def stamp(mode, *, inode=2, size=3):
    return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode, st_uid=0, st_gid=0,
        st_nlink=1, st_size=size, st_mtime_ns=3, st_ctime_ns=4)


class AndroidHostProfileContracts(unittest.TestCase):
    def test_one_ledger_counts_repeated_alias_reads_and_retains_failed_reservations(self):
        publisher = SimpleNamespace(shell_host_binding=Mock(return_value=binding("/usr/lib/a")))
        reader = P.Reader(publisher, 100)
        with patch.object(P.BASE.time, "monotonic", return_value=0):
            reader.bind("/usr/lib/a", limit=8)
            reader.bind("/lib/a", limit=8)
            self.assertEqual(P.READ_LIMIT - reader.remaining, 6)
            self.assertEqual(publisher.shell_host_binding.call_args.kwargs["link_reader"], reader.readlink)
            self.assertEqual(publisher.shell_host_binding.call_args.kwargs["resolver"], reader.resolve)
            self.assertEqual(publisher.shell_host_binding.call_args.kwargs["record_reader"], reader._file_record)
            publisher.shell_host_binding.side_effect = OSError("private detail")
            before = reader.remaining
            with self.assertRaises(OSError):
                reader.bind("/usr/lib/a", limit=8)
            self.assertEqual(before - reader.remaining, 8 + 1)
            reader.final_reserve = 100
            reader.remaining = 101
            action = Mock()
            with self.assertRaisesRegex(P.BASE.Stopped, "read-budget"):
                reader.charged(8, action, overread=1)
            action.assert_not_called()
            self.assertEqual(reader.remaining, 101)
            reader.final_reserve = 0  # Release the same ledger's final reserve, not new credit.
            reader.charged(8, lambda bound: (None, 3), overread=1)
            self.assertEqual(reader.remaining, 98)

    def test_bounded_readlink_uses_only_fixed_capacity_on_task_owned_synthetic_link(self):
        api = P.BoundedReadlink()
        with tempfile.TemporaryDirectory(prefix="mrk-profile-link-") as directory:
            path = Path(directory) / "selected"
            os.symlink("synthetic-target", path)
            self.assertEqual(api(path, P.LINK_CAPACITY), b"synthetic-target")
            with self.assertRaisesRegex(P.BASE.Refused, "profile-link-capacity"):
                api(path, P.LINK_CAPACITY - 1)
            api.call = Mock(return_value=P.LINK_CAPACITY)
            with self.assertRaisesRegex(P.BASE.Refused, "profile-link-truncated"):
                api(path, P.LINK_CAPACITY)
            self.assertEqual(api.call.call_args.args[2], P.LINK_CAPACITY)

    def test_link_ledger_admits_before_read_and_retains_drift_error_and_truncation(self):
        reader = P.Reader(SimpleNamespace(), 100)
        original = stamp(stat.S_IFLNK | 0o777, size=6)
        reader.link_api = Mock(return_value=b"target")
        with patch.object(P.BASE.time, "monotonic", return_value=0), patch.object(Path, "lstat", return_value=original):
            self.assertEqual(reader.readlink(Path("/selected")), "target")
            self.assertEqual(P.READ_LIMIT - reader.remaining, 6)
            reader.link_api.return_value = b"x" * P.LINK_CAPACITY
            before = reader.remaining
            with self.assertRaisesRegex(P.BASE.Refused, "profile-link-truncated"):
                reader.readlink(Path("/selected"))
            self.assertEqual(before - reader.remaining, P.LINK_CAPACITY)
            reader.link_api.side_effect = OSError("private failure")
            before = reader.remaining
            with self.assertRaises(OSError):
                reader.readlink(Path("/selected"))
            self.assertEqual(before - reader.remaining, P.LINK_CAPACITY)
            reader.link_api.reset_mock(side_effect=True, return_value=True)
            reader.remaining = P.LINK_CAPACITY - 1
            with self.assertRaisesRegex(P.BASE.Refused, "profile-link-capacity"):
                reader.readlink(Path("/selected"))
            reader.link_api.assert_not_called()
        reader.remaining = P.READ_LIMIT
        reader.link_api.return_value = b"target"
        with patch.object(P.BASE.time, "monotonic", return_value=0), \
             patch.object(Path, "lstat", side_effect=[original, stamp(original.st_mode, inode=99, size=6)]):
            with self.assertRaisesRegex(P.BASE.Refused, "profile-link-changed"):
                reader.readlink(Path("/selected"))
        self.assertEqual(P.READ_LIMIT - reader.remaining, P.LINK_CAPACITY)
        reader.link_api.reset_mock()
        with patch.object(P.BASE.time, "monotonic", return_value=100):
            with self.assertRaisesRegex(P.BASE.Stopped, "deadline"):
                reader.readlink(Path("/selected"))
        reader.link_api.assert_not_called()

    def test_resolver_bounds_cycles_components_and_original_post_without_opaque_fallback(self):
        reader = P.Reader(SimpleNamespace(), 100)
        link = stamp(stat.S_IFLNK | 0o777)
        with patch.object(P.BASE.time, "monotonic", return_value=0), \
             patch.object(Path, "resolve", side_effect=AssertionError("opaque resolver")), \
             patch.object(Path, "lstat", return_value=link):
            reader.readlink = Mock(side_effect=lambda path: "second" if str(path) == "/first" else "first")
            with self.assertRaisesRegex(P.BASE.Refused, "profile-resolve-links"):
                reader.resolve(Path("/first"))
            self.assertEqual(reader.readlink.call_count, 40)
        directory = stamp(stat.S_IFDIR | 0o755)
        with patch.object(P.BASE.time, "monotonic", return_value=0), patch.object(Path, "lstat", return_value=directory) as stats:
            with self.assertRaisesRegex(P.BASE.Refused, "profile-resolve-components"):
                reader.resolve(Path("/" + "/".join(["part"] * 257)))
            self.assertEqual(stats.call_count, 256)
        file = stamp(stat.S_IFREG | 0o644)
        reader.readlink = Mock(return_value="target")
        with patch.object(P.BASE.time, "monotonic", return_value=0), \
             patch.object(Path, "lstat", side_effect=[link, file, file, stamp(link.st_mode, inode=99)]):
            with self.assertRaisesRegex(P.BASE.Refused, "profile-resolve-changed"):
                reader.resolve(Path("/first"))

    def test_protected_binder_defaults_and_explicit_callbacks_have_identical_binding(self):
        directory, file, link = stamp(stat.S_IFDIR | 0o755), stamp(stat.S_IFREG | 0o644), stamp(stat.S_IFLNK | 0o777)
        def lstat(path):
            return link if str(path) == "/usr/selected" else file if str(path) == "/usr/target" else directory
        output = {"path": "target", "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        selected = Path("/usr/selected")
        with patch.object(Path, "lstat", lstat), patch.object(C.D, "file_record", return_value=output), \
             patch.object(C.os, "readlink", return_value="target") as default_link, \
             patch.object(Path, "resolve", return_value=Path("/usr/target")) as default_resolve:
            original = C.protected_host_file(selected, 8)
            self.assertEqual((default_link.call_count, default_resolve.call_count), (2, 2))
            default_link.reset_mock(); default_resolve.reset_mock()
            default_link.side_effect = default_resolve.side_effect = AssertionError("unaccounted default branch")
            read_link, resolve = Mock(return_value="target"), Mock(return_value=Path("/usr/target"))
            record = Mock(return_value=output)
            C.D.file_record.reset_mock()
            C.D.file_record.side_effect = AssertionError("buffered default read")
            actual = C.shell_host_binding(selected, absent=True, limit=8, link_reader=read_link,
                                          resolver=resolve, record_reader=record)
            record.assert_called_once_with(Path("/usr/target"), 8)
            C.D.file_record.assert_not_called()
            self.assertEqual(original, actual)
            self.assertEqual((read_link.call_count, resolve.call_count), (3, 2))
            default_link.assert_not_called(); default_resolve.assert_not_called()

    def test_source_pre_post_and_parser_body_share_the_read_ledger(self):
        source_file = stamp(stat.S_IFREG | 0o600)
        publisher = SimpleNamespace(D=SimpleNamespace(directory=Mock(),
            file_record=Mock(side_effect=AssertionError("buffered hash")),
            read=Mock(side_effect=AssertionError("buffered body"))))
        reader = P.Reader(publisher, 100)
        record = {"path": "source.py", "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        with patch.object(P.BASE.time, "monotonic", return_value=0), \
             patch.object(Path, "lstat", return_value=source_file), \
             patch.object(P.os, "open", return_value=90) as opened, \
             patch.object(P.os, "fstat", return_value=source_file), \
             patch.object(P.os, "read", side_effect=[b"a", b"bc", b""] * 3) as reads, \
             patch.object(P.os, "close") as closed:
            before = reader.source("desktop/tools/source.py")
            self.assertEqual(reader.body(Path("/fixed/body"), 8), b"abc")
            after = reader.source("desktop/tools/source.py")
            self.assertEqual(before, after)
            self.assertEqual(P.READ_LIMIT - reader.remaining, 9)
            self.assertEqual([call.args for call in reads.call_args_list], [(90, 4), (90, 3), (90, 1)] * 3)
            self.assertEqual(opened.call_count, 3)
            self.assertEqual([call.args for call in closed.call_args_list], [(90,)] * 3)
            for response, label in (([b"abcd"], "profile-file-grew"), ([b"a", b""], "profile-file-read-changed")):
                reads.reset_mock(side_effect=True); reads.side_effect = response
                closed.reset_mock(); prior = reader.remaining
                with self.assertRaisesRegex(P.BASE.Refused, label):
                    reader.body(Path("/fixed/body"), 8)
                self.assertEqual(prior - reader.remaining, 9)
                closed.assert_called_once_with(90)
            reads.side_effect = OSError("original synthetic read error")
            closed.reset_mock(); closed.side_effect = ValueError("synthetic close failure")
            prior = reader.remaining
            with self.assertRaisesRegex(OSError, "original synthetic read error") as failure:
                reader.body(Path("/fixed/body"), 8)
            self.assertEqual(prior - reader.remaining, 9)
            self.assertEqual(failure.exception.__notes__, ["profile original file close failed: ValueError"])
            closed.assert_called_once_with(90)
            reads.reset_mock(); closed.reset_mock(side_effect=True)
            with patch.object(P.BASE.time, "monotonic", side_effect=[0, 100]):
                with self.assertRaisesRegex(P.BASE.Stopped, "deadline"):
                    reader.body(Path("/fixed/body"), 8)
            reads.assert_not_called(); closed.assert_called_once_with(90)
        publisher.D.file_record.assert_not_called(); publisher.D.read.assert_not_called()
        # Same exclusive output lifecycle, with TWO original unbuffered readbacks.
        output = Mock()
        output.fileno.return_value = 90
        output.write.return_value = 3
        manager = MagicMock(__enter__=Mock(return_value=output), __exit__=Mock(return_value=False))
        reader._body, reader._file_record = Mock(return_value=(b"abc", 3)), Mock(return_value=record)
        order = Mock(); order.attach_mock(reader._body, "body"); order.attach_mock(reader._file_record, "record")
        path = Path("/fixed/output")
        with patch.object(Path, "open", return_value=manager) as opening, \
             patch.object(P.os, "fchmod") as mode, patch.object(P.os, "fsync") as sync:
            self.assertEqual(reader.write(path, b"abc"), record)
        opening.assert_called_once_with("xb")
        mode.assert_called_once_with(90, 0o600); sync.assert_called_once_with(90)
        self.assertEqual([call[0] for call in order.mock_calls], ["body", "record"])
        reader._body.assert_called_once_with(path, 3); reader._file_record.assert_called_once_with(path, 3)
        manager.__exit__.assert_called_once()

    def test_output_directory_guard_uses_charged_original_python_before_collection(self):
        expected = {"path": "/usr/bin/python3.12", "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        publisher = SimpleNamespace(D=SimpleNamespace(), directory_identity=Mock(return_value=(1, 2, 3)),
            C=SimpleNamespace(conventional_hosted_python_profile=Mock(return_value={"images": {"fixed": expected}})))
        reader = P.Reader(publisher, 100)
        reader.file = Mock(return_value={"file": {**expected, "mode": 0o755}})
        run = {"ImageVersion": "fixed", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.object(P.BASE.time, "monotonic", return_value=0), patch.object(P.sys, "executable", expected["path"]), \
             patch.dict(P.os.environ, {"RUNNER_TEMP": "/task-owned"}):
            root, original = reader.output_root(run)
            self.assertEqual((str(root), original), ("/task-owned/mrk-desktop-tools-123-1", (1, 2, 3)))
            reader.file.assert_called_once_with(expected["path"], 16 << 20)
            reader.file.return_value["file"]["sha256"] = "0" * 64
            publisher.directory_identity.reset_mock()
            with self.assertRaisesRegex(P.BASE.Refused, "profile-original-python"):
                reader.output_root(run)
            publisher.directory_identity.assert_not_called()

    def test_complete_font_roster_and_cache_namespace_are_separate_from_consumer_receipts(self):
        fonts = json.loads((SOURCE / "desktop/tools/android_material_data/fonts.json").read_bytes())
        details = {}
        for name, row in fonts["files"].items():
            root = str(Path(name).parent)
            detail = details.setdefault(root, {"directories": {}, "entries": []})
            detail["entries"].append({"path": Path(name).name, "present": True, "kind": "file", "canonical": row["path"],
                                     **{key: row[key] for key in ("size", "sha256", "mode")}})
        detail = details.setdefault("/var/cache/fontconfig", {"directories": {}, "entries": []})
        for name in fonts["directories"]["/var/cache/fontconfig"]:
            detail["entries"].append({"path": name, "present": True, "kind": "file", "canonical": "/var/cache/fontconfig/" + name,
                                     "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest(), "mode": 0o644})
        detail["directories"] = {name: {"children": list(children)} for name, children in fonts["directories"].items()}
        snapshot = {"suppliers": {"roots": deepcopy(fonts["supplierRoots"])}, "details": details}
        reader = SimpleNamespace(point=Mock(), bind=Mock(return_value={"absent": True}))
        with patch.object(P, "observed_file", return_value={"data": []}):
            result = P.font_correspondence(reader, snapshot, fonts, M)
            self.assertEqual(len(result["caches"]), len(M.FONT_DIRECTORIES))
            self.assertTrue(result["completeSourceRosterMatches"])
            self.assertTrue(result["freshFontConsumersRequired"])
            self.assertFalse(result["fontConsumersExecuted"])
            detail["directories"]["/var/cache/fontconfig"]["children"].append("unreviewed-cache")
            with self.assertRaisesRegex(P.BASE.Refused, "profile-font-roster"):
                P.font_correspondence(reader, snapshot, fonts, M)

    def test_stock_trust_rechecks_custom_ca_and_never_opens_custom_members(self):
        empty = {"status": "empty", "customBodiesRead": False, "customNamesExported": False}
        policy = SimpleNamespace(complete=Mock(return_value={"anchors": 121}))
        trust = SimpleNamespace(Policy=Mock(return_value=policy), POLICY_FILE="fixed.json", POLICY_LIMIT=4096, POLICY_SHA256="fixed")
        reader = SimpleNamespace(body=Mock(return_value=b"{}"), custom_ca=Mock(side_effect=[empty, empty]))
        with patch.object(P, "observed_file", return_value={"data": {}, "file": {}}) as observe:
            result = P.stock_correspondence(reader, trust)
            self.assertEqual(result["customCa"], empty)
            self.assertFalse(result["producerExecutionProven"])
            self.assertEqual(observe.call_count, 3)
            reader.custom_ca.side_effect = [empty, {**empty, "status": "nonempty"}]
            with self.assertRaisesRegex(P.BASE.Refused, "profile-custom-ca-changed"):
                P.stock_correspondence(reader, trust)
            observe.reset_mock()
            reader.custom_ca.side_effect = [{**empty, "status": "nonempty"}]
            with self.assertRaisesRegex(P.BASE.Refused, "profile-custom-ca-not-empty"):
                P.stock_correspondence(reader, trust)
            observe.assert_not_called()

    def test_snapshot_injects_both_internal_body_reads_and_preserves_native_default(self):
        self.assertIs(L.shell_data_snapshot.__kwdefaults__["body_reader"], L.read)
        module = "/usr/lib/x86_64-linux-gnu/gio/modules/giomodule.cache"
        egl = "/usr/share/glvnd/egl_vendor.d/50_mesa.json"
        raws = {module: b"synthetic cache\n", egl: canonical({"file_format_version": "1.0.0", "ICD": {"library_path": "libEGL_mesa.so.0"}})}
        bodies = Mock(side_effect=lambda path, bound: raws[str(path)])
        with patch.object(L, "SHELL_DATA_ROOTS", ((module, "file"), (egl, "file"))), \
             patch.object(L, "SHELL_MODULE_CACHES", {module: "/usr/lib/x86_64-linux-gnu/gio/modules"}), \
             patch.object(L, "shell_module_cache", return_value=[]), \
             patch.object(L, "read", side_effect=AssertionError("unmetered internal body read")):
            result = L.shell_data_snapshot(lambda path, **options: binding(str(path), raws[str(path)]), body_reader=bodies)
        self.assertEqual([str(call.args[0]) for call in bodies.call_args_list], [module, egl])
        self.assertEqual(result["eglLibraries"][egl], "/usr/lib/x86_64-linux-gnu/libEGL_mesa.so.0")

    def test_public_projection_rejects_unexpected_private_alias_text(self):
        expected = {"path": "/usr/lib/liba.so.1.2", "size": 3, "sha256": hashlib.sha256(b"abc").hexdigest(), "mode": 0o644}
        row = binding(expected["path"])
        row["selectedPath"] = "/usr/lib/liba.so.1"
        row["links"] = [["/usr/lib/liba.so.1", [1], "liba.so.1.2"]]
        self.assertEqual(P.public_file(row, expected, selected=row["selectedPath"])["aliases"][0]["target"], "liba.so.1.2")
        row["links"][0][2] = "../private-name/../lib/liba.so.1.2"
        with self.assertRaisesRegex(P.BASE.Refused, "profile-public-alias"):
            P.public_file(row, expected, selected=row["selectedPath"])
        row["links"] = [["/private/liba.so.1", [1], expected["path"]]]
        with self.assertRaisesRegex(P.BASE.Refused, "profile-public-alias"):
            P.public_file(row, expected, selected=row["selectedPath"])
        row["links"] = []
        row["sha256"] = "0" * 64
        with self.assertRaisesRegex(P.BASE.Refused, "profile-file-correspondence"):
            P.public_file(row, expected, selected=row["selectedPath"])

        elf = {"interpreter": "/lib64/ld-linux-x86-64.so.2", "needed": ["libc.so.6"], "soname": None,
               "versionDefinitions": [], "versionNeeds": {"libc.so.6": ["GLIBC_2.34"]}, "rpath": None, "runpath": None}
        self.assertEqual(P.public_preparation_elf(deepcopy(elf)), elf)
        known = {key: value for key, value in elf.items() if key not in {"rpath", "runpath"}}
        self.assertEqual(P.public_preparation_elf(deepcopy(elf), known), elf)
        for key, value in (("rpath", "/private/location"), ("interpreter", "/private/loader"),
                           ("soname", "private.so"), ("versionDefinitions", ["private-label"]),
                           ("versionNeeds", {"libc.so.6": ["PRIVATE_VALUE"]}),
                           ("versionNeeds", {"private/path": ["GLIBC_2.34"]})):
            with self.assertRaises(P.BASE.Refused):
                P.public_preparation_elf({**elf, key: value})
        with self.assertRaisesRegex(P.BASE.Refused, "profile-preparation-elf-source"):
            P.public_preparation_elf(elf, {**known, "versionNeeds": {"libc.so.6": ["GLIBC_2.35"]}})

    def test_explicit_package_selection_does_not_mutate_legacy_roster(self):
        original = P.BASE.PACKAGES
        raw = b"Package: libexample\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n"
        self.assertEqual(P.BASE.package_status(raw, packages=["libexample"])["libexample"]["status"], "observed")
        self.assertIs(P.BASE.PACKAGES, original)
        for selected in (["libexample", "libexample"], ["private/name"], [], ["pkg" + str(i) for i in range(129)]):
            with self.assertRaises(P.BASE.Refused):
                P.BASE.package_status(raw, packages=selected)

    def test_sdk_and_configuration_are_source_prospects_not_consumed_originals(self):
        with patch.object(H, "prepare") as prepare, patch.object(H, "settle") as settle, \
             patch.object(M, "_font_consumers") as fonts, patch.object(M, "_provider_consumers") as providers, \
             patch.object(P.BASE.time, "monotonic", return_value=0), patch.object(M, "_point", wraps=M._point) as point:
            result = P.prospective_rules({"hostPolicy": None}, M, H, 100)
            self.assertTrue(point.call_args_list)
            self.assertTrue(all(call.args == (100,) for call in point.call_args_list))
        self.assertEqual(len(result["sdk"]), 5)
        self.assertEqual(len(result["configuration"]), 3)
        self.assertTrue(all(row["pin"] is None and row["consumed"] is False for row in result["sdk"].values()))
        self.assertTrue(all(row["consumed"] is False for row in result["configuration"].values()))
        self.assertFalse(result["observedOrConsumed"])
        self.assertFalse(result["sdkSourcePinsIndependentlyAdmitted"])
        for operation in (prepare, settle, fonts, providers):
            operation.assert_not_called()

    def test_partial_failures_keep_independent_facts_without_private_errors_or_admission(self):
        reader = SimpleNamespace(point=Mock(), remaining=P.READ_LIMIT, deadline=100, s=SimpleNamespace(D=SimpleNamespace(canonical=canonical)))
        files = {name: {"file": {"selectedPath": "/usr/lib/" + name}} for name in ("bad", "good")}
        providers = {"osLibraries": files, "programs": {}, "loader": {"selectedPath": "/loader"}, "ldconfig": {"selectedPath": "/ldconfig"}}
        material = SimpleNamespace(SDK_IMAGE={"image": "fixed"}, CONFIGURATION_LIMIT=128 << 10)
        lifecycle = SimpleNamespace(shell_data_snapshot=Mock(return_value={}))
        def observe(_reader, name, *_args, **_kwargs):
            if name == "/usr/lib/bad":
                raise ValueError("private-path private-data")
            data = {"identity": material.SDK_IMAGE} if name == P.BASE.IMAGE_DATA else P.NETWORK_CONFIGURATION.get(name)
            return {"status": "observed", "data": data}
        reader.bind, reader.body = Mock(), Mock()
        with patch.object(P, "prospective_rules", return_value={"observedOrConsumed": False}), \
             patch.object(P, "observed_file", side_effect=observe), \
             patch.object(P, "snapshot_projection", return_value={"status": "observed"}), \
             patch.object(P, "loader_correspondence", return_value={"status": "observed"}), \
             patch.object(P, "font_correspondence", return_value={"status": "observed"}), \
             patch.object(P, "stock_correspondence", return_value={"status": "observed"}), \
             patch.object(P, "package_correspondence", return_value={"status": "observed"}):
            result = P.collect(reader, {}, providers, {"consumers": {}}, {}, lifecycle=lifecycle, material=material, hosted=None, trust=None)
        self.assertEqual(result["firstFailure"]["role"], "provider:bad")
        self.assertEqual(result["observations"]["provider:good"]["status"], "observed")
        self.assertEqual(result["observations"]["packages"]["status"], "observed")
        self.assertNotIn("private-", canonical(result).decode())
        for field in ("observationComplete", "collectionComplete", "profileActivated", "runtimeAdmission", "nativeQualification", "newConsent"):
            self.assertFalse(result[field])

    def test_package_membership_must_match_the_declared_provider_owner(self):
        name, member = "libexample", "/usr/lib/libexample.so.1"
        expected = {"binaryPackage": name + ":amd64", "architecture": "amd64", "version": "1.0",
                    "sourcePackage": name, "sourceVersion": "1.0"}
        providers = {"packages": {name + ":amd64": expected}, "osLibraries": {"libexample.so.1": {
            "file": {"path": member}, "package": name + ":amd64"}}, "programs": {}}
        selected = {member: None}
        def file(path, *_args, **_kwargs):
            if path == "/var/lib/dpkg/status":
                return {"data": {name: {"status": "observed", "fields": {"Package": name,
                    "Architecture": "amd64", "Version": "1.0", "Depends": "private-unrelated-value"}}}}
            return {"file": binding(path), "data": {"selectedMembers": selected}}
        reader = SimpleNamespace(point=Mock(), file=file,
            bind=lambda path, **opts: {"absent": True} if ":amd64" in path else binding(path),
            s=SimpleNamespace(D=SimpleNamespace(same=lambda a, b: a == b)))
        with patch.object(P, "EXTRA_PACKAGES", ()), patch.object(P, "PREPARATION_PACKAGES", {}):
            result = P.package_correspondence(reader, providers, {"files": {}})
            self.assertNotIn("private-unrelated-value", canonical(result).decode())
            selected.clear()
            with self.assertRaisesRegex(P.BASE.Refused, "profile-provider-package-membership"):
                P.package_correspondence(reader, providers, {"files": {}})

    def test_new_observer_cannot_invoke_native_or_broad_collection_and_pins_exact_data(self):
        source = (SOURCE / "desktop/tools/observe_android_host_profile.py").read_text()
        tree = ast.parse(source)
        calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
        for forbidden in ("subprocess.run", "subprocess.Popen", "os.system", "os.execve", "socket.socket",
                          "BASE.collect", "BASE.collect_sdk_network", "hosted.prepare", "hosted.settle",
                          "material._font_consumers", "material._provider_consumers", "lifecycle.shell_native_inputs"):
            self.assertNotIn(forbidden, calls)
        imports = {node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Name) and node.func.id == "local"
                   and node.args and isinstance(node.args[0], ast.Constant)}
        self.assertNotIn("prepare_hosted_ubuntu_data", imports)
        network_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                         and isinstance(node.func, ast.Attribute) and node.func.attr == "_network_configuration_data"]
        self.assertEqual(len(network_calls), 2)
        self.assertEqual({ast.unparse(node.args[2]) for node in network_calls}, {"deadline", "reader.deadline"})
        self.assertIn("reader.write", calls)
        self.assertNotIn("publisher.D.write", calls)
        data = (SOURCE / "desktop/tools" / P.PROVIDER_FILE).read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), P.PROVIDER_SHA256)
        control = json.loads(data)
        self.assertEqual((len(control["osLibraries"]), len(control["toolObjects"])), (53, 88))
        self.assertIsNone(json.loads((SOURCE / "desktop/tools/android_material_data/policy.json").read_bytes())["hostPolicy"])

    def test_workflow_batches_sdk_data_and_preserves_five_lifecycle_pins(self):
        workflow = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        lifecycle_sha = hashlib.sha256((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()).hexdigest()
        self.assertEqual(workflow.count("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '" + lifecycle_sha + "'"), 5)
        self.assertEqual(workflow.count("desktop/tools/observe_android_host_profile.py </dev/null"), 1)
        self.assertEqual(workflow.count("desktop/tools/android_hosted_data.py observe-sdk"), 1)
        self.assertNotIn("desktop/tools/observe_hosted_android.py </dev/null", workflow)
        steps = workflow.split("      - name: ")[1:]
        observe = next(s for s in steps if s.startswith("Observe only fixed Android host-profile DATA\n"))
        self.assertIn("ulimit -v 524288; ulimit -t 130; ulimit -n 64; ulimit -c 0; ulimit -f 2048", observe)
        self.assertIn("--signal=TERM --kill-after=2s 133s", observe)
        for s in steps:
            if "android_hosted_data.py prepare" in s or "installed-shell-compile" in s or "Select the fixed frontend compiler\n" in s:
                condition = next(line.strip() for line in s.splitlines() if line.strip().startswith("if:"))
                self.assertIn("steps.route.outputs.native == 'true'", condition)
                self.assertNotIn(P.BASE.METADATA_REF, condition)


if __name__ == "__main__":
    unittest.main()
