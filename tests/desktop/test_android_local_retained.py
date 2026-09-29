"""Inert local-route regressions; no SDK read, native command or publication.

The synthetic 12,375-row mapping proves the complete fixed roster and its only
permitted duplicate without copying a single tool or importing a build system.
Native loader, real files, build/sign/cancel and installed UI evidence are separate.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib.util
from pathlib import Path
import stat
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location("inert_local_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


M = module("android_material_preparation")
R = module("android_local_retained")
L = module("ubuntu_publication_lifecycle")


def context():
    return {"kind": R.SCOPE, "sourceCommit": "1" * 40, "sourceTree": "2" * 40, "taskId": "inert-retained",
            "preparation": {"path": "/inert/owner/local-preparation.json", "size": 1, "sha256": "a" * 64}}


def bootstrap_fixture():
    return SimpleNamespace(_ROOT=None, _END=0.0, _FAILED=False, _OWNER=None, _D=None,
        absolute=Path, directory=Mock(), check_source_pins=Mock(), CORE_PINS={}, DATA_PIN=(1, "a" * 64),
        _android_source_pins=Mock(return_value={}), copy_pinned=Mock(), _android_point=Mock(),
        _modules=Mock(), _android_material_engine=Mock())


def preparation_fixture():
    owner = Mock()
    check = SimpleNamespace(failed=False, root=Path("/inert/owner"), end=100.0, owner=owner)
    prepared = {"materials": {"inert": 1}, "publication": {"inert": 2}}
    engine = SimpleNamespace(android_retained_host_inputs=Mock(return_value={"inertHost": True}),
                             prepare_retained=Mock(return_value=prepared))
    lifecycle = SimpleNamespace(_ROOT=check.root, _END=check.end, _FAILED=False,
        _OWNER=SimpleNamespace(run_owned=owner), _android_point=Mock(), check_source_pins=Mock(),
        _android_material_engine=Mock(return_value=engine), bind_shell_android_profile=Mock())
    return check, prepared, engine, lifecycle


def layout():
    names = [R.AAPT2_SOURCE, *("gradle/repository/inert-%05d.jar" % index for index in range(12366))]
    previous = [{"path": name, "size": 1, "sha256": "a" * 64,
                 "finalMode": 0o555 if name == R.AAPT2_SOURCE else 0o444} for name in names]
    generated = {name: {"size": 1, "sha256": "b" * 64} for name in M.GENERATED}
    previous.extend({"path": name, "finalMode": 0o444, **pin} for name, pin in generated.items())
    current = [{"path": row["path"], "size": row["size"], "sha256": row["sha256"], "mode": row["finalMode"]}
               for row in previous if row["path"] not in M.GENERATED]
    current.append({"path": R.AAPT2_DESTINATION, "size": 1, "sha256": "a" * 64, "mode": 0o555})
    current.extend({"path": name, "size": 1, "sha256": "c" * 64, "mode": 0o444} for name in R.ABI_PATHS)
    return current, previous, generated


def sdk_fixture():
    definition = {"id": "android-sdk-license", "normalizedSha1": M.LICENSE_HASH,
                  "normalizedSha256": M.LICENSE_NORMALIZED_SHA256}
    bodies = {R.SDK_RECEIPT: b"\n" + M.LICENSE_HASH.encode("ascii")}
    for name, paths in R.SDK_PACKAGES.items():
        platform = name == "platforms;android-35"
        details = ('<type-details xsi:type="sdk:platformDetailsType"><api-level>35</api-level>'
            '<extension-level>13</extension-level><base-extension>true</base-extension><layoutlib api="15"/></type-details>'
            if platform else '<type-details xsi:type="generic:genericDetailsType"/>')
        bodies[paths["metadataPath"]] = (f'<common:repository xmlns:common="{M.COMMON_NAMESPACE}" '
            f'xmlns:sdk="{M.SDK_NAMESPACE}" xmlns:generic="{M.GENERIC_NAMESPACE}" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<license id="android-sdk-license">Inert definition only; not terms or consent.</license>'
            f'<localPackage path="{name}">{details}<revision><major>{2 if platform else 35}</major></revision>'
            f'<display-name>Android SDK {"Platform 35" if platform else "Build-Tools 35"}</display-name>'
            '<uses-license ref="android-sdk-license"/></localPackage></common:repository>').encode()
        bodies[paths["propertiesPath"]] = "".join(f"{key}={value}\n" for key, value in M.SDK_PROPERTIES[name].items()).encode()
    host = {"graph": {}, "bindings": {"files": {name: {"fixture": name} for name in bodies}}}
    sdk_pins = {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in bodies.items()}
    value = {"_retained": {"sdkPins": sdk_pins, "runtime": {"host": {
        "inputs": {"files": sorted(bodies), "directories": {}, "absences": []},
        "generated": {"sdkLicense": {"path": R.SDK_RECEIPT, "classification": R.SDK_CLASSIFICATION,
            "licenseDefinition": definition, "packages": [{"id": name, **paths} for name, paths in R.SDK_PACKAGES.items()]}}}}}}
    calls = []

    @contextmanager
    def reader(binding, selected, limit, deadline):
        calls.append(selected)
        if binding != host["bindings"]["files"][selected] or len(bodies[selected]) > limit:
            raise AssertionError("Inert SDK reader role mismatch")
        raw = bodies[selected]
        yield raw, {"binding": binding, "identity": ["inert-only"],
                    "file": {"path": selected, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": 0o644}}

    return value, host, bodies, reader, calls, definition


class LocalRetainedContractTests(unittest.TestCase):
    def test_local_context_never_invents_hosted_identifiers(self):
        self.assertEqual(R.local_instance(M, context()), "local-inert-retained-" + "2" * 12)
        for mutation in ({"runId": "123"}, {"job": "compile"}, {"kind": M.SCOPE}, {"taskId": "../another"}):
            with self.subTest(mutation=mutation), self.assertRaises(M.D.Refused):
                R.local_instance(M, {**context(), **mutation})

    def test_context_original_cannot_renew_deadlines_or_change_owner_directory_modes(self):
        selected = context()
        original = {"schemaVersion": 1, **{key: selected[key] for key in R.LOCAL_CONTEXT_FIELDS - {"preparation"}},
            "source": "/inert/source", "ownerRoot": "/inert/owner", "started": "1.0", "deadline": "3001.0",
            "finalityDeadline": "3011.0", "workBudgetSeconds": 3000, "finalityBudgetSeconds": 3010,
            "readerUid": 0, "readerGid": 0, "consumerUid": 1001, "consumerGid": 1001,
            "rootIdentity": [1, 2, stat.S_IFDIR | 0o700, 0, 0],
            "workIdentity": [1, 3, stat.S_IFDIR | 0o700, 0, 0]}
        identities = {Path("/inert/owner"): original["rootIdentity"],
                      Path("/inert/owner/work"): original["workIdentity"]}
        for case in ("valid", "renewed-work", "renewed-finality", "changed-work-mode"):
            record, endpoint = deepcopy(original), 3001.0
            if case == "renewed-work": endpoint += 1
            elif case == "renewed-finality": record["finalityDeadline"] = "3012.0"
            elif case == "changed-work-mode": record["workIdentity"][2] = stat.S_IFDIR | 0o755

            @contextmanager
            def reader(*args, **kwargs):
                yield M.D.canonical(record), ["inert-context-original"]

            with self.subTest(case=case), patch.object(R, "original_bytes", side_effect=reader), \
                 patch.object(M, "_directory_identity", side_effect=lambda path: identities[path]), \
                 patch.object(Path, "exists", return_value=True):
                if case == "valid":
                    observed, _ = R.context_original(M, selected, endpoint)
                    self.assertEqual(observed, original)
                else:
                    with self.assertRaises(M.D.Refused):
                        R.context_original(M, selected, endpoint)

    def test_unadmitted_local_profile_latches_before_commands_or_material_creation(self):
        check = SimpleNamespace(failed=False, end=time.monotonic() + 1, root=Path("/inert/owner"))
        local = SimpleNamespace(prepare=lambda *args, **kwargs: R.prepare(*args, **kwargs))
        with patch.object(R, "source_policy", return_value={"runtime": None}), \
             patch.object(M, "_retained_module", return_value=local), \
             patch.object(M, "_download") as download, patch.object(M, "_archive") as decoder, \
             patch.object(M, "_font_consumers") as font, patch.object(M, "_provider_consumers") as provider, \
             patch.object(Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(M.D.Refused, "runtime closure is not yet admitted"):
                M.prepare_retained(check, Path("/inert/source"), check.root / "work/android-retained", context=context(), host={})
            self.assertTrue(check.failed)
            for operation in (download, decoder, font, provider, mkdir):
                operation.assert_not_called()

    def test_hosted_failure_never_calls_local_api(self):
        check = SimpleNamespace(failed=False)
        with patch.object(M, "_prepare", side_effect=M.D.Refused("inert hosted refusal")), \
             patch.object(M, "_retained_module") as local:
            with self.assertRaisesRegex(M.D.Refused, "hosted refusal"):
                M.prepare(check, Path("/inert/source"), Path("/inert/material"), context={}, host={})
            local.assert_not_called()
            self.assertTrue(check.failed)

    def test_sdk_route_reads_only_five_local_originals_and_never_claims_consent(self):
        value, host, _, reader, calls, definition = sdk_fixture()
        with patch.object(M, "_stock_host_original", side_effect=reader), \
             patch.object(M, "_protected_binding"), patch.object(M, "_sdk_license_definition", return_value=definition):
            result = R.sdk_state(M, value, host, time.monotonic() + 1)
        self.assertEqual(set(calls), set(value["_retained"]["sdkPins"]))
        self.assertEqual(len(calls), 5)
        self.assertEqual(result["classification"], R.SDK_CLASSIFICATION)
        self.assertIs(result["producerExecutionProven"], False)
        self.assertIs(result["newConsent"], False)
        self.assertNotIn("image", result)
        self.assertNotIn("sourceRecipe", result)

    def test_sdk_changed_body_is_not_rescued_by_a_matching_current_parser_result(self):
        value, host, bodies, reader, _, definition = sdk_fixture()
        bodies[R.SDK_RECEIPT] = b"\n" + b"0" * 40
        with patch.object(M, "_stock_host_original", side_effect=reader), \
             patch.object(M, "_protected_binding"), patch.object(M, "_sdk_license_definition", return_value=definition):
            with self.assertRaisesRegex(M.D.Refused, "differs from SOURCE"):
                R.sdk_state(M, value, host, time.monotonic() + 1)

    def test_complete_mapping_reuses_retained_stage_and_only_derives_three_abi5_leaves(self):
        current, previous, generated = layout()
        files, mappings = R.material_rows(M, current, previous, generated=generated)
        self.assertEqual(len(files), 12375)
        self.assertEqual([r["path"] for r in mappings if r["root"] == "derived"], sorted(R.ABI_PATHS))
        aapt = [r for r in mappings if r["source"] == R.AAPT2_SOURCE]
        self.assertEqual([r["path"] for r in aapt], [R.AAPT2_SOURCE, R.AAPT2_DESTINATION])
        self.assertEqual({r["root"] for r in aapt}, {"retained"})
        for name in M.GENERATED:
            self.assertEqual(next(r for r in mappings if r["path"] == name), {"path": name, "root": "retained", "source": name})

    def test_incomplete_or_changed_material_union_refuses(self):
        current, previous, generated = layout()
        for case in ("missing", "duplicate", "bytes", "mode", "generated"):
            rows, old, pins = deepcopy(current), deepcopy(previous), deepcopy(generated)
            if case == "missing": rows.pop()
            elif case == "duplicate": rows[-1] = deepcopy(rows[0])
            elif case == "bytes": old[0]["sha256"] = "9" * 64
            elif case == "mode": old[0]["finalMode"] = 0o444
            else: pins[M.GENERATED[0]]["sha256"] = "9" * 64
            with self.subTest(case=case), self.assertRaises(M.D.Refused):
                R.material_rows(M, rows, old, generated=pins)

    def test_provider_reader_compares_material_projection_not_archive_provenance_schema(self):
        name = R.AAPT2_SOURCE
        spec = {"path": name, "size": 1, "sha256": "a" * 64, "mode": 0o555}
        sources = {"roots": {"retained": {"path": "/inert/retained/tools", "owner": [0, 0]}},
                   "files": [{"path": name, "root": "retained", "source": name}]}
        identity = [1, 2, stat.S_IFREG | 0o500, 0, 0, 1, 1, 3, 3]
        reader, inventory = R.material_reader(M, sources, [spec], {name: identity}, {},
                                              {"retained": {}}, time.monotonic() + 1)
        provider = {**spec, "source": {"kind": "archive", "id": "body-010", "member": "aapt2"},
                    "sourceMode": 0o755}
        with patch.object(R, "_read_material", return_value=(b"x", identity)) as consume:
            self.assertEqual(reader(name, provider), (b"x", identity))
            for changed in ({**provider, "size": True}, {**provider, "mode": 0o444},
                            {**provider, "sha256": "b" * 64}):
                with self.assertRaisesRegex(M.D.Refused, "unselected source"):
                    reader(name, changed)
            self.assertEqual(consume.call_count, 1)
        self.assertEqual(inventory["files"], [{"path": name, "identity": identity}])

    def test_preparation_uses_the_callers_existing_owner_and_protected_source_loader(self):
        compiler = module("ci_ubuntu_publication")
        check, prepared, engine, lifecycle = preparation_fixture()
        with patch.object(compiler, "local") as fresh_module:
            result = compiler.android_prepare_retained_inputs(check, Path("/inert/source"), context=context(),
                native={}, bindings={}, bind_path=Mock(), lifecycle=lifecycle)
            fresh_module.assert_not_called()
        self.assertEqual(result, (prepared, {"inertHost": True}))
        lifecycle._android_material_engine.assert_called_once_with(check.root, retained=True)
        lifecycle.bind_shell_android_profile.assert_called_once_with(prepared["materials"], prepared["publication"])
        lifecycle._ROOT = Path("/inert/different-owner")
        with self.assertRaisesRegex(compiler.D.Refused, "existing admitted root owner"):
            compiler.android_prepare_retained_inputs(check, Path("/inert/source"), context=context(),
                native={}, bindings={}, bind_path=Mock(), lifecycle=lifecycle)
        self.assertTrue(check.failed)
        self.assertTrue(lifecycle._FAILED)
        self.assertEqual(engine.prepare_retained.call_count, 1)

    def test_preparation_refuses_another_command_owner_even_with_matching_root_and_endpoint(self):
        compiler = module("ci_ubuntu_publication")
        check, _, engine, lifecycle = preparation_fixture()
        check.owner = Mock()
        with self.assertRaisesRegex(compiler.D.Refused, "existing admitted root owner"):
            compiler.android_prepare_retained_inputs(check, Path("/inert/source"), context=context(),
                native={}, bindings={}, bind_path=Mock(), lifecycle=lifecycle)
        self.assertTrue(check.failed)
        self.assertTrue(lifecycle._FAILED)
        engine.prepare_retained.assert_not_called()
        lifecycle.bind_shell_android_profile.assert_not_called()

    def test_preparation_binding_error_or_late_return_latches_both_originals_without_retry(self):
        compiler = module("ci_ubuntu_publication")
        for case in ("bind", "late"):
            with self.subTest(case=case):
                check, _, engine, lifecycle = preparation_fixture()
                if case == "bind":
                    lifecycle.bind_shell_android_profile.side_effect = OSError("inert binding failure")
                    expected = OSError
                else:
                    lifecycle._android_point.side_effect = [None, compiler.D.Refused("inert late final bind")]
                    expected = compiler.D.Refused
                with self.assertRaises(expected):
                    compiler.android_prepare_retained_inputs(check, Path("/inert/source"), context=context(),
                        native={}, bindings={}, bind_path=Mock(), lifecycle=lifecycle)
                self.assertTrue(check.failed)
                self.assertTrue(lifecycle._FAILED)
                with self.assertRaisesRegex(compiler.D.Refused, "failure is latched"):
                    compiler.android_prepare_retained_inputs(check, Path("/inert/source"), context=context(),
                        native={}, bindings={}, bind_path=Mock(), lifecycle=lifecycle)
                self.assertEqual(engine.prepare_retained.call_count, 1)
                self.assertEqual(lifecycle.bind_shell_android_profile.call_count, 1)

    def test_bootstrap_missing_profile_or_existing_owner_refuses_before_creation(self):
        compiler = module("ci_ubuntu_publication")
        for case in ("missing-profile", "existing-owner", "existing-data"):
            with self.subTest(case=case):
                lifecycle = bootstrap_fixture()
                if case == "existing-owner": lifecycle._OWNER = object()
                if case == "existing-data": lifecycle._D = object()
                with patch.object(compiler, "_ANDROID_RETAINED_START_ATTEMPTED", False), \
                     patch.object(compiler.os, "getresuid", return_value=(0, 0, 0)), \
                     patch.object(compiler.os, "getresgid", return_value=(0, 0, 0)), \
                     patch.object(compiler.os, "getgroups", return_value=[0]), \
                     patch.object(compiler.D, "read", return_value=b'{"runtime":null}'), \
                     patch.object(Path, "mkdir") as mkdir, patch.object(compiler, "Check") as check:
                    with self.assertRaises(compiler.D.Refused):
                        compiler.android_begin_retained_inputs(Path("/inert/source"),
                            Path("/var/lib/mrk-android-retained-inert"), lifecycle=lifecycle,
                            source_commit="1" * 40, source_tree="2" * 40, task_id="inert",
                            consumer_uid=1001, consumer_gid=1001)
                    self.assertTrue(lifecycle._FAILED)
                    self.assertIsNone(lifecycle._ROOT)
                    mkdir.assert_not_called()
                    check.assert_not_called()
                    lifecycle._modules.assert_not_called()

    def test_bootstrap_collision_never_becomes_owned_cleanup_root_or_allows_restart(self):
        compiler = module("ci_ubuntu_publication")
        lifecycle = bootstrap_fixture()
        with patch.object(compiler, "_ANDROID_RETAINED_START_ATTEMPTED", False), \
             patch.object(compiler.os, "getresuid", return_value=(0, 0, 0)), \
             patch.object(compiler.os, "getresgid", return_value=(0, 0, 0)), \
             patch.object(compiler.os, "getgroups", return_value=[0]), \
             patch.object(compiler.D, "read", return_value=b'{"runtime":{}}'), \
             patch.object(Path, "mkdir", side_effect=FileExistsError("inert collision")) as mkdir, \
             patch.object(compiler, "Check") as check:
            args = (Path("/inert/source"), Path("/var/lib/mrk-android-retained-inert"))
            kwargs = dict(lifecycle=lifecycle, source_commit="1" * 40, source_tree="2" * 40,
                          task_id="inert", consumer_uid=1001, consumer_gid=1001)
            with self.assertRaises(FileExistsError):
                compiler.android_begin_retained_inputs(*args, **kwargs)
            self.assertTrue(lifecycle._FAILED)
            self.assertIsNone(lifecycle._ROOT)
            with self.assertRaisesRegex(compiler.D.Refused, "cannot be replaced or restarted"):
                compiler.android_begin_retained_inputs(*args, **kwargs)
            self.assertEqual(mkdir.call_count, 1)
            check.assert_not_called()
            lifecycle.copy_pinned.assert_not_called()

    def test_publication_source_map_rejects_roots_aliases_and_escape(self):
        current, previous, generated = layout()
        files, mappings = R.material_rows(M, current, previous, generated=generated)
        sources = {"schemaVersion": 2, "route": R.SCOPE, "roots": {
            "retained": {"path": "/inert/retained/tools", "owner": [0, 0]},
            "derived": {"path": "/inert/owner/work/android-retained/tools", "owner": [0, 0]}}, "files": mappings}
        self.assertEqual(L._android_retained_source_rows(sources, files), sources["roots"])
        for case in ("version", "route", "owner", "root-overlap", "traversal", "rename", "missing"):
            bad = deepcopy(sources)
            if case == "version": bad["schemaVersion"] = True
            elif case == "route": bad["route"] = "android-same-job-local-v1"
            elif case == "owner": bad["roots"]["retained"]["owner"] = [False, False]
            elif case == "root-overlap": bad["roots"]["derived"]["path"] = bad["roots"]["retained"]["path"] + "/child"
            elif case == "traversal": bad["files"][0]["source"] = "gradle/../another"
            elif case == "rename": bad["files"][2]["source"] = bad["files"][1]["source"]
            else: bad["files"].pop()
            with self.subTest(case=case), self.assertRaises(L.Refused):
                L._android_retained_source_rows(bad, files)

    def test_failed_publication_latches_both_existing_owner_and_publisher(self):
        check = SimpleNamespace(failed=False)
        with patch.object(L, "_ANDROID_RETAINED_ADMISSION", None), patch.object(L, "_FAILED", False), \
             patch.object(L, "_android_retained_admission", return_value=({}, {})), \
             patch.object(L, "_publish_android", side_effect=OSError("inert consuming close")):
            with self.assertRaises(OSError):
                L.publish_retained_android(check, {"inert": True})
            self.assertTrue(check.failed)
            self.assertTrue(L._FAILED)

    def test_failed_native_consumer_cannot_cross_final_publication_gate(self):
        check = SimpleNamespace(failed=True)
        with patch.object(L, "_ANDROID_RETAINED_ADMISSION", ({}, {}, {})), patch.object(L, "_FAILED", False), \
             patch.object(L, "_android_retained_admission") as admission, patch.object(L, "_finish_android_publication") as finish:
            with self.assertRaisesRegex(L.Refused, "consumers did not settle"):
                L.finish_retained_android(check, {})
            admission.assert_not_called()
            finish.assert_not_called()
            self.assertTrue(L._FAILED)

    def test_missing_local_source_selector_cannot_use_hosted_source_pins(self):
        with patch.object(L, "ANDROID_PREPARATION_PINS", {"inert": (1, "a" * 64)}), \
             patch.object(L, "ANDROID_RETAINED_PREPARATION_PINS", None):
            with self.assertRaisesRegex(L.Refused, "source pins are pending"):
                L._android_source_pins(retained=True)

    def test_capacity_charges_both_filesystems_before_consuming_ram_original(self):
        value = {"_retained": {"runtime": {"consumerScratchBytes": 256 << 20,
                    "minimumAvailableRamBytes": 1536 << 20}, "abiBodies": {"body-146": {"size": 1}}}}
        files, indexes = [{"path": "jdk/lib/inert", "size": 1}], [{"decodedBytes": 1}]
        available = SimpleNamespace(f_bavail=1 << 20, f_frsize=4096, f_favail=1 << 20)
        exhausted = SimpleNamespace(f_bavail=0, f_frsize=4096, f_favail=1 << 20)
        with patch.object(R.os, "statvfs", side_effect=[available, exhausted]) as capacity, \
             patch.object(R.os, "open") as read_ram:
            with self.assertRaisesRegex(M.D.Refused, "simultaneous publication/consumer capacity"):
                R.capacity(M, value, Path("/inert/private-parent"), files, indexes, time.monotonic() + 1)
            self.assertEqual([call.args[0] for call in capacity.call_args_list],
                             [Path("/inert/private-parent"), Path("/opt")])
            read_ram.assert_not_called()

    def test_capacity_ram_close_error_stays_failed_and_keeps_named_post(self):
        value = {"_retained": {"runtime": {"consumerScratchBytes": 256 << 20,
                    "minimumAvailableRamBytes": 1536 << 20}, "abiBodies": {"body-146": {"size": 1}}}}
        files, indexes = [{"path": "jdk/lib/inert", "size": 1}], [{"decodedBytes": 1}]
        available = SimpleNamespace(f_bavail=1 << 20, f_frsize=4096, f_favail=1 << 20)
        identity = [1, 2, stat.S_IFREG | 0o444, 0, 0, 1, 0, 3, 3]
        resource = SimpleNamespace(getrlimit=Mock(return_value=(65536, 65536)), RLIMIT_NOFILE=7, RLIM_INFINITY=-1)
        with patch.dict("sys.modules", {"resource": resource}), \
             patch.object(R.os, "statvfs", return_value=available), \
             patch.object(Path, "lstat") as named, patch.object(M, "_identity", return_value=identity), \
             patch.object(R.os, "open", return_value=41), patch.object(R.os, "fstat"), \
             patch.object(R.os, "read", side_effect=[b"MemAvailable: 3000000 kB\n", b""]), \
             patch.object(R.os, "close", side_effect=OSError("inert RAM consuming close")) as close:
            with self.assertRaisesRegex(OSError, "RAM consuming close"):
                R.capacity(M, value, Path("/inert/private-parent"), files, indexes, time.monotonic() + 1)
            close.assert_called_once_with(41)
            self.assertEqual(named.call_count, 2)  # Original plus post-close named binding.

    def test_capacity_keeps_the_existing_descriptor_floor_before_ram_or_publication(self):
        value = {"_retained": {"runtime": {"consumerScratchBytes": 256 << 20,
                    "minimumAvailableRamBytes": 1536 << 20}, "abiBodies": {"body-146": {"size": 1}}}}
        resource = SimpleNamespace(getrlimit=Mock(return_value=(1024, 65536)), RLIMIT_NOFILE=7, RLIM_INFINITY=-1)
        available = SimpleNamespace(f_bavail=1 << 20, f_frsize=4096, f_favail=1 << 20)
        with patch.dict("sys.modules", {"resource": resource}), \
             patch.object(R.os, "statvfs", return_value=available), patch.object(R.os, "open") as read_ram:
            with self.assertRaisesRegex(M.D.Refused, "descriptor admission floor"):
                R.capacity(M, value, Path("/inert/private-parent"), [{"path": "jdk/lib/inert", "size": 1}],
                           [{"decodedBytes": 1}], time.monotonic() + 1)
            read_ram.assert_not_called()

    def test_material_reader_keeps_post_on_original_consuming_close_error(self):
        pin = {"path": "/inert/evidence/source.json", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest(), "mode": 0o400}
        identity = [1, 2, stat.S_IFREG | 0o400, 0, 0, 1, 1, 3, 3]

        @contextmanager
        def fail_close(*args):
            yield b"x"
            raise OSError("inert original close failure")

        with patch.object(M, "_private", return_value=identity) as private, \
             patch.object(M, "_directory_identity", return_value=[1, 1, stat.S_IFDIR | 0o700, 0, 0]), \
             patch.object(M.os, "listxattr", return_value=[]), \
             patch.object(M, "_stock_original_bytes", side_effect=fail_close):
            with self.assertRaisesRegex(OSError, "original close failure"):
                with R.original_bytes(M, pin, time.monotonic() + 1) as (raw, observed):
                    self.assertEqual(raw, b"x")
                    self.assertEqual(observed, identity)
            self.assertGreaterEqual(private.call_count, 2)  # Initial binding plus all-outcome named POST.

    def test_expired_work_stays_failed_but_original_named_post_uses_only_finality_reserve(self):
        pin = {"path": "/inert/evidence/source.json", "size": 1, "sha256": hashlib.sha256(b"x").hexdigest(), "mode": 0o400}
        identity = [1, 2, stat.S_IFREG | 0o400, 0, 0, 1, 1, 3, 3]
        observed = []

        def point(deadline):
            observed.append(deadline)
            if deadline <= 100.0:
                raise M.D.Refused("inert work endpoint expired")

        @contextmanager
        def expired(*args):
            point(100.0)
            yield b"x"

        with patch.object(M, "_private", return_value=identity) as private, \
             patch.object(M, "_directory_identity", return_value=[1, 1, stat.S_IFDIR | 0o700, 0, 0]), \
             patch.object(M.os, "listxattr", return_value=[]), patch.object(M, "_point", side_effect=point), \
             patch.object(M, "_stock_original_bytes", side_effect=expired):
            with self.assertRaisesRegex(M.D.Refused, "work endpoint expired"):
                with R.original_bytes(M, pin, 100.0):
                    self.fail("Expired work must never grant a consumer")
            self.assertEqual(observed, [100.0, 110.0])
            self.assertGreaterEqual(private.call_count, 2)

    def test_successful_named_post_cannot_convert_late_work_into_success(self):
        pin = {"path": "/inert/evidence/source.json", "size": 1,
               "sha256": hashlib.sha256(b"x").hexdigest(), "mode": 0o400}
        identity = [1, 2, stat.S_IFREG | 0o400, 0, 0, 1, 1, 3, 3]
        endpoints = []

        def point(deadline):
            endpoints.append(deadline)
            if deadline == 100.0:
                raise M.D.Refused("inert final work endpoint expired")

        @contextmanager
        def original(*args):
            yield b"x"

        with patch.object(M, "_private", return_value=identity), \
             patch.object(M, "_directory_identity", return_value=[1, 1, stat.S_IFDIR | 0o700, 0, 0]), \
             patch.object(M.os, "listxattr", return_value=[]), patch.object(M, "_point", side_effect=point), \
             patch.object(M, "_stock_original_bytes", side_effect=original):
            with self.assertRaisesRegex(M.D.Refused, "final work endpoint expired"):
                with R.original_bytes(M, pin, 100.0) as (raw, _):
                    self.assertEqual(raw, b"x")
            self.assertEqual(endpoints, [110.0, 100.0])


if __name__ == "__main__":
    unittest.main()
