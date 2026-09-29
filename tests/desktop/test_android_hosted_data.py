"""Focused hosted DATA contracts; no native tool, root service, SDK or network.

Only the one reader test creates ordinary bytes in its own temporary directory.
All configuration/StopPost effects below are mocked; they are not native proof.
"""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SOURCE = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location("test_hosted_" + name,
        SOURCE / "desktop/tools" / (name + ".py"))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


H = module("android_hosted_data")
M = module("android_material_preparation")
L = module("ubuntu_publication_lifecycle")


def fixture():
    inputs = {H.SOURCE_SDK + "/" + name: {"size": 1, "sha256": "a" * 64} for name in H.SOURCE_INPUTS}
    files = sorted([H.IMAGE, str(H.MANIFEST), *(str(H.SDK_ROOT / name) for name in H.SOURCE_INPUTS),
                    *H.CONFIGURATION])
    value = {"hostPolicy": {"inputs": {"files": files, "directories": deepcopy(H.DIRECTORIES), "absences": []},
        "generated": {"sdkLicense": {
            "path": str(H.SDK_ROOT / "licenses/android-sdk-license"), "classification": H.ORIGIN,
            "imagePath": H.IMAGE, "sourceRecipe": deepcopy(M.SDK_SOURCE_RECIPE),
            "licenseDefinition": {"id": "android-sdk-license", "normalizedSha1": M.LICENSE_HASH,
                                  "normalizedSha256": M.LICENSE_NORMALIZED_SHA256},
            "packages": [{"id": name, "metadataPath": str(H.SDK_ROOT / name.replace(";", "/") / "package.xml"),
                "propertiesPath": str(H.SDK_ROOT / name.replace(";", "/") / "source.properties")}
                for name in M.SDK_PACKAGE_PATHS],
            "provisioning": {"schemaVersion": 1, "root": str(H.ROOT), "manifestPath": str(H.MANIFEST),
                "image": deepcopy(M.SDK_IMAGE), "sourceInputs": inputs,
                "configuration": {name: H.pin(raw) for name, raw in H.CONFIGURATION.items()}}}}}}
    return value


def context():
    return {"sourceCommit": "b" * 40, "runId": "17", "runAttempt": "1", "job": "compile"}


def full9(ino=17):
    return [9, ino, stat.S_IFREG | 0o444, 0, 0, 1, 1, 2**60 + 13, 2**60 + 23]


def stat_row(values):
    return SimpleNamespace(**dict(zip(("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
        "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"), values)))


class HostedAndroidDataContracts(unittest.TestCase):
    def test_import_is_resource_free(self):
        with patch.object(H.os, "open", side_effect=AssertionError("no DATA opened at import")), \
             patch.object(H.os, "mkdir", side_effect=AssertionError("no output at import")), \
             patch.object(H.os, "rename", side_effect=AssertionError("no namespace effect at import")):
            module("android_hosted_data")

    def test_missing_exact_policy_refuses_before_source_read_or_output(self):
        api = M._hosted_api()
        for value in ({}, {"hostPolicy": None}, {"hostPolicy": {"generated": {}}}):
            with self.subTest(value=value), \
                 patch.object(H, "_sdk_originals", side_effect=AssertionError("no read without independent pins")) as read, \
                 patch.object(H, "_mkdir", side_effect=AssertionError("no creation without independent pins")) as create:
                with self.assertRaises(H.Refused):
                    H.prepare(api, value, context(), 1.0, {"device": 9})
                read.assert_not_called()
                create.assert_not_called()

    def test_rule_requires_all_five_exact_source_pins_image_and_new_origin(self):
        value = fixture()
        self.assertEqual(H.rule(M._hosted_api(), value), value["hostPolicy"]["generated"]["sdkLicense"])
        def omitted(item):
            item["hostPolicy"]["generated"]["sdkLicense"]["provisioning"]["sourceInputs"].pop(next(iter(
                item["hostPolicy"]["generated"]["sdkLicense"]["provisioning"]["sourceInputs"])))
        def learned(item):
            item["hostPolicy"]["generated"]["sdkLicense"]["provisioning"]["sourceInputs"] = None
        def image(item):
            item["hostPolicy"]["generated"]["sdkLicense"]["provisioning"]["image"]["image_version"] = "different"
        def origin(item):
            item["hostPolicy"]["generated"]["sdkLicense"]["classification"] = M.SDK_RECEIPT_CLASSIFICATION
        def alias(item):
            item["hostPolicy"]["inputs"]["files"].append(next(iter(item["hostPolicy"]["generated"]["sdkLicense"]["provisioning"]["sourceInputs"])))
            item["hostPolicy"]["inputs"]["files"].sort()
        for change in (omitted, learned, image, origin, alias):
            changed = deepcopy(value)
            change(changed)
            with self.subTest(change=change.__name__), self.assertRaises(H.Refused):
                H.rule(M._hosted_api(), changed)
        changed = deepcopy(value)
        next(iter(changed["hostPolicy"]["generated"]["sdkLicense"]["provisioning"]["sourceInputs"].values()))["size"] = True
        with self.assertRaises(H.Refused):
            H.rule(M._hosted_api(), changed)

    def test_source_context_cannot_be_relabelled_from_another_attempt(self):
        value, original = fixture(), context()
        proof = {"classification": H.ORIGIN, "provisioning": {"context": original}}
        host = {"graph": {"androidGenerated": {"sdkLicense": proof}}}
        H.context_correspondence(value, host, {**original, "sourceTree": "c" * 40})
        for name, wrong in (("sourceCommit", "d" * 40), ("runId", "18"), ("runAttempt", "2"), ("job", "elsewhere")):
            with self.subTest(field=name), self.assertRaises(H.Refused):
                H.context_correspondence(value, host, {**original, name: wrong})
        proof["classification"] = M.SDK_RECEIPT_CLASSIFICATION
        with self.assertRaises(H.Refused):
            H.context_correspondence(value, host, original)

    def test_snapshot_receipt_does_not_enter_preinstalled_or_retained_route(self):
        helper = SimpleNamespace(receipt_state=Mock(return_value={"classification": H.ORIGIN}),
                                 SDK_ROOT=H.SDK_ROOT)
        with patch.object(M, "_hosted_module", return_value=helper), \
             patch.object(M, "_sdk_receipt_rule", side_effect=AssertionError("no old origin")), \
             patch.object(M, "_retained_module", side_effect=AssertionError("no retained fallback")):
            result = M._sdk_receipt_state(fixture(), {}, time.monotonic() + 5)
            self.assertEqual(result["classification"], H.ORIGIN)
            self.assertEqual(M._sdk_receipt_path(result), str(H.SDK_ROOT / "licenses/android-sdk-license"))
            self.assertEqual(M._sdk_receipt_path({"classification": M.SDK_RECEIPT_CLASSIFICATION}), M.SDK_RECEIPT)
            self.assertEqual(M._sdk_receipt_path({"classification": "local-retained-sdk-current-use-v1"}),
                             "/opt/android-sdk/licenses/android-sdk-license")
        helper.receipt_state.assert_called_once()

    def test_fixed_configuration_is_complete_and_keeps_only_actual_loopback_choice(self):
        end = time.monotonic() + 5
        resolver = M._network_configuration_data("/etc/resolv.conf", H.CONFIGURATION["/etc/resolv.conf"], end)
        self.assertEqual(resolver["nameservers"], ["127.0.0.53"])
        self.assertEqual(resolver["search"], ["."])
        self.assertEqual(M._network_configuration_data("/etc/host.conf", H.CONFIGURATION["/etc/host.conf"], end),
                         {"multi": True})
        hosts = M._network_configuration_data("/etc/hosts", H.CONFIGURATION["/etc/hosts"], end)
        self.assertEqual([row["address"] for row in hosts["records"]], ["127.0.0.1", "::1"])

    def test_low_trust_reader_keeps_real_identity_and_never_learns_approval(self):
        with tempfile.TemporaryDirectory(prefix="mrk-hosted-data-contract-") as temporary:
            path = Path(temporary) / "input.txt"
            raw = b"synthetic DATA only\n"
            path.write_bytes(raw)
            result, original = H.read_original(path, 128, time.monotonic() + 5,
                                               protected=False, expected=H.pin(raw))
            self.assertEqual(result, raw)
            self.assertEqual(original["classification"], "low-trust-data-original")
            self.assertEqual(original["identity"], H.identity(path.lstat()))
            self.assertTrue(all(type(number) is int for number in original["identity"]))
            with self.assertRaisesRegex(H.Refused, "independent-byte-pin"):
                H.read_original(path, 128, time.monotonic() + 5,
                                protected=False, expected={"size": len(raw), "sha256": "0" * 64})
            alias = path.parent / "alias.txt"
            alias.symlink_to(path.name)
            with self.assertRaises(OSError):
                H.read_original(alias, 128, time.monotonic() + 5, protected=False)

    def test_failed_sole_close_preserves_first_error_and_consumes_each_slot_once(self):
        first = H.Refused("original-failure")
        fds = [73, 74]
        with patch.object(H.os, "close", side_effect=OSError("synthetic-close")) as close:
            with self.assertRaises(H.Refused) as caught:
                H._close_all(fds, first)
        self.assertIs(caught.exception, first)
        self.assertEqual(fds, [])
        self.assertEqual([call.args for call in close.call_args_list], [(74,), (73,)])
        self.assertEqual(first.hosted_data_close_errors, ["OSError", "OSError"])

    def test_nested_and_first_close_failures_retain_all_diagnostics(self):
        first = H.Refused("first-read-failure")
        first.hosted_data_close_errors = ["InterruptedError"]
        for slots, failures, expected in (
            ([81, 82], [OSError("close82"), ValueError("close81")],
             ["InterruptedError", "OSError", "ValueError"]),
            ([83], [RuntimeError("close83")],
             ["InterruptedError", "OSError", "ValueError", "RuntimeError"]),
        ):
            original_slots = list(slots)
            with patch.object(H.os, "close", side_effect=failures) as close:
                with self.assertRaises(H.Refused) as caught:
                    H._close_all(slots, first)
            self.assertIs(caught.exception, first)
            self.assertEqual(first.hosted_data_close_errors, expected)
            self.assertEqual(slots, [])
            self.assertEqual([call.args[0] for call in close.call_args_list], original_slots[::-1])
        slots = [91, 92]
        with patch.object(H.os, "close", side_effect=[OSError("close92"), ValueError("close91")]) as close:
            with self.assertRaisesRegex(H.Refused, "hosted-data-original-close") as caught:
                H._close_all(slots, None)
        self.assertEqual(caught.exception.hosted_data_close_errors, ["OSError", "ValueError"])
        self.assertEqual(slots, [])
        self.assertEqual([call.args[0] for call in close.call_args_list], [92, 91])

    def test_full_nine_identity_keeps_nanoseconds_and_source_owner(self):
        values = full9()
        binding = {"identity": [values[index] for index in (0, 1, 2, 5, 6, 7, 8)]}
        self.assertTrue(H._binding_identity(binding, values))
        wrong = values.copy()
        wrong[8] += 1
        self.assertFalse(H._binding_identity(binding, wrong))
        for index, changed in ((3, 1001), (5, 2), (2, stat.S_IFREG | 0o644), (7, float(values[7]))):
            wrong = values.copy()
            wrong[index] = changed
            with self.subTest(index=index), self.assertRaises(H.Refused):
                H._binding_identity(binding, wrong)

    def test_unknown_target_collision_never_renames_or_overwrites(self):
        row = {"path": "/etc/hosts", "size": 1, "sha256": "a" * 64, "identity": full9()}
        @contextmanager
        def parent(*args):
            yield 72  # No actual descriptor operation is reachable below.
        with patch.object(H, "_same"), patch.object(H, "_parent", parent), \
             patch.object(H.os, "stat", return_value=stat_row(full9())), \
             patch.object(H, "_rename_noreplace", side_effect=AssertionError("collision cannot mutate")) as rename:
            with self.assertRaisesRegex(H.Refused, "namespace-collision"):
                H._rename(row, Path("/var/lib/synthetic-original"), time.monotonic() + 5, 9)
        rename.assert_not_called()

    def test_no_replace_primitive_never_falls_back_after_a_racing_collision(self):
        import ctypes
        import errno
        function = Mock(return_value=-1)
        with patch.object(ctypes, "CDLL", return_value=SimpleNamespace(renameat2=function)), \
             patch.object(ctypes, "get_errno", return_value=errno.EEXIST), \
             patch.object(ctypes, "set_errno") as set_errno, \
             patch.object(H.os, "rename", side_effect=AssertionError("no replacing fallback")) as replace:
            with self.assertRaisesRegex(H.Refused, "namespace-collision"):
                H._rename_noreplace(71, "source", 72, "target", time.monotonic() + 5)
        set_errno.assert_called_once_with(0)
        self.assertEqual(function.call_args.args, (71, b"source", 72, b"target", 1))
        self.assertEqual(function.argtypes,
            (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint))
        self.assertIs(function.restype, ctypes.c_int)
        replace.assert_not_called()
        for code in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
            with self.subTest(errno=code), \
                 patch.object(ctypes, "CDLL", return_value=SimpleNamespace(renameat2=Mock(return_value=-1))), \
                 patch.object(ctypes, "get_errno", return_value=code), \
                 patch.object(ctypes, "set_errno"):
                with self.assertRaisesRegex(H.Refused, "no-replace-unavailable"):
                    H._rename_noreplace(71, "source", 72, "target", time.monotonic() + 5)

    def test_setup_failure_has_bounded_cleanup_without_replacing_the_first_error(self):
        first = H.Refused("setup-original-failure")
        now, work_end, action_end = 50.0, 45.0, 55.0
        result = {"configuration": [], "errors": [], "allOriginalsRestored": False}
        with patch.object(H, "rule", return_value={"provisioning": {"sourceInputs": {}}}), \
             patch.object(H, "_sdk_originals", return_value=({}, {}, {})), \
             patch.object(H, "_configuration_originals", return_value=[]), \
             patch.object(H, "_absent"), patch.object(H, "_kernel", return_value=b"original-mounts"), \
             patch.object(H, "_mkdir", side_effect=first), patch.object(H.time, "monotonic", return_value=now), \
             patch.object(H, "_restore", return_value=result) as restore, \
             patch.object(H, "_fresh", side_effect=OSError("cleanup-record-failure")):
            with self.assertRaises(H.Refused) as caught:
                H.prepare(None, {}, context(), work_end, {"device": 9, "mountInfo": b"original-mounts"},
                          cleanup_end=action_end)
        self.assertIs(caught.exception, first)
        self.assertEqual(restore.call_args.args, ([], action_end, 9))
        self.assertIs(first.hosted_setup_cleanup, result)
        self.assertEqual(first.hosted_setup_cleanup_record_error, "OSError")

    def test_post_prepare_failures_restore_known_pairs_with_the_original_action_end(self):
        rows = [{"original": {"path": name}} for name in H.CONFIGURATION]
        prepared = {"configuration": rows}
        api = SimpleNamespace(policy=Mock(return_value={}))
        host = {"device": 9}
        cleanup_result = {"configuration": [{"restored": True}, {"restored": False}],
                          "errors": [{"errorType": "Refused"}], "allOriginalsRestored": False}
        for stage in ("work-end", "parser-errors", "parser-raises", "action-end", "output"):
            first = BrokenPipeError("synthetic-output") if stage == "output" else H.Refused("synthetic-" + stage)
            def point(end):
                if (stage, end) in (("work-end", 45.0), ("action-end", 55.0)):
                    raise first
            retire_errors = ["OSError"] if stage == "parser-errors" else []
            with self.subTest(stage=stage), \
                 patch.object(H.sys, "argv", ["hosted-data", "prepare"]), \
                 patch.object(H.time, "monotonic", side_effect=[0.0, 50.0, 50.0]), \
                 patch.object(H, "_environment", return_value=context()), \
                 patch.object(H, "filesystem", return_value=host), patch.object(H.os, "umask"), \
                 patch.object(H, "_engine", return_value=api), \
                 patch.object(H, "prepare", return_value=prepared) as prepare, \
                 patch.object(H, "point", side_effect=point), \
                 patch.object(H, "_retire_parser_sources", return_value=retire_errors,
                              side_effect=first if stage == "parser-raises" else None), \
                 patch.object(H, "print", create=True, side_effect=first if stage == "output" else None), \
                 patch.object(H, "_restore", return_value=cleanup_result) as restore, \
                 patch.object(H, "_fresh", side_effect=OSError("synthetic-cleanup-record")):
                with self.assertRaises((H.Refused, BrokenPipeError)) as caught:
                    H.main()
            if stage == "parser-errors":
                self.assertEqual(str(caught.exception), "hosted-data-parser-source-retirement")
            else:
                self.assertIs(caught.exception, first)
            prepare.assert_called_once_with(api, {}, context(), 45.0, host, cleanup_end=55.0)
            restore.assert_called_once_with(rows, 55.0, 9)
            self.assertIs(caught.exception.hosted_setup_cleanup, cleanup_result)
            self.assertEqual(caught.exception.hosted_setup_cleanup_record_error, "OSError")
            self.assertEqual(caught.exception.hosted_parser_cleanup_errors, retire_errors)

    def test_failed_prepare_is_not_restored_twice_and_keeps_the_first_error(self):
        first = H.Refused("prepare-already-attempted-cleanup")
        first.hosted_setup_cleanup = {"allOriginalsRestored": False, "errors": ["retained"]}
        api = SimpleNamespace(policy=Mock(return_value={}))
        with patch.object(H.sys, "argv", ["hosted-data", "prepare"]), \
             patch.object(H.time, "monotonic", side_effect=[0.0, 50.0]), \
             patch.object(H, "_environment", return_value=context()), \
             patch.object(H, "filesystem", return_value={"device": 9}), patch.object(H.os, "umask"), \
             patch.object(H, "_engine", return_value=api), patch.object(H, "prepare", side_effect=first), \
             patch.object(H, "_retire_parser_sources", side_effect=OSError("parser-cleanup")) as retire, \
             patch.object(H, "_restore", side_effect=AssertionError("no duplicate restoration")) as restore, \
             patch.object(H, "print", create=True, side_effect=AssertionError("no success output")) as output:
            with self.assertRaises(H.Refused) as caught:
                H.main()
        self.assertIs(caught.exception, first)
        self.assertEqual(first.hosted_setup_cleanup, {"allOriginalsRestored": False, "errors": ["retained"]})
        self.assertEqual(first.hosted_parser_retirement_error, "OSError")
        self.assertEqual(retire.call_args.args[1:], (55.0, 9))
        restore.assert_not_called()
        output.assert_not_called()
        failed_restore = H.Refused("original-entry-failure")
        with patch.object(H.time, "monotonic", return_value=50.0), \
             patch.object(H, "_restore", side_effect=OSError("unknown-restore")) as restore, \
             patch.object(H, "_fresh", side_effect=AssertionError("no fabricated result")) as record:
            H._setup_failure(failed_restore, [], context(), 55.0, 9)
        self.assertEqual(failed_restore.hosted_setup_cleanup_error, "OSError")
        self.assertFalse(hasattr(failed_restore, "hosted_setup_cleanup"))
        restore.assert_called_once_with([], 55.0, 9)
        record.assert_not_called()

    def test_restore_collects_conflict_and_still_settles_independent_owned_pairs(self):
        rows = [{"original": {"path": name}, "backup": {"path": "/private/" + Path(name).name},
                 "installed": {"path": name}, "temporary": {"path": "/etc/.private-" + Path(name).name}}
                for name in H.CONFIGURATION]
        def same(row, *args):
            if row["path"] == "/etc/hosts":
                raise H.Refused("changed-original")
        def rename(row, destination, *args):
            return {**row, "path": str(destination)}
        with patch.object(H, "_same", side_effect=same), patch.object(H, "_rename", side_effect=rename), \
             patch.object(H, "_unlink_owned") as unlink:
            result = H._restore(rows, time.monotonic() + 5, 9)
        self.assertFalse(result["allOriginalsRestored"])
        self.assertEqual(result["errors"], [{"path": "/etc/hosts", "errorType": "Refused"}])
        self.assertEqual(sum(row["restored"] for row in result["configuration"]), 2)
        self.assertEqual(unlink.call_count, 2)

    def test_standalone_root_or_caller_json_is_not_stoppost_authority(self):
        with patch.object(H.os, "getresuid", return_value=(0, 0, 0)), \
             patch.object(H.os, "getresgid", return_value=(0, 0, 0)), \
             patch.object(H.os, "getppid", return_value=27), \
             patch.object(H, "filesystem", side_effect=AssertionError("no read/mutation before owner admission")) as filesystem:
            with self.assertRaisesRegex(H.Refused, "original-manager-child"):
                H.settle({}, {}, time.monotonic() + 5, None)
        filesystem.assert_not_called()

    def test_saved_stoppost_admits_real_domain_before_importing_settlement_helper(self):
        value = {"sourceSha": "b" * 40, "runId": "17", "attempt": "1", "shell": {"localTransport": {}}}
        with patch.object(L, "shell_android_saved", return_value=True), \
             patch.object(L.os, "getppid", return_value=1), \
             patch.object(L, "command", return_value=SimpleNamespace(stdout=b"original-show")) as command, \
             patch.object(L, "_domain_admission", side_effect=L.Refused("MainPID not zero")) as domain, \
             patch.object(L, "_android_material_engine", side_effect=AssertionError("no import before finality")) as engine:
            with self.assertRaisesRegex(L.Refused, "MainPID not zero"):
                L._android_hosted_stop(value)
        engine.assert_not_called()
        self.assertIs(domain.call_args.kwargs["stop_boundary"], True)
        fields = command.call_args.args[1][3]
        self.assertIn("ControlPID,MainPID", fields)

    def test_actual_postcompile_workflow_guard_accepts_only_saved3_private_transport(self):
        source = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        anchor = "          import os, re\n          artifact = os.environ.get('MRK_INSTALLED_SHELL_ARTIFACT_ID', '')"
        self.assertEqual(source.count(anchor), 1)
        start = source.index(anchor)
        end = source.index("\n          PY\n", start)
        guard = compile(textwrap.dedent(source[start:end]), "<original-postcompile-route-guard>", "exec")
        original = {"GITHUB_REF": "refs/heads/verify/desktop-installed-shell",
            "MRK_INSTALLED_SHELL_SCOPE": "android-saved-signing3-v1",
            "MRK_INSTALLED_SHELL_TRANSPORT": "android-same-job-local-v1",
            "GITHUB_RUN_ATTEMPT": "7", "MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT": "7",
            "MRK_INSTALLED_SHELL_ARTIFACT_ID": "", "MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": "a" * 64,
            "MRK_INSTALLED_SHELL_ROSTER_SHA256": "b" * 64}
        with patch.object(os, "environ", original.copy()):
            exec(guard, {})
        for changes in (
            {"MRK_INSTALLED_SHELL_SCOPE": "session-apple-review1-v1"},
            {"MRK_INSTALLED_SHELL_SCOPE": ""},
            {"MRK_INSTALLED_SHELL_TRANSPORT": "actions-artifact-v1",
             "MRK_INSTALLED_SHELL_ARTIFACT_ID": "17", "MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": ""},
            {"MRK_INSTALLED_SHELL_PRODUCER_ATTEMPT": "6"},
            {"MRK_INSTALLED_SHELL_ARTIFACT_ID": "17"},
            {"MRK_INSTALLED_SHELL_LOCAL_TRANSPORT_SHA256": ""},
            {"MRK_INSTALLED_SHELL_ROSTER_SHA256": "not-a-pin"},
        ):
            with self.subTest(changes=changes), patch.object(os, "environ", {**original, **changes}), \
                 self.assertRaises(SystemExit):
                exec(guard, {})

    def test_workflow_uses_both_saved_selectors_and_all_five_exact_lifecycle_pins(self):
        source = (SOURCE / ".github/workflows/desktop-ubuntu-publication.yml").read_text()
        digest = hashlib.sha256((SOURCE / "desktop/tools/ubuntu_publication_lifecycle.py").read_bytes()).hexdigest()
        self.assertEqual(source.count("MRK_UBUNTU_LIFECYCLE_ENTRY_SHA256: '" + digest + "'"), 5)
        selector = "github.ref == 'refs/heads/verify/desktop-installed-shell' && 'android-saved-signing3-v1'"
        transport = "github.ref == 'refs/heads/verify/desktop-installed-shell' && 'android-same-job-local-v1'"
        self.assertEqual(source.count(selector), 2)
        self.assertEqual(source.count(transport), 2)
        self.assertIn("env.MRK_INSTALLED_SHELL_SCOPE != 'android-saved-signing3-v1'", source)
        self.assertIn("android_hosted_data.py prepare", source)
        self.assertIn("android_hosted_data.py observe-sdk", source)
        self.assertNotIn("android_hosted_data.py settle", source)
        self.assertIsNone(L.ANDROID_PREPARATION_PINS)
        self.assertIsNone(L.ANDROID_RETAINED_PREPARATION_PINS)


if __name__ == "__main__":
    unittest.main()
