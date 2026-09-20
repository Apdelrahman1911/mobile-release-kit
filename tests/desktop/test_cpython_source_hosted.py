"""Focused inert contracts; never systemd, network, useradd, mount or native work.

These tests intentionally import only the hosted entry's inert definitions.
Actual source/helper/command and effective-run acceptance remain separate.
"""
from __future__ import annotations

import copy
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / "desktop/tools/cpython_source_hosted.py"
WORKFLOW = ROOT / ".github/workflows/desktop-cpython-source-build.yml"
SPEC = importlib.util.spec_from_file_location("_mrk_source_hosted_test", ENTRY)
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


class HostedSourceTests(unittest.TestCase):
    def test_missing_gate_refuses_before_input_read_import_or_effect(self):
        # The explicit fixture remains meaningful after a reviewed literal pin
        # is selected. It does not assert that legitimate admission stays None.
        with mock.patch.object(H, "APPROVED_HOSTED_INPUTS_SHA256", None), \
             mock.patch.object(H, "read") as read, \
             mock.patch.object(H, "owner_modules") as owner, \
             mock.patch.object(H.Path, "mkdir") as mkdir:
            with self.assertRaisesRegex(H.Refused, "Missing SHA256"):
                H.admission(Path("/not-read"), Path("/not-read"))
        read.assert_not_called()
        owner.assert_not_called()
        mkdir.assert_not_called()

    def test_index_is_closed_and_separates_admission_from_six_helpers(self):
        self.assertEqual(len(H.CONTROLS), 15)
        self.assertEqual(len(H.HELPERS), 7)
        self.assertIn("cpython_source_admission.py", H.HELPERS)
        self.assertNotIn(H.ENTRY_NAME, H.HELPERS)
        value = {"schema": "mrk-cpython-source-hosted-inputs-1", "profile": H.PROFILE,
                 "state": "reviewed-inputs-only", "controls": [], "recipeFiles": []}
        raw = H.canonical(value)
        with mock.patch.object(H, "APPROVED_HOSTED_INPUTS_SHA256", H.digest(raw)), \
             mock.patch.object(H, "read", return_value=raw), mock.patch.object(H, "bound") as bound:
            with self.assertRaisesRegex(H.Refused, "closed roster"):
                H.admission(Path("/not-read"), Path("/not-read"))
        bound.assert_not_called()
        with self.assertRaises(H.Refused):
            H.decode(b'{"x":1,"x":2}\n')
        for name in ("../escape", "/absolute", "double//slash", "space name", "a/./b"):
            with self.subTest(name=name), self.assertRaises(H.Refused):
                H.relative(name)

    def test_source_member_data_grammar_is_scoped_and_canonical(self):
        self.assertEqual(H.SOURCES, ("cpython", "libffi", "openssl", "zlib"))
        data_names = ("Mac/Icons/Disk Image.icns", "Mac/Icons/Python Folder.icns",
                      "Python-3.14.7/Mac/Icons/Disk Image.icns", "m4/lt~obsolete.m4",
                      " source dir/part  ~ name.c ")
        for identifier in H.SOURCES:
            # Grammar is not file admission; source_tree still requires the
            # exact archive root and membership in the pinned full inventory.
            for name in (*data_names, "Modules/config.c.in", "a" * 512):
                with self.subTest(identifier=identifier, name=name):
                    self.assertEqual(H.source_member_name(identifier, name), name)
            for name in ("", "/absolute", "a//b", "a/", "./a", "a/./b", "../a", "a/../b",
                         "a\\b", "a\tb", "a\nb", "a\rb", "a\x00b", "a\x7fb", "a\u00a0b", "a\u00e9b",
                         "a*", "a?", "a;", "a$", "a" * 513, None, b"bytes"):
                with self.subTest(identifier=identifier, name=name), self.assertRaises(H.Refused):
                    H.source_member_name(identifier, name)
        for identifier in ("other", "CPython", "cpython/extra", "", None):
            with self.subTest(identifier=identifier), self.assertRaises(H.Refused):
                H.source_member_name(identifier, "Modules/config.c.in")
        for name in data_names:
            with self.subTest(name=name), self.assertRaises(H.Refused):
                H.relative(name)

    def test_public_redirects_never_downgrade_or_forward_public_token_cross_origin(self):
        handler = H.PublicRedirect()
        request = urllib.request.Request("https://registry-1.docker.io/v2/library/ubuntu/blobs/sha256:fixture",
                                         headers={"Authorization": "Bearer fixture-only"})
        with self.assertRaises(H.Refused):
            handler.redirect_request(request, None, 302, "", {}, "http://cdn.example/fixture")
        redirected = handler.redirect_request(request, None, 302, "", {}, "https://cdn.example/fixture")
        self.assertIsNone(redirected.get_header("Authorization"))
        for url in ("https://name:password@example.test/file", "file:///tmp/fixture", "https://example.test:8443/file"):
            with self.subTest(url=url), self.assertRaises(H.Refused):
                H.https_url(url)

    def test_fixed_namespace_uid_drop_and_writable_mount_roster(self):
        argv = H.bwrap_argv({"uid": 999, "gid": 998})
        self.assertEqual(argv[0], "/usr/bin/bwrap")
        self.assertLess(argv.index("--ro-bind"), argv.index("/usr/bin/setpriv"))
        self.assertLess(argv.index("/usr/bin/setpriv"), argv.index("/usr/bin/python3.12"))
        self.assertEqual(argv[-1], "inside")
        for flag in ("--unshare-user", "--unshare-user-try", "--unshare-all", "--assert-userns-disabled"):
            self.assertNotIn(flag, argv)
        for flag in ("--unshare-net", "--clear-groups", "--no-new-privs", "--inh-caps=-all",
                     "--ambient-caps=-all", "--bounding-set=-all"):
            self.assertIn(flag, argv)
        binds = [(argv[i + 1], argv[i + 2]) for i, part in enumerate(argv) if part == "--bind"]
        self.assertEqual(binds, [(str(H.WORK), "/work"), (str(H.WORK / "shm"), "/dev/shm")])
        self.assertEqual(argv[argv.index("--size") + 1], str(64 << 10))
        self.assertEqual(H.PROPERTIES["RestrictNamespaces"], "~user")
        self.assertTrue(H.userns_denied("cgroup ipc net mnt pid uts time"))
        self.assertTrue(H.userns_denied(str(0x6c020000)))
        for value in ("user mnt uts ipc pid net", "yes", "no", str(0x7c020000), "mnt uts pid"):
            self.assertFalse(H.userns_denied(value))

    def test_root_controller_mount_setuid_exception_is_exact(self):
        def check(path, uid, mode):
            item = SimpleNamespace(st_uid=uid, st_mode=mode)
            with mock.patch.object(H, "HOST_TOOLS", (path,)), \
                 mock.patch.object(H.Path, "lstat", return_value=item), \
                 mock.patch.object(H, "record", return_value={"fixture": True}) as readback:
                actual = H.platform_tools()
            readback.assert_called_once_with(Path(path))
            return actual

        for path, mode in (("/usr/bin/mount", 0o4755), ("/usr/bin/mount", 0o755),
                           ("/usr/bin/systemd-run", 0o755)):
            with self.subTest(path=path, mode=mode):
                self.assertEqual(check(path, 0, H.stat.S_IFREG | mode), [{"fixture": True}])
        for path, uid, mode in (("/usr/bin/mount", 1, H.stat.S_IFREG | 0o4755),
                               ("/usr/bin/systemd-run", 0, H.stat.S_IFREG | 0o4755),
                               ("/usr/bin/mount", 0, H.stat.S_IFLNK | 0o755),
                               *(("/usr/bin/mount", 0, H.stat.S_IFREG | mode)
                                 for mode in (0o4711, 0o4775, 0o4757, 0o2755, 0o6755))):
            with self.subTest(path=path, uid=uid, mode=mode), self.assertRaises(H.Refused):
                check(path, uid, mode)

    def test_host_thread_supplementary_gid_also_blocks_account(self):
        ordinary = {"Uid": "1000 1000 1000 1000", "Gid": "1000 1000 1000 1000", "Groups": "4 27 1000"}
        self.assertFalse(H.thread_uses_account(ordinary, 999, 998))
        self.assertFalse(H.thread_uses_account({**ordinary, "Groups": ""}, 999, 998))
        # NSS and primary Gid can be clear while an extant thread still holds
        # the allocated supplementary group; the existing census must refuse.
        self.assertTrue(H.thread_uses_account({**ordinary, "Groups": "4 998 1000"}, 999, 998))
        for field, value in (("Uid", 999), ("Gid", 998)):
            for index in range(4):
                identities = [1000] * 4
                identities[index] = value
                with self.subTest(field=field, index=index):
                    self.assertTrue(H.thread_uses_account({**ordinary, field: " ".join(map(str, identities))}, 999, 998))
        with self.assertRaises(KeyError):
            H.thread_uses_account({"Uid": ordinary["Uid"], "Gid": ordinary["Gid"]}, 999, 998)

    def test_effective_unit_policy_is_read_back_not_just_requested(self):
        values = {name: "fixture" for name in H.SHOW}
        for name in ("Type", "ExitType", "Restart", "KillMode", "OOMPolicy", "SendSIGKILL", "NoNewPrivileges", "Delegate"):
            values[name] = H.PROPERTIES[name]
        values.update(Id="fixture.service", MemoryMax=str(6 * H.GiB), MemorySwapMax="0", TasksMax="64",
                      RuntimeMaxUSec="40min", RuntimeRandomizedExtraUSec="0", TimeoutStartUSec="10s",
                      TimeoutStopUSec="10s", RestrictNamespaces="mnt uts ipc pid net cgroup")

        def check(candidate):
            result = SimpleNamespace(stdout="".join(k + "=" + v + "\n" for k, v in candidate.items()).encode("ascii"))
            with mock.patch.object(H, "run", return_value=result) as original:
                actual = H.show_unit("fixture.service")
            original.assert_called_once()
            return actual

        self.assertEqual(check(values), values)
        for field, wrong in (("MemoryMax", "max"), ("MemorySwapMax", "1"), ("TasksMax", "infinity"),
                             ("OOMPolicy", "continue"), ("ExitType", "main"), ("KillMode", "process"),
                             ("RuntimeMaxUSec", "41min"), ("TimeoutStopUSec", "infinity"),
                             ("RestrictNamespaces", "mnt uts ipc pid net user"), ("Id", "other.service")):
            with self.subTest(field=field), self.assertRaises(H.Refused):
                check({**values, field: wrong})

    def test_any_group_oom_or_resource_event_latches_failure(self):
        observation = {"events": {"memory.events": {"low": 0, "high": 0, "max": 0, "oom": 0,
                        "oom_kill": 0, "oom_group_kill": 0}, "pids.events": {"max": 0}}, "memoryPeak": 100}
        self.assertTrue(H.no_denials(observation))
        for group, event in (("memory.events", "max"), ("memory.events", "oom"),
                             ("memory.events", "oom_kill"), ("memory.events", "oom_group_kill"),
                             ("pids.events", "max")):
            failed = copy.deepcopy(observation)
            failed["events"][group][event] = 1
            with self.subTest(event=event):
                self.assertFalse(H.no_denials(failed))

    def _original_fixture(self):
        root = H.WORK / "receipts"
        controls = {name: H.canonical({"fixture": name}) for name in
                    ("source-lock.json", "source-execution-review.json", "rootfs.json")}
        data = {"blobs": controls}
        payload, table = {}, []

        def put(name, raw):
            payload[root / name] = raw
            return {"path": name, "size": len(raw), "sha256": H.digest(raw)}

        projection = {"profile": H.PROFILE, "sourcePrefix": "/work/stage", "files": [], "directories": [], "omissions": []}
        projected = put("source-projection.json", H.canonical(projection))
        result = {"schema": "mrk-cpython-source-result-1", "profile": H.PROFILE, "state": "mandatory-work-complete",
            "inputLockSha256": H.digest(controls["source-lock.json"]), "executionReviewSha256": H.digest(controls["source-execution-review.json"]),
            "rootfsSha256": H.digest(controls["rootfs.json"]), "startMonotonicNs": 0,
            "deadlineMonotonicNs": 2400 * 1_000_000_000, "endMonotonicNs": 100,
            "projectionSha256": projected["sha256"], "phases": []}
        for number, name in enumerate(H.PHASES):
            native = name not in {"openssl-layout", "python-project"}
            fixed = {"name": name, "argv": ["/fixture-tool", name] if native else [],
                     "cwd": "/work/build/fixture", "environment": {"PATH": "/usr/bin:/bin"}}
            table.append(fixed)
            wanted = {n for n in H.receipt_roster() if n.startswith(name + "-")}
            if name == "python-project":
                wanted = {"source-projection.json"}
            files = [projected if leaf == "source-projection.json" else put(leaf, b"fixture-data\n") for leaf in sorted(wanted)]
            phase = {"profile": H.PROFILE, "state": "complete", "phase": name, "argv": fixed["argv"],
                "cwd": fixed["cwd"], "environmentSha256": H.digest(H.canonical(fixed["environment"])),
                "originalExitCode": 0 if native else None, "kind": "native" if native else "data",
                "inputLockSha256": result["inputLockSha256"], "deadlineMonotonicNs": result["deadlineMonotonicNs"],
                "startMonotonicNs": number * 2, "endMonotonicNs": number * 2 + 1, "observedIgnoredError": False,
                "stdout": put(name + ".stdout", b"fixture-out\n"), "stderr": put(name + ".stderr", b""), "dataFiles": files}
            result["phases"].append(put(name + ".json", H.canonical(phase)))
        result_record = put("source-result.json", H.canonical(result))
        put("source-output.json", H.canonical({"result": result_record,
            "stage": {key: value for key, value in projection.items() if key != "profile"}}))
        return data, payload, table, result_record

    def _check_original_fixture(self, data, payload, table, result_record):
        loader = SimpleNamespace(exec_module=lambda module: None)
        fake_spec = SimpleNamespace(loader=loader)
        fake_recipe = SimpleNamespace(fixed_phases=lambda: table)
        with mock.patch.object(H, "read", side_effect=lambda path, limit=H.JSON_LIMIT: payload[path]), \
             mock.patch.object(H, "record", return_value={**result_record, "path": str(H.WORK / "receipts/source-result.json")}), \
             mock.patch.object(H.importlib.util, "spec_from_file_location", return_value=fake_spec), \
             mock.patch.object(H.importlib.util, "module_from_spec", return_value=fake_recipe):
            return H.original_results(data)

    def test_original_fourteen_results_require_real_status_streams_and_configuration(self):
        fixture = self._original_fixture()
        self.assertEqual(self._check_original_fixture(*fixture)["profile"], H.PROFILE)
        for field, wrong in (("originalExitCode", 1), ("originalExitCode", False),
                             ("dataFiles", []), ("observedIgnoredError", True)):
            data, payload, table, result_record = self._original_fixture()
            leaf = H.WORK / "receipts/zlib-configure.json"
            phase = H.decode(payload[leaf])
            phase[field] = wrong
            payload[leaf] = H.canonical(phase)
            # Rebind the synthetic caller's phase index: failure must come from
            # required-work validation, not only a deliberately stale hash.
            result_path = H.WORK / "receipts/source-result.json"
            result = H.decode(payload[result_path])
            result["phases"][0] = {"path": leaf.name, "size": len(payload[leaf]), "sha256": H.digest(payload[leaf])}
            payload[result_path] = H.canonical(result)
            with self.subTest(field=field, wrong=wrong), self.assertRaises(H.Refused):
                self._check_original_fixture(data, payload, table, result_record)

    def test_missing_phase_or_stream_cannot_be_manufactured_from_other_outputs(self):
        data, payload, table, result_record = self._original_fixture()
        path = H.WORK / "receipts/source-result.json"
        result = H.decode(payload[path])
        result["phases"].pop()
        payload[path] = H.canonical(result)
        with self.assertRaises(H.Refused):
            self._check_original_fixture(data, payload, table, result_record)
        data, payload, table, result_record = self._original_fixture()
        del payload[H.WORK / "receipts/python-build.stdout"]
        with self.assertRaises(KeyError):
            self._check_original_fixture(data, payload, table, result_record)

    def test_retention_names_separate_data_and_phase_and_archive_cap_is_hard(self):
        self.assertIn("openssl-layout-data.json", H.receipt_roster())
        self.assertIn("openssl-layout.json", H.receipt_roster())
        self.assertNotIn("arbitrary-secret.txt", H.receipt_roster())
        sink = io.BytesIO()
        writer = H.CappedTarWriter(sink)
        with mock.patch.object(H, "PUBLIC_BYTES", 8):
            self.assertEqual(writer.write(b"four"), 4)
            with self.assertRaises(H.Refused):
                writer.write(b"overflow")
        self.assertEqual(sink.getvalue(), b"four")

    def test_failure_diagnostic_is_stage_and_safe_class_not_arbitrary_exception_message(self):
        fake_sys = SimpleNamespace(argv=["entry", "inside"], flags=SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1))
        for error, expected in ((ValueError("private-url-and-token"), "ValueError"),
                                (H.Refused("Effective controller limits differ"), "Effective controller limits differ")):
            with mock.patch.object(H, "sys", fake_sys), mock.patch.object(H, "_STAGE", "fixture-limits"), \
                 mock.patch.object(H.os, "umask"), mock.patch.object(H, "inside", side_effect=error), \
                 self.assertRaises(SystemExit) as captured:
                H.main()
            self.assertIn("inside/fixture-limits", str(captured.exception))
            self.assertIn(expected, str(captured.exception))
            self.assertNotIn("private-url-and-token", str(captured.exception))

    def test_workflow_has_one_first_attempt_no_matrix_and_exact_artifact_paths(self):
        raw = WORKFLOW.read_text(encoding="utf-8")
        for required in ("branches: [verify/desktop-cpython-source-build]", "runs-on: ubuntu-24.04",
                         "contents: read", "group: desktop-cpython-source-build", "cancel-in-progress: false",
                         '"$GITHUB_RUN_ATTEMPT" == 1', '"$GITHUB_WORKFLOW_SHA" == "$GITHUB_SHA"',
                         '"$MRK_EXPECTED_SHA" == "$GITHUB_SHA"', '"$MRK_PUSH_EVENT_AFTER" == "$GITHUB_SHA"',
                         "persist-credentials: false", "compression-level: 0", "overwrite: false"):
            self.assertIn(required, raw)
        for forbidden in ("matrix:", "self-hosted", "pull_request:", "secrets.", "id-token:", "setup-python@",
                          "apt-get", "docker run", "actions/cache@", "continue-on-error:", "/**\n          if-no-files-found"):
            # The explanatory self-hosted-policy comment is not a runner label.
            if forbidden == "self-hosted":
                self.assertNotIn("runs-on: self-hosted", raw)
            else:
                self.assertNotIn(forbidden, raw)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", raw)
        self.assertIn("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a", raw)


if __name__ == "__main__":
    unittest.main()
