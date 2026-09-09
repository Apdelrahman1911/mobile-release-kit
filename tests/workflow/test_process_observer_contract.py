"""Pure observer contracts: bytes, inert API doubles and static source checks.

No C/helper/ps/native fixture is executed. Every test starts with explicit
process/signal/wait guards; selected metadata collection uses inert results.
These checks are not evidence of macOS SDK, kernel or process behavior.
"""
from __future__ import annotations

import ast
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from . import process_fixture as fixture


class ProcessObserverContractTests(unittest.TestCase):
    def setUp(self):
        for module, name in ((fixture.subprocess, "Popen"), (fixture.subprocess, "run"),
                             (fixture.os, "fork"), (fixture.os, "kill"),
                             (fixture.os, "killpg"), (fixture.os, "waitpid")):
            self.enterContext(patch.object(module, name, create=True,
                                           side_effect=AssertionError("native operation forbidden in pure contract")))
        self.pid, self.group, self.uid, self.gid = 101, 101, 501, 20
        self.selected = "/private/tmp/mrk-ci-pure/bootstrap/process-observer"

    def record(self, status=2, exiting=0, state="live"):
        return f"MRK_PROCESS_V1 present 101 101 501 501 501 20 20 20 {status} {exiting} {state}\n".encode()

    def parse(self, stdout, stderr=b"", status=0, **changes):
        values = dict(group=self.group, uid=self.uid, gid=self.gid)
        values.update(changes)
        return fixture.parse_observer(stdout, stderr, status, self.pid, **values)

    def test_bsd_states_are_typed_and_zombie_precedes_inexit(self):
        for status, exiting, expected in ((2, 0, "live"), (3, 0, "live"), (4, 0, "live"),
                                         (5, 0, "zombie"), (5, 1, "zombie"),
                                         (2, 1, "indeterminate"), (4, 1, "indeterminate"),
                                         (1, 0, "indeterminate"), (0, 0, "indeterminate"),
                                         (2**32 - 1, 0, "indeterminate")):
            with self.subTest(status=status, exiting=exiting):
                self.assertEqual(self.parse(self.record(status, exiting, expected)), expected)
        self.assertEqual(self.parse(b"MRK_PROCESS_V1 absent 101\n"), "absent")

    def test_inconsistent_classification_never_proves_ready_or_dead(self):
        for status, exiting, wrong in ((5, 1, "indeterminate"), (5, 0, "live"),
                                      (2, 1, "live"), (1, 0, "live"),
                                      (2, 0, "zombie"), (99, 0, "zombie")):
            with self.subTest(status=status, exiting=exiting, wrong=wrong), self.assertRaises(AssertionError):
                self.parse(self.record(status, exiting, wrong))

    def test_all_identity_fields_and_integer_bounds_are_checked(self):
        original = self.record().rstrip(b"\n").split(b" ")
        for field, wrong in ((2, b"102"), (3, b"102"), (4, b"502"), (5, b"502"),
                             (6, b"502"), (7, b"21"), (8, b"21"), (9, b"21"),
                             (2, b"0101"), (2, b"-1"), (2, b"2147483648"),
                             (3, b"1"), (4, b"4294967296"), (10, b"4294967296"),
                             (11, b"2"), (11, b"+0")):
            fields = original.copy(); fields[field] = wrong
            with self.subTest(field=field, wrong=wrong), self.assertRaises(AssertionError):
                self.parse(b" ".join(fields) + b"\n")
        for changes in ({"uid": True}, {"uid": 0}, {"gid": -1}, {"group": True}, {"group": 1}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                self.parse(self.record(), **changes)
        with self.assertRaises(AssertionError):
            self.parse(b"MRK_PROCESS_V1 absent 102\n")

    def test_frames_output_limits_and_status_are_strict(self):
        valid = self.record()
        for output in (valid[:-1], valid + b"\n", valid + valid, valid.replace(b"\n", b"\r\n"),
                       valid.replace(b" present ", b"  present "), valid.replace(b"V1", b"V2"),
                       valid.replace(b" 101 ", b"\t101 ", 1), b"x" * 513, "not bytes", bytearray(valid)):
            with self.subTest(type=type(output).__name__), self.assertRaises(AssertionError):
                self.parse(output)
        for status in (1, 2, 3, -9, True, 0.0):
            with self.subTest(status=status), self.assertRaises(AssertionError):
                self.parse(valid, status=status)
        with self.assertRaises(AssertionError):
            self.parse(valid, stderr=b"unexpected diagnostic")

    def test_denial_and_generic_errors_are_never_absence(self):
        for output, status in ((b"MRK_PROCESS_V1 denied 101 kernel 1\n", 2),
                               (b"MRK_PROCESS_V1 denied 101 identity 0\n", 2),
                               (b"MRK_PROCESS_V1 error SELF_QUERY\n", 3),
                               (b"MRK_PROCESS_V1 absent 101\n", 2),
                               (b"MRK_PROCESS_V1 denied 101 kernel 1\n", 0)):
            with self.subTest(output=output, status=status), self.assertRaises(AssertionError):
                self.parse(output, status=status)

    def test_system_ps_preserves_indeterminate_and_requires_scoped_real_rows(self):
        for status, expected in ((b"R", "live"), (b"Ss", "live"), (b"T", "live"),
                                 (b"Z", "zombie"), (b"?E", "indeterminate"),
                                 (b"H", "indeterminate"), (b"X", "indeterminate")):
            with self.subTest(status=status):
                self.assertEqual(fixture.parse_ps(b" 101 101 " + status + b"\n", b"", 0, 101, group=101), expected)
        self.assertEqual(fixture.parse_ps(b"", b"", 1, 101), "absent")
        for output, status in ((b"", 0), (b"101 101 ZE\n", 0), (b"101 101 Z\n", 1),
                               (b"102 101 Z\n", 0), (b"101 102 Z\n", 0),
                               (b"101 101 Z\n101 101 Z\n", 0)):
            with self.subTest(output=output, status=status), self.assertRaises(AssertionError):
                fixture.parse_ps(output, b"", status, 101, group=101)

    def test_missing_darwin_selector_fails_without_any_ci_environment(self):
        with patch.object(fixture, "sys", SimpleNamespace(platform="darwin")), \
             patch.object(fixture, "_PROCESS_OBSERVER", None), patch.dict(fixture.os.environ, {}, clear=True):
            with self.assertRaisesRegex(AssertionError, "admitted selector"):
                fixture.observer_environment()
            with self.assertRaisesRegex(AssertionError, "admitted selector"):
                fixture.process_state(101)
        fixture.subprocess.run.assert_not_called()

    def test_selector_rejects_platform_and_lexical_substitutions_before_metadata(self):
        for platform, value in (("linux", self.selected), ("darwin", ""),
                                ("darwin", "/bin/ps"), ("darwin", "relative/process-observer"),
                                ("darwin", self.selected + "\0"),
                                ("darwin", self.selected.replace("bootstrap/", "bootstrap/../bootstrap/")),
                                ("darwin", self.selected.replace("/private/tmp/", "/tmp/"))):
            with self.subTest(platform=platform, value=value), \
                 patch.object(fixture, "sys", SimpleNamespace(platform=platform)), \
                 patch.object(fixture, "_PROCESS_OBSERVER", value), \
                 patch.object(Path, "lstat", side_effect=AssertionError("metadata must not be reached")) as metadata:
                with self.assertRaises(AssertionError):
                    fixture.observer_environment()
                metadata.assert_not_called()

    def test_selector_metadata_is_immutable_and_ambient_replacement_is_ignored(self):
        selected = Path(self.selected)
        file = dict(st_mode=stat.S_IFREG | 0o555, st_uid=0, st_nlink=1)
        directory = dict(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        for file_change, dir_change, resolves, accepted in (({}, {}, selected, True),
                                                            ({"st_uid": 501}, {}, selected, False),
                                                            ({"st_nlink": 2}, {}, selected, False),
                                                            ({"st_mode": stat.S_IFREG | 0o755}, {}, selected, False),
                                                            ({"st_mode": stat.S_IFLNK | 0o555}, {}, selected, False),
                                                            ({}, {"st_mode": stat.S_IFDIR | 0o775}, selected, False),
                                                            ({}, {"st_uid": 501}, selected, False),
                                                            ({}, {}, Path("/different"), False)):
            def metadata(path):
                return SimpleNamespace(**({**file, **file_change} if path == selected else {**directory, **dir_change}))
            with self.subTest(file=file_change, directory=dir_change, resolves=resolves), \
                 patch.object(fixture, "sys", SimpleNamespace(platform="darwin")), \
                 patch.object(fixture, "_PROCESS_OBSERVER", self.selected), \
                 patch.dict(fixture.os.environ, {fixture.OBSERVER_VARIABLE: "/untrusted/replacement"}), \
                 patch.object(Path, "lstat", autospec=True, side_effect=metadata), \
                 patch.object(Path, "resolve", autospec=True, return_value=resolves):
                if accepted:
                    self.assertEqual(fixture.observer_environment(), {fixture.OBSERVER_VARIABLE: self.selected})
                else:
                    with self.assertRaises(AssertionError):
                        fixture.observer_environment()

    def test_observer_collection_has_clean_environment_and_original_deadline(self):
        result = SimpleNamespace(stdout=self.record(), stderr=b"", returncode=0)
        with patch.object(fixture, "_observer_path", return_value=self.selected), \
             patch.object(fixture.os, "getuid", return_value=501, create=True), \
             patch.object(fixture.os, "getgid", return_value=20, create=True), \
             patch.object(fixture.time, "monotonic", side_effect=[10, 10.4, 10.5]), \
             patch.dict(fixture.os.environ, {"DYLD_INSERT_LIBRARIES": "fictional-canary", "PYTHONHOME": "fictional-canary"}), \
             patch.object(fixture.subprocess, "run", return_value=result) as run:
            self.assertEqual(fixture.process_state(101, group=101, deadline=11), "live")
        self.assertEqual(run.call_args.args, ([self.selected, "101"],))
        self.assertEqual(run.call_args.kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
        self.assertAlmostEqual(run.call_args.kwargs["timeout"], .6)
        self.assertTrue(run.call_args.kwargs["close_fds"])
        self.assertEqual(run.call_args.kwargs["stdin"], fixture.subprocess.DEVNULL)

    def test_expired_deadline_prevents_launch_and_late_result_cannot_pass(self):
        with patch.object(fixture.time, "monotonic", return_value=11), self.assertRaises(AssertionError):
            fixture.process_state(101, deadline=11)
        fixture.subprocess.run.assert_not_called()
        result = SimpleNamespace(stdout=self.record(), stderr=b"", returncode=0)
        with patch.object(fixture, "_observer_path", return_value=self.selected), \
             patch.object(fixture.time, "monotonic", side_effect=[10, 10.4, 11]), \
             patch.object(fixture.subprocess, "run", return_value=result), self.assertRaisesRegex(AssertionError, "deadline"):
            fixture.process_state(101, deadline=11)

    def test_launch_timeout_and_metadata_unavailability_do_not_fallback(self):
        with patch.object(fixture, "_observer_path", return_value=self.selected), \
             patch.object(fixture.time, "monotonic", return_value=0), \
             patch.object(fixture.subprocess, "run", side_effect=fixture.subprocess.TimeoutExpired("fictional-canary", 1)) as run:
            with self.assertRaisesRegex(AssertionError, "observation failed") as raised:
                fixture.process_state(101, deadline=1)
            self.assertNotIn("fictional-canary", str(raised.exception))
            self.assertEqual(run.call_count, 1)
        with patch.object(fixture, "sys", SimpleNamespace(platform="darwin")), \
             patch.object(fixture, "_PROCESS_OBSERVER", self.selected), \
             patch.object(Path, "lstat", side_effect=OSError("fictional-canary")):
            with self.assertRaisesRegex(AssertionError, "metadata unavailable"):
                fixture.observer_environment()

    def test_linux_unset_uses_only_fixed_system_ps(self):
        with patch.object(fixture, "sys", SimpleNamespace(platform="linux")), \
             patch.object(fixture, "_PROCESS_OBSERVER", None), \
             patch.object(fixture.time, "monotonic", return_value=0), \
             patch.object(fixture.subprocess, "run", return_value=SimpleNamespace(stdout=b"101 101 S\n", stderr=b"", returncode=0)) as run:
            self.assertEqual(fixture.observer_environment(), {})
            self.assertEqual(fixture.process_state(101, group=101, deadline=1), "live")
        self.assertEqual(run.call_args.args[0], ["/bin/ps", "-o", "pid=,pgid=,stat=", "-p", "101"])

    def test_indeterminate_readiness_and_cleanup_keep_the_same_deadline(self):
        for method, states, deadline in (("assert_live", ["indeterminate", "live"], 7),
                                         ("assert_dead", ["indeterminate", "live", "zombie"], 3)):
            with self.subTest(method=method), patch.object(fixture.time, "monotonic", return_value=0), \
                 patch.object(fixture.time, "sleep") as sleep, patch.object(fixture, "process_state", side_effect=states) as observe:
                getattr(fixture, method)(101, group=101, **({"deadline": deadline} if method == "assert_live" else {}))
                self.assertEqual(observe.call_count, len(states))
                self.assertTrue(all(call.kwargs == {"group": 101, "deadline": deadline} for call in observe.call_args_list))
                self.assertEqual(sleep.call_count, len(states) - 1)
        with patch.object(fixture.time, "monotonic", side_effect=[0, 3]), \
             patch.object(fixture.time, "sleep") as sleep, patch.object(fixture, "process_state", return_value="indeterminate"):
            with self.assertRaisesRegex(AssertionError, "deadline"):
                fixture.assert_dead(101)
            sleep.assert_not_called()

    def test_absence_is_not_readiness_and_false_alive_is_not_cleanup_proof(self):
        for state in ("zombie", "absent"):
            with self.subTest(state=state), patch.object(fixture, "process_state", return_value=state):
                with self.assertRaisesRegex(AssertionError, "before readiness"):
                    fixture.assert_live(101, deadline=1)
        with patch.object(fixture, "process_state", return_value="indeterminate"):
            self.assertFalse(fixture.alive(101))

    def test_private_driver_environments_forward_only_the_fixed_selector(self):
        from . import profile_process_fixture as profile
        class NoSpawn(Exception):
            pass
        for module in (fixture, profile):
            with self.subTest(module=module.__name__), \
                 patch.object(profile, "command", return_value=["fixed-fixture", "driver"]), \
                 patch.object(module, "observer_environment", return_value={fixture.OBSERVER_VARIABLE: self.selected}), \
                 patch.dict(fixture.os.environ, {"PATH": "/usr/bin", "DYLD_INSERT_LIBRARIES": "fictional-canary",
                                                 "TMPDIR": "/foreign", "TMP": "/foreign", "TEMP": "/foreign"}, clear=True), \
                 patch.object(module.subprocess, "Popen", side_effect=NoSpawn) as spawn:
                with self.assertRaises(NoSpawn):
                    module.run_case(Path("/unused"), "success")
                expected = {"PATH", fixture.OBSERVER_VARIABLE} | ({"PYTHONPATH"} if module is fixture else {"TMPDIR", "TMP", "TEMP"})
                self.assertEqual(set(spawn.call_args.kwargs["env"]), expected)
                self.assertEqual(spawn.call_args.kwargs["env"][fixture.OBSERVER_VARIABLE], self.selected)
                if module is profile:
                    self.assertEqual(spawn.call_args.kwargs["env"], {"PATH": "/usr/bin", fixture.OBSERVER_VARIABLE: self.selected,
                                                                   "TMPDIR": "/unused", "TMP": "/unused", "TEMP": "/unused"})

    def test_native_zombie_probe_keeps_original_handle_unreaped_until_production_cleanup(self):
        # Static regression guard only. Native behavior is still required in CI.
        source = Path(__file__).with_name("test_profile_processes.py").read_text()
        tree = ast.parse(source)
        method = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                      and node.name == "test_actual_zombie_group_is_reaped_and_absent_after_cleanup")
        calls = [node for node in ast.walk(method) if isinstance(node, ast.Call)]
        observation = next(node.lineno for node in calls if isinstance(node.func, ast.Name) and node.func.id == "process_state")
        cleanup = next(node.lineno for node in calls if isinstance(node.func, ast.Attribute) and node.func.attr == "_reap_profile_group")
        self.assertLess(observation, cleanup)
        for call in calls:
            if (isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name)
                    and call.func.value.id == "process" and call.func.attr in {"poll", "wait"}):
                self.assertGreater(call.lineno, cleanup)
