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
        root = Path("/unused")
        selector = {fixture.OBSERVER_VARIABLE: self.selected}
        with patch.dict(fixture.os.environ, {"PATH": "/usr/bin", "DYLD_INSERT_LIBRARIES": "fictional-canary",
                                             "PYTHONPATH": "fictional-canary", "PYTHONHOME": "fictional-canary",
                                             fixture.OBSERVER_VARIABLE: "/untrusted/replacement",
                                             "TMPDIR": "/foreign", "TMP": "/foreign", "TEMP": "/foreign"}, clear=True):
            with self.subTest(driver="generic"), \
                 patch.object(fixture, "observer_environment", return_value=selector) as observer, \
                 patch.object(fixture.subprocess, "Popen", side_effect=NoSpawn) as spawn:
                with self.assertRaises(NoSpawn):
                    fixture.run_case(root, "success")
                observer.assert_called_once_with()
                source = Path(fixture.__file__).resolve()
                spawn.assert_called_once_with(
                    [fixture.sys.executable, "-P", str(source), "driver", str(root), "success", "0"],
                    env={"PATH": "/usr/bin", "PYTHONPATH": str(source.parents[2] / "src"), **selector},
                    stdout=fixture.subprocess.PIPE, stderr=fixture.subprocess.PIPE, start_new_session=True)
            # Intercept construction, not just Popen: the real driver checks
            # native child waitability before launching. No workspace is made.
            argv = ["fixed-fixture", "driver"]
            with self.subTest(driver="profile"), \
                 patch.object(profile, "observer_environment", return_value=selector) as observer, \
                 patch.object(profile, "command", return_value=argv) as command, \
                 patch.object(profile.FixtureDriver, "__init__", side_effect=AssertionError("real driver construction forbidden")) as init, \
                 patch.object(profile, "FixtureDriver", side_effect=NoSpawn) as driver:
                with self.assertRaises(NoSpawn):
                    profile.run_case(SimpleNamespace(path=root), "success")
                observer.assert_called_once_with()
                command.assert_called_once_with("driver", root, root, "success")
                driver.assert_called_once_with(argv, env={"PATH": "/usr/bin", **selector,
                                                         "TMPDIR": "/unused", "TMP": "/unused", "TEMP": "/unused"})
                init.assert_not_called()
                fixture.subprocess.Popen.assert_not_called()

    def test_native_zombie_probe_precedes_the_owning_keepers_original_wait(self):
        # Static source-chain regression guard only; native CI must still prove
        # the behavior. Never import/construct the owner or execute its fixture.
        def definition(scope, name):
            matches = [node for node in scope.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name == name]
            self.assertEqual(len(matches), 1, name)
            return matches[0]

        def shape(scope, kind, source, field=None):
            expected = ast.parse(source).body[0]
            if isinstance(expected, ast.Expr):
                expected = expected.value
            matches = []
            for node in ast.walk(scope):
                if isinstance(node, kind):
                    value = getattr(node, field) if field else node
                    if isinstance(value, ast.AST) and ast.dump(value) == ast.dump(expected):
                        matches.append(node)
            self.assertEqual(len(matches), 1, source)
            return matches[0]

        def ordered(*nodes):
            # Call only within one function/file, never across source trees.
            for earlier, later in zip(nodes, nodes[1:]):
                self.assertLess(earlier.lineno, later.lineno)

        def body(node):
            # ast.walk(If) also visits its else: evidence must be in the
            # selected branch, not merely somewhere under the condition.
            return ast.Module(body=node.body, type_ignores=[])

        workflow = ast.parse(Path(__file__).with_name("test_profile_processes.py").read_text())
        bindings = definition(ast.parse(Path(__file__).with_name("profile_process_fixture.py").read_text()), "ProfileBindings")
        owner = ast.parse((Path(__file__).resolve().parents[2] / "src/mobile_release/_profile_process.py").read_text())
        case = definition(definition(workflow, "ProfileGroupCleanupTests"),
                          "test_actual_zombie_is_observed_before_its_owning_keeper_consumes_the_wait")
        shape(case, ast.Assign, 'result = run_case(workspace, "zombie")')
        shape(case, ast.Call, 'self.assertEqual(result["result"], "success")')
        shape(case, ast.Call, 'self.assertTrue(result["zombieObserved"] and result["deadBeforeFallback"] and result["scratchRemoved"])')

        observe, tick = definition(bindings, "observe"), definition(bindings, "tick")
        published = shape(observe, ast.If, 'event == "child_published"', "test")
        evidence = shape(body(published), ast.Assign, 'child, acquisition = evidence["child"], evidence["acquisition"]')
        identity = shape(body(published), ast.Assert, 'acquisition.child is child and acquisition.settled', "test")
        unreaped = shape(body(published), ast.Assert, 'child.receipt is None and not child.numeric_retired', "test")
        validator = shape(body(published), ast.If, 'child_role == "validator"', "test")
        publication = shape(body(validator), ast.Call,
                            'record(self.root / "validator-published", json.dumps({"pid": child.pid, "group": os.getpgrp()}))')
        ordered(evidence, identity, unreaped, publication)

        outer_only = shape(tick, ast.If, 'self.role != "outer" or self._observing', "test")
        self.assertEqual(len(outer_only.body), 1)
        self.assertIsInstance(outer_only.body[0], ast.Return)
        probe = shape(tick, ast.If, 'self.mode == "zombie" and (self.root / "validator-published").exists() and not self.zombie_observed', "test")
        published_pid = shape(body(probe), ast.Assign, 'publication = json.loads((self.root / "validator-published").read_text())')
        observation = shape(body(probe), ast.Assign, 'state = process_state(publication["pid"], group=publication["group"], deadline=limit)')
        not_absent = shape(body(probe), ast.Assert, 'state != "absent"', "test")
        zombie = shape(body(probe), ast.If, 'state == "zombie"', "test")
        observed = shape(body(zombie), ast.Assign, 'self.zombie_observed = True')
        witness = shape(body(zombie), ast.Call, 'self.log("actual_validator_zombie", validator_pid=publication["pid"])')
        release = shape(tick, ast.Call, 'record(self.root / "zombie-observed", "actual unreaped zombie")')
        self.assertIn(release, tuple(ast.walk(body(zombie))))
        ordered(published_pid, observation, not_absent, zombie, observed, witness, release)

        gate = shape(observe, ast.If, 'role == "keeper" and event == "child_published" and self.mode == "zombie"', "test")
        gate_loop = shape(body(gate), ast.While,
                          'not (self.root / "zombie-observed").exists() and time.monotonic_ns() < self.run_deadline_ns', "test")
        required_observation = shape(body(gate), ast.Assert, '(self.root / "zombie-observed").exists()', "test")
        ordered(publication, gate_loop, required_observation)

        spawn = definition(owner, "_spawn")
        joined = shape(spawn, ast.If, 'granted and task.join_once(context.run)', "test")
        actual_child = shape(body(joined), ast.Assign, 'child = task.acquisition.child')
        event = shape(body(joined), ast.Call,
                      '_role_event(context.role, "child_published", child=child, acquisition=task.acquisition, child_role=child_role)')
        returned = shape(body(joined), ast.Return, 'child', "value")
        ordered(actual_child, event, returned)
        work = definition(definition(owner, "_Keeper"), "work")
        creation = shape(work, ast.Call, '_spawn', "func")
        self.assertEqual(ast.dump(creation.args[4]), ast.dump(ast.Constant(value="validator")))
        self.assertTrue(any(isinstance(node, ast.Assign) and node.value is creation
                            and ast.dump(node.targets[0]) == ast.dump(ast.parse('self.validator = None').body[0].targets[0])
                            for node in work.body))
        wait = shape(work, ast.Call, '_wait_child', "func")
        self.assertEqual(ast.dump(wait.args[1]), ast.dump(ast.parse('self.validator', mode="eval").body))
        self.assertEqual(ast.dump(wait.args[4]), ast.dump(ast.Constant(value="validator_reaped")))
        self.assertTrue(any(isinstance(node, ast.Assign) and node.value is wait
                            and ast.dump(node.targets[0]) == ast.dump(ast.parse('self.receipt = None').body[0].targets[0])
                            for node in work.body))
        ordered(creation, wait)

        wait_child = definition(owner, "_wait_child")
        retired = shape(wait_child, ast.Call, 'child.retire_numeric()')
        consumed = shape(wait_child, ast.Assign, 'receipt = child.poll_wait()')
        has_receipt = shape(wait_child, ast.If, 'receipt is not None', "test")
        reported = shape(body(has_receipt), ast.Call, '_role_event(context.role, event, receipt=receipt)')
        returned = shape(body(has_receipt), ast.Return, 'receipt', "value")
        ordered(retired, consumed, reported, returned)

        patches = definition(bindings, "_enter_patches")
        captured = shape(patches, ast.Assign, 'original_wait, original_join = native.Child.poll_wait, owner.threading.Thread.join')
        wrapper = definition(patches, "poll_wait")
        call = shape(wrapper, ast.Call, 'original_wait', "func")
        original_return = shape(wrapper, ast.Assign, 'receipt = original_wait(child)')
        self.assertIs(original_return.value, call)
        self.assertIn(original_return, wrapper.body)
        retirement = shape(wrapper, ast.Assert, 'child.numeric_retired and child.wait_state in {"OWNED", "POLLABLE"}', "test")
        real_receipt = shape(wrapper, ast.If, 'receipt is not None', "test")
        saved = shape(body(real_receipt), ast.Assign, 'self.wait_witnesses[id(child)] = receipt')
        witnessed = shape(body(real_receipt), ast.Call, 'self.log("original_wait_return", receipt=_receipt(receipt))')
        returned = shape(wrapper, ast.Return, 'receipt', "value")
        ordered(retirement, original_return, saved, witnessed, returned)
        installed = shape(patches, ast.Call, 'self._install_patch(patch.object(obj, name, implementation))')
        install_loop = next(node for node in patches.body if isinstance(node, ast.For) and installed in ast.walk(node))
        shape(install_loop.iter, ast.Tuple, '(native.Child, "poll_wait", poll_wait)')
        shape(install_loop.iter, ast.Tuple, '(owner, "_role_event", self.observe)')
        ordered(captured, wrapper, installed)
        reaped = shape(observe, ast.If, 'event in {"validator_reaped", "keeper_reaped", "custodian_reaped"}', "test")
        shape(body(reaped), ast.Assign, 'child, receipt = self.child_for(child_role), evidence["receipt"]')
        shape(body(reaped), ast.Assert, 'child.receipt is receipt and child.wait_state == "REAPED" and child.numeric_retired', "test")
        shape(body(reaped), ast.Assert, 'self.wait_witnesses.get(id(child)) is receipt', "test")

        # Observation/publication may not steal a wait. The wrapper permits
        # exactly the captured original above, not an extra consuming API.
        consuming = {"poll_wait", "waitpid", "waitid", "wait", "poll", "communicate", "_wait_child"}
        for scope in (tick, observe, spawn, wrapper):
            for node in ast.walk(scope):
                if isinstance(node, ast.Call):
                    name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", None)
                    self.assertNotIn(name, consuming, scope.name)
