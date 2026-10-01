"""Narrow Ubuntu alpha composition contracts, never a native/package acceptance run.

These tests import the reviewed DATA/owner definitions. They do not start
services, compilers, an application, a private Python runtime, or an installer.
Small executable-mode fixtures are byte DATA only and are never executed.
"""
from __future__ import annotations

import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[2]


def local(name):
    spec = importlib.util.spec_from_file_location(
        "_alpha_contract_" + name, SOURCE / "desktop/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = local("linux_alpha_package_data")
O = local("linux_alpha_package")


def pin(name, body):
    return {"path": name, "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def cargo_message(role):
    binary, relative, features = A.ROLES[role]
    return {
        "reason": "compiler-artifact", "package_id": "fixture-root@0.1.0",
        "manifest_path": str(SOURCE / "desktop/src-tauri/Cargo.toml"),
        "target": {"name": binary, "kind": ["bin"],
                   "src_path": str(SOURCE / "desktop/src-tauri" / relative)},
        "features": features[:], "fresh": False,
        "profile": {"test": False, "opt_level": "0", "debug_assertions": True},
        "executable": str(Path("/contract-target") / A.TARGET / "debug" / binary),
        "filenames": [str(Path("/contract-target") / A.TARGET / "debug" / binary)],
    }


def compiler_bytes(*messages):
    return b"".join(A.P.canonical(row) + b"\n" for row in messages)


def elf_row(domain, *, name=None, needed=(), needs=None, definitions=()):
    return {"domain": domain, "elf": {"soname": name, "needed": list(needed),
        "versionNeeds": needs or {}, "versionDefinitions": list(definitions)}}



class ClientFixture:
    """No OS child or descriptor: finite original-client failure injection."""
    def __init__(self, *, stdout=b"query\n", stderr=b"", interrupt=None,
                 close_error=False, late=False, cannot_join=False, constructor_error=None):
        self.tick, self.interrupt, self.close_error = 0, interrupt, close_error
        self.constructor_error = constructor_error
        self.late, self.cannot_join, self.kills, self.waits = late, cannot_join, 0, 0
        self.reads = {701: [stdout, b""] if stdout else [b""],
                      702: [stderr, b""] if stderr else [b""]}
        self.ended, self.closes, self.entries, self.selector_closes = set(), [], {}, 0
        self.process = SimpleNamespace(pid=700, returncode=None)
        self.process.stdout, self.process.stderr = self.stream(701), self.stream(702)
        self.process.poll = lambda: self.process.returncode
        self.process.kill = self.kill
        self.process.wait = self.wait
        self.selector = SimpleNamespace(register=self.register, unregister=self.unregister,
            select=self.select, get_map=lambda: self.entries, close=self.close_selector)

    def stream(self, number):
        return SimpleNamespace(fileno=lambda: number, close=lambda: self.close_stream(number))

    def close_stream(self, number):
        self.closes.append(number)
        if self.close_error and number == 701:
            raise OSError(5, "injected consuming close")

    def register(self, stream, _events, number):
        self.entries[stream.fileno()] = SimpleNamespace(fileobj=stream, data=number)

    def unregister(self, stream):
        del self.entries[stream.fileno()]

    def select(self, _timeout):
        if self.interrupt is not None:
            error, self.interrupt = self.interrupt, None
            raise error
        return [(entry, 1) for entry in list(self.entries.values())]

    def read(self, descriptor, _size):
        value = self.reads[descriptor].pop(0)
        returncode = self.process.returncode
        if not value:
            self.ended.add(descriptor)
            if self.ended == {701, 702} and returncode is None and not self.cannot_join:
                self.process.returncode = 0
        return value

    def clock(self):
        self.tick += 100_000_000
        return self.tick

    def kill(self):
        self.kills += 1
        if self.cannot_join:
            raise OSError(5, "injected original kill refusal")
        self.process.returncode = -9

    def wait(self, timeout):
        self.waits += 1
        if self.cannot_join:
            raise O.subprocess.TimeoutExpired(["synthetic-manager"], timeout)
        if self.late:
            self.tick += 40_000_000_000
            self.late = False
        return self.process.returncode

    def close_selector(self):
        self.selector_closes += 1

    def patches(self):
        return (
            mock.patch.object(O.subprocess, "Popen", return_value=self.process, side_effect=self.constructor_error),
            mock.patch.object(O.selectors, "DefaultSelector", return_value=self.selector),
            mock.patch.object(O.os, "set_blocking"),
            mock.patch.object(O.os, "read", side_effect=self.read),
            mock.patch.object(O.time, "monotonic_ns", side_effect=self.clock),
            mock.patch.object(O.signal, "pthread_sigmask", return_value=set()),
        )


class CurrentInputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Genuine source-bound controls, not an invented runtime receipt.
        cls.policy, cls.runtime, cls.supplier = A.current_controls(SOURCE)

    def check_policy_refused(self, altered):
        original_read = A.D.read
        binding = SOURCE / A.CONTROLS / "runtime-bindings.json"
        def read(path, *args, **kwargs):
            return A.P.canonical(altered) + b"\n" if path == binding else original_read(path, *args, **kwargs)
        with mock.patch.object(A.D, "read", side_effect=read), self.assertRaises(ValueError):
            A.current_controls(SOURCE)

    def test_genuine_current_controls_keep_exact_no_lf_bridge_and_full_membership(self):
        inputs = self.policy["source"]
        encoded = A.P.canonical(inputs["files"])
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), inputs["inventorySha256"])
        self.assertNotEqual(hashlib.sha256(A.D.canonical(inputs["files"])).hexdigest(),
                            inputs["inventorySha256"])
        self.assertEqual(len(self.runtime), 613)
        self.assertEqual(len(self.supplier), 598)
        self.assertEqual(len(A.P.CURRENT_BOOTSTRAPS), 12)
        self.assertEqual(set(self.runtime), {row["destination"] for row in self.supplier}
                         | {"core.zip", "github-ca.pem", "manifest.json"} | set(A.P.CURRENT_BOOTSTRAPS))
        self.assertEqual(self.runtime["manifest.json"]["sha256"], self.policy["manifestSha256"])
        self.assertEqual(self.runtime["core.zip"]["sha256"], self.policy["coreSha256"])

    def test_lf_bridge_mismatched_mq_and_changed_source_projection_are_refused(self):
        cases = []
        value = copy.deepcopy(self.policy)
        value["source"]["inventorySha256"] = hashlib.sha256(A.D.canonical(value["source"]["files"])).hexdigest()
        cases.append(("LF source bridge", value))
        for key in ("manifestSha256", "protocolSha256", "coreSha256"):
            value = copy.deepcopy(self.policy)
            value[key] = "0" * 64
            cases.append((key, value))
        value = copy.deepcopy(self.policy)
        value["source"]["files"][0]["sha256"] = "0" * 64
        # Rebind the list, so actual source-byte admission, not only its hash,
        # must reject the changed projection.
        value["source"]["inventorySha256"] = hashlib.sha256(A.P.canonical(value["source"]["files"])).hexdigest()
        cases.append(("changed actual source", value))
        for label, value in cases:
            with self.subTest(label=label):
                self.check_policy_refused(value)

    def test_complete_current_package_mapping_contains_both_binaries_and_every_runtime_file(self):
        binaries = {name: pin(name, ("fixture:" + name).encode()) for name in A.S.BINARIES}
        notices = {"COMPONENTS.json": pin("COMPONENTS.json", b"{}")}
        kit = {"LICENSE.txt": pin("LICENSE.txt", b"synthetic notice")}
        data_rows, controls = A.U.package_rows(A.S, binaries, self.runtime, kit, notices,
            self.policy["manifestSha256"], "0.1.0~alpha.contract", "libc6 (>= 2.39)")
        prefix = "usr/lib/mobile-release-kit/runtime-input/" + A.TARGET + "/" + self.policy["manifestSha256"] + "/"
        actual_runtime = {name.removeprefix(prefix): row for name, row in data_rows.items()
                          if name.startswith(prefix) and row["type"] == "file"}
        self.assertEqual(set(actual_runtime), set(self.runtime))
        for name, record in self.runtime.items():
            self.assertEqual(actual_runtime[name], {"type": "file", "size": record["size"],
                "sha256": record["sha256"], "mode": 0o555 if name == "python/bin/python3" else 0o444})
        for name, destination in A.S.BINARIES.items():
            self.assertEqual(data_rows[destination], {"type": "file", "mode": 0o755,
                "size": binaries[name]["size"], "sha256": binaries[name]["sha256"]})
        self.assertEqual(set(controls), {".", "control", "postinst", "prerm", "postrm"})
        self.assertEqual(sum(row["type"] == "file" for row in data_rows.values()),
                         613 + len(binaries) + len(kit) + len(notices) + 2)


class CompilerAndDependencyContracts(unittest.TestCase):
    def test_each_fresh_ordinary_compiler_role_has_exact_features_and_terminal_record(self):
        finished = {"reason": "build-finished", "success": True}
        for role in ("main", "publisher"):
            with self.subTest(role=role):
                good = cargo_message(role)
                selected, units = A.compiler_artifact(compiler_bytes(good, finished), role,
                                                     SOURCE, Path("/contract-target"))
                self.assertEqual(selected["role"], role)
                self.assertEqual(selected["features"], A.ROLES[role][2])
                self.assertEqual(len(units), 1)
                variants = []
                altered = copy.deepcopy(good)
                altered["features"] = sorted(set(good["features"]) | {"development-runtime"})
                variants.append(("wrong features", [altered, finished]))
                altered = copy.deepcopy(good)
                altered["fresh"] = True
                variants.append(("stale executable", [altered, finished]))
                altered = copy.deepcopy(good)
                altered["profile"]["test"] = True
                variants.append(("test executable", [altered, finished]))
                variants += [
                    ("opposite role", [cargo_message("publisher" if role == "main" else "main"), finished]),
                    ("duplicate executable", [good, good, finished]),
                    ("failed compiler", [good, {"reason": "build-finished", "success": False}]),
                    ("unterminated compiler", [good]),
                    ("bytes after terminal", [good, finished, finished]),
                ]
                for label, messages in variants:
                    with self.subTest(case=label), self.assertRaises(ValueError):
                        A.compiler_artifact(compiler_bytes(*messages), role, SOURCE, Path("/contract-target"))

    def test_cargo_hardlink_output_retains_independent_bytes_and_detects_later_change(self):
        with tempfile.TemporaryDirectory(prefix="mrk-alpha-contract-") as temporary:
            root = Path(temporary)
            original = root / "original"
            original.write_bytes(b"inert compiler-output fixture; never execute\n")
            original.chmod(0o755)
            os.link(original, root / "cargo-linked")
            record = A.retain_binary({"path": str(original)}, root / "retained/binary")
            self.assertEqual(original.stat().st_nlink, 2)
            self.assertEqual((root / "retained/binary").stat().st_nlink, 1)
            self.assertNotEqual(record["original"]["identity"][:2], record["retained"]["identity"][:2])
            A.verify_retained_binary(record)
            original.write_bytes(b"changed after the next compiler invocation\n")
            with self.assertRaises(ValueError):
                A.verify_retained_binary(record)

    def test_static_provider_versions_and_private_system_domains_do_not_merge(self):
        private = elf_row("private-runtime", needed=["libssl.so.3"], needs={"libssl.so.3": ["OPENSSL_3.0.0"]})
        system = elf_row("shipped", needed=["libssl.so.3"], needs={"libssl.so.3": ["OPENSSL_3.0.0"]})
        providers = {
            "private-runtime": elf_row("private-runtime", name="libssl.so.3", definitions=["OPENSSL_3.0.0"]),
            "shipped": elf_row("os", name="libssl.so.3", definitions=["OPENSSL_3.0.0"]),
        }
        def provider(requester, name):
            key = "private-lib" if requester["domain"] == "private-runtime" else "system-lib"
            return key, providers[requester["domain"]]
        graph = A.static_edges({"private-app": private, "gui": system}, provider)
        self.assertEqual({row["to"] for row in graph["edges"]}, {"private-lib", "system-lib"})
        broken = copy.deepcopy(providers)
        broken["shipped"]["elf"]["versionDefinitions"] = []
        with self.assertRaises(ValueError):
            A.static_edges({"gui": system}, lambda requester, name: ("system-lib", broken["shipped"]))
        with self.assertRaises(ValueError):
            A.static_edges({"gui": system},
                lambda requester, name: ("system-lib", elf_row("os", name="libcrypto.so.3")))
        with self.assertRaises(ValueError):
            A.static_edges({"private-app": private, "gui": system},
                lambda requester, name: ("colliding-provider", providers[requester["domain"]]))

    def test_actual_dependency_floors_allow_security_supersession_not_unbound_packages(self):
        packages = {
            "libc6:amd64": {"binaryPackage": "libc6:amd64", "version": "2.39-0ubuntu8.6"},
            "libegl-mesa0:amd64": {"binaryPackage": "libegl-mesa0:amd64", "version": "25.0.7-0ubuntu0.24.04.3"},
        }
        dependencies = A.package_dependencies(packages, {"libegl-mesa0:amd64"}, ["libc6 (>= 2.38)"])
        self.assertEqual(dependencies,
            "libc6 (>= 2.38), libegl-mesa0 (>= 25.0.7-0ubuntu0.24.04.3)")
        self.assertNotIn(" (= ", dependencies)
        with self.assertRaises(ValueError):
            A.package_dependencies(packages, {"unbound-module"}, ["libc6 (>= 2.38)"])
        with self.assertRaises(ValueError):
            A.package_dependencies(packages, set(), ["unbound-provider (>= 1)"])


    def test_clean_shlibdeps_stdout_does_not_hide_unresolved_symbol_warning(self):
        raw = b"shlibs:Depends=libc6 (>= 2.38)\n"
        self.assertEqual(A.shlibdeps_relations(raw, b""), ["libc6 (>= 2.38)"])
        with self.assertRaises(ValueError):
            A.shlibdeps_relations(raw, b"dpkg-shlibdeps: warning: symbol unresolved\n")
        with self.assertRaises(ValueError):
            A.shlibdeps_relations(raw + b"hidden second record\n", b"")


class OwnerFailureContracts(unittest.TestCase):
    def original(self, **changes):
        value = {name: "" for name in O.UNIT_PROPERTIES}
        value.update(Id="mrk-contract.service", LoadState="loaded", ActiveState="active",
            SubState="exited", InvocationID="a" * 32, MainPID="0", ExecMainPID="1234",
            ControlGroup="/system.slice/mrk-contract.service", Result="exit-code",
            ExecMainCode="1", ExecMainStatus="17", ExecMainStartTimestampMonotonic="100",
            ExecMainExitTimestampMonotonic="200", Restart="no", KillMode="control-group",
            RemainAfterExit="yes", RuntimeMaxUSec="1min")
        value.update(changes)
        return value

    def manager(self, observed):
        owner = O.UnitOwner(Path("/contract-task"), {"deadlineNs": 10 ** 30})
        initial = self.original(MainPID="1234", SubState="running", Result="success",
                                ExecMainCode="0", ExecMainStatus="0", ExecMainExitTimestampMonotonic="0")
        owner.live["build"] = {"name": initial["Id"], "initial": initial,
            "eventsFd": 901, "cgroupFd": 900, "cgroupIdentity": (1, 2)}
        owner.show = mock.Mock(return_value=observed)
        owner.control = mock.Mock()
        owner.populated = mock.Mock(return_value=(False, "retired"))
        return owner

    def test_absent_unit_properties_are_not_confused_with_a_partial_existing_unit(self):
        raw = b"Id=mrk-contract.service\nLoadState=not-found\nActiveState=inactive\nSubState=dead\n"
        self.assertEqual(O.unit_values(raw, allow_absent=True)["LoadState"], "not-found")
        with self.assertRaises(ValueError):
            O.unit_values(raw)
        with self.assertRaises(ValueError):
            O.unit_values(raw + b"InvocationID=" + b"a" * 32 + b"\n", allow_absent=True)
        with self.assertRaises(ValueError):
            O.unit_values(raw.replace(b"not-found", b"loaded"), allow_absent=True)

    def test_original_failure_is_preserved_before_stop_and_replacement_is_not_stopped(self):
        terminal = self.original()
        owner = self.manager(terminal)
        with mock.patch.object(O.os, "close") as close:
            result = owner.stop_original("build", main=terminal)
        self.assertEqual(result["mainBeforeStop"]["Result"], "exit-code")
        self.assertEqual(result["mainBeforeStop"]["ExecMainStatus"], "17")
        self.assertEqual(result["originalCgroupFinality"], "retired")
        self.assertTrue(result["closed"])
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900)])
        self.assertEqual(owner.live, {})
        replaced = self.manager(self.original(InvocationID="b" * 32))
        with mock.patch.object(O.os, "close") as close, self.assertRaises(ValueError):
            replaced.stop_original("build")
        replaced.control.assert_not_called()
        close.assert_not_called()

    def test_original_close_failure_is_consumed_once_and_cannot_gate_package_success(self):
        terminal = self.original()
        owner = self.manager(terminal)
        with mock.patch.object(O.os, "close", side_effect=[OSError(5, "injected close"), None]) as close:
            with self.assertRaises(ValueError):
                owner.stop_original("build", main=terminal)
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900)])
        self.assertEqual(owner.live, {})
        self.assertEqual(owner.errors, [5])
        self.assertFalse(owner.results[0]["closed"])

    def test_changed_precompile_notices_and_symlink_logs_are_refused_before_transfer(self):
        before = pin("COMPONENTS.json", b"original admitted notices")
        changed = pin("COMPONENTS.json", b"changed after compilation")
        for final in [[], [changed]]:
            events = [
                {"event": "inputs-admitted", "noticeFiles": [before]},
                {"event": "binary-retained", "role": "main"},
                {"event": "binary-retained", "role": "publisher"},
                {"event": "built", "result": {"noticeFiles": final}},
            ]
            with self.subTest(final=final), self.assertRaises(ValueError):
                O.transfer_build(Path("/contract-task"), {}, events, A)
        with tempfile.TemporaryDirectory(prefix="mrk-alpha-contract-") as temporary:
            root = Path(temporary)
            logs = root / "logs"
            logs.mkdir(mode=0o700)
            normal = root / "normal"
            normal.mkdir(mode=0o700)
            (normal / "0001-compile-main.stdout").write_bytes(b"normal original capture")
            # Directory root ownership belongs to native producer qualification,
            # not this non-root byte-copy and no-follow fixture.
            destinations = [root / "ordinary-copy", root / "preserved"]
            created = []
            def fixture_directory(path, mode=0o700, uid=0, gid=0):
                self.assertEqual((path, mode, uid, gid),
                                 (destinations[len(created)], 0o700, 0, 0))
                path.mkdir(mode=0o700)  # Real exclusive creation; never reuse.
                path.chmod(mode)
                item = path.lstat()
                self.assertTrue(O.stat.S_ISDIR(item.st_mode))
                self.assertEqual((item.st_uid, item.st_gid, O.stat.S_IMODE(item.st_mode)),
                                 (os.getuid(), os.getgid(), mode))
                created.append(path)
                return list(O.identity(item)[:5])
            with mock.patch.object(O, "make_directory", side_effect=fixture_directory):
                O.preserve_logs(normal, root / "ordinary-copy", os.getuid())
                self.assertEqual((root / "ordinary-copy/0001-compile-main.stdout").read_bytes(),
                                 b"normal original capture")
                unrelated = root / "unrelated"
                unrelated.write_bytes(b"unrelated synthetic DATA, not a log")
                (logs / "0001-compile-main.stdout").symlink_to(unrelated)
                with self.assertRaises(ValueError):
                    O.preserve_logs(logs, root / "preserved", os.getuid())
                self.assertEqual(list((root / "preserved").iterdir()), [])
                self.assertEqual(unrelated.read_bytes(), b"unrelated synthetic DATA, not a log")
            self.assertEqual(created, destinations)


    def test_attempted_stop_is_never_resubmitted_or_named_unit_readopted(self):
        terminal = self.original()
        owner = self.manager(terminal)
        owner.control.side_effect = InterruptedError("original stop client interrupted")
        with mock.patch.object(O.os, "close") as close:
            with self.assertRaises(InterruptedError):
                owner.stop_original("build", main=terminal)
            self.assertTrue(owner.live["build"]["stopAttempted"])
            stop_deadline = owner.live["build"]["stopDeadlineNs"]
            owner.show.side_effect = AssertionError("must not adopt a collected named unit")
            result = owner.stop_original("build")
        self.assertEqual(owner.control.call_count, 1)
        self.assertEqual(owner.show.call_count, 1)
        self.assertEqual(result["stopDeadlineNs"], stop_deadline)
        self.assertEqual(result["mainBeforeStop"]["ExecMainStatus"], "17")
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900)])

    def test_manager_original_capture_success_and_all_failure_paths_are_finite_owned_and_closed(self):
        cases = [
            ("success", {}, None, True),
            ("constructor interruption", {"constructor_error": InterruptedError("synthetic constructor")}, InterruptedError, False),
            ("overflow", {"stdout": b"x" * 64}, ValueError, True),
            ("interrupt", {"interrupt": InterruptedError("synthetic interrupt")}, InterruptedError, True),
            ("keyboard", {"interrupt": KeyboardInterrupt()}, KeyboardInterrupt, True),
            ("late completion", {"late": True}, ValueError, True),
            ("close uncertainty", {"close_error": True}, OSError, False),
            ("join uncertainty", {"cannot_join": True}, ValueError, False),
        ]
        for name, arguments, expected, finality in cases:
            with self.subTest(case=name):
                fixture, receipts = ClientFixture(**arguments), []
                with ExitStack() as stack:
                    for patch in fixture.patches():
                        stack.enter_context(patch)
                    if expected is None:
                        result = O.manager_command(["/usr/bin/systemctl", "show", "synthetic.service"],
                            environment={}, cwd=Path("/contract-task"), limit=16, receipts=receipts)
                        self.assertEqual(result.stdout, b"query\n")
                    else:
                        with self.assertRaises(expected):
                            O.manager_command(["/usr/bin/systemctl", "show", "synthetic.service"],
                                environment={}, cwd=Path("/contract-task"), limit=16, receipts=receipts)
                self.assertEqual(fixture.closes, [] if name == "constructor interruption" else [701, 702])
                self.assertEqual(fixture.selector_closes, 0 if name == "constructor interruption" else 1)
                if name == "constructor interruption":
                    self.assertTrue(receipts[0]["launchAttempted"])
                    self.assertFalse(receipts[0]["originalHandleReturned"])
                self.assertEqual(len(receipts), 1)
                self.assertEqual(receipts[0]["final"], finality)
                self.assertLessEqual(fixture.kills, 1)
                if name == "overflow":
                    self.assertTrue(receipts[0]["outputOverflow"])
                    self.assertEqual(receipts[0]["stdoutBytes"], 64)
                if name == "late completion":
                    self.assertFalse(receipts[0]["withinDeadline"])

    def test_worker_command_completion_after_original_deadline_is_not_accepted(self):
        fixture = ClientFixture(late=True)
        with ExitStack() as stack:
            for patch in fixture.patches():
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(O, "write_new"))
            emit = stack.enter_context(mock.patch.object(O, "emit"))
            command = O.Commands(10 ** 30, {}, Path("/contract-task"), Path("/contract-logs"))
            with self.assertRaisesRegex(ValueError, "after its deadline"):
                command("late-original", ["synthetic-unused-command"], timeout=15)
        self.assertEqual(fixture.closes, [701, 702])
        self.assertEqual(len(command.records), 1)
        self.assertEqual(command.records[0]["exit"], 0)
        self.assertEqual(emit.call_args.args[0], "command-failed")

    def test_compiler_public_diagnostics_do_not_include_raw_text_or_private_paths(self):
        raw = compiler_bytes({"reason": "compiler-message", "message": {
            "code": {"code": "E0308"}, "message": "DO_NOT_PUBLISH_RAW", "rendered": "PRIVATE_TRANSCRIPT",
            "spans": [
                {"file_name": str(SOURCE / "desktop/src-tauri/src/main.rs"), "line_start": 7, "line_end": 8,
                 "text": [{"text": "PRIVATE_SNIPPET"}]},
                {"file_name": "/private/credentials/token.rs", "line_start": 1, "line_end": 1},
            ]}})
        self.assertEqual(O.compiler_diagnostics(raw, SOURCE), [
            {"code": "E0308", "spans": [{"path": "desktop/src-tauri/src/main.rs", "lineStart": 7, "lineEnd": 8}]}])
        self.assertEqual(O.public_compiler_diagnostics([{
            "code": "E0308", "spans": [{"path": "desktop/../private", "lineStart": 1, "lineEnd": 1}]}]),
            [{"code": "E0308", "spans": []}])



if __name__ == "__main__":
    unittest.main()
