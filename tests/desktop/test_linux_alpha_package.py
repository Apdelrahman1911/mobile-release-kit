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
import io
import json
import os
from pathlib import Path
import tempfile
import stat
import tarfile
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


class HostedDistroDataContracts(unittest.TestCase):
    def test_mode_only_data_transition_requires_original_identity_and_complete_roster(self):
        before = (10, 20, stat.S_IFDIR | 0o777, 0, 0, 2, 4096, 100, 200)
        after = before[:2] + (stat.S_IFDIR | 0o755,) + before[3:8] + (201,)
        self.assertTrue(O.hosted_data_mode_transition(before, after, 0o755))
        for index in (0, 1, 3, 4, 5, 6, 7):
            with self.subTest(changed_identity=index):
                changed = list(after)
                changed[index] += 1
                self.assertFalse(O.hosted_data_mode_transition(before, tuple(changed), 0o755))
        self.assertFalse(O.hosted_data_mode_transition(before, after[:-1] + (199,), 0o755))
        self.assertFalse(O.hosted_data_mode_transition(before, after, 0o644))
        file_before = (10, 21, stat.S_IFREG | 0o777, 0, 0, 1, 6, 100, 200)
        file_after = file_before[:2] + (stat.S_IFREG | 0o644,) + file_before[3:8] + (201,)
        self.assertTrue(O.hosted_data_mode_transition(file_before, file_after, 0o644))

        # Synthetic original descriptors only: no real chmod/read/close occurs.
        scope = O.HostedDistroData({"GPL", "GPL-3"})
        state = {501: before, 502: file_before}
        children, bodies = {501: ["doc"]}, {502: b"notice"}
        scope.entries = {
            "/usr/share": {"path": "/usr/share", "fd": 501, "kind": "directory",
                           "original": before, "identity": before, "children": ["doc"]},
            "/usr/share/doc/libc6/copyright": {
                "path": "/usr/share/doc/libc6/copyright", "fd": 502, "kind": "file",
                "original": file_before, "identity": file_before, "body": b"notice"},
        }
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                  "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        scope._named = lambda row: state[row["fd"]]
        scope._body = lambda row: bodies[row["fd"]]

        def chmod(descriptor, mode):
            current = state[descriptor]
            state[descriptor] = (current[:2] + (stat.S_IFMT(current[2]) | mode,)
                                 + current[3:8] + (current[8] + 1,))

        with mock.patch.object(O.os, "fstat", side_effect=lambda fd: SimpleNamespace(**dict(zip(fields, state[fd])))), \
                mock.patch.object(O.os, "listdir", side_effect=lambda fd: children[fd]), \
                mock.patch.object(O.os, "fchmod", side_effect=chmod) as mutation, \
                mock.patch.object(O.os, "close") as close:
            scope.normalize()
            self.assertEqual(mutation.call_args_list, [mock.call(501, 0o755), mock.call(502, 0o644)])
            self.assertEqual(scope.mode_attempts, 2)
            scope.post()
            children[501] = ["doc", "unexpected"]
            with self.assertRaises(O.Refused):
                scope.post()
            children[501] = ["doc"]
            bodies[502] = b"change"
            with self.assertRaises(O.Refused):
                scope.post()
            bodies[502] = b"notice"
            self.assertEqual(scope.finish(), [])
            self.assertEqual(close.call_args_list, [mock.call(502), mock.call(501)])

    def test_data_preparation_rejects_escaped_alias_and_collects_consuming_close_errors(self):
        self.assertTrue(O.hosted_data_path("/usr/share/doc/libgcc-13-dev/copyright", "documentation"))
        self.assertTrue(O.hosted_data_path("/usr/share/common-licenses/GPL-3", "common-license",
                                         common_names={"GPL-3"}))
        self.assertTrue(O.hosted_data_path("/usr/share/glvnd/egl_vendor.d/50_mesa.json", "egl"))
        self.assertTrue(O.hosted_data_path("/usr/share/applications", "applications", directory=True))
        for path, domain in (
                ("/usr/share/applications/never.json", "applications"),
                ("/opt/node/bin/node", "documentation"), ("/usr/share/doc/../copyright", "documentation"),
                ("/usr/share/doc/libc6/other", "documentation"), ("/usr/share/common-licenses/not-reviewed", "common-license"),
                ("/usr/share/glvnd/egl_vendor.d/subdir/50_mesa.json", "egl")):
            with self.subTest(path=path):
                self.assertFalse(O.hosted_data_path(path, domain, common_names={"GPL-3"}))
        scope, visited = O.HostedDistroData({"GPL-3"}), []

        def node(path, _parent, _name):
            visited.append(path)
            if path == "/usr/share/doc/libgcc-13-dev":
                return {"kind": "link", "target": alias_target}
            return {"kind": "file" if path.endswith("/copyright") else "directory", "fd": 601, "path": path}
        scope._node = node
        # normpath(hop/../gcc-13-base) is in-domain, but a live hop alias
        # can make it resolve elsewhere. Refuse before any target acquisition.
        for alias_target in ("../../../opt/unrelated", "hop/../gcc-13-base",
                             "/usr/share/doc/hop/../gcc-13-base", "./gcc-13-base", "gcc-13-base/"):
            with self.subTest(alias_target=alias_target):
                visited.clear()
                with self.assertRaises(O.Refused):
                    scope.bind("/usr/share/doc/libgcc-13-dev/copyright", "documentation")
                self.assertEqual(visited, ["/", "/usr", "/usr/share", "/usr/share/doc",
                                           "/usr/share/doc/libgcc-13-dev"])
        for alias_target in ("gcc-13-base", "../doc/gcc-13-base", "/usr/share/doc/gcc-13-base"):
            with self.subTest(canonical_alias=alias_target):
                selected = scope.bind("/usr/share/doc/libgcc-13-dev/copyright", "documentation")
                self.assertEqual(selected["path"], "/usr/share/doc/gcc-13-base/copyright")

        scope.entries = {"one": {"fd": 611}, "two": {"fd": 612}}
        scope.post = mock.Mock(side_effect=O.Refused("injected original post failure"))
        with mock.patch.object(O.os, "close", side_effect=[OSError("injected close"), None]) as close:
            self.assertEqual(scope.finish(), ["hosted-data-post", "hosted-data-close"])
            self.assertEqual(close.call_args_list, [mock.call(612), mock.call(611)])
            self.assertTrue(all(row["fd"] is None for row in scope.entries.values()))
            scope.finish()
            self.assertEqual(close.call_count, 2)


class StartupContracts(unittest.TestCase):
    def test_fixed_protected_task_root_and_parent_invariants_are_not_relaxed(self):
        correct = "/var/lib/mrk-alpha-36868013001-1-" + "a" * 24
        self.assertTrue(O.task_path(correct))
        for value in (correct.replace("/var/lib", "/opt"), correct + "/child",
                      correct + "\n", correct.replace("-1-", "-0-"), "/var/lib/../lib/" + correct.rsplit("/", 1)[1]):
            with self.subTest(path=value):
                self.assertFalse(O.task_path(value))
        self.assertEqual(O.TASK_PARENT, Path("/var/lib"))
        safe = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        with mock.patch.object(O.Path, "lstat", return_value=safe):
            O.protected_parent(O.TASK_PARENT)
        for changes, reason in (
                ({"st_mode": stat.S_IFREG | 0o644}, "protected-parent-not-directory"),
                ({"st_uid": 1000}, "protected-parent-owner"),
                ({"st_gid": 1000}, "protected-parent-owner"),
                ({"st_mode": stat.S_IFDIR | 0o777}, "protected-parent-mode")):
            with self.subTest(invariant=reason, changes=changes):
                value = SimpleNamespace(**(vars(safe) | changes))
                with mock.patch.object(O.Path, "lstat", return_value=value), self.assertRaises(O.ParentRefused) as caught:
                    O.protected_parent(O.TASK_PARENT)
                self.assertEqual(caught.exception.reason, reason)

    def test_real_startup_failure_never_dispatches_workers_or_discloses_exception_text(self):
        args = SimpleNamespace(source_sha="a" * 40, run_id="36868013001", attempt="1")
        environment = {
            "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "GITHUB_REPOSITORY": O.REPOSITORY, "GITHUB_REF": O.REF, "GITHUB_EVENT_NAME": "push",
            "GITHUB_SHA": args.source_sha, "GITHUB_WORKFLOW_SHA": args.source_sha,
            "GITHUB_WORKFLOW_REF": O.REPOSITORY + "/" + O.WORKFLOW + "@" + O.REF,
        }
        marker = "private-fixture-exception-and-path"
        for phase, reason, may_exist in (
                ("host-identity", "predicate-refused", False),
                ("workflow-identity", "predicate-refused", False),
                ("protected-task-parent", "protected-parent-mode", False),
                ("create-task-directory", "already-exists", True),
                ("create-task-subdirectories", "permission-denied", True),
                ("resource-pressure", "predicate-refused", True),
                ("initialize-manager", "unexpected", True)):
            with self.subTest(phase=phase), ExitStack() as stack:
                stack.enter_context(mock.patch.dict(O.os.environ, environment, clear=True))
                stack.enter_context(mock.patch.object(O.sys, "platform", "linux"))
                stack.enter_context(mock.patch.object(O.os, "getuid", return_value=1000 if phase == "host-identity" else 0))
                stack.enter_context(mock.patch.object(O.os, "geteuid", return_value=0))
                stack.enter_context(mock.patch.object(O.Path, "read_text", return_value='ID=ubuntu\nVERSION_ID="24.04"\n'))
                stack.enter_context(mock.patch.object(O.Path, "is_file", return_value=True))
                stack.enter_context(mock.patch.object(O.os, "urandom", return_value=b"a" * 12))
                parent = stack.enter_context(mock.patch.object(O, "protected_parent"))
                mkdir = stack.enter_context(mock.patch.object(O, "make_directory"))
                pressure = stack.enter_context(mock.patch.object(O, "pressure"))
                manager = stack.enter_context(mock.patch.object(O, "UnitOwner"))
                account = stack.enter_context(mock.patch.object(O, "create_account"))
                spawn = stack.enter_context(mock.patch.object(O.subprocess, "Popen"))
                diagnostic = io.StringIO()
                stack.enter_context(mock.patch.object(O.sys, "stderr", diagnostic))
                failure = None
                if phase == "workflow-identity":
                    O.os.environ["GITHUB_REF"] = marker
                elif phase == "protected-task-parent":
                    failure = O.ParentRefused("protected-parent-mode")
                    parent.side_effect = failure
                elif phase == "create-task-directory":
                    failure = FileExistsError(marker)
                    mkdir.side_effect = failure
                elif phase == "create-task-subdirectories":
                    failure = PermissionError(marker)
                    mkdir.side_effect = [None, failure]
                elif phase == "resource-pressure":
                    failure = O.Refused(marker)
                    pressure.side_effect = failure
                elif phase == "initialize-manager":
                    failure = RuntimeError(marker)
                    manager.side_effect = failure
                with self.assertRaises(BaseException) as caught:
                    O.route(args)
                if failure is not None:
                    self.assertIs(caught.exception, failure)
                output = diagnostic.getvalue()
                self.assertEqual(json.loads(output), {
                    "schema": "mrk-ubuntu-alpha-startup-failure-v1", "phase": phase, "reason": reason,
                    "taskWorkerStartAttempted": False, "taskDirectoryMayExist": may_exist,
                })
                self.assertNotIn(marker, output)
                self.assertEqual(output.count("\n"), 1)
                account.assert_not_called()
                spawn.assert_not_called()
                if phase != "initialize-manager":
                    manager.assert_not_called()
        self.assertEqual(O.startup_diagnostic(marker, RuntimeError(marker)), {
            "schema": "mrk-ubuntu-alpha-startup-failure-v1", "phase": "startup-internal",
            "reason": "unexpected", "taskWorkerStartAttempted": False, "taskDirectoryMayExist": False,
        })


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
            "eventsFd": 901, "cgroupFd": 900, "cgroupParentFd": 902, "cgroupIdentity": (1, 2)}
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

    def cgroup_fixture(self):
        manager = self.manager(self.original())
        del manager.populated  # Exercise the actual original-FD observation.
        def info(inode, mode, links):
            return SimpleNamespace(st_dev=1, st_ino=inode, st_mode=mode,
                st_uid=0, st_gid=0, st_nlink=links, st_size=0,
                st_mtime_ns=1, st_ctime_ns=1)
        observed = {900: info(2, stat.S_IFDIR | 0o755, 2),
                    901: info(3, stat.S_IFREG | 0o444, 1),
                    902: info(4, stat.S_IFDIR | 0o755, 8)}
        book = manager.live["build"]
        book.update(cgroupParentFd=902, cgroupParentPath=Path("/sys/fs/cgroup/system.slice"),
            cgroupParentIdentity=O.identity(observed[902])[:5],
            eventsIdentity=O.identity(observed[901])[:5], stopAttempted=True)
        return manager, book, observed

    def test_retired_original_events_read_requires_retained_parent_and_absent_name(self):
        manager, book, observed = self.cgroup_fixture()
        absent = FileNotFoundError(O.errno.ENOENT, "synthetic original name absent")
        with mock.patch.object(O.os, "fstat", side_effect=lambda fd: observed[fd]), \
             mock.patch.object(O.os, "lseek") as seek, \
             mock.patch.object(O.os, "read", side_effect=OSError(O.errno.ENODEV, "synthetic retired kernfs")) as read, \
             mock.patch.object(O.os, "stat", side_effect=absent) as named, \
             mock.patch.object(O.Path, "lstat", return_value=observed[902]) as parent:
            self.assertEqual(manager.populated(book), (False, "retired"))
        seek.assert_called_once_with(901, 0, os.SEEK_SET)
        read.assert_called_once_with(901, 4097)
        self.assertEqual(named.call_args_list, [
            mock.call(book["name"], dir_fd=902, follow_symlinks=False)] * 2)
        self.assertEqual(parent.call_count, 3)
        self.assertEqual(book["retirementReadErrno"], O.errno.ENODEV)
        self.assertEqual(book["retirementOperation"], "events-read")
        self.assertEqual(book["retirementErrno"], O.errno.ENODEV)
        self.assertIsNone(manager.cgroup_failure)
        self.assertIn("build", manager.live)  # Observation is not settlement.
        manager.control.assert_not_called()

    def test_retired_original_events_seek_keeps_read_unexecuted_and_prior_failure(self):
        for prior_failure in (None,
                {"operation": "events-read", "errno": O.errno.EIO, "eventsReadErrno": None}):
            with self.subTest(prior_failure=prior_failure is not None):
                manager, book, observed = self.cgroup_fixture()
                manager.cgroup_failure = prior_failure
                manager.cgroup_read_errno = O.errno.ENODEV  # A prior read is not this seek.
                book["mainBeforeStop"] = self.original()
                absent = FileNotFoundError(O.errno.ENOENT, "synthetic original name absent")
                with mock.patch.object(O.os, "fstat", side_effect=lambda fd: observed[fd]), \
                     mock.patch.object(O.os, "lseek",
                         side_effect=OSError(O.errno.ENODEV, "synthetic retired seek")) as seek, \
                     mock.patch.object(O.os, "read") as read, \
                     mock.patch.object(O.os, "stat", side_effect=absent) as named, \
                     mock.patch.object(O.Path, "lstat", return_value=observed[902]) as parent:
                    self.assertEqual(manager.populated(book), (False, "retired"))
                seek.assert_called_once_with(901, 0, os.SEEK_SET)
                read.assert_not_called()
                self.assertEqual(named.call_args_list, [
                    mock.call(book["name"], dir_fd=902, follow_symlinks=False)] * 2)
                self.assertEqual(parent.call_count, 3)
                self.assertEqual(book["retirementOperation"], "events-seek")
                self.assertEqual(book["retirementErrno"], O.errno.ENODEV)
                self.assertNotIn("retirementReadErrno", book)
                self.assertIsNone(manager.cgroup_read_errno)
                self.assertIs(manager.cgroup_failure, prior_failure)
                self.assertEqual(book["mainBeforeStop"]["ExecMainStatus"], "17")
                self.assertIn("build", manager.live)  # Retirement is not worker success or settlement.
                self.assertTrue(all(key in book for key in ("cgroupFd", "eventsFd", "cgroupParentFd")))
                manager.control.assert_not_called()

    def test_retirement_refuses_replacement_parent_drift_and_other_seek_or_read_errors(self):
        cases = (
            ("original name remains", "present", None, O.errno.ENODEV, True, ValueError),
            ("replacement name", "replacement", None, O.errno.ENODEV, True, ValueError),
            ("parent drift", "drift", None, O.errno.ENODEV, True, ValueError),
            ("other seek errno", "absent", O.errno.EIO, O.errno.ENODEV, True, OSError),
            ("other read errno", "absent", None, O.errno.EIO, True, OSError),
            ("before stop attempt", "absent", None, O.errno.ENODEV, False, OSError),
            ("seek replacement name", "replacement", O.errno.ENODEV, None, True, ValueError),
            ("seek parent drift", "drift", O.errno.ENODEV, None, True, ValueError),
            ("seek before stop attempt", "absent", O.errno.ENODEV, None, False, OSError),
            ("seek name reappears", "reappears", O.errno.ENODEV, None, True, ValueError),
        )
        for label, named_kind, seek_errno, read_errno, attempted, expected in cases:
            with self.subTest(case=label):
                manager, book, observed = self.cgroup_fixture()
                book["stopAttempted"] = attempted
                parent = copy.copy(observed[902])
                replacement = copy.copy(observed[900])
                replacement.st_ino += 10
                if named_kind == "drift":
                    parent.st_ino += 10
                named_result = observed[900] if named_kind == "present" else replacement
                absent = FileNotFoundError(O.errno.ENOENT, "synthetic absence")
                named_effect = ([absent, replacement] if named_kind == "reappears" else
                    None if named_kind in ("present", "replacement") else absent)
                with mock.patch.object(O.os, "fstat", side_effect=lambda fd: observed[fd]), \
                     mock.patch.object(O.os, "lseek",
                         side_effect=OSError(seek_errno, "synthetic seek") if seek_errno else None), \
                     mock.patch.object(O.os, "read",
                         side_effect=OSError(read_errno, "synthetic read") if read_errno else None) as read, \
                     mock.patch.object(O.os, "stat", return_value=named_result,
                         side_effect=named_effect) as named, \
                     mock.patch.object(O.Path, "lstat", return_value=parent), \
                     self.assertRaises(expected):
                    manager.populated(book)
                self.assertNotIn("retirementOperation", book)
                self.assertNotIn("retirementErrno", book)
                self.assertNotIn("retirementReadErrno", book)
                self.assertIn("build", manager.live)
                self.assertIsNotNone(manager.cgroup_failure)
                if seek_errno:
                    read.assert_not_called()
                    self.assertIsNone(manager.cgroup_failure["eventsReadErrno"])
                failed_errno = seek_errno if seek_errno else read_errno
                if failed_errno != O.errno.ENODEV or not attempted or named_kind == "drift":
                    named.assert_not_called()
                if failed_errno != O.errno.ENODEV or not attempted:
                    self.assertEqual(manager.cgroup_failure, {
                        "operation": "events-seek" if seek_errno else "events-read",
                        "errno": failed_errno, "eventsReadErrno": None})
                if named_kind == "reappears":
                    self.assertEqual(named.call_count, 2)
                manager.control.assert_not_called()

    def test_partial_cgroup_admission_consumes_every_acquired_fd_and_keeps_first_error(self):
        for failure_at in ("events-open", "events-bind"):
            with self.subTest(failure_at=failure_at):
                manager, book, observed = self.cgroup_fixture()
                manager.live.clear()
                manager.errors.append(O.errno.ENOSPC)  # An earlier cleanup failure remains sticky.
                error = OSError(O.errno.EIO, "private synthetic admission failure")
                opened = [902, 900, error if failure_at == "events-open" else 901]
                def fstat(fd):
                    if fd == 901:
                        raise error
                    return observed[fd]
                count = 2 if failure_at == "events-open" else 3
                with mock.patch.object(O.os, "open", side_effect=opened), \
                     mock.patch.object(O.os, "fstat", side_effect=fstat), \
                     mock.patch.object(O.Path, "lstat", return_value=observed[902]), \
                     mock.patch.object(O.os, "stat", return_value=observed[900]), \
                     mock.patch.object(O.os, "close",
                         side_effect=[OSError(O.errno.EBADF, "synthetic close")] + [None] * (count - 1)) as close:
                    with self.assertRaises(OSError) as caught:
                        manager.bind_cgroup(book["name"], book["initial"])
                self.assertIs(caught.exception, error)
                self.assertEqual(close.call_args_list,
                    [mock.call(fd) for fd in ([900, 902] if count == 2 else [901, 900, 902])])
                self.assertEqual(manager.errors, [O.errno.ENOSPC, O.errno.EBADF])
                self.assertEqual(manager.live, {})
                self.assertEqual(manager.cgroup_failure,
                    {"operation": failure_at, "errno": O.errno.EIO, "eventsReadErrno": None})

    def test_expired_pre_submission_attempt_is_not_a_submitted_stop_or_success(self):
        terminal = self.original()
        manager = self.manager(terminal)
        manager.configuration["deadlineNs"] = 0
        with mock.patch.object(O.time, "monotonic_ns", return_value=30_000_000_000), \
             mock.patch.object(O.os, "close") as close:
            with self.assertRaisesRegex(ValueError, "before submission") as original_failure:
                manager.stop_original("build", main=terminal)
            self.assertTrue(manager.live["build"]["stopAttempted"])
            manager.control.assert_not_called()
            manager.show.side_effect = AssertionError("must not re-adopt an attempted original")
            result = manager.stop_original("build")
        self.assertIsInstance(original_failure.exception, ValueError)
        self.assertEqual(result["mainBeforeStop"]["ExecMainStatus"], "17")
        self.assertEqual(result["originalCgroupFinality"], "retired")
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900), mock.call(902)])
        manager.control.assert_not_called()

    def test_unknown_finality_retains_original_outcome_and_closed_syscall_diagnostic(self):
        manager = self.manager(self.original())
        manager.results.append({"role": "build", "originalCgroupFinality": "unknown",
            "closed": True, "mainBeforeStop": self.original()})
        manager.cgroup_failure = {"operation": "events-read", "errno": O.errno.EIO, "eventsReadErrno": None}
        marker = "/private/never-publish-this synthetic credential"
        value = O.failure_summary(Path("/contract-task"), manager, OSError(O.errno.EIO, marker),
                                  "worker-build", "build", False)
        self.assertFalse(value["originalFinality"])
        self.assertEqual(value["unit"]["exitStatus"], "17")
        self.assertEqual(value["unit"]["result"], "exit-code")
        self.assertEqual(value["cgroupObservation"], manager.cgroup_failure)
        self.assertNotIn(marker, json.dumps(value))
        for altered in (
            {"operation": marker, "errno": O.errno.EIO, "eventsReadErrno": None},
            {"operation": [], "errno": O.errno.EIO, "eventsReadErrno": None},
            {"operation": "events-read", "errno": True, "eventsReadErrno": None},
            {"operation": "events-read", "errno": O.errno.EIO, "eventsReadErrno": O.errno.EIO},
        ):
            self.assertIsNone(O.public_cgroup_diagnostic(altered))

    def test_original_failure_is_preserved_before_stop_and_replacement_is_not_stopped(self):
        terminal = self.original()
        owner = self.manager(terminal)
        with mock.patch.object(O.os, "close") as close:
            result = owner.stop_original("build", main=terminal)
        self.assertEqual(result["mainBeforeStop"]["Result"], "exit-code")
        self.assertEqual(result["mainBeforeStop"]["ExecMainStatus"], "17")
        self.assertEqual(result["originalCgroupFinality"], "retired")
        self.assertTrue(result["closed"])
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900), mock.call(902)])
        self.assertEqual(owner.live, {})
        replaced = self.manager(self.original(InvocationID="b" * 32))
        with mock.patch.object(O.os, "close") as close, self.assertRaises(ValueError):
            replaced.stop_original("build")
        replaced.control.assert_not_called()
        close.assert_not_called()

    def test_original_close_failure_is_consumed_once_and_cannot_gate_package_success(self):
        terminal = self.original()
        owner = self.manager(terminal)
        with mock.patch.object(O.os, "close", side_effect=[OSError(5, "injected close"), None, None]) as close:
            with self.assertRaises(ValueError):
                owner.stop_original("build", main=terminal)
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900), mock.call(902)])
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
        self.assertEqual(close.call_args_list, [mock.call(901), mock.call(900), mock.call(902)])

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


    def test_build_failure_stage_survives_actual_worker_event_and_final_root_projection(self):
        marker = "/private/never-publish-this build-input credential"
        class TaskRoot:
            def __truediv__(self, part):
                return SOURCE if part == "source" else Path("/contract-task") / part
        task = TaskRoot()
        for stage in ("metadata-main", "native-notices"):
            with self.subTest(stage=stage):
                error = ValueError(marker)
                command = mock.Mock(return_value=SimpleNamespace(stdout=b"synthetic-metadata"))
                command.environment = {"PATH": "/usr/bin:/bin"}
                data_module = SimpleNamespace(
                    ROLES=A.ROLES, U=SimpleNamespace(shell_compiler_inputs=mock.Mock(return_value=({}, {}))),
                    reconstruct_runtime=mock.Mock(return_value=({"manifestSha256": "a" * 64,
                        "protocolSha256": "b" * 64}, Path("/contract-runtime"))),
                    metadata_graph=mock.Mock(return_value=({}, {}, {})),
                    collect_notices=mock.Mock(return_value=(Path("/contract-notices"), [])),
                    support_inputs=mock.Mock(return_value={}), native_notices=mock.Mock(return_value=[]),
                    support_unchanged=mock.Mock())
                failing = data_module.metadata_graph if stage == "metadata-main" else data_module.native_notices
                failing.side_effect = error
                output = io.BytesIO()
                with mock.patch.object(O, "data", return_value={"deadlineNs": 1, "githubTooling": {}}), \
                     mock.patch.object(O, "worker_go"), mock.patch.object(O, "load_data", return_value=data_module), \
                     mock.patch.object(O, "worker_environment", return_value={}), \
                     mock.patch.object(O, "Commands", return_value=command), \
                     mock.patch.object(O.sys, "stdout", SimpleNamespace(buffer=output)), \
                     self.assertRaises(ValueError) as caught:
                    O.worker(task, "build")
                self.assertIs(caught.exception, error)
                events = output.getvalue().splitlines()
                self.assertEqual(len(events), 1)
                event = json.loads(events[0])
                self.assertEqual(set(event), {"event", "diagnostic"})
                self.assertEqual(event["event"], "build-failed")
                diagnostic = event["diagnostic"]
                self.assertEqual(diagnostic["stage"], stage)
                self.assertEqual(diagnostic["errorClass"], "ValueError")
                self.assertTrue(1 <= len(diagnostic["locations"]) <= 2)
                for location in diagnostic["locations"]:
                    self.assertEqual(location["file"], "desktop/tools/linux_alpha_package.py")
                    self.assertTrue(O.build_worker.__code__.co_firstlineno <= location["line"]
                                    < O.package_worker.__code__.co_firstlineno)
                manager = SimpleNamespace(cgroup_failure=None, clients=[], results=[])
                with mock.patch.object(O, "read", return_value=output.getvalue()):
                    public = O.failure_summary(task, manager, O.Refused(marker), "worker-build", "build", True)
                self.assertEqual(public["buildFailure"], diagnostic)
                self.assertNotIn(marker, json.dumps(public))
                self.assertNotIn(marker, output.getvalue().decode())
                data_module.support_unchanged.assert_not_called()
                self.assertFalse(any(call.args[0].startswith("compile-") for call in command.call_args_list))

    def test_build_diagnostic_bounds_unknown_data_and_finality_preserve_original_failure(self):
        marker = "/private/do-not-publish diagnostic-marker"
        hidden_class = type("PrivateCredentialClass", (ValueError,), {})
        unknown = O.build_failure_diagnostic(marker, hidden_class(marker), SOURCE)
        self.assertEqual(unknown, {"stage": "unknown", "errorClass": "unexpected", "locations": []})
        def nested(depth):
            if depth:
                return nested(depth - 1)
            O.need(False, marker)
        try:
            nested(40)
        except O.Refused as error:
            self.assertEqual(O.build_failure_diagnostic("reconstruct-runtime", error, SOURCE)["locations"], [])
        event = {"event": "build-failed", "diagnostic": unknown}
        manager = SimpleNamespace(cgroup_failure=None, clients=[], results=[])
        task, failure = Path("/contract-task"), O.Refused(marker)
        def project(raw, finality=True):
            with mock.patch.object(O, "read", return_value=raw) as read:
                value = O.failure_summary(task, manager, failure, "worker-build", "build", finality)
                if not finality:
                    read.assert_not_called()
            self.assertNotIn(marker, json.dumps(value))
            self.assertNotIn("PrivateCredentialClass", json.dumps(value))
            return value
        command = {"event": "command-failed", "command": {"label": "metadata-main", "exit": 1,
            "stdoutBytes": 0, "stderrBytes": 0, "stdoutSha256": "a" * 64, "stderrSha256": "b" * 64}}
        later = copy.deepcopy(command)
        later["command"]["label"] = "metadata-publisher"
        raw = b"".join(O.canonical(row) + b"\n" for row in (command, event, later))
        public = project(raw)
        self.assertEqual(public["command"]["label"], "metadata-main")
        self.assertEqual(public["buildFailure"], unknown)
        self.assertNotIn("buildFailure", project(raw, False))
        malformed = []
        for key, value in (("stage", marker), ("errorClass", marker),
                           ("locations", [{"file": marker, "line": 1}]),
                           ("locations", [{"file": O.BUILD_DIAGNOSTIC_FILES[0], "line": True}]),
                           ("locations", [{"file": O.BUILD_DIAGNOSTIC_FILES[0], "line": 1}] * 3)):
            changed = copy.deepcopy(event)
            changed["diagnostic"][key] = value
            malformed.append(O.canonical(changed) + b"\n")
        malformed.extend((O.canonical({**event, "raw": marker}) + b"\n",
                          (O.canonical(event) + b"\n") * 2,
                          O.canonical(event) + b"\nnot-complete-json\n"))
        for raw in malformed:
            with self.subTest(raw=raw[:80]):
                public = project(raw)
                self.assertNotIn("buildFailure", public)
                self.assertEqual(public["workerDiagnostic"], "unavailable")
        original = ValueError(marker)
        command = SimpleNamespace(environment={"PATH": "/usr/bin:/bin"})
        data_module = SimpleNamespace(reconstruct_runtime=mock.Mock(side_effect=original))
        with mock.patch.object(O, "emit", side_effect=OSError("closed synthetic stream")), \
             self.assertRaises(ValueError) as caught:
            O.build_worker(task, {}, command, data_module)
        self.assertIs(caught.exception, original)



class CargoNoticeContracts(unittest.TestCase):
    """Original archive/licensing DATA only; no build, service or native child."""

    def archive(self, *, name="notice-fixture", version="1.0.0", license_file=None,
                members=(), repository="https://github.com/fixture/notices", revision=None):
        metadata = {"name": name, "version": version, "license": "MIT", "repository": repository}
        if license_file is not None:
            metadata["license-file"] = license_file
        cargo = ("[package]\n" + "".join(key + " = " + json.dumps(value) + "\n"
                                        for key, value in metadata.items())).encode()
        roster = [("Cargo.toml", cargo, tarfile.REGTYPE), *members]
        if revision is not None:
            roster.append((".cargo_vcs_info.json", A.P.canonical(
                {"git": {"sha1": revision}, "path_in_vcs": ""}), tarfile.REGTYPE))
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:gz") as archive:
            for relative, body, kind in roster:
                item = tarfile.TarInfo(name + "-" + version + "/" + relative)
                item.type, item.mode = kind, 0o644
                item.size = len(body) if item.isfile() else 0
                if item.issym() or item.islnk():
                    item.linkname = "unrelated-notice"
                archive.addfile(item, io.BytesIO(body) if item.isfile() else None)
        package = {"name": name, "version": version, "license": "MIT", "license_file": license_file,
                   "source": "registry+https://github.com/rust-lang/crates.io-index",
                   "id": name + "@" + version, "manifest_path": "/fixture/" + name + "/Cargo.toml"}
        return output.getvalue(), package

    def rule(self, raw, package, *, archive_members=(), upstream=()):
        return {"name": package["name"], "version": package["version"],
                "archiveSha256": A.sha(raw), "licenseMetadata": "MIT",
                "packageRepository": "https://github.com/fixture/notices",
                "upstreamRepository": "https://github.com/fixture/notices",
                "revision": "a" * 40, "pathInVcs": "", "selectedLicense": "MIT",
                "archiveMembers": list(archive_members), "upstreamNotices": list(upstream)}

    def select(self, raw, package, rule=None, root=Path("/unused-notice-root"), records=None):
        rules = {} if rule is None else {(package["name"], package["version"]): rule}
        return A._crate_notices(raw, package, A.sha(raw), root, records or {}, rules)

    def test_declared_original_and_conventional_notices_are_preserved_without_duplicates(self):
        body, conventional = b"Original declaration fixture\n", b"Original license fixture\n"
        raw, package = self.archive(license_file="legal/terms.txt", members=(
            ("legal/", b"", tarfile.DIRTYPE), ("legal/terms.txt", body, tarfile.REGTYPE),
            ("LICENSE-MIT", conventional, tarfile.REGTYPE)))
        members, provenance = self.select(raw, package)
        self.assertEqual(dict(members), {"legal/terms.txt": body, "LICENSE-MIT": conventional})
        self.assertIsNone(provenance)
        raw, package = self.archive(license_file="LICENSE-MIT",
                                    members=(("LICENSE-MIT", conventional, tarfile.REGTYPE),))
        self.assertEqual(self.select(raw, package)[0], [("LICENSE-MIT", conventional)])

    def test_declared_missing_escaping_nonordinary_and_duplicate_members_are_refused(self):
        for declared, members in (
            ("/terms.txt", ()), ("../terms.txt", ()), ("legal/../terms.txt", ()),
            ("C:/terms.txt", ()), ("legal\\terms.txt", ()), ("terms.txt", ()),
            ("terms.txt", (("terms.txt", b"", tarfile.SYMTYPE),)),
            ("terms.txt", (("terms.txt", b"", tarfile.LNKTYPE),)),
            ("terms.txt", (("terms.txt/", b"", tarfile.DIRTYPE),)),
            ("terms.txt", (("terms.txt", b"one", tarfile.REGTYPE),
                           ("terms.txt", b"two", tarfile.REGTYPE))),
        ):
            with self.subTest(declared=declared, kinds=[row[2] for row in members]):
                raw, package = self.archive(license_file=declared, members=members)
                with self.assertRaises(ValueError):
                    self.select(raw, package)

    def test_authors_requires_an_exact_reviewed_archive_identity_not_a_filename_heuristic(self):
        body = b"Synthetic complete licensing declaration for the archive contract\n"
        raw, package = self.archive(revision="a" * 40, members=(("AUTHORS", body, tarfile.REGTYPE),))
        self.assertEqual(self.select(raw, package), ([], None))
        rule = self.rule(raw, package, archive_members=[pin("AUTHORS", body)])
        members, provenance = self.select(raw, package, rule)
        self.assertEqual(members, [("AUTHORS", body)])
        self.assertEqual(provenance["archiveMembers"], rule["archiveMembers"])
        self.assertEqual(provenance["selectedLicense"], "MIT")
        altered = []
        for key, value in (("archiveSha256", "b" * 64), ("packageRepository", "https://example.invalid"),
                           ("revision", "b" * 40), ("pathInVcs", "other"), ("licenseMetadata", "Apache-2.0")):
            changed = copy.deepcopy(rule)
            changed[key] = value
            altered.append(changed)
        changed = copy.deepcopy(rule)
        changed["archiveMembers"][0]["sha256"] = "b" * 64
        altered.append(changed)
        for changed in altered:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.select(raw, package, changed)

    def test_supplement_preserves_original_bytes_and_refuses_changed_text(self):
        raw, package = self.archive(revision="a" * 40)
        original = b"Original upstream license fixture; never replaced with an SPDX label.\n"
        with tempfile.TemporaryDirectory(prefix="mrk-alpha-notice-contract-") as temporary:
            root = Path(temporary)
            relative = "LICENSE-MIT"
            (root / relative).write_bytes(original)
            row = pin(relative, original)
            rule = self.rule(raw, package, upstream=[{"path": relative, "upstreamPath": "LICENSE-MIT"}])
            members, provenance = self.select(raw, package, rule, root, {relative: row})
            self.assertEqual(members, [("upstream/LICENSE-MIT", original)])
            self.assertEqual(provenance["upstreamNotices"][0]["sha256"], row["sha256"])
            (root / relative).write_bytes(b"Changed upstream source")
            with self.assertRaises(ValueError):
                self.select(raw, package, rule, root, {relative: row})

    def test_real_supplement_inventory_is_source_bound_and_cms_attribution_is_accurate(self):
        root, records, rules = A._rust_notice_inputs(SOURCE)
        self.assertEqual(set(rules), {("cms", "0.2.3"), ("defmt-parser", "1.0.0"),
                                      ("r-efi", "5.3.0"), ("r-efi", "6.0.0")})
        cms = rules[("cms", "0.2.3")]
        self.assertEqual(cms["selectedLicense"], "Apache-2.0")
        self.assertEqual([row["path"] for row in cms["archiveMembers"]], ["README.md"])
        self.assertEqual([row["upstreamPath"] for row in cms["upstreamNotices"]], ["der/LICENSE-APACHE"])
        with tempfile.TemporaryDirectory(prefix="mrk-alpha-notice-input-contract-") as temporary:
            source = Path(temporary)
            copied = source / A.RUST_NOTICE_ROOT
            copied.mkdir(parents=True)
            for relative in [*records, "inputs.json"]:
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((root / relative).read_bytes())
            A._rust_notice_inputs(source)
            manifest = (copied / "inputs.json").read_bytes()
            (copied / "inputs.json").write_bytes(manifest + b" ")
            with self.assertRaises(ValueError):
                A._rust_notice_inputs(source)
            (copied / "inputs.json").write_bytes(manifest)
            extra = copied / "unreviewed.txt"
            extra.write_bytes(b"not an original admitted notice")
            with self.assertRaises(ValueError):
                A._rust_notice_inputs(source)
            extra.unlink()
            (copied / next(iter(records))).write_bytes(b"changed original")
            with self.assertRaises(ValueError):
                A._rust_notice_inputs(source)

    def build_module(self, collection, graph=None):
        return SimpleNamespace(
            NoticeInputsRefused=A.NoticeInputsRefused, ROLES=A.ROLES,
            U=SimpleNamespace(shell_compiler_inputs=mock.Mock(return_value=({}, {}))),
            reconstruct_runtime=mock.Mock(return_value=({"manifestSha256": "a" * 64,
                "protocolSha256": "b" * 64}, Path("/contract-runtime"))),
            metadata_graph=mock.Mock(return_value=(graph or {}, {}, {})),
            collect_notices=collection, support_inputs=mock.Mock())

    def capture_refusal(self, task, module, exception):
        command = mock.Mock(return_value=SimpleNamespace(stdout=b"synthetic-metadata"))
        command.environment = {"PATH": "/usr/bin:/bin"}
        output = io.BytesIO()
        with mock.patch.object(O.sys, "stdout", SimpleNamespace(buffer=output)), \
             self.assertRaises(exception) as caught:
            O.build_worker(task, {"githubTooling": {}}, command, module)
        self.assertEqual([call.args[0] for call in command.call_args_list],
                         ["metadata-main", "metadata-publisher"])
        module.support_inputs.assert_not_called()
        events = output.getvalue().splitlines()
        self.assertEqual(len(events), 1)
        event = json.loads(events[0])
        self.assertEqual(set(event), {"event", "diagnostic"})
        self.assertEqual(event["event"], "build-failed")
        return caught.exception, event["diagnostic"], output.getvalue()

    def test_two_missing_crates_are_reported_together_before_any_frontend_or_compile(self):
        with tempfile.TemporaryDirectory(prefix="mrk-alpha-notice-aggregate-") as temporary:
            task = Path(temporary)
            source, work = task / "source", task / "build"
            retained = source / "desktop/packaging/debian/native-notices"
            retained.mkdir(parents=True)
            original = b"Local synthetic baseline license\n"
            (retained / "LICENSE").write_bytes(original)
            baseline = A.P.canonical({"files": [pin("LICENSE", original)]})
            (retained / "inputs.json").write_bytes(baseline)
            cache = work / "cargo/registry/cache/contract-index"
            cache.mkdir(parents=True)
            graph, locked, expected = {"packages": []}, [], []
            for name in ("missing-one", "missing-two"):
                raw, package = self.archive(name=name)
                (cache / (name + "-1.0.0.crate")).write_bytes(raw)
                graph["packages"].append(package)
                locked.append("[[package]]\n" + "".join(key + " = " + json.dumps(value) + "\n"
                    for key, value in {"name": name, "version": "1.0.0", "source": package["source"],
                                       "checksum": A.sha(raw)}.items()))
                expected.append({"name": name, "version": "1.0.0", "archiveSha256": A.sha(raw),
                                 "reason": "missing-original-notices"})
            manifest = source / "desktop/src-tauri/Cargo.lock"
            manifest.parent.mkdir(parents=True)
            manifest.write_text("\n".join(locked), encoding="utf-8")
            module = self.build_module(A.collect_notices, graph)
            with mock.patch.object(A.U, "NOTICE_INPUTS_SHA256", A.sha(baseline)), \
                 mock.patch.object(A.U, "native_source_notice_inputs"), \
                 mock.patch.object(A, "_rust_notice_inputs", return_value=(source, {}, {})):
                error, diagnostic, output = self.capture_refusal(task, module, A.NoticeInputsRefused)
            self.assertEqual(error.failures, expected)
            self.assertEqual(diagnostic["stage"], "crate-notices")
            self.assertEqual(diagnostic["noticeFailureTotal"], 2)
            self.assertEqual(diagnostic["noticeFailures"], expected)
            manager = SimpleNamespace(cgroup_failure=None, clients=[], results=[])
            with mock.patch.object(O, "read", return_value=output):
                public = O.failure_summary(task, manager, ValueError("private marker"),
                                           "worker-build", "build", True)
            self.assertEqual(public["buildFailure"], diagnostic)
            with mock.patch.object(O, "read") as read:
                public = O.failure_summary(task, manager, ValueError("private marker"),
                                           "worker-build", "build", False)
                read.assert_not_called()
            self.assertNotIn("buildFailure", public)

    def test_notice_diagnostic_is_bounded_typed_and_rejects_extra_private_or_malformed_data(self):
        rows = [{"name": "missing-" + str(index), "version": "1.0.0", "archiveSha256": "a" * 64,
                 "reason": "missing-original-notices"} for index in range(65)]
        actual = A.NoticeInputsRefused(rows)
        module = self.build_module(mock.Mock(side_effect=actual))
        caught, diagnostic, _ = self.capture_refusal(Path("/contract-task"), module, A.NoticeInputsRefused)
        self.assertIs(caught, actual)
        self.assertEqual(diagnostic["noticeFailureTotal"], 65)
        self.assertEqual(diagnostic["noticeFailures"], rows[:64])
        self.assertEqual(O.public_build_diagnostic(diagnostic), diagnostic)
        marker = "/private/do-not-publish notice-marker"
        impostor = type("NoticeInputsRefused", (ValueError,), {})(marker)
        impostor.failures = rows
        malformed = A.NoticeInputsRefused([{**rows[0], "path": marker}])
        for error in (impostor, malformed):
            module = self.build_module(mock.Mock(side_effect=error))
            caught, value, output = self.capture_refusal(Path("/contract-task"), module, ValueError)
            self.assertIs(caught, error)
            self.assertNotIn("noticeFailures", value)
            self.assertNotIn(marker, output.decode())
        invalid = []
        for key, value in (("noticeFailureTotal", True), ("noticeFailureTotal", 1025),
                           ("noticeFailureTotal", 63), ("noticeFailures", rows[:63]),
                           ("stage", "compile-main"), ("errorClass", "ValueError"), ("raw", marker)):
            changed = copy.deepcopy(diagnostic)
            changed[key] = value
            invalid.append(changed)
        for key, value in (("name", marker), ("version", marker), ("archiveSha256", "A" * 64),
                           ("reason", marker), ("path", marker)):
            changed = copy.deepcopy(diagnostic)
            changed["noticeFailures"][0][key] = value
            invalid.append(changed)
        changed = copy.deepcopy(diagnostic)
        changed["noticeFailures"][1] = dict(changed["noticeFailures"][0])
        invalid.append(changed)
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(O.public_build_diagnostic(value))


if __name__ == "__main__":
    unittest.main()
