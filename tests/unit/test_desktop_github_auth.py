"""Private synthetic DATA only unless a test explicitly invokes original C/A/W.

No installed gh, real home/config/keyring, native admission or network is used.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mobile_release import _desktop_github_auth_protocol as wire
from mobile_release._desktop_github_auth_config import schema_one
from mobile_release._desktop_github_auth_control import GhAuthInput
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release.cancellation import DefaultCancellation
from mobile_release.desktop_github_auth import GhAuthOperation, _Engine
from mobile_release.owned_process import ProcessCleanupError, ProcessError, run_owned


def frame(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def fixture():
    def snapshot(mode, size=12):
        return {"identity": [1, 2, stat.S_IFREG | mode, 1001, 1001, 1, size, 123, 456], "sha256": "a" * 64}
    return {"protocol": wire.PROTOCOL, "id": "gh-auth-fixture", "role": "token", "login": "fixture-login",
            "projectId": "fixture-project", "repository": "fixture-owner/fixture-repo", "generation": 1,
            "revision": "fixture-revision", "native": {"uid": 1001, "gid": 1001, "home": "/fixture/home",
                "config": "/fixture/home/.config/gh", "executable": "/fixture/official/gh", "tool": snapshot(0o755),
                "files": {"config.yml": snapshot(0o600), "hosts.yml": snapshot(0o600)}},
            "clock": {"workEndNs": 40_000_000_000, "hardEndNs": 50_000_000_000}}


class ProtocolTests(unittest.TestCase):
    def test_native_encoder_exact_private_fixture_parity(self):
        raw = (json.dumps(fixture(), separators=(",", ":")) + "\n").encode()
        request = wire.parse_request(raw)
        self.assertEqual(len(raw), 808)
        self.assertEqual(request.digest, "a4a83b521da35bcb0178bf1b0ec9f34e161d65f87a96c9e0172e0bb984931a7e")

    def test_exact_selected_login_fixed_commands_and_environment_not_ambient(self):
        value = fixture()
        request = wire.parse_request(frame(value))
        self.assertEqual(request.arguments(), ("/fixture/official/gh", "auth", "token", "--hostname", "github.com", "--user", "fixture-login"))
        self.assertEqual(set(request.environment()), {"PATH", "HOME", "GH_CONFIG_DIR", "LANG", "LC_ALL", "GH_HOST",
            "GH_PAGER", "GH_PROMPT_DISABLED", "GH_NO_UPDATE_NOTIFIER", "GH_NO_EXTENSION_UPDATE_NOTIFIER", "NO_COLOR"})
        self.assertEqual(request.environment()["GH_CONFIG_DIR"], "/fixture/home/.config/gh")
        value["role"] = "version"
        self.assertEqual(wire.parse_request(frame(value)).arguments(), ("/fixture/official/gh", "--version"))
        self.assertNotIn("fixture-login", repr(request))
        self.assertNotIn("/fixture", repr(request.tool))

    def test_no_arbitrary_role_args_environment_or_account_inventory(self):
        for role in ("status", "list", "auth", "login", "switch", "api", "extension", "sh", [], None):
            with self.subTest(role=role), self.assertRaises(wire.ProtocolError):
                value = fixture(); value["role"] = role; wire.parse_request(frame(value))
        for key, value in (("argv", ["--help"]), ("environment", {"GH_TOKEN": "synthetic"}), ("retry", True)):
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                data = fixture(); data[key] = value; wire.parse_request(frame(data))

    def test_bounded_login_scope_and_no_selected_account_fallback(self):
        for login in ("", "--other", "-x", "x-", "two--names", "x\nother", "x" * 40, "https://example.invalid", ["fixture"]):
            with self.subTest(login=login), self.assertRaises(wire.ProtocolError):
                value = fixture(); value["login"] = login; wire.parse_request(frame(value))
        for key, invalid in (("id", "../id"), ("projectId", " "), ("revision", "x" * 65), ("generation", True),
                             ("repository", "a/../b"), ("repository", "https://example.invalid/a/b"),
                             ("repository", "\ud800/fixture")):
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                value = fixture(); value[key] = invalid; wire.parse_request(frame(value))

    def test_native_paths_are_not_ambient_or_unbounded_or_alternate_configuration(self):
        for key, invalid in (("home", "relative"), ("home", "/fixture/../home"), ("home", "/fixture//home"),
                             ("config", "/unselected/gh"), ("executable", "/fixture/sh"), ("executable", "/fixture\\gh"),
                             ("uid", 0), ("gid", -1)):
            with self.subTest(key=key, invalid=invalid), self.assertRaises(wire.ProtocolError):
                value = fixture(); value["native"][key] = invalid; wire.parse_request(frame(value))

    def test_file_snapshots_require_fixed_private_files_and_exact_regular_tool(self):
        for kind, index, invalid in (("tool", 2, stat.S_IFLNK | 0o777), ("tool", 2, stat.S_IFREG | 0o644),
                                      ("tool", 2, stat.S_IFREG | 0o4777), ("tool", 5, 2), ("tool", 6, wire.TOOL_LIMIT + 1),
                                      ("hosts.yml", 2, stat.S_IFREG | 0o644), ("hosts.yml", 3, 2),
                                      ("hosts.yml", 6, wire.CONFIG_LIMIT + 1)):
            with self.subTest(kind=kind, index=index), self.assertRaises(wire.ProtocolError):
                value = fixture(); row = value["native"]["tool"] if kind == "tool" else value["native"]["files"][kind]
                row["identity"][index] = invalid; wire.parse_request(frame(value))
        value = fixture(); value["native"]["files"]["other.yml"] = value["native"]["files"]["hosts.yml"]
        with self.assertRaises(wire.ProtocolError):
            wire.parse_request(frame(value))

    def test_duplicate_nested_oversized_or_coalesced_frames_are_refused(self):
        raw = frame(fixture())
        for invalid in (raw + raw, raw[:-1], raw.replace(b'"generation":1', b'"generation":1,"generation":1'),
                        b'[{"nested":' * 100 + b'null' + b'}]' * 100 + b'\n', b'"' + b'x' * wire.REQUEST_LIMIT + b'"\n'):
            with self.subTest(size=len(invalid)), self.assertRaises(wire.ProtocolError):
                wire.parse_request(invalid)

    def test_native_raw_clock_cannot_extend_independent_cleanup_window(self):
        for key, invalid in (("workEndNs", 0), ("workEndNs", 50_000_000_001), ("hardEndNs", 50_000_000_001),
                             ("workEndNs", 1.0), ("hardEndNs", 1 << 64)):
            with self.subTest(key=key), self.assertRaises(wire.ProtocolError):
                value = fixture(); value["clock"][key] = invalid; wire.parse_request(frame(value))

    def test_ready_go_and_private_binary_terminal_bind_exact_original_request(self):
        request = wire.parse_request(frame(fixture()))
        raw = wire.terminal(request, "ok", b"synthetic-private-output-not-a-credential\n")
        self.assertEqual(wire.parse_terminal(raw, request), ("ok", b"synthetic-private-output-not-a-credential\n"))
        self.assertLessEqual(len(wire.ready(request)), wire.READY_LIMIT)
        self.assertNotIn(b"synthetic-private", wire.ready(request))
        self.assertNotIn(b"synthetic-private", wire.go(request))
        other = fixture(); other["login"] = "other-login"; other = wire.parse_request(frame(other))
        with self.assertRaises(wire.ProtocolError):
            wire.parse_terminal(raw, other)
        self.assertNotEqual(wire.go(request), wire.go(other))

    def test_failure_unknown_or_timeout_never_carries_any_private_output(self):
        request = wire.parse_request(frame(fixture()))
        for status in wire.STATUSES[1:]:
            self.assertEqual(wire.parse_terminal(wire.terminal(request, status), request), (status, b""))
            with self.assertRaises(wire.ProtocolError):
                wire.terminal(request, status, b"synthetic-private-output")
        for raw in (b"", wire.terminal(request, "ok", b"x") + b"x", wire.terminal(request, "ok", b"x")[:-1]):
            with self.assertRaises(wire.ProtocolError):
                wire.parse_terminal(raw, request)

    def test_private_output_bounds_are_role_specific_not_a_generic_capture(self):
        data = fixture()
        for role, limit in (("token", wire.TOKEN_LIMIT), ("version", 1024)):
            data["role"] = role; request = wire.parse_request(frame(data))
            wire.terminal(request, "ok", b"x" * limit)
            for invalid in (b"", b"x" * (limit + 1), "synthetic"):
                with self.subTest(role=role), self.assertRaises(wire.ProtocolError):
                    wire.terminal(request, "ok", invalid)


class ConfigSchemaTests(unittest.TestCase):
    def test_shared_native_python_closed_schema_cases(self):
        rows = json.loads((Path(__file__).parents[1] / "fixtures/gh_auth_schema_one.json").read_text())
        self.assertEqual(len(rows), 50)
        for row in rows:
            with self.subTest(case=row["name"]):
                self.assertIs(schema_one(row["text"].encode()), row["accepted"])

    def test_bounded_private_config_lines_aliases_and_raw_bytes(self):
        for value in (b'version: 1\n' + b'#' * 65536, b'version: 1\n' + b'\n' * 256,
                      b'version: 1\naliases:\n' + b''.join(f'  a{i}: fixture\n'.encode() for i in range(65)),
                      b'version: 1\neditor: \xff\n', 'version: 1', None):
            self.assertFalse(schema_one(value))
        self.assertTrue(schema_one(bytearray(b'version: 1\n')))


@contextmanager
def synthetic_operation(*, role="token", config_bytes=b'version: 1\naliases:\n  co: pr checkout\n'):
    """Actual private files/pipe and original guard, NOT native nomination.

    The request is deliberately constructed DATA because this Linux test user
    may be root; production's native-input parser correctly refuses root.
    No installed gh/config/keyring or standard input descriptor is inspected.
    """
    with tempfile.TemporaryDirectory(prefix="mrk-gh-auth-fixture-") as directory:
        base = Path(directory)
        home, tool = base / "home", base / "tool" / "gh"
        config = home / ".config" / "gh"
        config.mkdir(parents=True, mode=0o700)
        tool.parent.mkdir(mode=0o700)
        tool.write_bytes(b"inert fixture, never executed by these operation tests\n")
        tool.chmod(0o700)
        for name in ("config.yml", "hosts.yml"):
            target = config / name
            target.write_bytes(config_bytes if name == "config.yml" else b"synthetic private file, no credentials or account\n")
            target.chmod(0o600)
        def snapshot(path):
            return wire.FileSnapshot(path, wire.identity(path.stat()), hashlib.sha256(path.read_bytes()).hexdigest())
        request = replace(wire.parse_request(frame(fixture())), role=role,
            uid=os.getuid(), gid=os.getgid(), home=home, config=config, tool=snapshot(tool),
            files=tuple(snapshot(config / name) for name in ("config.yml", "hosts.yml")))
        source = GhAuthInput(time.monotonic())
        guard = DefaultCancellation(ProcessCleanupError, "Synthetic gh-auth lifetime did not settle")
        read_fd, writer = os.pipe()
        # Test-only inherited-pipe placement; production acquire owns FD0.
        source.fd = read_fd
        value = os.fstat(read_fd)
        source.identity = (value.st_dev, value.st_ino, value.st_mode)
        source.acquired = True
        os.set_blocking(read_fd, False)
        operation = None
        try:
            guard.install()
            guard._install_saved_command_source(source)
            source.initial, source.request_returned = request, True
            guard.activate()
            operation = GhAuthOperation(request, source, guard)
            yield operation, writer
        finally:
            try:
                if operation is not None:
                    operation.cleanup()
            finally:
                try:
                    source.close()
                finally:
                    guard.restore()
                    os.close(writer)


class OperationTests(unittest.TestCase):
    def begin(self, operation, writer):
        operation.admit()
        self.assertEqual(operation.source.ready(), wire.ready(operation.request))
        os.write(writer, wire.go(operation.request))
        operation.source.go()

    def completed(self, operation, output=b"synthetic-private-output-not-a-credential\n", error=b"", code=0):
        return subprocess.CompletedProcess(operation.request.arguments(), code, output, error)

    def test_legacy_unknown_and_malformed_current_config_never_launch_even_version(self):
        cases = (b"editor: vim\n", b'version: 0\n', b'version: 1\nversion: 0\n',
                 b'aliases:\n  version: 1\n', b'"version": 1\n', b'version: !!str 1\n',
                 b'version: 1\n---\nversion: 0\n', b'version: 1\neditor: "private-fixture-secret',
                 b'editor: |\n  version: 1\n')
        for role in ("version", "token"):
            for value in cases:
                with self.subTest(role=role), synthetic_operation(role=role, config_bytes=value) as (operation, _):
                    with patch("mobile_release._command_process.run_command") as command:
                        with self.assertRaises(wire.ProtocolError) as caught:
                            operation.admit()
                        self.assertFalse(operation.entered or operation.command_admitted)
                        self.assertIsNone(operation.output)
                        self.assertNotIn("private-fixture", str(caught.exception))
                        command.assert_not_called()

    def test_final_owned_command_seam_rechecks_original_config_before_caw(self):
        with synthetic_operation(role="version") as (operation, writer):
            self.begin(operation, writer)
            operation.entered = True  # Exercise the actual shared owned seam directly.
            operation.request.files[0].path.write_bytes(b'editor: "private-fixture-changed"\n')
            with patch("mobile_release._command_process.run_command") as command:
                with self.assertRaises(wire.ProtocolError) as caught:
                    run_owned(operation.request.arguments(), environ=operation.request.environment(),
                              cwd=operation.request.home, timeout=15, capture=True, text=False,
                              output_limit=8192, cancellation=operation.guard)
                command.assert_not_called()
                self.assertFalse(operation.command_admitted)
                self.assertNotIn("private-fixture", str(caught.exception))

    def test_fixed_source_domain_rejects_subclass_and_changed_domain(self):
        self.assertIs(source_domain(GhAuthInput(time.monotonic())), SavedCommandDomain.GitHubAuth)
        class Lookalike(GhAuthInput):
            pass
        for source in (Lookalike(time.monotonic()), GhAuthInput(time.monotonic())):
            if type(source) is GhAuthInput:
                source._domain = SavedCommandDomain.GitHubHistory
            with self.assertRaises(ValueError):
                source_domain(source)

    def test_exact_shared_run_owned_hook_admits_only_one_command(self):
        with synthetic_operation() as (operation, writer):
            self.begin(operation, writer)
            with patch("mobile_release._command_process.run_command", return_value=self.completed(operation)) as command:
                operation.run()
                self.assertEqual(command.call_count, 1)
                args, options = command.call_args
                self.assertEqual(args, (operation.request.arguments(),))
                self.assertEqual(options["environ"], operation.request.environment())
                self.assertEqual(options["cwd"], operation.request.home)
                self.assertIs(options["cancellation"], operation.guard)
                self.assertFalse(options["text"])
                self.assertEqual(options["output_limit"], 8192)
                self.assertLessEqual(options["timeout"], 15)
                self.assertTrue(operation.entered and operation.command_admitted and operation.returned)
                with self.assertRaises(wire.ProtocolError):
                    operation.run()
                self.assertEqual(command.call_count, 1)

    def test_ambient_tokens_routing_and_caller_commands_fail_before_caw(self):
        cases = ({"argv": ["/bin/sh", "-c", "true"]}, {"cwd": Path("/")},
                 {"environ": {"GH_TOKEN": "synthetic", "HTTP_PROXY": "http://example.invalid"}},
                 {"text": True}, {"capture": False}, {"output_limit": 32768},
                 {"on_start": lambda _: None}, {"execution_scope": object()},
                 {"journal_binding": object()}, {"_evidence": object()}, {"cleanup": True})
        for replacement in cases:
            with self.subTest(field=next(iter(replacement))), synthetic_operation() as (operation, writer):
                self.begin(operation, writer)
                operation.entered = True  # Test the actual shared hook directly.
                options = dict(argv=operation.request.arguments(), environ=operation.request.environment(),
                    cwd=operation.request.home, timeout=15, capture=True, text=False, output_limit=8192,
                    cancellation=operation.guard)
                options.update(replacement)
                with patch("mobile_release._command_process.run_command") as command, self.assertRaises((ValueError, wire.ProtocolError)):
                    run_owned(**options)
                command.assert_not_called()

    def test_configuration_change_and_go_replay_refuse_without_command(self):
        with synthetic_operation() as (operation, writer):
            operation.admit()
            operation.source.ready()
            target = operation.request.files[1].path
            target.write_bytes(b"changed synthetic config\n")
            os.write(writer, wire.go(operation.request))
            with patch("mobile_release._command_process.run_command") as command:
                with self.assertRaises(wire.ProtocolError):
                    operation.source.go()
                with self.assertRaises(wire.ProtocolError):
                    operation.source.go()
                self.assertTrue(operation.source.go_returned)
                command.assert_not_called()

    def test_wrong_go_and_stop_are_spent_and_never_retried(self):
        with synthetic_operation() as (operation, writer):
            operation.admit(); operation.source.ready()
            os.write(writer, b"MRK-GH-AUTH-GO/1 " + b"0" * 64 + b"\n")
            with self.assertRaises(wire.ProtocolError):
                operation.source.go()
            with self.assertRaises(wire.ProtocolError):
                operation.source.go()
        with synthetic_operation() as (operation, writer):
            self.begin(operation, writer)
            os.write(writer, b"STOP\n")
            with patch("mobile_release._command_process.run_command") as command, self.assertRaises(KeyboardInterrupt):
                operation.run()
            command.assert_not_called()
            self.assertEqual(operation.source.stop_reason, "cancelled")

    def test_error_stderr_or_oversize_never_becomes_private_result(self):
        for output, error, code in ((b"x", b"synthetic-private-stderr", 0), (b"x", b"", 1),
                                    (b"", b"", 0), (b"x" * (wire.TOKEN_LIMIT + 1), b"", 0)):
            with self.subTest(code=code, sizes=(len(output), len(error))), synthetic_operation() as (operation, writer):
                self.begin(operation, writer)
                with patch("mobile_release._command_process.run_command", return_value=self.completed(operation, output, error, code)), self.assertRaises(wire.ProtocolError) as caught:
                    operation.run()
                self.assertIsNone(operation.output)
                self.assertNotIn("synthetic-private", str(caught.exception))

    def test_unknown_original_caw_cleanup_is_absorbing(self):
        with synthetic_operation() as (operation, writer):
            self.begin(operation, writer)
            unknown = ProcessCleanupError("Synthetic unknown cleanup", dispatched=True, contained=False)
            with patch("mobile_release._command_process.run_command", side_effect=unknown) as command:
                with self.assertRaises(ProcessCleanupError) as caught:
                    operation.run()
                self.assertIs(caught.exception, unknown)
                with self.assertRaises(wire.ProtocolError):
                    operation.run()
                command.assert_called_once()
            operation.cleanup()
            self.assertTrue(operation.unknown)
            self.assertFalse(operation.closed)
            self.assertIsNone(operation.output)

    def test_descriptor_close_lost_return_is_retired_once_and_original_error_preserved(self):
        with synthetic_operation() as (operation, _):
            operation.admit()
            selected = operation.originals[-1].fd
            original_close = os.close
            failure = KeyboardInterrupt()
            closed = []
            def close(number):
                closed.append(number)
                original_close(number)
                if number == selected:
                    raise failure  # Already consumed; no real leaked descriptor.
            with patch("mobile_release.desktop_github_auth.os.close", side_effect=close):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    operation.cleanup()
                self.assertIs(caught.exception, failure)
                operation.cleanup()
            self.assertEqual(closed.count(selected), 1)
            self.assertEqual(len(closed), 3)
            self.assertTrue(operation.unknown and operation.guard.lifetime_ledger.fatal)
            self.assertTrue(all(row.fd is None and row.close_claimed for row in operation.originals))

    def test_terminal_is_private_and_requires_original_cleanup_not_just_command_result(self):
        for settled in (False, True):
            with self.subTest(settled=settled), synthetic_operation() as (operation, writer):
                self.begin(operation, writer)
                with patch("mobile_release._command_process.run_command", return_value=self.completed(operation)):
                    operation.run()
                engine = _Engine(time.monotonic())
                engine.input, engine.guard = operation.source, operation.guard
                engine.operation, engine.request, engine.frames = operation, operation.request, 1
                if settled:
                    operation.cleanup(); operation.source.close(); operation.guard.restore()
                with patch.object(engine, "write") as write:
                    engine.terminal()
                self.assertTrue(write.call_args.kwargs["terminal"])
                status, output = wire.parse_terminal(write.call_args.args[0], operation.request)
                self.assertEqual(status, "ok" if settled else "cleanup-unknown")
                self.assertEqual(bool(output), settled)
                self.assertIsNone(operation.output)


class OriginalContainmentTests(unittest.TestCase):
    def test_gh_shaped_parent_exit_does_not_discharge_its_live_helper(self):
        """Actual unchanged C/A/W, only this test's owned Python fixture child.

        The helper closes captured pipes, so parent exit plus EOF is deliberately
        insufficient. No installed gh, security helper or native admission runs.
        """
        with tempfile.TemporaryDirectory(prefix="mrk-gh-auth-caw-") as directory:
            root = Path(directory)
            source, marker = root / "gh-shaped.py", root / "helper-survived"
            source.write_text("import os, time\n"
                "child = os.fork()\n"
                "if child == 0:\n"
                "    os.close(0); os.close(1); os.close(2)\n"
                "    time.sleep(1.5)\n"
                "    with open('helper-survived', 'wb') as stream: stream.write(b'unsafe')\n"
                "    os._exit(0)\n"
                "os.write(1, b'synthetic-private-output-not-a-credential\\n')\n"
                "os._exit(0)\n", encoding="utf-8")
            result = run_owned(("/usr/bin/python3", "-I", "-S", "-B", str(source)),
                environ={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, cwd=root,
                timeout=5, capture=True, text=False, output_limit=8192)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"synthetic-private-output-not-a-credential\n")
            self.assertEqual(result.stderr, b"")
            time.sleep(1.6)
            self.assertFalse(marker.exists(), "original C/A/W must settle its group, not just gh exit/EOF")


if __name__ == "__main__":
    unittest.main()
