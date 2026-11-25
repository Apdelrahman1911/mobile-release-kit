"""Actual fixed worker/control/dispatch, with explicitly FAKE C/A/W results.

Only tiny task-owned files and real held pipes are used. The nominated tool is
inert text, the reused JKS/certificate bytes are deliberately unusable, and the
lowest run_command boundary is replaced: no child, JDK, key, native M2 lease,
vault, Store or network operation runs. A provisional private terminal here is
NOT native settlement, saved-key evidence or platform qualification.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from helpers import android_config
from test_desktop_upload_key import encoded, fixture, private_go, synthetic_container
from mobile_release import _desktop_upload_key_control as control
from mobile_release import _desktop_upload_key_jks as jks
from mobile_release import _desktop_upload_key_protocol as wire
from mobile_release import desktop_upload_key as worker
from mobile_release._desktop_saved_command_control import SavedCommandDomain, source_domain
from mobile_release.owned_process import run_owned


def engine_fixture(*, go="valid", changed=None):
    """Run main on this main thread; a bounded pipe peer supplies only GO/STOP.

    Darwin/user/uptime observations are synthetic. Files, hashes, original
    descriptors, request/GO decoding, cancellation, source checks, final
    run_owned admission and cleanup are the actual implementations.
    """
    with tempfile.TemporaryDirectory(prefix="mrk-upload-engine-") as directory:
        base = Path(directory)
        root, scratch_parent = base / "project", base / "scratch"
        (root / "release").mkdir(parents=True)
        scratch_parent.mkdir(mode=0o700)
        config = root / "release/mobile-release.json"
        data = android_config(status="unverified")
        original_config = (json.dumps(data, indent=2) + "\n").encode()
        config.write_bytes(original_config)
        canonical = json.dumps(data, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":"), allow_nan=False).encode()
        app = data["android"]["applicationId"].encode("ascii")
        tool = base / "jdk/bin/keytool"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"inert test fixture; never executed\n")
        tool.chmod(0o755)
        tool_stat = tool.stat()

        # Only the native platform/UID nomination is simulated. On non-root
        # test users the inert fixture's UID is viewed as the required protected
        # tool owner; its actual inode, mode, timestamps and bytes stay checked.
        def native_stat(value):
            if (value.st_dev, value.st_ino) != (tool_stat.st_dev, tool_stat.st_ino):
                return value
            fields = {name: getattr(value, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_gid", "st_nlink",
                "st_size", "st_mtime_ns", "st_ctime_ns")}
            return SimpleNamespace(**fields, st_uid=0)

        native_os = SimpleNamespace(**vars(os))
        native_os.getuid = native_os.geteuid = lambda: 1001
        native_os.getgid = native_os.getegid = os.getgid
        native_os.stat = lambda *args, **kwargs: native_stat(os.stat(*args, **kwargs))
        native_os.fstat = lambda number: native_stat(os.fstat(number))
        native_time = SimpleNamespace(monotonic=time.monotonic, CLOCK_UPTIME_RAW=12345,
                                      clock_gettime_ns=lambda _: time.monotonic_ns())
        value = fixture()
        value["native"].update(uid=1001, gid=os.getgid(), executable=str(tool),
            tool={"identity": list(wire.identity(native_stat(tool_stat))),
                  "sha256": hashlib.sha256(tool.read_bytes()).hexdigest()})
        observed = root.stat()
        value["native"]["saved"] = {
            "root": str(root), "identity": [observed.st_dev, observed.st_ino,
                observed.st_mode, observed.st_uid, observed.st_gid],
            "configBytes": len(original_config),
            "configSha256": hashlib.sha256(original_config).hexdigest(),
            "draftSha256": hashlib.sha256(canonical).hexdigest(),
            "appIdentitySha256": hashlib.sha256(
                b"dev.mobile-release-kit.desktop/credential-app-identity/v1\0"
                + b"\x01" + len(app).to_bytes(4, "big") + app).hexdigest(),
        }
        made, commands, seam_calls, peer_errors = [], [], [], []
        output, error_output = bytearray(), bytearray()
        peer_go = []
        original_engine = worker._Engine
        generated, certificate = synthetic_container()

        def make_engine(started):
            result = original_engine(started)
            made.append(result)
            return result

        def fake_caw(argv, **options):
            # This is deliberately NOT a successful real process receipt.
            # No process is ever admitted, so the real ledger's idle predicate
            # permits disposal of these wholly synthetic, task-owned files.
            operation = made[0].operation
            source = operation.source
            commands.append((operation.pending, tuple(argv), options,
                operation.admitted, source.go_returned, source_domain(source),
                source.guard._saved_command_input() is source))
            number = operation.scratch.file.number
            before = os.fstat(number)
            if operation.pending == "generate":
                jks.check_empty(os.pread(number, wire.JKS_LIMIT, 0), b"a" * 64)
                if os.pwrite(number, generated, 0) != len(generated):
                    raise AssertionError("synthetic fixture write was incomplete")
                os.ftruncate(number, len(generated))
                os.fsync(number)
            after = os.fstat(number)
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or os.pread(number, wire.JKS_LIMIT, 0) != generated):
                raise AssertionError("synthetic output lost its original inode")
            return subprocess.CompletedProcess(argv, 0,
                certificate if operation.pending == "export" else b"",
                b"synthetic-private-keytool-note")

        def final_seam(argv, **options):
            seam_calls.append(made[0].operation.pending)
            if changed == "saved-config":
                config.write_bytes(original_config + b"\n")
            elif changed == "environment":
                options["environ"] = {**options["environ"], "UNREVIEWED_FIXTURE": "1"}
            # Not a replacement dispatcher: the ORIGINAL closed admission and
            # source recheck must reject changes before fake_caw is reachable.
            return run_owned(argv, **options)

        original_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        parent_environment = dict(os.environ)
        saved_fds, owned_fds = [], set()
        peer = None

        def close_fixture_fd(number):
            if number in owned_fds:
                owned_fds.remove(number)
                os.close(number)

        try:
            for number in (0, 1, 2):
                saved_fds.append(os.dup(number))
            pairs = []
            for standard in (0, 1, 2):
                reader, writer = os.pipe()
                owned_fds.update((reader, writer))
                pairs.append((reader, writer))
                os.dup2(reader if standard == 0 else writer, standard)
                close_fixture_fd(reader if standard == 0 else writer)
            input_writer, output_reader, error_reader = pairs[0][1], pairs[1][0], pairs[2][0]
            for number in (input_writer, output_reader, error_reader):
                os.set_blocking(number, False)
            # A short actual work endpoint makes late-GO finite without
            # replacing poll, guard.check, sleep or deadline decisions.
            value["clock"]["workEndNs"] = time.monotonic_ns() + (
                400_000_000 if go == "late" else 5_000_000_000)
            value["clock"]["hardEndNs"] = value["clock"]["workEndNs"] + 10_000_000_000
            request_raw = encoded(value)
            request = wire.parse_request(request_raw)
            if os.write(input_writer, request_raw) != len(request_raw):
                raise AssertionError("synthetic request write was incomplete")

            def pipe_peer():
                open_readers = {output_reader: output, error_reader: error_output}
                responded = False
                end = time.monotonic() + 3
                try:
                    while open_readers:
                        if time.monotonic() >= end:
                            raise AssertionError("bounded synthetic peer timed out")
                        readable, _, _ = select.select(list(open_readers), [], [], 0.025)
                        for number in readable:
                            block = os.read(number, 4096)
                            if not block:
                                del open_readers[number]
                                continue
                            open_readers[number].extend(block)
                            if len(output) > wire.RESPONSE_LIMIT or len(error_output) > 1024:
                                raise AssertionError("synthetic private pipe exceeded its bound")
                        if not responded and len(output) >= wire.READY_LENGTH:
                            if bytes(output[:wire.READY_LENGTH]) != wire.ready(request):
                                raise AssertionError("worker did not emit the original READY")
                            responded = True
                            if go == "stop-eof":
                                close_fixture_fd(input_writer)
                                continue
                            payload = private_go(request)
                            if go == "wrong":
                                payload[len(wire.GO_MAGIC)] ^= 1
                            elif go == "late":
                                # Use the original parsed/clamped endpoint,
                                # not a new budget or a fake stop flag.
                                time.sleep(max(0, made[0].input.work_end - time.monotonic()) + 0.015)
                            elif go == "stop-after-go":
                                payload += b"\n"  # Actual active-source STOP byte.
                            peer_go.append(go)
                            try:
                                if os.write(input_writer, payload) != len(payload):
                                    raise AssertionError("synthetic GO write was incomplete")
                            except BrokenPipeError:
                                if go != "late":
                                    raise
                except BaseException as error:
                    peer_errors.append(error)
                finally:
                    for number in (input_writer, output_reader, error_reader):
                        close_fixture_fd(number)

            peer = threading.Thread(target=pipe_peer, name="upload-key-synthetic-pipe-peer")
            peer.start()
            with patch.object(worker, "_Engine", side_effect=make_engine), \
                 patch.object(worker, "sys", SimpleNamespace(platform="darwin", exc_info=sys.exc_info)), \
                 patch.object(worker, "os", native_os), \
                 patch.object(worker, "Path", return_value=scratch_parent), \
                 patch.object(control, "time", native_time), \
                 patch.object(worker, "run_owned", side_effect=final_seam), \
                 patch("mobile_release._command_process.run_command", side_effect=fake_caw):
                result = worker.main(started=time.monotonic())
        finally:
            # The peer uses only nonblocking pipes + a three-second deadline.
            # Restore the caller's descriptors and positively join BEFORE any
            # assertion or fixture removal, including failure paths.
            for standard, original in enumerate(saved_fds):
                os.dup2(original, standard)
                os.close(original)
            if peer is not None:
                peer.join()
            for number in tuple(owned_fds):
                close_fixture_fd(number)

        engine = made[0]
        retained = engine in worker._RETAINED
        if retained:
            # Only this no-process synthetic fixture is retired from the test
            # global; report the actual retained/unknown result to assertions.
            worker._RETAINED.remove(engine)
        return SimpleNamespace(engine=engine, result=result, output=bytes(output), error=bytes(error_output),
            peer_errors=peer_errors, peer_go=peer_go, request=request, commands=commands, seam_calls=seam_calls,
            generated=generated, certificate=certificate, retained=retained,
            scratch_exists=engine.operation.scratch.path.exists(),
            config_after=config.read_bytes(), original_config=original_config,
            environment_unchanged=dict(os.environ) == parent_environment,
            handlers_restored=all(signal.getsignal(sig) is original for sig, original in original_handlers.items()))


class UploadKeyEngineTests(unittest.TestCase):
    def settled_terminal(self, result, status):
        self.assertEqual(result.peer_errors, [])
        self.assertEqual(result.result, 0)  # Clean private protocol, not success/finality.
        self.assertEqual(result.error, b"")
        self.assertEqual(result.output[:wire.READY_LENGTH], wire.ready(result.request))
        header = result.output[wire.READY_LENGTH:wire.READY_LENGTH + wire.END_HEADER_LENGTH]
        self.assertEqual(header[:len(wire.END_MAGIC)], wire.END_MAGIC)
        self.assertEqual(header[len(wire.END_MAGIC):len(wire.END_MAGIC) + 64],
                         (result.request.id + result.request.generation).encode())
        index, key_size, certificate_size = struct.unpack(">BII", header[-9:])
        self.assertEqual(wire.STATUSES[index], status)
        self.assertEqual(len(result.output), wire.READY_LENGTH + wire.END_HEADER_LENGTH + key_size + certificate_size)
        if status != "ok":
            self.assertEqual((key_size, certificate_size), (0, 0))
        engine, operation = result.engine, result.engine.operation
        self.assertTrue(engine.terminal_claimed and engine.frames == 2)
        self.assertTrue(operation.closed and operation.saved.closed and operation.scratch.closed)
        self.assertFalse(operation.unknown or result.retained or result.scratch_exists)
        self.assertTrue(engine.input.closed and engine.output.closed and engine.error_output.closed)
        self.assertEqual(engine.guard.handler_state, "RESTORED")
        self.assertTrue(result.handlers_restored and result.environment_unchanged)
        self.assertFalse(any(engine.input.private_go) or any(operation.scratch.raw) or any(operation.saved.raw))
        self.assertIsNone(operation.certificate)
        self.assertIsNone(operation.command_result)
        return key_size, certificate_size

    def test_actual_ready_go_generate_export_private_terminal_and_cleanup(self):
        result = engine_fixture()
        self.assertEqual(self.settled_terminal(result, "ok"), (len(result.generated), len(result.certificate)))
        self.assertEqual(result.output[wire.READY_LENGTH + wire.END_HEADER_LENGTH:], result.generated + result.certificate)
        self.assertEqual(result.peer_go, ["valid"])
        self.assertEqual(result.seam_calls, ["generate", "export"])
        self.assertEqual([row[0] for row in result.commands], ["generate", "export"])
        operation = result.engine.operation
        for role, argv, options, admitted, go_returned, domain, bound in result.commands:
            self.assertEqual(admitted, role)
            self.assertTrue(go_returned and bound)
            self.assertIs(domain, SavedCommandDomain.GenerateUploadKey)
            self.assertEqual(argv, result.request.arguments(operation.scratch.path, export=role == "export"))
            self.assertIs(options["cancellation"], result.engine.guard)
            self.assertIs(options["capture"], True)
            self.assertIs(options["text"], False)
            self.assertEqual(options["output_limit"], wire.COMMAND_OUTPUT_LIMIT)
            self.assertGreaterEqual(options["timeout"], 1)
            self.assertLessEqual(options["timeout"], 5)
            self.assertEqual(options["cwd"], operation.scratch.path)
            self.assertEqual(set(options["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL",
                wire.STORE_PASSWORD_ENV, wire.KEY_PASSWORD_ENV})
            self.assertEqual(options["environ"][wire.STORE_PASSWORD_ENV], "a" * 64)
            self.assertEqual(options["environ"][wire.KEY_PASSWORD_ENV], "b" * 64)
            self.assertNotIn("a" * 64, " ".join(argv))
            self.assertNotIn("b" * 64, " ".join(argv))
        self.assertEqual(result.config_after, result.original_config)

    def test_wrong_or_late_go_and_actual_stop_never_dispatch_generation(self):
        for go, status in (("wrong", "refused"), ("late", "timed-out"),
                           ("stop-eof", "cancelled"), ("stop-after-go", "cancelled")):
            with self.subTest(go=go):
                result = engine_fixture(go=go)
                self.settled_terminal(result, status)
                self.assertEqual(result.seam_calls, [])
                self.assertEqual(result.commands, [])
                self.assertFalse(result.engine.operation.generated or result.engine.operation.exported)
                self.assertTrue(result.engine.input.go_claimed)
                self.assertEqual(result.engine.input.go_returned, go == "stop-after-go")
                self.assertEqual(result.config_after, result.original_config)

    def test_final_original_run_owned_seam_rechecks_saved_config_and_environment(self):
        for changed in ("saved-config", "environment"):
            with self.subTest(changed=changed):
                result = engine_fixture(changed=changed)
                self.settled_terminal(result, "refused")
                self.assertEqual(result.seam_calls, ["generate"])
                self.assertEqual(result.commands, [])
                self.assertTrue(result.engine.input.go_returned)
                self.assertIsNone(result.engine.operation.admitted)
                self.assertFalse(result.engine.operation.generated or result.engine.operation.exported)
                self.assertIsInstance(result.engine.primary, wire.ProtocolError)
                self.assertEqual(result.config_after,
                    result.original_config + (b"\n" if changed == "saved-config" else b""))


if __name__ == "__main__":
    unittest.main()
