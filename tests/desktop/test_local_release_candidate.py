"""Real tiny retained files; inert original Android build/native boundaries.

The existing service fixture supplies synthetic producer/command finality. This
does not execute Gradle/JDK/native tools or prove real signing/parent settlement.
Checked-reader descriptors, retained bytes, drift checks and consuming closes
are real. Actual service run/terminal ordering and existing projection are used.
"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import test_android_build_protocol as protocol
import test_android_build_service as service_data
from mobile_release import local_release_candidate as C
from mobile_release import desktop_android_build as service
from mobile_release._desktop_android_build_files import AndroidFileError
from mobile_release.android_build_signing import SignedAndroidOperation
from mobile_release.build_inputs import _file
from mobile_release.config import ReleaseConfig
from mobile_release.owned_process import ProcessCleanupError


class LocalAndroidHandoffTests(unittest.TestCase):
    def patched(self, target, name, *args, **kwargs):
        return self.stack.enter_context(patch.object(target, name, *args, **kwargs))

    def forbidden(self, target, name):
        return self.patched(target, name, side_effect=AssertionError("unexpected native boundary"))

    def setUp(self):
        self.assertNotEqual(os.getuid(), 0)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-handoff-")
        self.addCleanup(self.temporary.cleanup)
        self.patched(os, "getpid", return_value=1234)  # Existing inert original identities only.
        # Native profile admission is an inert service boundary. Keep the real
        # Linux checked-reader ancestry rules for the actual namespace files.
        self.patched(service, "PROFILES", new={key: ("linux", *value[1:])
                     for key, value in service.PROFILES.items()})
        self.patched(service.os, "getcwd", return_value="/inert/cwd")
        self.source_fds = []
        self.addCleanup(self.close_sources)

    def close_sources(self):
        for fd in self.source_fds:
            if fd is not None:
                os.close(fd)

    def subject(self):
        f = service_data._InertRun(self, signature=True)
        root = Path(self.temporary.name) / ("case-" + str(len(self.source_fds)))
        root.mkdir(mode=0o700)
        op, source = f.operation, f.source
        op.root = root
        op.inputs = f.bound = replace(f.bound, config=ReleaseConfig(root / "release/mobile-release.json", root, f.bound.config.data))
        f.namespace.root = root
        path = f.artifact.path
        path.parent.mkdir(parents=True, mode=0o700)
        body = b"tiny signed-artifact stand-in; never interpreted or executed\n"
        path.write_bytes(body)
        path.chmod(0o600)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        fd_index = len(self.source_fds)
        self.source_fds.append(fd)
        from types import SimpleNamespace
        f.artifact._snapshot = SimpleNamespace(identity=_file(os.fstat(fd)))
        f.artifact._reader = None
        f.artifact.size, f.artifact.sha256 = len(body), hashlib.sha256(body).hexdigest()
        def artifact_check():
            if (_file(os.fstat(fd)) != f.artifact._snapshot.identity
                    or _file(os.stat(path, follow_symlinks=False)) != f.artifact._snapshot.identity):
                raise AndroidFileError("artifact-changed")
        f.artifact.check.side_effect = artifact_check
        source.work_end = time.monotonic() + 60
        data = protocol.signed_request_data()
        for key in ("savedConfig", "savedVersion", "artifactValidation"):
            data["context"][key] = f.request.context[key]
        data["native"].update(projectRoot=str(root), cwd="/inert/cwd")
        request = protocol.wire.parse_request(protocol.encoded(data))
        f.request = f.run.request = op.request = request
        source.signed = True
        op.signing = signing = SignedAndroidOperation(op)
        signing.phase = "inspecting"
        self.patched(signing, "closed", return_value=True)
        self.patched(source, "material_closed", return_value=True)
        def signed(_bound):
            f.events.append("inert-signed-body")
            op._roles = {role: "returned" for role in ("keytool-input", "gradle", "aab-sign", "bundletool", "jarsigner", "keytool")}
            op._returned = {role: 0 for role in op._roles}
            op._signature_passed = True
            f.ledger._commands, f.ledger._command_dispatched = 6, True
            f.disposition.update(work="retained-work", artifacts="retained-incomplete")
        self.patched(f.run, "_signed_body", side_effect=signed)
        def inspect(*args, **kwargs):
            f.events.append("inspect")
            op.zip_metadata = f.metadata
            return f.findings
        f.inspect_call.side_effect = inspect
        def close():
            f.close()
            os.close(fd)
            self.source_fds[fd_index] = None
        op.close.side_effect = close
        return f, path, body

    def settle(self, f):
        f.settle_outer()  # Inert existing source/handler finality, never native proof.
        terminal = f.run.terminal()
        self.assertEqual(terminal["outcome"], "complete")
        return terminal

    def test_service_retains_same_artifact_before_close_and_joins_only_original_terminal(self):
        f, path, body = self.subject()
        before = len(os.listdir("/proc/self/fd"))
        real_capture = C.LocalAndroidBuildHandoff._capture
        def capture(handoff, run, artifact):
            self.assertIn("finish-work", f.events)
            self.assertNotIn("operation-close", f.events)
            f.events.append("handoff-capture")
            return real_capture(handoff, run, artifact)
        with patch.object(C.LocalAndroidBuildHandoff, "_capture", new=capture):
            with C.retain_android_build_inputs(f.run) as handoff:
                f.run.run()
                self.assertTrue(handoff.captured)
                self.assertFalse(handoff.producer_joined)
                with self.assertRaises(C.LocalCandidateError): handoff.observation()
                self.assertLess(f.events.index("handoff-capture"), f.events.index("operation-close"))
                self.settle(f)
                observed = handoff.observation()
                self.assertTrue(observed["producerCoreSettled"])
                self.assertFalse(observed["candidatePrepared"] or observed["storeAuthorized"])
                self.assertEqual(observed["outerTransportFinality"], "not-established")
                self.assertEqual(observed["inspection"]["artifacts"][0]["freshness"], "not-established")
                self.assertEqual(observed["inspection"]["assurances"]["sourceBinding"], "not-established")
                self.assertNotIn("PRIVATE_", json.dumps(observed))
                observed["inspection"]["artifacts"][0]["sha256"] = "e" * 64
                self.assertEqual(handoff.observation()["inspection"]["artifacts"][0]["sha256"],
                                 hashlib.sha256(body).hexdigest())
                self.assertEqual(handoff.saved_inputs(), (f.bound.saved.configuration.raw, f.bound.saved.version_raw))
                with handoff.artifact_blocks() as blocks:
                    self.assertEqual(b"".join(blocks), body)
                self.assertEqual(_file(os.fstat(handoff.reader._number(handoff.node.slot))), _file(path.stat()))
            self.assertTrue(handoff.closed)
            self.assertTrue(all(slot.state == "CLOSED" for slot in handoff.reader.descriptors))
            self.assertEqual(len(os.listdir("/proc/self/fd")), before - 1)  # Producer FD also closed.
            self.assertEqual(path.read_bytes(), body)
            with self.assertRaises(C.LocalCandidateError): handoff.observation()
        f.build_call.assert_not_called()  # The signed/native body was explicitly inert.

    def test_only_original_signed_pre_dispatch_registration_is_accepted(self):
        f, _, _ = self.subject()
        with patch.object(C, "_Reader") as reader:
            with self.assertRaises(C.LocalCandidateError): C.LocalAndroidBuildHandoff({"result": "old report"})
            f.run._run_claimed = True
            with self.assertRaises(C.LocalCandidateError): C.LocalAndroidBuildHandoff(f.run)
            f.run._run_claimed = False
            f.operation.signing = None
            with self.assertRaises(C.LocalCandidateError): C.LocalAndroidBuildHandoff(f.run)
            reader.assert_not_called()

    def test_replaced_snapshot_or_mismatched_saved_bytes_never_capture(self):
        for fault in ("snapshot", "saved-bytes"):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                real_acquire = C._Reader.acquire
                def acquire(reader, selected, policy, project):
                    path.unlink()
                    path.write_bytes(b"foreign replacement")
                    path.chmod(0o600)
                    return real_acquire(reader, selected, policy, project)
                if fault == "snapshot":
                    context = patch.object(C._Reader, "acquire", new=acquire)
                else:
                    real_used = f.operation.used_inputs
                    def used():
                        config, version = real_used()
                        config["sha256"] = "e" * 64
                        return config, version
                    context = patch.object(f.operation, "used_inputs", side_effect=used)
                with context, C.retain_android_build_inputs(f.run) as handoff:
                    with self.assertRaises(C.LocalCandidateError): f.run.run()
                    self.assertTrue(handoff.failed)
                    self.assertFalse(handoff.captured)
                    with self.assertRaises(C.LocalCandidateError): handoff.observation()
                self.assertTrue(path.exists())

    def test_early_unknown_terminal_is_absorbing_not_later_adopted(self):
        f, _, _ = self.subject()
        with C.retain_android_build_inputs(f.run) as handoff:
            f.run.run()
            self.assertEqual(f.run.terminal()["outcome"], "unknown")
            self.assertTrue(handoff.failed)
            self.settle(f)
            self.assertFalse(handoff.producer_joined)
            with self.assertRaises(C.LocalCandidateError): handoff.observation()

    def test_original_producer_close_failure_vetoes_provisional_handoff(self):
        f, path, body = self.subject()
        original = f.operation.close.side_effect
        failure = ProcessCleanupError("PRIVATE_CLOSE", dispatched=True, contained=False)
        def close():
            original()
            raise failure
        f.operation.close.side_effect = close
        with C.retain_android_build_inputs(f.run) as handoff:
            with self.assertRaises(ProcessCleanupError) as caught: f.run.run()
            self.assertIs(caught.exception, failure)
            self.assertIs(f.run.primary, failure)
            self.assertTrue(handoff.captured and handoff.failed)
            self.assertFalse(handoff.producer_joined)
            with self.assertRaises(C.LocalCandidateError): handoff.observation()
        self.assertEqual(path.read_bytes(), body)

    def test_reader_original_close_lost_return_is_not_retried_or_deleted(self):
        f, path, body = self.subject()
        original_close, target, attempts = os.close, [None], []
        def close(fd):
            original_close(fd)
            if fd == target[0]:
                attempts.append(fd)
                raise OSError("PRIVATE_CLOSE")
        with patch.object(os, "close", side_effect=close):
            with self.assertRaises(ProcessCleanupError):
                with C.retain_android_build_inputs(f.run) as handoff:
                    f.run.run()
                    self.settle(f)
                    target[0] = handoff.reader._number(handoff.node.slot)
        self.assertEqual(attempts, [target[0]])
        self.assertTrue(handoff.failed and handoff.closed)
        self.assertTrue(all(slot.number is None for slot in handoff.reader.descriptors))
        self.assertEqual(path.read_bytes(), body)

    def test_read_budget_and_abandoned_read_cannot_mint_consumption(self):
        for fault in ("budget", "abandoned", "partial"):
            with self.subTest(fault=fault):
                f, _, body = self.subject()
                with C.retain_android_build_inputs(f.run) as handoff:
                    f.run.run()
                    self.settle(f)
                    if fault == "budget":
                        for _ in range(2):
                            with handoff.artifact_blocks() as blocks: self.assertEqual(b"".join(blocks), body)
                        with self.assertRaises(C.LocalCandidateError):
                            with handoff.artifact_blocks() as blocks: list(blocks)
                    else:
                        with self.assertRaises(C.LocalCandidateError):
                            with handoff.artifact_blocks() as blocks:
                                if fault == "partial": next(blocks)
                    self.assertTrue(handoff.failed)

    def test_capture_hash_cancel_and_fd_quote_fail_before_handoff_use(self):
        for fault in ("hash", "cancel", "fd-cap"):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                original = os.pread
                interrupted = KeyboardInterrupt()
                altered = [False]
                def read(fd, size, offset):
                    body = original(fd, size, offset)
                    if not altered[0] and size > 1:
                        altered[0] = True
                        if fault == "cancel": raise interrupted
                        if fault == "hash": return bytes([body[0] ^ 1]) + body[1:]
                    return body
                with ExitStack() as stack:
                    stack.enter_context(patch.object(os, "pread", side_effect=read))
                    reader = None
                    if fault == "fd-cap":
                        stack.enter_context(patch.object(C, "MAX_HANDOFF_FDS", len(path.parts) + 1))
                        reader = stack.enter_context(patch.object(C, "_Reader"))
                    with C.retain_android_build_inputs(f.run) as handoff:
                        with self.assertRaises(KeyboardInterrupt if fault == "cancel" else C.LocalCandidateError) as caught:
                            f.run.run()
                        if fault == "cancel": self.assertIs(caught.exception, interrupted)
                        self.assertTrue(handoff.failed)
                        self.assertFalse(handoff.captured or handoff.producer_joined)
                    if reader is not None:
                        reader.assert_not_called()
                        self.assertFalse(altered[0])
                self.assertTrue(path.exists())

    def test_drift_and_original_deadline_after_core_join_withhold_use(self):
        for fault in ("changed", "deadline"):
            with self.subTest(fault=fault):
                f, path, _ = self.subject()
                with C.retain_android_build_inputs(f.run) as handoff:
                    f.run.run()
                    self.settle(f)
                    if fault == "changed": path.write_bytes(b"changed original bytes")
                    else: f.source.work_end = time.monotonic() - 1
                    with self.assertRaises(Exception): handoff.observation()


if __name__ == "__main__":
    unittest.main()
