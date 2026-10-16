"""Fixed publication helper with real tiny file/journal custody and inert HTTP.

No credentials, TLS, network, native child or renderer consent is supplied.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _desktop_github_setup_engine as entry
from mobile_release import _github_connection_transport as transport
from mobile_release import _github_setup_publication_runtime as runtime
from mobile_release import _github_setup_publication_transport as live
from mobile_release import github_setup_secret_inputs as inputs
from mobile_release import github_setup_publication as policy
from test_github_setup_publication import Reader, target, source


class PublicationRuntimeTests(unittest.TestCase):
    def setUp(self):
        holder = tempfile.TemporaryDirectory(prefix="mrk-publication-test-")
        self.addCleanup(holder.cleanup)
        self.home = Path(holder.name)
        self.root = self.home / "project"; self.root.mkdir()
        (self.root / "release").mkdir()
        self.path = self.root / policy.CONFIG_PATH
        self.raw = source().files[0]; self.path.write_bytes(self.raw)
        details = self.root.stat()
        self.capture = {"root": str(self.root), "rootIdentity": {"device": str(details.st_dev),
            "inode": str(details.st_ino), "mode": details.st_mode, "uid": details.st_uid, "gid": details.st_gid}}
        self.reader = Reader()

    def initial(self, kind, prepared=None):
        return policy._canonical({"protocol": policy.PROTOCOL, "id": "publication_fixture", "action": {
            "kind": kind, "target": target().value(), "source": self.capture if kind in {"prepare", "publish"} else None,
            "home": None if kind == "prepare" else str(self.home),
            "preparedSha256": None if prepared is None else hashlib.sha256(policy._canonical(prepared)).hexdigest()}}) + b"\n"

    def go(self, request, prepared=None):
        return policy._canonical({"protocol": policy.PROTOCOL, "id": request.id, "go": {
            "requestSha256": request.digest, "token": None if request.kind == "pending" else "INERT_TOKEN",
            "prepared": prepared}}) + b"\n"

    def factory(self, token, **kwargs):
        self.assertEqual(token, "INERT_TOKEN")
        budget = kwargs["_setup_budget"]
        self.assertIs(budget.profile, transport._ExchangeProfile.PUBLICATION)
        self.assertEqual(budget.end, budget.started + 60)
        def send(method, path, body, *, _role):
            transport._request_limits(budget.profile, _role, method, path)
            return self.reader(policy.HttpRequest(method, path, body))
        return send

    def run_operation(self, kind, prepared=None):
        request = runtime.parse_initial(self.initial(kind, prepared))
        token, retained = runtime.parse_go(self.go(request, prepared), request)
        with patch.object(live, "_make_live_exchange", side_effect=self.factory):
            result = runtime.execute(request, token, retained, started=time.monotonic(), runtime_dir="/inert")
        encoded = runtime.encode_result(request, result)
        self.assertNotIn(b"INERT_TOKEN", encoded)
        self.assertNotIn(str(self.root).encode(), encoded)
        return result

    def test_real_capture_prepare_publish_restart_pending_and_readonly_reconciliation(self):
        result = self.run_operation("prepare")
        self.assertEqual(result["reason"], "none")
        self.assertEqual(result["configuration"]["savedConfig"], policy._fingerprint(self.raw))
        self.assertEqual(policy.Prepared.parse(result["prepared"]).source.files[0], self.raw)
        self.assertTrue(all(row.method == "GET" for row in self.reader.calls))
        prepared = result["prepared"]
        self.reader.fail_phase = "pull"
        result = self.run_operation("publish", prepared)
        self.assertEqual(result["publication"]["effect"], "potentially-applied")
        self.assertEqual(result["publication"]["claimed"], list(policy.PHASES))
        before = len(self.reader.calls)
        pending = self.run_operation("pending")["pending"]
        self.assertEqual(len(self.reader.calls), before)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["claimed"], list(policy.PHASES))
        self.assertNotIn(self.raw.decode(), json.dumps(pending))
        self.reader.fail_phase = None
        result = self.run_operation("reconcile")
        self.assertEqual(result["publication"]["effect"], "draft-pr-observed")
        self.assertTrue(all(row.method == "GET" for row in self.reader.calls[before:]))
        leaves = self.home / ".local/share/mobile-release-kit/github-setup-publication"
        self.assertTrue(all(row.stat().st_mode & 0o777 == 0o400 for row in leaves.iterdir()))
        # Reopened durable state is not permission to publish the same review.
        before = len(self.reader.calls)
        duplicate = self.run_operation("publish", prepared)
        self.assertEqual(duplicate["reason"], "branch-exists")
        self.assertTrue(all(row.method == "GET" for row in self.reader.calls[before:]))

    def test_capture_remains_original_oneuse_and_old_setup_profile_is_not_promoted(self):
        owner = transport._Budget(time.monotonic(), _profile=transport._ExchangeProfile.PUBLICATION)
        with inputs.observe_publication_configuration(self.capture, budget=owner) as actual:
            self.assertEqual(actual.saved_bytes(), self.raw)
            for _ in range(50): actual.checkpoint()  # More requests, not renewed time or byte quota.
            ledger = actual._budget
        self.assertTrue(ledger.closed); self.assertFalse(ledger.handles)
        self.assertEqual(ledger.live, 0)
        with self.assertRaises(inputs.SecretConfigurationError): actual.saved_bytes()
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_publication_configuration(self.capture, budget=owner): pass
        ordinary = transport._Budget(time.monotonic(), _profile=transport._ExchangeProfile.SETUP)
        with self.assertRaises(inputs.SecretConfigurationError):
            with inputs.observe_publication_configuration(self.capture, budget=ordinary): pass
        self.assertEqual(ordinary.end, ordinary.started + 10)

    def test_changed_config_and_unsafe_alias_refuse_before_http(self):
        prepared = self.run_operation("prepare")["prepared"]
        self.reader.calls.clear()
        self.path.write_bytes(self.raw.replace(b'"main"', b'"changed"'))
        result = self.run_operation("publish", prepared)
        self.assertEqual(result["reason"], "source-changed")
        self.assertEqual(self.reader.calls, [])
        self.path.write_bytes(self.raw)
        alias = self.path.with_name("MOBILE-RELEASE.JSON"); alias.write_bytes(self.raw)
        result = self.run_operation("prepare")
        self.assertEqual(result["reason"], "configuration-changed")
        self.assertEqual(self.reader.calls, [])

    def test_closed_initial_and_private_go_bind_original_exact_review(self):
        prepared = policy.prepare(target(), source(), self.reader).view()
        request = runtime.parse_initial(self.initial("publish", prepared))
        token, restored = runtime.parse_go(self.go(request, prepared), request)
        self.assertEqual(token, "INERT_TOKEN"); self.assertEqual(restored.view(), prepared)
        for mutate in (lambda row: row["go"].update(requestSha256="0" * 64),
                       lambda row: row["go"]["prepared"]["files"][0].update(path="release/version.properties"),
                       lambda row: row["go"]["prepared"].update(confirmation="auto approved")):
            value = json.loads(self.go(request, prepared)); mutate(value)
            with self.assertRaises(ValueError):
                runtime.parse_go(policy._canonical(value) + b"\n", request)
        for mutate in (lambda row: row["action"].update(kind="dispatch"),
                       lambda row: row["action"]["source"].update(path="arbitrary"),
                       lambda row: row.update(token="INERT_TOKEN")):
            value = json.loads(self.initial("publish", prepared)); mutate(value)
            with self.assertRaises(ValueError): runtime.parse_initial(policy._canonical(value) + b"\n")

    def test_cooldown_survives_failure_and_actual_journal_close_vetoes_result(self):
        reader = self.reader
        def limited(request):
            return transport.ReadResult({"status": 403, "body": None, "failure": "none"},
                                        transport._control("rate-limited", delay=17))
        self.reader = limited
        result = self.run_operation("prepare")
        self.assertEqual(result["reason"], "rate-limited")
        self.assertEqual(result["control"]["cooldownSeconds"], 17)
        self.reader = reader
        request = runtime.parse_initial(self.initial("pending"))
        closed = []
        class FailedClose(runtime.Journal):
            def close(self):
                super().close(); closed.append(self)
                raise OSError("inert lost close outcome")
        with patch.object(runtime, "Journal", FailedClose), self.assertRaises(OSError):
            runtime.execute(request, None, None, started=time.monotonic(), runtime_dir="/inert")
        self.assertEqual(len(closed), 1)
        self.assertTrue(closed[0].closed); self.assertFalse(closed[0].ancestors)

    def test_same_setup_entry_dispatches_publication_but_preserves_all_original_fd_closes(self):
        raw = self.initial("prepare")
        retired = []
        def close(fd):
            retired.append(fd)
            if fd == 102: raise OSError("inert close failure")
        descriptors = iter((101, 102))
        proxy = SimpleNamespace(path=os.path, devnull=os.devnull, O_RDONLY=os.O_RDONLY,
            dup=lambda _: next(descriptors), set_inheritable=lambda *_: None, open=lambda *_: 103,
            dup2=lambda *args, **kwargs: None, close=close)
        started = time.monotonic()
        with patch.object(entry, "os", proxy), patch.object(entry, "_read_initial", return_value=raw) as initial, \
             patch.object(runtime, "run_owned") as run:
            self.assertEqual(entry.main(started=started, runtime_dir="/inert"), 74)
        self.assertEqual(retired, [103, 102, 101])
        self.assertEqual(initial.call_args.args[1], started + 10)
        self.assertEqual(run.call_args.kwargs["started"], started)
        self.assertEqual(run.call_args.args, (101, 102, raw))
