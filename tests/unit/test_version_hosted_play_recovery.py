"""Actual Journal/Material/source transitions with inert transport/child doubles.

No Git, Ruby, provider, credential or native receipt runs in these tests. Real
OpenSSL and the actual SDK command sequence have separate Ruby ABI tests. The
opaque capsules here are deliberately structural DATA, never crypto evidence.
"""
import base64
from contextlib import contextmanager, ExitStack, redirect_stderr, redirect_stdout
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tomllib
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import version_hosted as h
from mobile_release import version_hosted_play_recovery as recovery
from mobile_release import version_hosted_store as store
from mobile_release import version_ci as ci
from test_version_hosted_platforms import Case, environment
from test_version_ci import NOW


def opaque(aad, version="inert-v1"):
    # Structural ciphertext fixture only. Never decrypted by a real provider.
    return recovery.Capsule(version, base64.b64encode(b"N" * 12).decode(),
        base64.b64encode(b"opaque INERT cipher bytes").decode(), base64.b64encode(b"T" * 16).decode(),
        hashlib.sha256(aad).hexdigest())


class HostedPlayRecoveryTests(unittest.TestCase):
    @contextmanager
    def case(self, schema=3, *, opt_in=True):
        with TemporaryDirectory() as temporary, ExitStack() as stack:
            c = Case(self, Path(temporary), schema)
            env = environment(c.platform)
            if opt_in:
                env.update({recovery.KEY: base64.b64encode(b"K" * 32).decode(), recovery.VERSION: "inert-v1"})
            stack.enter_context(patch.dict(os.environ, env, clear=True))
            stack.enter_context(patch.object(ci.time, "monotonic", lambda: c.clock))
            stack.enter_context(patch.object(h.time, "time", lambda: NOW + .75))
            stack.enter_context(patch.object(ci, "run_owned", c.git))
            stack.enter_context(patch.object(store, "finite_scratch", c.scratch))
            stack.enter_context(patch.object(recovery, "finite_scratch", c.scratch))
            stack.enter_context(patch.object(subprocess, "Popen", side_effect=AssertionError("no process permitted")))
            c.source = h._Source(c.root, c.context, SimpleNamespace(check=c.current))
            c.source.capture(); c.source.checked_ca(c.tooling)
            c.material = store.Material(c.tooling, platform=c.platform)
            c.source.material = c.material
            c.remote = h._Remote(c.fixture.authority, c.source, c.send)
            c.recovery_calls = []
            stack.enter_context(patch.object(store, "run_owned", lambda argv, **kw: self.inventory(c, argv, **kw)))
            stack.enter_context(patch.object(recovery, "run_owned", lambda argv, **kw: self.cleanup_child(c, argv, **kw)))
            yield c

    def inventory(self, c, argv, **kw):
        if tuple(argv) == h.ios.fixed_argv(c.tooling):
            return c.child(argv, **kw)
        self.assertEqual(tuple(argv), h.android.fixed_argv(c.tooling))
        env = kw["environ"]
        c.provider_calls.append("android"); c.events.append(("child", "android"))
        self.assertFalse({h.TOKEN_ENV, "GH_TOKEN", *store._IOS} & env.keys())
        self.assertEqual(kw["output_limit"], h.android.FRAME_LIMIT)
        self.assertIs(kw["cancellation"], c.source.guard)
        self.assertEqual(int(env["MOBILE_RELEASE_PLAY_HARD_END_NS"]), (c.source.end - 8) * 10**9)
        self.assertEqual(kw["timeout"], int(c.source.end - 8 - c.clock))
        pending = h.Envelope.parse(c.repo.journal).play_query
        self.assertIsNotNone(pending)
        self.assertIsNone(pending.recovery)
        aad = json.loads(env[recovery.AAD])
        self.assertEqual((aad["candidateId"], aad["attemptId"], aad["requestSha256"]),
                         (pending.candidate_id, pending.attempt_id, pending.request_sha256))
        frame = c.play_frame(env["MOBILE_RELEASE_PLAY_CONTEXT"])
        if not frame["temporaryEdit"]["deleteConfirmed"]:
            frame["queryFinished"] = False # Actual Ruby failed() contracts this flag.
        frame["hostedRecovery"] = (opaque(env[recovery.AAD].encode()).value()
            if frame["temporaryEdit"]["insertAttempted"] and not frame["temporaryEdit"]["deleteConfirmed"] else None)
        if c.after_child:
            c.after_child(frame)
        if c.failure == "child-unknown":
            raise OSError("INERT unjoined child")
        if c.failure == "late": c.clock = c.source.end
        return subprocess.CompletedProcess(argv, 1 if c.failure == "nonzero" else 0,
            h.p.canonical(frame) + b"\n", b"INERT stderr" if c.failure == "stderr" else b"")

    def retain(self, c):
        c.failure = "delete"
        with self.assertRaises(h.Refused) as error:
            c.reserve()
        self.assertEqual(error.exception.reason, "play-recovery")
        value = h.Envelope.parse(c.repo.journal)
        self.assertEqual(value.schema_version, 3)
        self.assertIsNotNone(value.play_query.recovery)
        self.assertIsNone(value.play_query.recovery.claim)
        self.assertEqual(c.repo.ledger_puts, 0)
        return value

    def restart_cleanup(self, c, retained):
        c.failure = c.after_child = c.after_write = None
        for key in store._IOS: os.environ.pop(key, None)
        os.environ["MOBILE_RELEASE_OPERATION"] = "recover-play-edit"
        os.environ.pop(h.POLICY_ENV, None)
        original = retained.play_query
        c.context = replace(c.context, confirmation=f"recover-play-edit:{original.candidate_id}:{original.attempt_id}",
            authority={**c.context.authority, "attempt": c.context.authority["attempt"] + 1})
        c.repo.context = c.context
        c.source = h._Source(c.root, c.context, SimpleNamespace(check=c.current))
        c.material = store.Material(c.tooling, platform="android")
        c.source.material = c.material
        c.source.checked_ca(c.tooling)
        c.remote = h._Remote(c.fixture.authority, c.source, c.send)
        c.remote.max_calls = recovery.MAX_REQUESTS

    def cleanup_child(self, c, argv, **kw):
        mode = argv[-1]
        self.assertEqual(tuple(argv[:-1]), ("bundle", "exec", "ruby", str(c.tooling / "fastlane/play_edit_recovery.rb")))
        self.assertIn(mode, {"verify", "delete"})
        c.recovery_calls.append(mode); c.events.append(("cleanup-child", mode))
        self.assertIs(kw["cancellation"], c.source.guard)
        self.assertEqual((kw["output_limit"], kw["text"]), (1024, False))
        env = kw["environ"]
        self.assertFalse({h.TOKEN_ENV, "GH_TOKEN", *store._IOS, store._GOOGLE} & env.keys())
        self.assertEqual(env[recovery.KEY], os.environ[recovery.KEY])
        pending = h.Envelope.parse(c.repo.journal).play_query
        self.assertEqual(pending.recovery.capsule.value(), json.loads(env[recovery.CAPSULE]))
        if mode == "verify":
            self.assertIsNone(pending.recovery.claim)
            self.assertLessEqual(kw["timeout"], 5)
        else:
            self.assertIsNotNone(pending.recovery.claim)
            self.assertLessEqual(int(env["MOBILE_RELEASE_PLAY_HARD_END_NS"]), (c.source.end - 8) * 10**9)
        output = {"schemaVersion": 1, "scope": recovery.PURPOSE, "mode": mode,
            "capsuleSha256": h.p.digest(pending.recovery.capsule.value()), "aadSha256": pending.recovery.capsule.aad_sha256}
        if mode == "verify": output["verified"] = True
        else: output.update(deleteAttempted=True, deleteConfirmed=True)
        c.clock += 1
        if c.after_child: c.after_child(mode, output)
        if c.failure == mode + "-unknown": raise OSError("INERT original child unknown")
        if c.failure == mode + "-late": c.clock = c.source.end
        return subprocess.CompletedProcess(argv, 1 if c.failure == mode + "-failed" else 0,
            h.p.canonical(output) + b"\n", b"INERT stderr" if c.failure == mode + "-stderr" else b"")

    def recover(self, c, retained):
        return recovery._recover(c.source, c.settings, c.remote, c.material,
                                 retained.play_query.candidate_id, retained.play_query.attempt_id)

    def test_joined_failed_delete_retains_only_capsule_then_two_closed_children_clear_same_row(self):
        for schema in (3, 4):
            with self.subTest(schema=schema), self.case(schema) as c:
                retained = self.retain(c)
                self.assertEqual(c.repo.journal_puts, 3)
                self.assertTrue(c.material._play_closed)
                self.assertTrue(c.material._play_consumed)
                self.assertEqual(c.events[-2:], [("journal", 3, True), ("http", h.JOURNAL_READ, "GET")])
                write = c.events.index(("journal", 3, True))
                self.assertLess(c.events.index(("scratch-close", "store-selection")), write)
                for private in ("INERT-edit-private", os.environ[recovery.KEY], "client_email", "INERT PRIVATE ERROR"):
                    self.assertNotIn(private, c.repo.journal.decode())
                self.restart_cleanup(c, retained)
                with patch.object(h, "uuid4", side_effect=AssertionError("cleanup must not choose/remint")):
                    result = self.recover(c, retained)
                self.assertEqual(c.recovery_calls, ["verify", "delete"])
                self.assertEqual(c.source.git_calls, 9)
                self.assertLessEqual(c.remote.calls, 24)
                self.assertEqual(c.repo.journal_puts, 5)
                after = h.Envelope.parse(c.repo.journal)
                self.assertEqual(after.schema_version, 3)
                self.assertEqual(after.state, retained.state)
                self.assertIsNone(after.play_query)
                self.assertEqual(result["allocation"], "not-performed")
                self.assertEqual(c.repo.ledger_puts, 0)
                self.assertNotIn("INERT-edit-private", json.dumps(result))

    def test_unknown_or_malformed_original_never_attaches_recovery(self):
        for failure in ("child-unknown", "nonzero", "stderr", "late", "close-store-selection", "close-online-runner"):
            with self.subTest(failure=failure), self.case() as c:
                c.failure = failure
                with self.assertRaises(Exception): c.reserve()
                retained = h.Envelope.parse(c.repo.journal)
                self.assertEqual(retained.schema_version, 2)
                self.assertIsNone(retained.play_query.recovery)
                self.assertEqual(c.repo.journal_puts, 2)
        for change in ("id", "insert-body", "path", "extra", "aad", "finished", "unknown-insert"):
            with self.subTest(change=change), self.case() as c:
                c.failure = "delete"
                def mutate(frame):
                    if change == "id": frame["temporaryEdit"]["editId"] = "different"
                    elif change == "insert-body": frame["pages"][0]["response"]["bodyBase64"] = base64.b64encode(b"{}").decode()
                    elif change == "path": frame["pages"][0]["request"]["path"] += "/other"
                    elif change == "extra": frame["unknown"] = "not a closed frame"
                    elif change == "aad": frame["hostedRecovery"]["aadSha256"] = "f" * 64
                    elif change == "finished": frame["queryFinished"] = True
                    else: frame["pages"][0]["response"].update(bodyBase64=None, failure="provider_request_unconfirmed")
                c.after_child = mutate
                with self.assertRaises(Exception): c.reserve()
                self.assertEqual(c.repo.journal_puts, 2)
                self.assertIsNone(h.Envelope.parse(c.repo.journal).play_query.recovery)

    def test_lost_retention_ack_preserves_original_poison_and_no_allocation_or_same_original_retry(self):
        with self.case() as c:
            c.failure, c.after_write = "delete", 3
            with self.assertRaises(h.Refused): c.reserve()
            capture = c.material.recovery
            self.assertTrue(capture.consumed)
            self.assertTrue(capture.journal._poisoned)
            retained = c.repo.journal
            with self.assertRaises(h.Refused):
                recovery.retain_play_recovery(capture.journal, capture.row.request, c.source, capture.original)
            self.assertEqual(c.repo.journal, retained)
            self.assertEqual(c.repo.ledger_puts, 0)

    def test_preclaim_verification_failures_and_closes_do_not_spend_capsule(self):
        for failure in ("verify-failed", "verify-stderr", "verify-unknown", "verify-late", "close-store-selection", "close-online-runner"):
            with self.subTest(failure=failure), self.case() as c:
                retained = self.retain(c); self.restart_cleanup(c, retained)
                before = c.repo.journal
                c.failure = failure
                with self.assertRaises(Exception): self.recover(c, retained)
                self.assertEqual(c.repo.journal, before)
                self.assertEqual(c.recovery_calls, ["verify"])
                self.assertIsNone(h.Envelope.parse(c.repo.journal).play_query.recovery.claim)

    def test_claim_lost_ack_or_conflict_cannot_enter_delete_and_reload_stays_spent(self):
        for fault in ("lost", "conflict"):
            with self.subTest(fault=fault), self.case() as c:
                retained = self.retain(c); self.restart_cleanup(c, retained)
                if fault == "lost":
                    c.after_write = 4
                else:
                    def advance(mode, _):
                        if mode == "verify":
                            current = h.Envelope.parse(c.repo.journal)
                            c.repo.journal = replace(current, revision=current.revision + 1).to_bytes()
                            c.repo.advance() # Inert concurrent whole-journal CAS, not a retry.
                    c.after_child = advance
                with self.assertRaises(h.Refused): self.recover(c, retained)
                self.assertEqual(c.recovery_calls, ["verify"])
                self.assertEqual(c.repo.ledger_puts, 0)
                if fault == "lost":
                    self.assertIsNotNone(h.Envelope.parse(c.repo.journal).play_query.recovery.claim)
                    self.restart_cleanup(c, retained)
                    with self.assertRaises(h.Refused): self.recover(c, retained)
                    self.assertEqual(c.recovery_calls, ["verify"])

    def test_delete_refusal_unknown_and_postreturn_failure_keep_one_claim_and_never_retry(self):
        for failure in ("delete-failed", "delete-stderr", "delete-unknown", "delete-late", "404", "unknown-close", "changed-key"):
            with self.subTest(failure=failure), self.case() as c:
                retained = self.retain(c); self.restart_cleanup(c, retained)
                c.failure = failure
                def change(mode, output):
                    if mode == "delete":
                        if failure == "404": output["deleteConfirmed"] = False
                        elif failure == "unknown-close": c.failure = "close-store-selection"
                        elif failure == "changed-key": os.environ[recovery.KEY] = base64.b64encode(b"X" * 32).decode()
                c.after_child = change
                with self.assertRaises(Exception): self.recover(c, retained)
                state = h.Envelope.parse(c.repo.journal)
                self.assertIsNotNone(state.play_query.recovery.claim)
                self.assertEqual(state.state, retained.state)
                self.assertEqual(c.recovery_calls, ["verify", "delete"])
                self.assertEqual(c.repo.journal_puts, 4)
                self.restart_cleanup(c, retained)
                with self.assertRaises(h.Refused): self.recover(c, retained)
                self.assertEqual(c.recovery_calls, ["verify", "delete"])

    def test_lost_final_ack_or_concurrent_journal_never_overwrites_current_state(self):
        for fault in ("lost", "conflict"):
            with self.subTest(fault=fault), self.case() as c:
                retained = self.retain(c); self.restart_cleanup(c, retained)
                if fault == "lost": c.after_write = 5
                else:
                    def advance(mode, _):
                        if mode == "delete":
                            current = h.Envelope.parse(c.repo.journal)
                            c.repo.journal = replace(current, revision=current.revision + 1).to_bytes()
                            c.repo.advance()
                    c.after_child = advance
                with self.assertRaises(h.Refused): self.recover(c, retained)
                state = h.Envelope.parse(c.repo.journal)
                self.assertEqual(state.state, retained.state)
                self.assertEqual(c.recovery_calls, ["verify", "delete"])
                self.assertEqual(c.repo.ledger_puts, 0)
                self.assertEqual(state.play_query is None, fault == "lost")

    def test_legacy_fence_wrong_selectors_key_version_and_original_source_refuse_before_claim(self):
        for fault in ("legacy", "candidate", "attempt", "version", "source"):
            with self.subTest(fault=fault), self.case() as c:
                retained = self.retain(c); self.restart_cleanup(c, retained)
                before = c.repo.journal
                if fault == "legacy":
                    current = h.Envelope.parse(before)
                    c.repo.journal = replace(current, schema_version=2,
                        play_query=replace(current.play_query, recovery=None)).to_bytes()
                    c.repo.advance(); before = c.repo.journal
                elif fault == "candidate": retained = replace(retained,
                    play_query=replace(retained.play_query, candidate_id="00000000-0000-4000-8000-000000000001"))
                elif fault == "attempt": retained = replace(retained,
                    play_query=replace(retained.play_query, attempt_id="00000000-0000-4000-8000-000000000001"))
                elif fault == "version":
                    os.environ[recovery.VERSION] = "other-v2"
                    c.material = store.Material(c.tooling, platform="android"); c.source.material = c.material
                else: c.config_raw += b" "  # Actual current reread no longer matches the original committed binding.
                with self.assertRaises(Exception): self.recover(c, retained)
                self.assertEqual(c.repo.journal, before)
                self.assertEqual(c.recovery_calls, [])

    def test_ios_progress_preserves_full_v3_capsule_and_claim_without_rewriting_default_versions(self):
        for spent in (False, True):
            with self.subTest(spent=spent), self.case(2, opt_in=False) as c:
                retained = c.retain_play()
                cap = opaque(b"structural previous capsule, not native proof")
                claim = recovery.Claim("00000000-0000-4000-8000-000000000002", "50", 1) if spent else None
                retained = replace(retained, schema_version=3,
                    play_query=replace(retained.play_query, recovery=recovery.Record(cap, claim)))
                c.repo.journal = retained.to_bytes(); c.repo.advance()
                c.retained_play = retained.play_query
                proposed = []
                def observe(role, request):
                    if role == h.JOURNAL_WRITE:
                        frame = h.Envelope.parse(base64.b64decode(json.loads(request.body)["content"]))
                        self.assertEqual(frame.schema_version, 3)
                        self.assertEqual(frame.play_query, retained.play_query)
                        for row in retained.state.candidates:
                            self.assertEqual(frame.state.candidate(row.local_project_id), row)
                        proposed.append(frame)
                c.repo.before = observe
                result = c.reserve()
                self.assertEqual(result["status"], "reserved")
                self.assertEqual(len(proposed), 5)
                self.assertEqual(c.provider_calls, ["ios"])
                self.assertEqual(c.repo.ledger_puts, 1)
                self.assertEqual(h.Envelope.parse(c.repo.journal).play_query, retained.play_query)

    def test_capsule_and_state_bounds_are_canonical_and_never_create_cleanup_authority(self):
        with self.case() as c:
            retained = self.retain(c)
            raw = retained.to_bytes()
            self.assertEqual(h.Envelope.parse(raw), retained)
            cap = retained.play_query.recovery.capsule.value()
            for change in ({"nonce": "AA=="}, {"tag": "AA=="}, {"algorithm": "other"}, {"extra": False},
                           {"ciphertext": base64.b64encode(b"x" * 2049).decode()}):
                with self.subTest(change=tuple(change)), self.assertRaises(Exception):
                    recovery.Capsule.parse({**cap, **change})
            with self.assertRaises(h.Refused): replace(retained, schema_version=2).to_bytes()
            value = json.loads(raw); value["schemaVersion"] = 4
            with self.assertRaises(Exception): h.Envelope.parse(h.p.canonical(value) + b"\n")
            with self.assertRaises(h.Refused): h.Envelope.parse(b" " * (h.MAX_STATE_BYTES + 1))
            self.restart_cleanup(c, retained)
            journal = h._Journal(c.remote, c.settings); journal.load()
            self.assertIsNone(journal._play_original)
            row = recovery._selected(journal, journal.play_query)
            with self.assertRaises(h.Refused): journal._commit_play_recovery(journal.play_query, None, row)
            self.assertIsNone(journal._play_original)

    def test_partial_opt_in_and_wrong_cli_never_select_a_provider_or_echo_input(self):
        with self.case() as c:
            for change in ({recovery.KEY: ""}, {recovery.VERSION: ""}, {recovery.KEY: "not-base64"},
                           {recovery.KEY: base64.b64encode(b"x" * 31).decode()}, {recovery.VERSION: "bad label"}):
                with self.subTest(change=tuple(change)), patch.dict(os.environ, change), self.assertRaises(h.Refused):
                    store.Material(c.tooling, platform="android")
            for args in ([], ["cleanup", "INERT-edit-private"], ["retry"], ["cleanup", "--force"]):
                out, err = io.StringIO(), io.StringIO()
                with redirect_stdout(out), redirect_stderr(err):
                    self.assertEqual(recovery.main(args), 1)
                self.assertEqual(out.getvalue(), "")
                self.assertNotIn("INERT-edit-private", err.getvalue())
                self.assertNotIn(os.environ[recovery.KEY], err.getvalue())
            self.assertEqual(c.provider_calls, [])

    def test_child_result_is_closed_typed_data_and_never_an_unjoined_receipt(self):
        for mode, change in (("verify", {"verified": 1}), ("verify", {"schemaVersion": True}),
                             ("verify", {"extra": False}), ("delete", {"deleteConfirmed": 1}),
                             ("delete", {"capsuleSha256": "f" * 64})):
            with self.subTest(mode=mode, change=tuple(change)), self.case() as c:
                retained = self.retain(c); self.restart_cleanup(c, retained)
                c.after_child = lambda current, output: output.update(change) if current == mode else None
                with self.assertRaises(h.Refused): self.recover(c, retained)
                value = h.Envelope.parse(c.repo.journal)
                self.assertEqual(value.play_query.recovery.claim is not None, mode == "delete")
                self.assertEqual(c.repo.ledger_puts, 0)

    def test_fixed_cleanup_admission_uses_public_selectors_actual_job_and_no_policy_or_p8(self):
        with self.case() as c:
            retained = self.retain(c); self.restart_cleanup(c, retained)
            with patch.dict(os.environ, {ci.AUTHORITY_ENV: c.fixture.settings}):
                settings, candidate, attempt = recovery._admit(c.context)
                self.assertEqual(settings.authority, c.settings.authority)
                self.assertEqual((candidate, attempt), (retained.play_query.candidate_id, retained.play_query.attempt_id))
                for context in (replace(c.context, current_job="android_build"), replace(c.context, platform="ios"),
                                replace(c.context, confirmation=c.context.confirmation + ":retry"),
                                replace(c.context, confirmation="recover-play-edit:raw-edit:raw-edit")):
                    with self.assertRaises(Exception): recovery._admit(context)
                for name, value in ((h.POLICY_ENV, "{}"), ("MOBILE_RELEASE_DESKTOP_REQUEST", "a" * 32),
                                    ("MOBILE_RELEASE_RECOVERY_RUN_ID", "50"), ("MOBILE_RELEASE_OPERATION", "reserve-version")):
                    with patch.dict(os.environ, {name: value}), self.assertRaises(h.Refused): recovery._admit(c.context)
            with patch.dict(os.environ, {store._P8: "INERT not used"}), self.assertRaises(h.Refused):
                store.Material(c.tooling, platform="android")
            self.assertEqual(c.recovery_calls, [])
        # The actual shared Context permits paired cleanup only in this same
        # protected job; no generic "both" workflow mode is introduced.
        with self.case(4) as c:
            retained = self.retain(c); self.restart_cleanup(c, retained)
            env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": c.context.repository["fullName"],
                "GITHUB_REPOSITORY_ID": c.context.repository["id"], "GITHUB_SHA": c.context.authority["headSha"],
                "GITHUB_REF": c.context.authority["ref"], "GITHUB_JOB": "version_reserve",
                "MOBILE_RELEASE_SELECTED_PLATFORM": "both", "MOBILE_RELEASE_CONFIRMATION": c.context.confirmation,
                ci.AUTHORITY_ENV: c.fixture.settings}
            with patch.dict(os.environ, env), patch.object(h.workflow, "workflow_authority", return_value=c.context.authority):
                current = h.workflow.Context.current("candidate", "both")
                self.assertEqual(recovery._admit(current)[1:], (retained.play_query.candidate_id, retained.play_query.attempt_id))
                for key, value in (("GITHUB_JOB", "ios_store"), ("MOBILE_RELEASE_SELECTED_PLATFORM", "ios"),
                                   ("MOBILE_RELEASE_OPERATION", "candidate"), ("MOBILE_RELEASE_CONFIRMATION", "recover-play-edit:raw:raw")):
                    with patch.dict(os.environ, {key: value}), self.assertRaises(h.workflow.WorkflowError):
                        h.workflow.Context.current("candidate", "both")
                with self.assertRaises(h.workflow.WorkflowError): h.workflow.Context.current("production-submit", "both")
        # Parse the real packaging metadata rather than matching source text:
        # the new fixed Ruby entry and its required existing reader ship together.
        metadata = tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text())
        packaged = metadata["tool"]["setuptools"]["data-files"]["share/mobile-release-kit/fastlane"]
        for name in ("fastlane/play_edit_recovery.rb", "fastlane/android_store_versions.rb"):
            self.assertEqual(packaged.count(name), 1)


if __name__ == "__main__":
    unittest.main()
