"""Synthetic core-pipeline tests, NOT a spawned/native-channel qualification.

Only fixed stdin/stdout are substituted. The real EditInput finite parser,
DefaultCancellation, root custody, identity checkout/plan, transaction, and
recovery objects run on task-owned temporary project fixtures. No subprocess,
build, provider, credentials or real inherited descriptors are used.
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from mobile_release import _desktop_edit_engine as engine
from mobile_release import _desktop_identity_protocol as wire
from mobile_release import init_transaction as tx
from mobile_release import project_identity as identity
from mobile_release.cancellation import CleanupScope
from mobile_release.config_payloads import prepare_edit_ignore
from tests.unit.test_project_identity import ANDROID, IOS, OLD, NEW, PBX, android, ios
from tests.unit.helpers import android_config

SESSION = "1" * 32


class IdentityEngineTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="mrk-identity-engine-fixture-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sources = android()
        self.write_sources()

    def write_sources(self):
        self.sources[identity.IGNORE_PATH] = prepare_edit_ignore(b"# synthetic engine fixture\n")[0]
        for path, data in self.sources.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o640)

    def run_engine(self, *, selection=ANDROID, desired=NEW, recover=False, discard=None, intent="new-application",
                   change_request=None, before_request=None):
        child = engine._Engine(time.monotonic(), domain="project_identity")
        frames, active_request = [], []
        st = self.root.stat()
        registered = {"device": str(st.st_dev), "inode": str(st.st_ino), "mode": st.st_mode, "uid": st.st_uid, "gid": st.st_gid}

        def source_request(sequence):
            if before_request: before_request(sequence)
            mode = "recover" if recover else "edit"
            if sequence == 0:
                op, params = "open", {"root": str(self.root), "registeredIdentity": registered, "intent": mode}
                if not recover: params["selection"] = selection.as_dict()
            elif sequence == discard:
                op, params = "discard", {}
            elif sequence == 1:
                op, params = "prepare", {"intent": mode, "revision": frames[0]["result"]["revision"]}
                if not recover: params.update(desiredIdentity=desired, identityIntent=intent)
            else:
                op, params = "apply", {"intent": mode, "planToken": frames[1]["result"]["planToken"]}
            if change_request: change_request(sequence, params)
            return json.dumps({"protocol": wire.PROTOCOL, "session": SESSION, "seq": sequence, "op": op, "params": params}).encode() + b"\n"

        original_request = engine.EditInput.request
        def request(control, sequence, session):
            self.assertIs(control, child.input)
            active_request.append(sequence)
            try: return original_request(control, sequence, session)
            finally: active_request.clear()

        def acquire(control):
            control._owner()
            self.assertFalse(control.acquired)
            self.assertIsNone(control.fd)
            control.acquired = True  # fixture boundary owns NO inherited FD.

        def poll(control, guard):
            control._owner()
            self.assertIs(control.guard, guard)
            if control.stopped: guard.cancelled = True
            if active_request and not control.active and not control.buffer and not control.close_claimed:
                control.buffer.extend(source_request(active_request[0]))

        def output(raw, **kwargs):
            self.assertLess(child.frames, 3)
            self.assertLessEqual(len(raw), wire.RESPONSE_LIMIT)
            child.frames += 1
            frames.append(json.loads(raw))

        child.write = output
        scope = CleanupScope(child.guard, child.cleanup, owns_cancellation=True, first_primary=True)
        with ExitStack() as stack:
            stack.enter_context(patch.object(engine.EditInput, "acquire", acquire))
            stack.enter_context(patch.object(engine.EditInput, "request", request))
            stack.enter_context(patch.object(engine.EditInput, "poll", poll))
            blocking = stack.enter_context(patch.object(engine.os, "set_blocking"))
            stack.enter_context(patch("subprocess.Popen", side_effect=AssertionError("No project command or child belongs to this fixture")))
            try:
                try:
                    with scope: child.run()
                finally:
                    scope.__exit__(*sys.exc_info())
            except BaseException as error:
                child._remember(error)
            child.terminal()
        # Do not close engine output: this fixture never acquired FDs1/2.
        blocking.assert_called_once_with(1, False)
        self.assertTrue(child.input.closed)
        self.assertEqual(child.guard.handler_state, "RESTORED")
        self.assertFalse(child.guard.lifetime_ledger.fatal)
        if child.lease is not None: self.assertTrue(child.lease.closed)
        self.assertEqual(frames[-1]["kind"], "terminal")
        self.assertEqual(frames[-1]["result"]["resources"], "settled", frames)
        return child, frames

    def originals(self):
        for path, data in self.sources.items(): self.assertEqual((self.root / path).read_bytes(), data, path)
        self.assertFalse(any((self.root / state).exists() for state in tx.ALL_STATE_NAMES))

    def test_real_android_pipeline_mutates_only_actual_id_and_saved_id(self):
        sentinel = self.root / "app" / "Unrelated.kt"
        sentinel.write_bytes(b"package com.example.source\n// untouched source\n")
        st, data = sentinel.stat(), sentinel.read_bytes()
        child, frames = self.run_engine()
        self.assertEqual([f["kind"] for f in frames], ["opened", "prepared", "terminal"])
        self.assertEqual(child.outcome.effect, "committed")
        self.assertEqual(child.outcome.journal, "clean")
        self.assertEqual(child.outcome.reason, "none")
        self.assertEqual(frames[-1]["result"]["planToken"], frames[1]["result"]["planToken"])
        self.assertEqual(child.lease.profile, tx.TypedEditProfile.PROJECT_IDENTITY)
        for path, before in self.sources.items():
            self.assertEqual((self.root / path).read_bytes(), before.replace(OLD.encode(), NEW.encode()) if path in
                             {identity.CONFIG_PATH, "app/build.gradle.kts"} else before)
        self.assertEqual((sentinel.stat(), sentinel.read_bytes()), (st, data))
        self.assertIn(b'namespace = "com.example.source"', (self.root / "app/build.gradle.kts").read_bytes())

    def test_real_ios_pipeline_uses_selected_native_target_and_shared_scheme(self):
        self.sources.update(ios()); self.write_sources()
        child, frames = self.run_engine(selection=IOS)
        self.assertEqual(child.outcome.effect, "committed", frames)
        self.assertEqual(frames[0]["result"]["view"]["configurations"], ["Debug", "Release"])
        self.assertEqual((self.root / PBX).read_bytes(), self.sources[PBX].replace(OLD.encode(), NEW.encode()))
        self.assertEqual((self.root / "app/build.gradle.kts").read_bytes(), self.sources["app/build.gradle.kts"])

    def test_default_existing_and_saved_approved_or_store_app_veto_cannot_be_overridden_by_new_intent(self):
        existing = identity.IdentitySelection("android", ":app")
        for chosen, status, app_id in ((existing, "unverified", None), (ANDROID, "approved", None), (ANDROID, "blocked", None), (IOS, "unverified", "123456")):
            with self.subTest(platform=chosen.platform, status=status, store=app_id is not None):
                self.sources = ios() if chosen.platform == "ios" else android()
                config = json.loads(self.sources[identity.CONFIG_PATH]); config[chosen.platform]["identityStatus"] = status
                if chosen.platform == "android" and status == "approved": config["android"] = android_config()["android"]
                if app_id: config["ios"]["appStoreAppId"] = app_id
                self.sources[identity.CONFIG_PATH] = json.dumps(config).encode() + b"\n"; self.write_sources()
                child, frames = self.run_engine(selection=chosen)
                self.assertEqual(child.outcome.effect, "not_started", frames)
                self.assertEqual(child.outcome.reason, "invalid_params")
                self.assertEqual(frames[-1]["result"]["diagnostic"]["code"], "existing-application")
                self.assertEqual([f["kind"] for f in frames], ["opened", "terminal"])
                self.originals()

    def test_unknown_is_not_absence_and_explicit_new_application_review_is_separate(self):
        child, frames = self.run_engine(intent="preserve")
        self.assertEqual(child.outcome.effect, "not_started")
        self.assertEqual(frames[-1]["result"]["diagnostic"]["code"], "new-intent-required")
        self.originals()
        for discard in (1, 2):
            child, frames = self.run_engine(discard=discard)
            self.assertEqual(child.outcome.effect, "not_started")
            if discard == 2:
                self.assertEqual(frames[1]["result"]["view"]["warnings"], [wire.NEW_WARNING])
                self.assertEqual(frames[1]["result"]["view"]["invalidations"], wire.INVALIDATIONS)
            self.originals()

    def test_same_identity_is_noop_even_for_existing_application(self):
        child, frames = self.run_engine(selection=identity.IdentitySelection("android", ":app"), desired=OLD, intent="preserve")
        self.assertEqual((child.outcome.effect, child.outcome.journal, child.outcome.reason), ("unchanged", "not_created", "none"))
        self.assertEqual(frames[1]["result"]["view"]["state"], "unchanged")
        self.originals()

    def test_wrong_root_revision_token_and_mode_never_rebind_original_plan(self):
        def mutation(seq, key, value):
            def change(actual, params):
                if actual == seq:
                    if key == "uid": params["registeredIdentity"][key] += 1
                    else: params[key] = value
            return change
        for seq, key, value in ((0, "uid", None), (1, "revision", "e" * 32), (1, "intent", "recover"),
                                (2, "planToken", "e" * 32), (2, "intent", "recover")):
            with self.subTest(seq=seq, key=key):
                child, frames = self.run_engine(change_request=mutation(seq, key, value))
                self.assertEqual(child.outcome.effect, "not_started", frames)
                self.assertNotEqual(child.outcome.reason, "none")
                self.originals()

    def test_unsupported_dynamic_layout_gives_precise_source_help_without_prepare(self):
        self.sources["app/build.gradle.kts"] = b'plugins { id("com.android.application") }\nandroid { defaultConfig { applicationId = provider.get() } }\n'
        self.write_sources()
        child, frames = self.run_engine(discard=1)
        view = frames[0]["result"]["view"]
        self.assertEqual(view["state"], "unsupported")
        self.assertEqual(view["diagnostics"][0]["path"], "app/build.gradle.kts")
        self.assertEqual(view["diagnostics"][0]["line"], 2)
        self.assertTrue(view["nextStep"])
        self.assertEqual(child.outcome.effect, "not_started")
        self.originals()

    def test_new_control_after_review_refuses_original_plan_and_preserves_foreign_file(self):
        foreign = self.root / "gradle.properties"
        def insert(seq):
            if seq == 2: foreign.write_bytes(b"# intervening project control\n")
        child, frames = self.run_engine(before_request=insert)
        self.assertEqual(child.outcome.effect, "not_started", frames)
        self.assertEqual(child.outcome.reason, "stale_revision")
        self.assertEqual(foreign.read_bytes(), b"# intervening project control\n")
        self.originals()

    def test_known_commit_pending_survives_discard_and_fresh_original_recovery(self):
        move = tx.InitWorkspace._move
        reached = []
        def after_commit(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
            result = move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
            if destination == "COMMITTED" and not reached:
                reached.append(owner)
                raise OSError("synthetic returned committed move")
            return result
        with patch.object(tx.InitWorkspace, "_move", after_commit), patch.object(tx.InitWorkspace, "_fixed_recovery", return_value=None):
            child, frames = self.run_engine()
        self.assertEqual(len(reached), 1)
        self.assertEqual((child.outcome.effect, child.outcome.journal, child.outcome.reason),
                         ("committed", "recovery_required", "filesystem_error"), frames)
        self.assertTrue((self.root / tx.READY).exists())
        for discard in (1, 2):
            child, frames = self.run_engine(recover=True, discard=discard)
            self.assertEqual((child.outcome.effect, child.outcome.journal, child.outcome.reason),
                             ("committed", "recovery_required", "pending_state"), frames)
            self.assertEqual(frames[0]["result"]["view"]["action"], "committed_cleanup")
            self.assertTrue((self.root / tx.READY).exists())
        child, frames = self.run_engine(recover=True)
        self.assertEqual((child.outcome.effect, child.outcome.journal, child.outcome.reason), ("committed", "clean", "none"), frames)
        self.assertEqual(frames[0]["result"]["view"], frames[1]["result"]["view"])
        self.assertEqual((self.root / "app/build.gradle.kts").read_bytes(), self.sources["app/build.gradle.kts"].replace(OLD.encode(), NEW.encode()))
        self.assertFalse(any((self.root / state).exists() for state in tx.ALL_STATE_NAMES))

    def test_idle_recovery_is_read_only_and_cannot_prepare_a_fake_cleanup(self):
        child, frames = self.run_engine(recover=True, discard=1)
        self.assertEqual(frames[0]["result"]["view"]["state"], "idle")
        self.assertEqual(child.outcome.effect, "not_started")
        self.originals()
        child, frames = self.run_engine(recover=True)
        self.assertEqual(child.outcome.effect, "not_started")
        self.assertEqual(child.outcome.reason, "invalid_params")
        self.assertEqual([f["kind"] for f in frames], ["opened", "terminal"])
        self.originals()


if __name__ == "__main__": unittest.main()
