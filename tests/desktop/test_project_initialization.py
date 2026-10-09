"""Initialization DATA and original-owner filesystem tests, not Mac qualification.

Filesystem cases reuse InitRootLease/DefaultCancellation and the real existing
transaction/restoration engine. Fault cases stop after a returned owned effect
and suppress only automatic same-invocation cleanup; they are controlled-error
recovery, not an abrupt-process or power-loss claim. The separate existing
unit transaction child fixture covers one real kill/join/restart cut.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack, contextmanager, nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _desktop_edit_engine as engine
from mobile_release import _desktop_edit_protocol as edit_wire
from mobile_release import _desktop_initialization_protocol as wire
from mobile_release import github_workflow_recovery as recovery
from mobile_release import initialization_recovery as inspect
from mobile_release import initialization_targets as targets
from mobile_release import init_transaction as tx
from mobile_release import project_initialization as initialize
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.config_edit import ConfigEditFailure
from mobile_release.config_payloads import prepare_edit_ignore
from mobile_release.errors import ValidationError
from mobile_release.init_workspace_custody import InitRootLease
from mobile_release.workflow_payloads import pinned_schema_reference

PROFILE = tx.TypedEditProfile.PROJECT_INITIALIZATION
REPOSITORY, SHA = "example/mobile-release-kit", "a" * 40
SESSION, REVISION, TOKEN = "1" * 32, "2" * 32, "3" * 32


def draft():
    return {"schemaVersion": 1,
            "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
            "source": {"candidateBranch": "main", "productionBranch": "production"},
            "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
            "ios": {"enabled": False},
            "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
            "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
            "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []}}


def frame(seq, op, params, protocol=wire.PROTOCOL):
    return json.dumps({"protocol": protocol, "session": SESSION, "seq": seq, "op": op, "params": params}).encode() + b"\n"


def request(seq, op, params):
    return edit_wire.parse_request(frame(seq, op, params), sequence=seq, session=None if seq == 0 else SESSION,
                                   protocol=wire.PROTOCOL)


def full9(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def namespace(root):
    return {path.relative_to(root).as_posix(): (full9(path.lstat()), path.read_bytes() if path.is_file() else None)
            for path in (root, *sorted(root.rglob("*")))}


def forbidden(*_args, **_kwargs):
    raise AssertionError("unexpected descriptor, transaction, new preparation, or public terminal access")


class InitializationDataTests(unittest.TestCase):
    def test_descriptor_roundtrip_role_bounds_and_complete_plan_refuse_mutations(self):
        source = draft()
        value = targets.prepare_input(source, REPOSITORY, SHA.upper())
        self.assertNotIn("$schema", source, "preparation must not mutate the caller's unsaved draft")
        expected = copy.deepcopy(source)
        expected["$schema"] = pinned_schema_reference(REPOSITORY, SHA)
        self.assertEqual(json.loads(value.configuration), expected)
        context = value.context()
        restored = targets.from_context(context)
        self.assertEqual((restored.configuration, restored.workflows, restored.paths),
                         (value.configuration, value.workflows, value.paths))
        self.assertEqual(value.paths[:6], targets.FIXED_PATHS)
        self.assertEqual(value.paths[6:], tuple(sorted(value.paths[6:])))
        self.assertEqual(len(value.paths), 10)
        self.assertEqual(value.limits, (512 * 1024, 1024 * 1024, *((1024 * 1024,) * 4), *((8 * 1024 * 1024,) * 4)))
        for obj in (value, restored):
            for copy_call in (copy.copy, copy.deepcopy):
                with self.assertRaises(TypeError):
                    copy_call(obj)
        mutations = [lambda c: c.update(extra=True), lambda c: c.update(schemaVersion=True),
                     lambda c: c.update(configurationUtf8=c["configurationUtf8"] + " "),
                     lambda c: c.update(toolingRepository="another/toolkit"),
                     lambda c: c.update(toolingSha="b" * 40),
                     lambda c: c["templateSet"].update(resourceSha256="f" * 64),
                     lambda c: c["templateSet"].update(resourceVersion=2),
                     lambda c: c["templateSet"].update(coreVersion="999.999.999")]
        for mutate in mutations:
            changed = copy.deepcopy(context)
            mutate(changed)
            with self.subTest(context=changed.keys()), self.assertRaises(targets.DescriptorError):
                targets.from_context(changed)
        maximum = (tx.MAX_TOTAL_BYTES - value.retained_quote) // 4
        value.check_budget(maximum)
        with self.assertRaises(targets.DescriptorError):
            value.check_budget(maximum + 1)
        with self.assertRaises(targets.DescriptorError):
            targets._control_quote({**context, "configurationUtf8": '"' * (tx.MAX_CONTROL_BYTES // 2)},
                                   value.paths, value.directories)
        for root in ("Release/store", ".github/workflows/mobile-preflight.yml"):
            changed = draft()
            changed["metadata"]["root"] = root
            with self.assertRaises(targets.DescriptorError):
                targets.prepare_input(changed, REPOSITORY, SHA)
        changed = draft()
        changed["metadata"]["androidLocales"] = [f"en-{i:03d}" for i in range(63)]
        with patch.object(targets, "_proposal", forbidden), self.assertRaises(targets.DescriptorError):
            targets.prepare_input(changed, REPOSITORY, SHA)  # 252 metadata rows, rejected before proposal/materialization.
        changed = draft()
        changed["android"]["enabled"] = False
        with patch.object(targets, "_proposal", forbidden), self.assertRaises(targets.DescriptorError):
            targets.prepare_input(changed, REPOSITORY, SHA)

        identity = {"device": 1, "inode": 2, "mode": 0o700}
        header = {"schemaVersion": 2, "domain": targets.DOMAIN, "transactionId": "4" * 32,
                  "root": identity, "initialization": context}
        plan = {**header, "directories": [{"path": path, "before": None,
                    "after": {"device": 1, "inode": 100 + i, "mode": 0o755}} for i, path in enumerate(value.directories)],
                "files": []}
        for i, path in enumerate(value.paths):
            raw = prepare_edit_ignore(b"")[0] if i == 1 else value.desired(i)
            plan["files"].append({"path": path, "before": None, "after": {"device": 1, "inode": 300 + i,
                "mode": 0o644, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}})
        receiver = SimpleNamespace(root_identity=identity, _file_limit=tx.MAX_FILE_BYTES,
                                   _valid_identity=tx.InitWorkspace._valid_identity)
        tx.InitWorkspace._validate_plan_data(receiver, header, plan)
        targets.plan_shape(value, plan)
        mutations = [lambda p: p["files"][6].update(path="release/unapproved.txt"),
                     lambda p: p["files"].reverse(), lambda p: p["directories"].pop(),
                     lambda p: p["initialization"].update(toolingSha="b" * 40),
                     lambda p: p["files"][0]["after"].update(size=0, sha256=hashlib.sha256(b"").hexdigest()),
                     lambda p: p["files"][6].update(before=copy.deepcopy(p["files"][6]["after"])),
                     lambda p: p["files"][6]["after"].update(size=1, sha256=hashlib.sha256(b"x").hexdigest())]
        for mutate in mutations:
            changed = copy.deepcopy(plan)
            mutate(changed)
            with self.assertRaises(ValidationError):
                tx.InitWorkspace._validate_plan_data(receiver, header, changed)
                targets.plan_shape(value, changed)
        for domain, reason in ((None, "legacy_journal"), ("metadata-text", "foreign_journal")):
            old = {"schemaVersion": 1} if domain is None else {"schemaVersion": 2, "domain": domain}
            with self.assertRaises(inspect.InspectionRefusal) as refused:
                inspect.header_data(tx._json(old))
            self.assertEqual(refused.exception.reason, reason)

    def test_closed_protocol_freezes_open_input_and_bounds_conflicts_without_promoting_data(self):
        identity = {"device": "1", "inode": "2", "mode": 0o40755, "uid": 1000, "gid": 1000}
        params = {"root": "/inert/registered-project", "registeredIdentity": identity, "intent": "initialize",
                  "draft": draft(), "toolingRepository": REPOSITORY, "toolingSha": SHA}
        opened = request(0, "open", params)
        self.assertEqual(opened.params["draft"], params["draft"])
        for bad in ({**params, "paths": []}, {**params, "intent": "recover"},
                    {"root": params["root"], "intent": "recover"},
                    {**params, "draftRevision": 1}):
            with self.assertRaises(edit_wire.ProtocolError):
                request(0, "open", bad)
        for protocol in (edit_wire.PROTOCOL, edit_wire.WORKFLOW_PROTOCOL):
            with self.assertRaises(edit_wire.ProtocolError):
                edit_wire.parse_request(frame(0, "open", params, protocol), sequence=0, session=None,
                                        protocol=wire.PROTOCOL)
        request(0, "open", {"root": params["root"], "registeredIdentity": identity, "intent": "recover"})
        prepared = request(1, "prepare", {"revision": REVISION, "intent": "initialize"})
        request(2, "apply", {"planToken": TOKEN, "intent": "initialize"})
        for bad in ({"revision": REVISION}, {"revision": REVISION, "intent": "initialize", "draft": {}},
                    {"revision": REVISION, "intent": "initialize", "toolingSha": "b" * 40}):
            with self.assertRaises(edit_wire.ProtocolError):
                request(1, "prepare", bad)
        result = {"kind": "conflict", "intent": "initialize", "revision": REVISION,
                  "effect": "not_started", "journal": "not_created", "resources": "settled", "reason": "none",
                  "conflict": {"schemaVersion": 1, "reason": "existing_targets_differ", "files": [
                      {"kind": "workflow", "path": targets.FIXED_PATHS[2], "beforeBytes": 1024 * 1024}]}}
        encoded = wire.response(prepared, "terminal", result)
        self.assertLessEqual(len(encoded), 16 * 1024)
        self.assertNotIn(b"planToken", encoded)
        for mutate in (lambda r: r["conflict"]["files"][0].update(beforeBytes=1024 * 1024 + 1),
                       lambda r: r.update(resources="unknown"), lambda r: r.update(reason="filesystem_error"),
                       lambda r: r["conflict"]["files"].append(r["conflict"]["files"][0])):
            changed = copy.deepcopy(result)
            mutate(changed)
            with self.assertRaises(edit_wire.ProtocolError):
                wire.response(prepared, "terminal", changed)


class InitializationFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(sys.platform.startswith("linux") or sys.platform == "darwin")
        self.temporary = tempfile.TemporaryDirectory(prefix="mrk-initialization-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.data = targets.prepare_input(draft(), REPOSITORY, SHA)
        self.metadata = self.root / self.data.paths[6]
        self.metadata.parent.mkdir(parents=True)
        self.metadata.write_bytes(b"user metadata is not regenerated\n")
        self.metadata.chmod(0o640)
        self.ignore = self.root / ".gitignore"
        self.ignore.write_bytes(b"# user CRLF\r\n*.log\r\n")
        self.ignore.chmod(0o600)
        self.sentinel = self.root / "unrelated.txt"
        self.sentinel.write_bytes(b"unrelated user input\n")
        self.metadata_before, self.sentinel_before = full9(self.metadata.stat()), full9(self.sentinel.stat())
        self.ignore_before = self.ignore.read_bytes(), self.ignore.stat().st_ino, stat.S_IMODE(self.ignore.stat().st_mode)

    @contextmanager
    def lease(self, *, recover=False):
        registered = self.root.stat()
        guard = DefaultCancellation(ValidationError, "initialization test custody failed")
        lease = InitRootLease(self.root, cancellation=guard, profile=PROFILE, initialization_recovery=recover,
                              registered_identity={"device": registered.st_dev, "inode": registered.st_ino,
                                                   "mode": registered.st_mode, "uid": registered.st_uid, "gid": registered.st_gid})
        cleanup = CleanupScope(guard, lease.close, owns_cancellation=True, first_primary=True)
        try:
            with cleanup:
                guard.install()
                guard.activate()
                lease.acquire()
                yield lease
        finally:
            cleanup.__exit__(*sys.exc_info())
        self.assertTrue(lease.closed)
        self.assertFalse(guard.lifetime_ledger.fatal)
        self.assertEqual(guard.handler_state, "RESTORED")

    def prepared(self, lease):
        checkout = initialize.capture_project_initialization(lease, draft(), REPOSITORY, SHA)
        before = namespace(self.root)
        plan = initialize.prepare_project_initialization(lease, checkout, checkout.revision)
        self.assertIs(type(plan), initialize.PreparedInitialization)
        self.assertEqual(namespace(self.root), before, "Prepare must not create private state or destinations")
        wire.initialization_view(plan.view)
        return checkout, plan

    def pending(self, point):
        """Actual returned effects, controlled error; not a process interruption."""
        original_move, original_state, original_unlink = tx.InitWorkspace._move, tx.InitWorkspace._state_move, tx.InitWorkspace._unlink
        failure, reached = OSError("test-only stop after actual initialization effect"), []

        def move(owner, source_fd, source, destination_fd, destination, expected, **kwargs):
            result = original_move(owner, source_fd, source, destination_fd, destination, expected, **kwargs)
            chosen = (source, destination) == (("new-0", "mobile-release.json") if point == "installed-config" else
                                               ("commit.pending", "COMMITTED"))
            if point in {"installed-config", "committed"} and chosen and not reached:
                reached.append(owner)
                raise failure
            return result

        def state(owner, old, new):
            if point == "preparing" and (old, new) == (tx.PREPARING, tx.READY) and not reached:
                reached.append(owner)
                raise failure  # Full plan + all original controls already durable; no READY return.
            return original_state(owner, old, new)

        def unlink(owner, name, **kwargs):
            result = original_unlink(owner, name, **kwargs)
            if point == "suffix" and name == "plan.json" and not reached:
                reached.append(owner)
                raise failure
            return result

        with self.lease() as lease:
            _, plan = self.prepared(lease)
            with ExitStack() as stack:
                stack.enter_context(patch.object(tx.InitWorkspace, "_move", move))
                stack.enter_context(patch.object(tx.InitWorkspace, "_state_move", state))
                stack.enter_context(patch.object(tx.InitWorkspace, "_unlink", unlink))
                if point != "suffix":
                    stack.enter_context(patch.object(tx.InitWorkspace, "_fixed_recovery", return_value=None))
                result = initialize.apply_project_initialization(lease, plan)
            self.assertEqual((result.journal, result.resources, result.reason),
                             ("recovery_required", "settled", "filesystem_error"))
            self.assertEqual(len(reached), 1)
            self.assertIs(reached[0]._primary, failure)
        return result

    def assert_restored(self):
        self.assertFalse(any((self.root / name).exists() for name in tx.ALL_STATE_NAMES))
        self.assertEqual((self.ignore.read_bytes(), self.ignore.stat().st_ino, stat.S_IMODE(self.ignore.stat().st_mode)), self.ignore_before)
        self.assertEqual(full9(self.metadata.stat()), self.metadata_before)
        self.assertEqual(full9(self.sentinel.stat()), self.sentinel_before)
        for path in self.data.paths:
            if path not in (".gitignore", self.metadata.relative_to(self.root).as_posix()):
                self.assertFalse((self.root / path).exists(), path)

    def test_complete_original_capture_frozen_draft_create_preserve_and_idempotence(self):
        with self.lease() as lease:
            initial = draft()
            checkout = initialize.capture_project_initialization(lease, initial, REPOSITORY, SHA)
            initial["metadata"]["root"] = "another/store"
            before = namespace(self.root)
            plan = initialize.prepare_project_initialization(lease, checkout, checkout.revision)
            self.assertEqual(namespace(self.root), before)
            wire.initialization_view(plan.view)
            self.assertEqual(tuple(row["path"] for row in plan.view["files"]), self.data.paths)
            self.assertEqual(plan.view["files"][6]["action"], "preserve")
            for obj in (checkout, plan, checkout._targets, checkout._revision):
                with self.assertRaises(TypeError):
                    copy.deepcopy(obj)
            result = initialize.apply_project_initialization(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("committed", "clean", "settled", "none"))
            self.assertEqual(initialize.apply_project_initialization(lease, plan).reason, "invalid_params")
        self.assertFalse(any((self.root / name).exists() for name in tx.ALL_STATE_NAMES))
        for index, path in enumerate(self.data.paths):
            if index == 1:
                self.assertEqual((self.root / path).read_bytes(), prepare_edit_ignore(self.ignore_before[0])[0])
                self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), 0o600)
            elif index != 6:
                self.assertEqual((self.root / path).read_bytes(), self.data.desired(index))
                self.assertEqual(stat.S_IMODE((self.root / path).stat().st_mode), 0o644)
        self.assertEqual(full9(self.metadata.stat()), self.metadata_before)
        self.assertEqual(full9(self.sentinel.stat()), self.sentinel_before)
        before = namespace(self.root)
        with self.lease() as lease, patch.object(tx.InitWorkspace, "_prepare", forbidden):
            _, plan = self.prepared(lease)
            result = initialize.apply_project_initialization(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("unchanged", "not_created", "settled", "none"))
        self.assertEqual(namespace(self.root), before)

    def test_known_existing_conflict_and_later_editor_change_never_replace_user_work(self):
        target = self.root / self.data.paths[2]
        target.parent.mkdir(parents=True)
        target.write_bytes(b"x" * (16 * 1024 + 1))
        before = namespace(self.root)
        with self.lease() as lease, patch.object(tx.InitWorkspace, "_prepare", forbidden):
            checkout = initialize.capture_project_initialization(lease, draft(), REPOSITORY, SHA)
            refused = initialize.prepare_project_initialization(lease, checkout, checkout.revision)
            self.assertIs(type(refused), initialize.InitializationConflict)
            self.assertEqual(refused.view["files"], [{"kind": "workflow", "path": self.data.paths[2], "beforeBytes": 16 * 1024 + 1}])
            self.assertFalse(hasattr(refused, "token"))
            initialize.discard_project_initialization(checkout)
        self.assertEqual(namespace(self.root), before)
        target.unlink()
        with self.lease() as lease:
            _, plan = self.prepared(lease)
            self.metadata.write_bytes(b"later editor content must survive\n")
            changed = namespace(self.root)
            result = initialize.apply_project_initialization(lease, plan)
            self.assertEqual((result.effect, result.journal, result.reason), ("not_started", "not_created", "stale_revision"))
            self.assertEqual(namespace(self.root), changed)
        self.assertFalse(any((self.root / name).exists() for name in tx.ALL_STATE_NAMES))

    def test_fresh_recovery_of_complete_preparing_and_installed_config_uses_same_engine(self):
        for point in ("preparing", "installed-config"):
            with self.subTest(point=point):
                self.pending(point)
                if point == "installed-config":
                    self.assertEqual((self.root / self.data.paths[0]).read_bytes(), self.data.configuration)
                with self.lease(recover=True) as lease, patch.object(tx.InitWorkspace, "_prepare", forbidden), patch.object(
                        tx.InitWorkspace, "_install", forbidden), patch.object(tx.InitWorkspace, "__enter__", forbidden):
                    checkout = initialize.capture_project_initialization_recovery(lease)
                    expected_action = "preparing_cleanup" if point == "preparing" else "rollback"
                    self.assertEqual(checkout.view["action"], expected_action)
                    wire.recovery_view(checkout.view)
                    before = namespace(self.root)
                    plan = initialize.prepare_project_initialization_recovery(lease, checkout, checkout.revision)
                    self.assertEqual(namespace(self.root), before)
                    result = initialize.apply_project_initialization_recovery(lease, plan)
                    self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                                     ("not_started" if point == "preparing" else "rolled_back", "clean", "settled", "none"))
                    self.assertEqual(initialize.apply_project_initialization_recovery(lease, plan).reason, "invalid_params")
                self.assert_restored()

        # An internally self-consistent persisted descriptor is still not a
        # grant when its claimed bundled resource differs from the actual core.
        self.pending("installed-config")
        journal = self.root / tx.READY
        names = ("header.json", "plan.json", "commit.pending", "rollback.pending")
        original = {name: (journal / name).read_bytes() for name in names}
        header, plan = (json.loads(original[name]) for name in names[:2])
        for record in (header, plan):
            record["initialization"]["templateSet"]["resourceSha256"] = "f" * 64
        (journal / "header.json").write_bytes(tx._json(header))
        (journal / "plan.json").write_bytes(tx._json(plan))
        for state, name in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
            (journal / name).write_bytes(tx.InitWorkspace._marker(plan, state))
        changed = namespace(self.root)
        with self.lease(recover=True) as lease:
            checkout = initialize.capture_project_initialization_recovery(lease)
            self.assertEqual((checkout.view["state"], checkout.view["reason"]), ("conflict", "resource_changed"))
            with self.assertRaises(ConfigEditFailure):
                initialize.prepare_project_initialization_recovery(lease, checkout, checkout.revision)
        self.assertEqual(namespace(self.root), changed)
        for name, raw in original.items():
            (journal / name).write_bytes(raw)
        with self.lease(recover=True) as lease:
            checkout = initialize.capture_project_initialization_recovery(lease)
            plan = initialize.prepare_project_initialization_recovery(lease, checkout, checkout.revision)
            result = initialize.apply_project_initialization_recovery(lease, plan)
            self.assertEqual((result.effect, result.journal, result.reason), ("rolled_back", "clean", "none"))
        self.assert_restored()

    def test_terminal_suffix_preserves_later_public_edits_and_header_only_remains_attention(self):
        self.pending("suffix")
        journal = self.root / tx.CLEANUP
        self.assertEqual({path.name for path in journal.iterdir()}, {"header.json", "COMMITTED"})
        later = self.root / self.data.paths[0]
        later.write_bytes(b"later config is not the generating canonical JSON\n")
        later_before = full9(later.stat())
        marker = (journal / "COMMITTED").read_bytes()
        (journal / "COMMITTED").unlink()
        before = namespace(self.root)
        with self.lease(recover=True) as lease:
            checkout = initialize.capture_project_initialization_recovery(lease)
            self.assertEqual((checkout.view["state"], checkout.view["reason"]), ("conflict", "incomplete_journal"))
            initialize.discard_project_initialization_recovery(checkout)
        self.assertEqual(namespace(self.root), before)
        (journal / "COMMITTED").write_bytes(marker)
        (journal / "COMMITTED").chmod(0o600)
        with self.lease(recover=True) as lease, patch.object(tx.InitWorkspace, "_current", forbidden), patch.object(recovery, "_current", forbidden):
            checkout = initialize.capture_project_initialization_recovery(lease)
            self.assertEqual((checkout.view["action"], checkout.view["files"], checkout.view["privateCleanup"]["fileCount"]),
                             ("committed_cleanup", [], 2))
            self.assertEqual(lease.last_outcome.effect, "committed")
            wire.recovery_view(checkout.view)
            plan = initialize.prepare_project_initialization_recovery(lease, checkout, checkout.revision)
            result = initialize.apply_project_initialization_recovery(lease, plan)
            self.assertEqual((result.effect, result.journal, result.resources, result.reason),
                             ("committed", "clean", "settled", "none"))
        self.assertEqual(later.read_bytes(), b"later config is not the generating canonical JSON\n")
        self.assertEqual(full9(later.stat()), later_before)
        self.assertFalse(journal.exists())


class InitializationRoutingTests(unittest.TestCase):
    def test_existing_engine_routes_frozen_initialization_and_keeps_recovery_facts_on_discard_error(self):
        data = targets.prepare_input(draft(), REPOSITORY, SHA)
        identity = {"device": "1", "inode": "2", "mode": 0o40755, "uid": 1000, "gid": 1000}
        context = {"configuration": {"byteLength": len(data.configuration), "sha256": hashlib.sha256(data.configuration).hexdigest()},
                   "templateSet": data.template(), "tooling": data.tooling()}
        view = {"schemaVersion": 1, "kind": "project-initialization-recovery", "state": "recoverable", "reason": "none",
                "action": "committed_cleanup", "transactionId": "4" * 32, "context": context, "files": [],
                "privateCleanup": {"fileCount": 2, "directoryCount": 1, "scope": "inspected-owned-journal-only"}}
        for intent, wrong_intent in (("initialize", False), ("recover", False), ("initialize", True), ("recover", True)):
            with self.subTest(intent=intent, wrong_intent=wrong_intent), ExitStack() as stack:
                guard = SimpleNamespace(handler_state="RESTORED", lifetime_ledger=SimpleNamespace(fatal=False),
                    install=lambda: None, activate=lambda: None, check=lambda: None,
                    _install_edit_source=lambda _value: None, deferred=lambda **_kw: nullcontext())
                params = {"root": "/inert/registered-project", "registeredIdentity": identity, "intent": intent}
                if intent == "initialize":
                    params.update(draft=draft(), toolingRepository=REPOSITORY, toolingSha=SHA)
                requests = iter([request(0, "open", params), request(1, "prepare", {"revision": REVISION,
                    "intent": "recover" if intent == "initialize" else "initialize"}) if wrong_intent else request(1, "discard", {})])
                control = SimpleNamespace(acquire=lambda: None, idle=lambda: None,
                    request=lambda *_args: next(requests), closed=False)
                control.close = lambda: setattr(control, "closed", True)
                class RoutingLease(SimpleNamespace):
                    @property
                    def last_outcome(self):
                        return recovery.recovery_outcome(self)
                lease = RoutingLease(guard=guard, closed=False, acquire=lambda: None,
                    _workflow_recovery_effect="not_started", _workflow_recovery_journal="unknown", _workflow_recovery_reason="none")
                lease.close = lambda: setattr(lease, "closed", True)
                checkout = SimpleNamespace(revision=REVISION, observed={"schemaVersion": 1, "fileCount": len(data.paths), "directoryCount": len(data.directories)}, view=view)
                def capture(*args):
                    if intent == "recover":
                        lease._workflow_recovery_effect, lease._workflow_recovery_journal = "committed", "recovery_required"
                    return checkout
                stack.enter_context(patch.object(engine, "DefaultCancellation", return_value=guard))
                stack.enter_context(patch.object(engine, "EditInput", return_value=control))
                constructor = stack.enter_context(patch.object(engine, "InitRootLease", return_value=lease))
                stack.enter_context(patch.object(engine.os, "set_blocking"))
                stack.enter_context(patch.object(engine, "_attempt_all", side_effect=lambda _guard, actions: [action() for action in actions]))
                captures = [stack.enter_context(patch.object(engine, name, side_effect=capture)) for name in
                            ("capture_project_initialization", "capture_project_initialization_recovery")]
                prepared = [stack.enter_context(patch.object(engine, name, side_effect=forbidden)) for name in
                            ("prepare_project_initialization", "prepare_project_initialization_recovery")]
                discards = [stack.enter_context(patch.object(engine, name)) for name in
                            ("discard_project_initialization", "discard_project_initialization_recovery")]
                child = engine._Engine(0.0, domain="project_initialization")
                frames = []
                child.write = lambda raw, **_kw: frames.append(json.loads(raw))
                if wrong_intent:
                    with self.assertRaises(edit_wire.ProtocolError):
                        child.run()
                else:
                    child.run()
                constructor.assert_called_once_with(Path(params["root"]), cancellation=guard, profile=PROFILE,
                    registered_identity={"device": 1, "inode": 2, "mode": 0o40755, "uid": 1000, "gid": 1000},
                    initialization_recovery=intent == "recover")
                self.assertEqual([call.call_count for call in captures], [int(intent == "initialize"), int(intent == "recover")])
                if intent == "initialize":
                    captures[0].assert_called_once_with(lease, draft(), REPOSITORY, SHA)
                    self.assertNotIn("draft", child.last_request.params if child.last_request.seq == 0 else frames[0]["result"])
                for call in prepared:
                    call.assert_not_called()
                child.cleanup()
                self.assertEqual([call.call_count for call in discards], [int(intent == "initialize"), int(intent == "recover")])
                if intent == "recover" and not wrong_intent:
                    self.assertEqual((child.outcome.effect, child.outcome.journal, child.outcome.reason),
                                     ("committed", "recovery_required", "pending_state"))
                    first = edit_wire.ProtocolError("inert first protocol failure")
                    child._remember(first)
                    guard.lifetime_ledger.fatal = True
                    child._remember(OSError("inert later close failure"))
                    self.assertIs(child.first, first)
                    child.terminal()
                    terminal = frames[-1]["result"]
                    self.assertEqual((terminal["intent"], terminal["effect"], terminal["journal"], terminal["resources"], terminal["reason"]),
                                     ("recover", "committed", "recovery_required", "unknown", "invalid_params"))


if __name__ == "__main__":
    unittest.main()
