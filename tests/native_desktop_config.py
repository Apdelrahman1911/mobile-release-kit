"""Closed hosted-only configuration fixtures; never unittest discovery.

Source authoring is not execution approval. Each approved invocation uses
``python3 -I -S -B ... --task-root <original-private-root> --case <fixed-case>``.
There is no subprocess controller, credential input, recovery command or
alternative transaction engine. Uncertainty ends native admission in this
interpreter; the workflow disposes the retained synthetic case directory/VM.

The separate github_workflows domain is source-only core qualification, not a
production permit. Its closed argv/env/receipt inventory never accepts a caller
path roster, replacement policy or ZIP selector. Rust owns the one ZIP parity
case and real bridge/owner/EOF fixtures; this file does not spawn a process.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import stat
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

_PARTITIONS = ("ordinary", "committed-fsync", "committed-close")
_GUARD_MESSAGE = "configuration fixture original ownership did not settle"
_RUN_CLAIMED = False
_RETAINED_BATCH: Any = None

_WORKFLOW_REPOSITORY = "Example/mobile-release-kit"
_WORKFLOW_SHA = "a" * 40
_WORKFLOW_FILES = (
    ("preflight", ".github/workflows/mobile-preflight.yml"),
    ("candidate", ".github/workflows/mobile-candidate.yml"),
    ("external-testing", ".github/workflows/mobile-external-testing.yml"),
    ("production-submit", ".github/workflows/mobile-production-submit.yml"),
)
_WORKFLOW_CASES = {
    "ordinary": (
        "capture-prepare-discard", "existing-differs", "oversized", "unreadable",
        "symlink-leaf", "symlink-ancestor", "hardlink", "aliased-leaf", "nonregular-fifo",
        "registered-root-replaced", "stale-leaf-bytes-before-prepare",
        "stale-leaf-inode-before-apply", "stale-ancestor-mode-before-prepare",
        "absent-ancestor-before-prepare", "absent-leaf-before-apply", "stale-root-before-apply",
        "pending-init", "pending-build", "contention-init", "contention-build", "review-unlocked",
        "partial-install-rollback", "incomplete-preparing", "wrong-roster-controls",
        "unowned-staging-slot", "rollback-pending-replaced", "cleanup-committed-unused-missing",
        "cleanup-rolled-back-unused-missing", "commit-pending-replaced",
    ),
    "committed-fsync": ("committed-fsync-injection",),
    "committed-close": ("committed-close-return-injection",),
}
_WORKFLOW_SOURCES = {
    "fixture": "tests/native_desktop_config.py",
    "workflowEdit": "src/mobile_release/github_workflow_edit.py",
    "configEdit": "src/mobile_release/config_edit.py",
    "transaction": "src/mobile_release/init_transaction.py",
    "rootCustody": "src/mobile_release/init_workspace_custody.py",
    "cancellation": "src/mobile_release/cancellation.py",
    "buildInputs": "src/mobile_release/build_inputs.py",
    "workflowPayloads": "src/mobile_release/workflow_payloads.py",
    "proposal": "src/mobile_release/api/_github_setup.py",
    "resource": "src/mobile_release/api/data/github-setup-v1.json",
    "canonicalPreflight": "templates/workflows/mobile-preflight.yml",
    "canonicalCandidate": "templates/workflows/mobile-candidate.yml",
    "canonicalExternalTesting": "templates/workflows/mobile-external-testing.yml",
    "canonicalProductionSubmit": "templates/workflows/mobile-production-submit.yml",
}
_WORKFLOW_DISK_CONFIG = b"fixed deliberately invalid on-disk configuration; never saved\n"
_WORKFLOW_IGNORE = b"# fixed workflow fixture ignore sentinel; never edited\n"
_WORKFLOW_DRAFT_SHA256 = "e7530b44993489441ab3b0530899b4376d49f1188d5def28979fcb5300d3cd34"
_WORKFLOW_TEMPLATE_SET = {
    "coreVersion": "0.3.0", "resourceVersion": 1,
    "resourceSha256": "4d486fc24ebf24271dbb5227174df7c8f28a530a97011e004da643fdad7fe17c",
}
_WORKFLOW_PAYLOAD_SHA256 = (
    "50845641f06763aab532900d1b3b186a5d684d465a4d63fab05f53c99f9685de",
    "8fb540be24c263c97f7dbf95df524a8b11633e5fa7b1dc92e77cd648ad16e32f",
    "97fa27d95cc7b2d75be0c3a0860af1d350edb6a52741ed87c0a5b13eca8386f1",
    "85865a4df661ef7c7b708b55598a70d56fd84957ce07c9c60f15bcf10a5554b8",
)


class FixtureRefused(Exception):
    pass


class FixtureUnknown(Exception):
    pass


def require(condition: bool) -> None:
    if not condition:
        raise AssertionError("fixed configuration fixture assertion failed")


def document() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "version": {"source": "release/version.properties", "nameKey": "VERSION_NAME", "buildKey": "BUILD_NUMBER"},
        "source": {"candidateBranch": "main", "productionBranch": "main"},
        "android": {"enabled": True, "applicationId": "org.fixture.app", "identityStatus": "unverified"},
        "ios": {"enabled": False},
        "metadata": {"root": "release/store", "androidLocales": ["en-US"], "iosLocales": []},
        "services": {"androidFirebase": "disabled", "iosFirebase": "disabled"},
        "projectChecks": {"preflight": [], "androidArtifact": [], "iosArtifact": []},
    }


@dataclass
class Runtime:
    edit: Any
    transaction: Any
    custody: Any
    build: Any
    cancellation: Any
    errors: Any
    payloads: Any
    workflow: Any = None
    workflow_payloads: Any = None
    workflow_setup: Any = None
    workflow_bytes: tuple[bytes, ...] = ()

    @property
    def ignore_bytes(self) -> bytes:
        return ("\n".join(self.transaction.IGNORE_LINES) + "\n").encode()


@dataclass
class Owner:
    guard: Any
    lease: Any
    outcome: Any = None
    closed: bool = False
    restored: bool = False
    fatal: bool = False


@dataclass
class Batch:
    runtime: Runtime
    root: Path
    partition: str
    blocked: bool = False
    retain: bool = False
    current: str = "startup"
    completed: list[str] = field(default_factory=list)
    owners: list[Owner] = field(default_factory=list)
    workflow_rows: list[dict[str, Any]] = field(default_factory=list)
    workflow_fixture_failed: bool = False
    workflow_after_unknown_probes: int = 0

    def case_root(self, name: str) -> Path:
        if self.blocked:
            raise FixtureUnknown()
        self.current = name
        root = self.root / name
        root.mkdir(mode=0o700)  # Exclusive fixed child, never an existing project.
        return root

    def record(self, owner: Owner, outcome: Any, *, expected_unknown: bool = False) -> Any:
        owner.outcome = outcome
        uncertain = (outcome.effect == "unknown" or outcome.journal == "unknown"
                     or outcome.resources == "unknown")
        if uncertain:
            self.blocked = self.retain = True
            if not expected_unknown:
                raise FixtureUnknown()
        if outcome.journal == "recovery_required":
            self.retain = True
        return outcome


@contextmanager
def owned_lease(batch: Batch, root: Path, *, expected_unknown: bool = False,
                registered_identity: dict[str, int] | None = None):
    """Prearmed real guard/lease, with unconditional original cleanup dispatch."""
    if batch.blocked:
        raise FixtureUnknown()
    runtime = batch.runtime
    guard = runtime.cancellation.DefaultCancellation(runtime.errors.ValidationError, _GUARD_MESSAGE)
    if runtime.workflow is None:
        require(registered_identity is None)
        lease = runtime.custody.InitRootLease(root, cancellation=guard)
    else:
        # Only this fixed fixture observes registration facts. No renderer,
        # argv, environment or supplied digest can provide root authority.
        identity = workflow_root_identity(root) if registered_identity is None else registered_identity
        lease = runtime.custody.InitRootLease(root, cancellation=guard,
            profile=runtime.transaction.TypedEditProfile.GITHUB_WORKFLOWS, registered_identity=identity)
    owner = Owner(guard, lease)
    batch.owners.append(owner)  # Retain even an incomplete/uncertain original.
    cleanup = runtime.cancellation.CleanupScope(
        guard, lease.close, owns_cancellation=True, first_primary=True)
    body_error = caught = None
    try:
        try:
            with cleanup:
                guard.install()
                guard.activate()
                lease.acquire()
                try:
                    yield owner
                except BaseException as error:
                    body_error = error
                    raise
        finally:
            cleanup.__exit__(*sys.exc_info())
    except BaseException as error:
        caught = error
    try:
        owner.closed = lease.closed is True
        owner.restored = guard.handler_state == "RESTORED"
        owner.fatal = guard.lifetime_ledger.fatal is True
    except BaseException:
        owner.fatal = True
    healthy = owner.closed and owner.restored and not owner.fatal
    if not healthy:
        batch.blocked = batch.retain = True
    if body_error is not None:
        raise body_error
    allowed = (expected_unknown and owner.outcome is not None
               and owner.outcome.effect == "committed" and owner.outcome.resources == "unknown")
    if allowed:
        # This does not clear sticky uncertainty or allow another owner. Even
        # late actual close returns do not manufacture a successful edit.
        batch.blocked = batch.retain = True
        return
    if not healthy:
        raise FixtureUnknown() from None
    if caught is not None:
        raise caught


@contextmanager
def actual_lock_holder(batch: Batch, root: Path, guard: Any, kind: str):
    """Use the actual existing init/build-input owners, never a bare flock."""
    require(kind in {"init", "build"})
    runtime = batch.runtime
    owner = (runtime.transaction.InitWorkspace(root) if kind == "init"
             else runtime.build._Project(root, guard, recovery=False))
    closed = False

    def close() -> None:
        nonlocal closed
        if kind == "init":
            owner.__exit__(None, None, None)
        else:
            owner.cleanup()
        closed = True  # Positive original call return, not just claimed state.

    cleanup = runtime.cancellation.CleanupScope(guard, close, owns_cancellation=False, first_primary=True)
    try:
        try:
            with cleanup:
                if kind == "init":
                    owner.__enter__()
                else:
                    owner.acquire()
                yield owner
        finally:
            cleanup.__exit__(*sys.exc_info())
    finally:
        if not closed or guard.lifetime_ledger.fatal:
            batch.blocked = batch.retain = True
            raise FixtureUnknown() from None
    if kind == "init":
        require(owner.fd == -1)
    else:
        require(owner.meta.close_state == "CLOSED")
        require(all(slot.close_state == "CLOSED" for slot in owner.directory.slots))


def seed(batch: Batch, root: Path, *, raw: bytes | None = None, ignore: bytes | None = None) -> None:
    (root / "release").mkdir(mode=0o700)
    config = root / "release/mobile-release.json"
    config.write_bytes(batch.runtime.payloads.serialize_config_data(document()) if raw is None else raw)
    config.chmod(0o640)
    ignored = root / ".gitignore"
    ignored.write_bytes(batch.runtime.ignore_bytes if ignore is None else ignore)
    ignored.chmod(0o600)
    (root / "unrelated.txt").write_bytes(b"fixed synthetic unrelated content\n")


def snapshot(root: Path) -> tuple[tuple[bytes, int, int, int], ...]:
    result = []
    for name in ("release/mobile-release.json", ".gitignore", "unrelated.txt"):
        path = root / name
        value = path.stat(follow_symlinks=False)
        require(stat.S_ISREG(value.st_mode))
        result.append((path.read_bytes(), value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode)))
    return tuple(result)


def no_journal(batch: Batch, root: Path) -> None:
    require(all(not (root / name).exists() for name in batch.runtime.transaction.STATE_NAMES))


def prepared(batch: Batch, owner: Owner, draft: dict[str, Any] | None = None):
    edit = batch.runtime.edit
    checkout = edit.capture_config_edit(owner.lease)
    plan = edit.prepare_config_edit(owner.lease, checkout, checkout.revision, checkout.base,
                                   document() if draft is None else draft)
    return checkout, plan


def refusal(batch: Batch, owner: Owner, reason: str, action) -> Any:
    try:
        action()
    except batch.runtime.edit.ConfigEditFailure as error:
        outcome = batch.record(owner, error.outcome)
        require((outcome.effect, outcome.journal, outcome.resources, outcome.reason)
                == ("not_started", "not_created", "settled", reason))
        return outcome
    raise AssertionError("fixed configuration refusal was not observed")


def create_case(batch: Batch) -> None:
    root = batch.case_root("create")
    runtime = batch.runtime
    with owned_lease(batch, root) as owner:
        checkout, plan = prepared(batch, owner)
        require(checkout.base is None and plan.view["createReleaseDirectory"] is True)
        require([item["action"] for item in plan.view["files"]] == ["create", "create"])
        require(not (root / "release").exists() and not (root / ".gitignore").exists())
        no_journal(batch, root)  # Real capture/prepare did not create staging.
        result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
        require((result.effect, result.journal, result.resources, result.reason)
                == ("committed", "clean", "settled", "none"))
        require(runtime.edit.apply_config_edit(owner.lease, plan).reason == "invalid_params")
    require((root / "release/mobile-release.json").read_bytes() == runtime.payloads.serialize_config_data(document()))
    require((root / ".gitignore").read_bytes() == runtime.ignore_bytes)
    require(sorted(path.name for path in root.iterdir()) == [".gitignore", "release"])
    require(sorted(path.name for path in (root / "release").iterdir()) == ["mobile-release.json"])
    no_journal(batch, root)
    batch.completed.append(batch.current)


def save_noop_ignore_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("save", "no-op", "ignore-append"):
        root = batch.case_root(kind)
        raw = b" \r\n" + json.dumps(document(), separators=(",", ":")).encode() + b"\r\n"
        ignore = (b"# retained synthetic comment\r\n/.mobile-release/\r\n" if kind == "ignore-append"
                  else ("\r\n".join("/" + line for line in runtime.transaction.IGNORE_LINES)).encode())
        seed(batch, root, raw=raw, ignore=ignore)
        before = snapshot(root)
        proposed = document()
        if kind == "save":
            proposed["source"]["projectReadTokenRequired"] = True
        with owned_lease(batch, root) as owner:
            _, plan = prepared(batch, owner, proposed)
            require(plan.view["rewritesConfigFormatting"] is (kind == "save"))
            require(plan.view["files"][0]["action"] == ("replace" if kind == "save" else "preserve"))
            require(plan.view["files"][1]["action"] == ("append" if kind == "ignore-append" else "preserve"))
            require(snapshot(root) == before)
            no_journal(batch, root)
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
            expected = ("unchanged", "not_created") if kind == "no-op" else ("committed", "clean")
            require((result.effect, result.journal) == expected and result.reason == "none")
        after = snapshot(root)
        require(after[2] == before[2])
        if kind != "save":
            require(after[0] == before[0])  # Actual bytes, device, inode, mode.
        else:
            require(after[0][0] == runtime.payloads.serialize_config_data(proposed))
            require(after[0][3] == before[0][3])
        if kind != "ignore-append":
            require(after[1] == before[1])
        else:
            require(after[1][0] == ignore + ("\n".join(runtime.transaction.IGNORE_LINES[1:]) + "\n").encode())
            require(after[1][3] == before[1][3])
        no_journal(batch, root)
        batch.completed.append(batch.current)


def refusal_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("ignore-conflict", "invalid-existing", "single-link-admission"):
        root = batch.case_root(kind)
        seed(batch, root, ignore=b"!unrelated.txt\n" if kind == "ignore-conflict" else None)
        if kind == "invalid-existing":
            invalid = document()
            invalid["schemaVersion"] = 2
            (root / "release/mobile-release.json").write_bytes(runtime.payloads.serialize_config_data(invalid))
        if kind == "single-link-admission":
            os.link(root / "release/mobile-release.json", root / "second-link.json")
        before = snapshot(root)
        with owned_lease(batch, root) as owner:
            if kind == "ignore-conflict":
                checkout = runtime.edit.capture_config_edit(owner.lease)
                refusal(batch, owner, "ignore_conflict", lambda: runtime.edit.prepare_config_edit(
                    owner.lease, checkout, checkout.revision, checkout.base, document()))
            else:
                reason = "invalid_config" if kind == "invalid-existing" else "filesystem_error"
                refusal(batch, owner, reason, lambda: runtime.edit.capture_config_edit(owner.lease))
        require(snapshot(root) == before)
        no_journal(batch, root)
        batch.completed.append(batch.current)


def stale_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("stale-config-bytes", "stale-config-inode", "stale-ignore-after-prepare",
                 "stale-release", "absent-release-appeared", "stale-root"):
        root = batch.case_root(kind)
        if kind != "absent-release-appeared":
            seed(batch, root)
        with owned_lease(batch, root) as owner:
            checkout = runtime.edit.capture_config_edit(owner.lease)
            if kind == "stale-ignore-after-prepare":
                plan = runtime.edit.prepare_config_edit(owner.lease, checkout, checkout.revision, checkout.base, document())
                (root / ".gitignore").write_bytes(runtime.ignore_bytes + b"# changed after review\n")
                result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
                require((result.effect, result.journal, result.reason) == ("not_started", "not_created", "stale_revision"))
                require(runtime.edit.apply_config_edit(owner.lease, plan).reason == "invalid_params")
            else:
                config = root / "release/mobile-release.json"
                if kind == "stale-config-bytes":
                    config.write_bytes(config.read_bytes() + b" \n")
                elif kind == "stale-config-inode":
                    original_inode = config.stat().st_ino
                    replacement = root / "replacement.json"
                    replacement.write_bytes(config.read_bytes())
                    replacement.chmod(0o640)
                    replacement.replace(config)
                    require(config.stat().st_ino != original_inode)
                elif kind == "stale-release":
                    (root / "release").rename(root / "original-release")
                    (root / "release").mkdir(mode=0o700)
                    config.write_bytes(runtime.payloads.serialize_config_data(document()))
                elif kind == "absent-release-appeared":
                    (root / "release").mkdir(mode=0o700)
                elif kind == "stale-root":
                    root.rename(batch.root / "original-stale-root")
                    root.mkdir(mode=0o700)
                refusal(batch, owner, "stale_revision", lambda: runtime.edit.prepare_config_edit(
                    owner.lease, checkout, checkout.revision, checkout.base, document()))
                refusal(batch, owner, "invalid_params", lambda: runtime.edit.prepare_config_edit(
                    owner.lease, checkout, checkout.revision, checkout.base, document()))
        no_journal(batch, root)
        batch.completed.append(batch.current)


def pending_cases(batch: Batch) -> None:
    runtime = batch.runtime
    entries = [("init-" + str(index), name, True) for index, name in enumerate(runtime.transaction.STATE_NAMES)]
    entries += [("build-pending", ".mobile-release/build-inputs", True),
                ("build-terminal", ".mobile-release/build-inputs-complete.json", False),
                ("build-stage", ".mobile-release/build-inputs-complete.stage", False),
                ("init-alias", ".MOBILE-RELEASE-INIT", True),
                ("malformed-private-mode", ".mobile-release", True)]
    for label, relative, directory in entries:
        root = batch.case_root(label)
        path = root / relative
        if "/" in relative:
            path.parent.mkdir(mode=0o700)
        if directory:
            path.mkdir(mode=0o700)
        else:
            path.write_bytes(b"fixed synthetic reserved state\n")
            path.chmod(0o600)
        if label == "malformed-private-mode":
            path.chmod(0o755)
        original = path.stat(follow_symlinks=False)
        with owned_lease(batch, root) as owner:
            refusal(batch, owner, "pending_state", lambda: runtime.edit.capture_config_edit(owner.lease))
        after = path.stat(follow_symlinks=False)
        require((after.st_dev, after.st_ino, after.st_mode) == (original.st_dev, original.st_ino, original.st_mode))
        require(not (root / "release").exists() and not (root / ".gitignore").exists())
        batch.completed.append(batch.current)


def contention_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("init", "build"):
        root = batch.case_root("contention-" + kind)
        with owned_lease(batch, root) as owner:
            with actual_lock_holder(batch, root, owner.guard, kind):
                refusal(batch, owner, "busy", lambda: runtime.edit.capture_config_edit(owner.lease))
        no_journal(batch, root)
        batch.completed.append(batch.current)
    root = batch.case_root("idle-review-unlocked")
    seed(batch, root)
    with owned_lease(batch, root) as owner:
        checkout = runtime.edit.capture_config_edit(owner.lease)
        with actual_lock_holder(batch, root, owner.guard, "build"):
            pass  # A real build-input lock is available after capture.
        plan = runtime.edit.prepare_config_edit(owner.lease, checkout, checkout.revision, checkout.base, document())
        with actual_lock_holder(batch, root, owner.guard, "init"):
            pass  # A real init lock is also available during plan review.
        runtime.edit.discard_config_edit(plan)
        require(runtime.edit.apply_config_edit(owner.lease, plan).reason == "invalid_params")
    no_journal(batch, root)
    batch.completed.append(batch.current)


def prepublication_rollback_case(batch: Batch) -> None:
    root = batch.case_root("precommit-publication-injection")
    seed(batch, root, ignore=b"# original ignore\n")
    before = snapshot(root)
    runtime = batch.runtime
    original = runtime.transaction.InitWorkspace._publish_terminal
    events = {"injected": 0, "rollback_verified": 0}

    def publish(workspace, fd, plan, state):
        if state == "COMMITTED":
            events["injected"] += 1
            raise OSError("fixed precommit publication injection")
        result = original(workspace, fd, plan, state)
        if state == "ROLLED_BACK" and workspace._terminal_seen == "ROLLED_BACK":
            events["rollback_verified"] += 1
        return result

    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    with owned_lease(batch, root) as owner:
        _, plan = prepared(batch, owner, proposed)
        with patch.object(runtime.transaction.InitWorkspace, "_publish_terminal", publish):
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
        require((result.effect, result.journal, result.resources, result.reason)
                == ("rolled_back", "clean", "settled", "filesystem_error"))
        require(events == {"injected": 1, "rollback_verified": 1})
    require(snapshot(root) == before)  # Real original inodes, not regenerated bytes.
    no_journal(batch, root)
    batch.completed.append(batch.current)


def legacy_public_apply_cases(batch: Batch) -> None:
    """Protect the unborrowed public API, not just the new typed edit route."""
    runtime = batch.runtime
    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    payload = runtime.payloads.serialize_config_data(proposed)
    original_publish = runtime.transaction.InitWorkspace._publish_terminal
    for kind in ("legacy-public-commit", "legacy-public-rollback"):
        root = batch.case_root(kind)
        seed(batch, root)
        before = snapshot(root)
        events = {"injected": 0, "rollback_verified": 0}
        injected = OSError("fixed legacy precommit publication injection")

        def publish(workspace, fd, plan, state):
            if state == "COMMITTED" and events["injected"] == 0:
                require(workspace._guard is None and workspace._scope is None)
                # The real public apply has already installed the replacement;
                # only terminal publication fails. Recovery is never replaced.
                require((root / "release/mobile-release.json").read_bytes() == payload)
                events["injected"] += 1
                raise injected
            result = original_publish(workspace, fd, plan, state)
            if state == "ROLLED_BACK" and workspace._terminal_seen == "ROLLED_BACK":
                events["rollback_verified"] += 1
            return result

        # An idle lease owns the guard/root but no short flock. The existing
        # legacy lock holder supplies the original public workspace and its
        # positive __exit__ receipt, including the exceptional cleanup path.
        with owned_lease(batch, root) as owner:
            with actual_lock_holder(batch, root, owner.guard, "init") as workspace:
                require(workspace._guard is None and workspace._scope is None)
                changes = [(workspace.observe("release/mobile-release.json"), payload),
                           (workspace.observe(".gitignore"), None)]
                if kind == "legacy-public-rollback":
                    with patch.object(runtime.transaction.InitWorkspace, "_publish_terminal", publish):
                        try:
                            workspace.apply(changes)
                        except runtime.errors.ValidationError as error:
                            require(error.__cause__ is injected)
                        else:
                            raise AssertionError("fixed legacy apply failure was not observed")
                    require(events == {"injected": 1, "rollback_verified": 1})
                else:
                    require(workspace.apply(changes) is None)
        after = snapshot(root)
        if kind == "legacy-public-rollback":
            require(after == before)  # Original bytes, device/inode and mode.
        else:
            require(after[0][0] == payload and after[0][3] == before[0][3]
                    and after[0][2] != before[0][2] and after[1:] == before[1:])
        no_journal(batch, root)
        require(sorted(path.name for path in root.iterdir()) == [".gitignore", "release", "unrelated.txt"])
        require(sorted(path.name for path in (root / "release").iterdir()) == ["mobile-release.json"])
        batch.completed.append(batch.current)


def committed_fsync_case(batch: Batch) -> None:
    root = batch.case_root("committed-fsync-injection")
    seed(batch, root)
    runtime = batch.runtime
    original_fsync = runtime.transaction.InitWorkspace._fsync
    original_rollback = runtime.transaction.InitWorkspace._rollback
    events = {"injected": 0, "rollback_calls": 0}

    def fsync(workspace, fd):
        if (workspace._publishing_terminal == "COMMITTED" and workspace._terminal_seen == "COMMITTED"
                and not workspace._terminal_durable and events["injected"] == 0):
            events["injected"] += 1
            raise OSError("fixed postdecision pre-fsync injection")
        return original_fsync(workspace, fd)

    def rollback(workspace, *args):
        events["rollback_calls"] += 1
        return original_rollback(workspace, *args)

    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    with owned_lease(batch, root) as owner:
        _, plan = prepared(batch, owner, proposed)
        with patch.object(runtime.transaction.InitWorkspace, "_fsync", fsync), \
             patch.object(runtime.transaction.InitWorkspace, "_rollback", rollback):
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan))
        require((result.effect, result.journal, result.resources, result.reason)
                == ("committed", "recovery_required", "settled", "filesystem_error"))
        require(events == {"injected": 1, "rollback_calls": 0})
    require((root / "release/mobile-release.json").read_bytes() == runtime.payloads.serialize_config_data(proposed))
    require((root / runtime.transaction.READY / "COMMITTED").is_file())
    batch.retain = True  # No recovery, no deleting a retained real journal.
    batch.completed.append(batch.current)


def committed_close_case(batch: Batch) -> None:
    root = batch.case_root("committed-close-return-injection")
    seed(batch, root)
    runtime = batch.runtime
    original_close = runtime.custody.LockedInitScope.close
    original_publish = runtime.transaction.InitWorkspace._publish_terminal
    original_apply = runtime.transaction.InitWorkspace.apply_typed
    events = {"injected": 0, "actual_scope_close_returned": False,
              "cancelled_after_commit": 0, "committed_carrier": False}
    proposed = document()
    proposed["source"]["projectReadTokenRequired"] = True
    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = prepared(batch, owner, proposed)

        def publish(workspace, fd, manifest, state):
            result = original_publish(workspace, fd, manifest, state)
            if state == "COMMITTED":
                require(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                events["cancelled_after_commit"] += 1
                owner.guard.cancelled = True
                raise KeyboardInterrupt  # Deterministic original-guard cancellation injection.
            return result

        def apply(workspace, changes):
            try:
                return original_apply(workspace, changes)
            except runtime.transaction.InitOperationFailure as error:
                events["committed_carrier"] = (error.outcome.effect == "committed"
                                                and error.outcome.reason == "cancelled")
                raise  # Preserve the real thrown carrier before scope close fails.

        def close(scope):
            terminal = scope.workspace is not None and scope.workspace._terminal_seen == "COMMITTED"
            if scope.lease is owner.lease and terminal and events["injected"] == 0:
                original_close(scope)
                events["actual_scope_close_returned"] = True
                events["injected"] += 1
                # Deterministic wrapper return loss AFTER actual close, not a
                # claim that the OS closed ambiguously or failed to close.
                raise OSError("fixed positive scope-close return loss injection")
            return original_close(scope)

        with patch.object(runtime.transaction.InitWorkspace, "_publish_terminal", publish), \
             patch.object(runtime.transaction.InitWorkspace, "apply_typed", apply), \
             patch.object(runtime.custody.LockedInitScope, "close", close):
            result = batch.record(owner, runtime.edit.apply_config_edit(owner.lease, plan), expected_unknown=True)
        require(result.effect == "committed" and result.resources == "unknown" and result.reason == "cancelled")
        require(events == {"injected": 1, "actual_scope_close_returned": True,
                           "cancelled_after_commit": 1, "committed_carrier": True})
        # No Apply again, filesystem reobserver, fresh owner or native admission
        # follows this uncertainty. Only original prearmed cleanup still runs.
    require(owner.closed and owner.restored and owner.fatal)
    require(batch.blocked and batch.retain)
    batch.completed.append(batch.current)


def workflow_document() -> dict[str, Any]:
    draft = document()
    draft["source"]["productionBranch"] = "production"
    return draft


def workflow_root_identity(root: Path) -> dict[str, int]:
    if type(_RETAINED_BATCH) is Batch and _RETAINED_BATCH.runtime.workflow is not None:
        workflow_probe(_RETAINED_BATCH)
    value = root.stat(follow_symlinks=False)
    require(stat.S_ISDIR(value.st_mode))
    return dict(device=value.st_dev, inode=value.st_ino, mode=value.st_mode,
                uid=value.st_uid, gid=value.st_gid)


def workflow_read(path: Path, limit: int) -> bytes:
    """Bounded fixture DATA only; no symlink/special-file read or chmod retry."""
    if type(_RETAINED_BATCH) is Batch and _RETAINED_BATCH.runtime.workflow is not None:
        workflow_probe(_RETAINED_BATCH)
    before = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit)

    def facts(value):
        # A read may update atime; it must not change bytes, object or permissions.
        return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
                value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)

    def opener(name, flags):
        return os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK)

    with open(path, "rb", opener=opener) as stream:
        opened = os.fstat(stream.fileno())
        require(facts(opened) == facts(before))
        data = stream.read(limit + 1)
        require(facts(os.fstat(stream.fileno())) == facts(opened))
    require(facts(path.stat(follow_symlinks=False)) == facts(before) and len(data) == before.st_size)
    return data


def workflow_probe(batch: Batch) -> None:
    # Workflow DATA readers/snapshot helpers deny probes after the outcome latch.
    # The original prearmed native closes are not fixture probes or new owners.
    if batch.blocked:
        batch.workflow_after_unknown_probes += 1
        raise FixtureUnknown()


def workflow_snapshot(batch: Batch, root: Path) -> tuple[Any, ...]:
    """Small private tree, lstat traversal; bytes/paths never enter the receipt.

    Directory timestamps/size are deliberately not equality evidence: a clean
    rollback changes directory metadata without replacing any original inode.
    Unreadable files and FIFOs are observed by lstat only, never opened.
    """
    workflow_probe(batch)
    rows: list[Any] = []
    total = 0

    def visit(path: Path, name: str, depth: int) -> None:
        nonlocal total
        require(depth <= 8 and len(rows) < 128)
        value = path.stat(follow_symlinks=False)
        identity = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, value.st_nlink)
        if stat.S_ISDIR(value.st_mode):
            rows.append((name, identity))
            names = sorted(item.name for item in path.iterdir())
            require(len(names) <= 128)
            for child in names:
                visit(path / child, child if name == "." else name + "/" + child, depth + 1)
        elif stat.S_ISREG(value.st_mode):
            require(value.st_size <= 2 * 1024 * 1024)
            data = workflow_read(path, 2 * 1024 * 1024) if value.st_mode & 0o444 else None
            total += len(data) if data is not None else 0
            require(total <= 16 * 1024 * 1024)
            rows.append((name, identity, value.st_size, data))
        elif stat.S_ISLNK(value.st_mode):
            target = os.readlink(path)
            require(len(os.fsencode(target)) <= 4096)
            rows.append((name, identity, target))
        else:
            require(stat.S_ISFIFO(value.st_mode))
            rows.append((name, identity))
    visit(root, ".", 0)
    return tuple(rows)


def workflow_absent(batch: Batch, path: Path) -> bool:
    workflow_probe(batch)
    try:
        path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return True
    return False


def workflow_journal_absent(batch: Batch, root: Path) -> bool:
    return all(workflow_absent(batch, root / name) for name in batch.runtime.transaction.STATE_NAMES)


def workflow_seed(batch: Batch, root: Path, *, directories: bool = False,
                  first_exact: bool = False) -> None:
    workflow_probe(batch)
    seed(batch, root, raw=_WORKFLOW_DISK_CONFIG, ignore=_WORKFLOW_IGNORE)
    if directories or first_exact:
        (root / ".github").mkdir(mode=0o750)
        (root / ".github/workflows").mkdir(mode=0o750)
        # Make the later mode-change case deterministic under hosted umask 077.
        # This is initial fixture creation, never a chmod-around-read-denial.
        (root / ".github").chmod(0o750)
        (root / ".github/workflows").chmod(0o750)
    if first_exact:
        path = root / _WORKFLOW_FILES[0][1]
        path.write_bytes(batch.runtime.workflow_bytes[0])
        path.chmod(0o640)


def workflow_prepare(batch: Batch, owner: Owner, checkout=None):
    runtime = batch.runtime
    if checkout is None:
        checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
    plan = runtime.workflow.prepare_github_workflow_edit(owner.lease, checkout, checkout.revision,
        workflow_document(), _WORKFLOW_REPOSITORY, _WORKFLOW_SHA)
    require(type(plan) is runtime.workflow.PreparedWorkflowEdit)
    view = plan.view
    require(tuple((row["id"], row["path"]) for row in view["files"]) == _WORKFLOW_FILES
            and tuple(row["generated"]["content"].encode("utf-8") for row in view["files"])
            == runtime.workflow_bytes and view["templateSet"] == _WORKFLOW_TEMPLATE_SET)
    return checkout, plan


def workflow_scopes_closed(owner: Owner) -> int:
    return sum(scope.closed is True and scope.claimed is True
               and scope.lock.close_state == "CLOSED" and scope.meta.close_state == "CLOSED"
               and scope.workspace is not None
               and all(slot.close_state == "CLOSED" for slot in scope.workspace._slots)
               for scope in owner.lease._scopes)


def workflow_equal(actual: Any, expected: Any) -> bool:
    """Strict assertion equality (bool is not int), not a receipt authority."""
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(workflow_equal(actual[k], v) for k, v in expected.items())
    if type(expected) in {tuple, list}:
        return len(actual) == len(expected) and all(workflow_equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def workflow_finish(batch: Batch, owner: Owner, outcome: Any, expected: tuple[str, ...],
                    observed: dict[str, Any], expected_facts: dict[str, Any]) -> None:
    """Only actual projections are emitted; expected constants only assert."""
    if batch.workflow_fixture_failed:
        raise FixtureUnknown()
    require(type(outcome) in {batch.runtime.edit.CoreEditOutcome, batch.runtime.transaction.InitApplyOutcome})
    actual = (outcome.effect, outcome.journal, outcome.resources, outcome.reason)
    require(actual == expected and owner.outcome is outcome and workflow_equal(observed, expected_facts))
    owner_view = {"closed": owner.closed, "handlerRestored": owner.restored, "fatal": owner.fatal}
    require(workflow_equal(owner_view, {"closed": True, "handlerRestored": True,
                                      "fatal": expected[2] == "unknown"}))
    uncertain = expected[0] == "unknown" or expected[2] == "unknown"
    require(batch.blocked is uncertain and (not uncertain or batch.retain))
    names = _WORKFLOW_CASES[batch.partition]
    require(len(batch.workflow_rows) < len(names) and batch.current == names[len(batch.workflow_rows)])
    row = {"case": batch.current,
           "outcome": dict(zip(("effect", "journal", "resources", "reason"), actual)),
           "owner": owner_view, "observed": observed}
    require(len(json.dumps(row, allow_nan=False, separators=(",", ":")).encode("utf-8")) <= 2048)
    batch.workflow_rows.append(row)
    batch.completed.append(batch.current)


@contextmanager
def workflow_witness(batch: Batch):
    """A broken injection/observer can never pass as the intended native fault.

    Intentional faults are raised OUTSIDE this scope. The real transaction may
    swallow a recovery exception, so fixture errors latch independently of its
    provisional outcome and end every later admission.
    """
    try:
        workflow_probe(batch)
        yield
    except BaseException:
        batch.workflow_fixture_failed = batch.blocked = batch.retain = True
        raise


def workflow_original(batch: Batch, owner: Owner, workspace: Any) -> None:
    require(type(workspace) is batch.runtime.transaction.InitWorkspace
            and workspace._scope is not None and workspace._scope.lease is owner.lease
            and workspace._guard is owner.guard and workspace._typed_claimed
            and workspace._typed_profile is batch.runtime.transaction.TypedEditProfile.GITHUB_WORKFLOWS)


def workflow_installed(batch: Batch, root: Path, workspace: Any) -> bool:
    workflow_probe(batch)
    require(workspace is not None and workspace._workflow_complete and workspace._workflow_plan is not None)
    manifest = json.loads(workspace._workflow_plan)  # Original frozen proof, not a journal re-parse.
    require(tuple(row["path"] for row in manifest["files"]) == tuple(path for _, path in _WORKFLOW_FILES))
    for (_, path), data, row in zip(_WORKFLOW_FILES, batch.runtime.workflow_bytes, manifest["files"]):
        after = row["after"]
        require(row["before"] is None and type(after) is dict)
        value = (root / path).stat(follow_symlinks=False)
        # New regular files honor the inherited umask (077 in this hosted lane).
        # Compare actual original staged mode/inode, never assume mode 0644.
        if (workflow_read(root / path, 16 * 1024) != data or after["sha256"] != hashlib.sha256(data).hexdigest()
                or (value.st_dev, value.st_ino, stat.S_IMODE(value.st_mode), value.st_size)
                != (after["device"], after["inode"], after["mode"], len(data))):
            return False
    return True


def workflow_capture_case(batch: Batch) -> None:
    root = batch.case_root("capture-prepare-discard")
    workflow_seed(batch, root)
    before = workflow_snapshot(batch, root)
    disk_before = snapshot(root)[0]
    runtime = batch.runtime
    with owned_lease(batch, root) as owner:
        checkout, plan = workflow_prepare(batch, owner)
        require(plan.view["createDirectories"] == [".github", ".github/workflows"]
                and [row["action"] for row in plan.view["files"]] == ["create"] * 4)
        require(workflow_snapshot(batch, root) == before and workflow_journal_absent(batch, root))
        runtime.workflow.discard_github_workflow_edit(plan)
        retired = plan._state == checkout._state == runtime.edit._RETIRED
        require(runtime.workflow.apply_github_workflow_edit(owner.lease, plan).reason == "invalid_params")
        result = batch.record(owner, owner.lease.last_outcome)
    observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root),
                "scopesClosed": workflow_scopes_closed(owner), "discardRetired": retired,
                "diskConfigUnchanged": snapshot(root)[0] == disk_before}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "none"), observed,
        {"snapshotUnchanged": True, "journalAbsent": True, "scopesClosed": 2,
         "discardRetired": True, "diskConfigUnchanged": True})


def workflow_conflict_case(batch: Batch) -> None:
    root = batch.case_root("existing-differs")
    workflow_seed(batch, root, directories=True)
    (root / _WORKFLOW_FILES[0][1]).write_bytes(b"fixed differing workflow; never replace\n")
    before = workflow_snapshot(batch, root)
    runtime = batch.runtime
    with owned_lease(batch, root) as owner:
        checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
        conflict = runtime.workflow.prepare_github_workflow_edit(owner.lease, checkout, checkout.revision,
            workflow_document(), _WORKFLOW_REPOSITORY, _WORKFLOW_SHA)
        require(type(conflict) is runtime.workflow.WorkflowConflict)
        result = batch.record(owner, conflict.outcome)
    observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root),
                "conflictIds": [row["id"] for row in conflict.view["conflicts"]],
                "tokenAbsent": not hasattr(conflict, "token") and checkout._prepared is None,
                "rechecks": owner.lease._rechecks}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "none"), observed,
        {"snapshotUnchanged": True, "journalAbsent": True, "conflictIds": ["preflight"],
         "tokenAbsent": True, "rechecks": 1})


def workflow_observation_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("oversized", "unreadable", "symlink-leaf", "symlink-ancestor", "hardlink",
                 "aliased-leaf", "nonregular-fifo"):
        root = batch.case_root(kind)
        workflow_seed(batch, root, directories=kind != "symlink-ancestor")
        leaf = root / _WORKFLOW_FILES[0][1]
        if kind == "oversized":
            leaf.write_bytes(b"x" * (runtime.workflow_setup.MAX_SNAPSHOT_FILE_BYTES + 1))
        elif kind == "unreadable":
            leaf.write_bytes(b"fixed unreadable workflow\n")
            leaf.chmod(0)
        elif kind == "symlink-leaf":
            leaf.symlink_to("../../unrelated.txt")
        elif kind == "symlink-ancestor":
            (root / "workflow-link-target").mkdir(mode=0o700)
            (root / ".github").symlink_to("workflow-link-target", target_is_directory=True)
        elif kind == "hardlink":
            os.link(root / "unrelated.txt", leaf)
        elif kind == "aliased-leaf":
            leaf.with_name(leaf.name.upper()).write_bytes(b"fixed aliased workflow\n")
        else:
            os.mkfifo(leaf, mode=0o600)
        before = workflow_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            result = refusal(batch, owner, "filesystem_error",
                             lambda: runtime.workflow.capture_github_workflow_edit(owner.lease))
        observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                    "journalAbsent": workflow_journal_absent(batch, root),
                    "observationRefused": result is owner.outcome and owner.lease._revision is None}
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "filesystem_error"),
            observed, {"snapshotUnchanged": True, "journalAbsent": True, "observationRefused": True})


def workflow_registered_root_case(batch: Batch) -> None:
    root = batch.case_root("registered-root-replaced")
    workflow_seed(batch, root, first_exact=True)
    registered = workflow_root_identity(root)
    original_before = workflow_snapshot(batch, root)
    original = batch.root / "registered-root-original"
    root.rename(original)
    root.mkdir(mode=0o700)
    workflow_seed(batch, root)
    replacement_before = workflow_snapshot(batch, root)
    runtime = batch.runtime
    observe_original = runtime.transaction.InitWorkspace.observe
    events = {"targetObservations": 0}

    def observe(workspace, *args, **kwargs):
        events["targetObservations"] += 1
        return observe_original(workspace, *args, **kwargs)

    count = len(batch.owners)
    with patch.object(runtime.transaction.InitWorkspace, "observe", observe):
        try:
            with owned_lease(batch, root, registered_identity=registered) as owner:
                runtime.workflow.capture_github_workflow_edit(owner.lease)
        except runtime.transaction.InitOperationFailure as error:
            require(type(error) is runtime.transaction.InitOperationFailure and len(batch.owners) == count + 1)
            owner = batch.owners[count]
            result = batch.record(owner, error.outcome)
        else:
            raise AssertionError("fixed registration replacement was not refused")
    observed = {"targetObservations": events["targetObservations"],
                "registeredIdentityChanged": workflow_root_identity(root) != registered,
                "replacementUnchanged": workflow_snapshot(batch, root) == replacement_before,
                "originalUnchanged": workflow_snapshot(batch, original) == original_before,
                "journalAbsent": workflow_journal_absent(batch, root) and workflow_journal_absent(batch, original)}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "stale_revision"), observed,
        {"targetObservations": 0, "registeredIdentityChanged": True, "replacementUnchanged": True,
         "originalUnchanged": True, "journalAbsent": True})


def workflow_stale_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("stale-leaf-bytes-before-prepare", "stale-leaf-inode-before-apply",
                 "stale-ancestor-mode-before-prepare", "absent-ancestor-before-prepare",
                 "absent-leaf-before-apply", "stale-root-before-apply"):
        root = batch.case_root(kind)
        workflow_seed(batch, root, directories=kind != "absent-ancestor-before-prepare",
                      first_exact=kind in {"stale-leaf-bytes-before-prepare", "stale-leaf-inode-before-apply"})
        original = None
        original_before = None
        at_apply = kind.endswith("before-apply")
        with owned_lease(batch, root) as owner:
            checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
            plan = workflow_prepare(batch, owner, checkout)[1] if at_apply else None
            leaf = root / _WORKFLOW_FILES[0][1]
            if kind == "stale-leaf-bytes-before-prepare":
                leaf.write_bytes(runtime.workflow_bytes[0] + b"# fixed later edit\n")
            elif kind == "stale-leaf-inode-before-apply":
                before_inode = leaf.stat(follow_symlinks=False).st_ino
                replacement = root / "replacement-workflow.yml"
                with replacement.open("xb") as stream:
                    stream.write(runtime.workflow_bytes[0])
                replacement.chmod(0o640)
                replacement.replace(leaf)
                require(leaf.stat(follow_symlinks=False).st_ino != before_inode)
            elif kind == "stale-ancestor-mode-before-prepare":
                (root / ".github/workflows").chmod(0o700)
            elif kind == "absent-ancestor-before-prepare":
                (root / ".github").mkdir(mode=0o700)
            elif kind == "absent-leaf-before-apply":
                leaf.write_bytes(runtime.workflow_bytes[0])
                leaf.chmod(0o640)
            else:
                original = batch.root / "stale-root-original"
                root.rename(original)
                original_before = workflow_snapshot(batch, original)
                root.mkdir(mode=0o700)
                workflow_seed(batch, root)
            before = workflow_snapshot(batch, root)  # After the deliberate external edit.
            if at_apply:
                result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
                retired = plan._state == checkout._state == runtime.edit._RETIRED
                require(runtime.workflow.apply_github_workflow_edit(owner.lease, plan).reason == "invalid_params")
            else:
                result = refusal(batch, owner, "stale_revision", lambda: workflow_prepare(batch, owner, checkout))
                retired = checkout._state == runtime.edit._RETIRED and checkout._prepared is None
        unchanged = workflow_snapshot(batch, root) == before
        absent = workflow_journal_absent(batch, root)
        if original is not None:
            unchanged = unchanged and workflow_snapshot(batch, original) == original_before
            absent = absent and workflow_journal_absent(batch, original)
        observed = {"snapshotUnchanged": unchanged, "journalAbsent": absent,
                    "rechecks": owner.lease._rechecks, "retired": retired}
        # Root check precedes workspace_scope's increment: that case has only
        # its original successful Prepare recheck, not a fictional Apply scope.
        rechecks = 2 if at_apply and kind != "stale-root-before-apply" else 1
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "stale_revision"),
            observed, {"snapshotUnchanged": True, "journalAbsent": True, "rechecks": rechecks, "retired": True})


def workflow_pending_cases(batch: Batch) -> None:
    for kind in ("init", "build"):
        root = batch.case_root("pending-" + kind)
        workflow_seed(batch, root)
        if kind == "init":
            (root / batch.runtime.transaction.READY).mkdir(mode=0o700)
        else:
            (root / ".mobile-release").mkdir(mode=0o700)
            (root / ".mobile-release/build-inputs").mkdir(mode=0o700)
        before = workflow_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            result = refusal(batch, owner, "pending_state",
                lambda: batch.runtime.workflow.capture_github_workflow_edit(owner.lease))
        observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                    "noTargetsCreated": workflow_absent(batch, root / ".github")}
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "pending_state"),
            observed, {"snapshotUnchanged": True, "noTargetsCreated": True})


def workflow_holder_closed(holder: Any, kind: str) -> bool:
    if kind == "init":
        return holder.fd == -1
    return (holder.claimed is True and holder.meta.close_state == "CLOSED"
            and all(slot.close_state == "CLOSED" for slot in holder.directory.slots))


def workflow_contention_cases(batch: Batch) -> None:
    runtime = batch.runtime
    for kind in ("init", "build"):
        root = batch.case_root("contention-" + kind)
        workflow_seed(batch, root)
        before = workflow_snapshot(batch, root)
        with owned_lease(batch, root) as owner:
            with actual_lock_holder(batch, root, owner.guard, kind) as holder:
                result = refusal(batch, owner, "busy",
                    lambda: runtime.workflow.capture_github_workflow_edit(owner.lease))
        observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                    "journalAbsent": workflow_journal_absent(batch, root),
                    "holderClosed": workflow_holder_closed(holder, kind)}
        workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "busy"), observed,
            {"snapshotUnchanged": True, "journalAbsent": True, "holderClosed": True})
    root = batch.case_root("review-unlocked")
    workflow_seed(batch, root)
    before = workflow_snapshot(batch, root)
    with owned_lease(batch, root) as owner:
        checkout = runtime.workflow.capture_github_workflow_edit(owner.lease)
        with actual_lock_holder(batch, root, owner.guard, "build") as build_holder:
            pass
        _, plan = workflow_prepare(batch, owner, checkout)
        with actual_lock_holder(batch, root, owner.guard, "init") as init_holder:
            pass
        runtime.workflow.discard_github_workflow_edit(plan)
        retired = checkout._state == plan._state == runtime.edit._RETIRED
        result = batch.record(owner, owner.lease.last_outcome)
    observed = {"snapshotUnchanged": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root),
                "holdersClosed": sum((workflow_holder_closed(build_holder, "build"),
                                      workflow_holder_closed(init_holder, "init"))),
                "scopesClosed": workflow_scopes_closed(owner), "discardRetired": retired}
    workflow_finish(batch, owner, result, ("not_started", "not_created", "settled", "none"), observed,
        {"snapshotUnchanged": True, "journalAbsent": True, "holdersClosed": 2,
         "scopesClosed": 2, "discardRetired": True})


def workflow_partial_rollback_case(batch: Batch) -> None:
    root = batch.case_root("partial-install-rollback")
    workflow_seed(batch, root)
    before = workflow_snapshot(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    move_original, rollback_original = workspace_type._move, workspace_type._rollback
    recovery_original = workspace_type._fixed_recovery
    events = {"firstLeafInstalled": False, "rollbackReturned": False, "injections": 0, "recoveryAttempts": 0}

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        value = move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)
        if workspace._installing and source == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started
                        and destination == Path(_WORKFLOW_FILES[0][1]).name)
                leaf = root / _WORKFLOW_FILES[0][1]
                installed = leaf.stat(follow_symlinks=False)
                events["firstLeafInstalled"] = (workflow_read(leaf, 16 * 1024) == runtime.workflow_bytes[0]
                    and (installed.st_dev, installed.st_ino, stat.S_IMODE(installed.st_mode))
                    == (expected["device"], expected["inode"], expected["mode"]))
                events["injections"] += 1
            raise OSError("fixed first-workflow-installed injection")
        return value

    def rollback(workspace, *args):
        value = rollback_original(workspace, *args)
        with workflow_witness(batch):
            workflow_original(batch, owner, workspace)
            events["rollbackReturned"] = workspace._terminal_seen == "ROLLED_BACK" and workspace._terminal_durable
        return value

    def recovery(workspace):
        events["recoveryAttempts"] += 1
        return recovery_original(workspace)

    with owned_lease(batch, root) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_move", move), patch.object(workspace_type, "_rollback", rollback), \
             patch.object(workspace_type, "_fixed_recovery", recovery):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
    observed = {**events, "snapshotRestored": workflow_snapshot(batch, root) == before,
                "journalAbsent": workflow_journal_absent(batch, root)}
    workflow_finish(batch, owner, result, ("rolled_back", "clean", "settled", "filesystem_error"), observed,
        {"firstLeafInstalled": True, "rollbackReturned": True, "injections": 1, "recoveryAttempts": 1,
         "snapshotRestored": True, "journalAbsent": True})


def workflow_incomplete_case(batch: Batch) -> None:
    root = batch.case_root("incomplete-preparing")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    write_original, recover_original, unlink_original = workspace_type._write, workspace_type.recover, workspace_type._unlink
    events = {"recoverCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    original_workspace = None

    def write(workspace, fd, name, data, mode=0o600, **kwargs):
        nonlocal original_workspace
        value = write_original(workspace, fd, name, data, mode, **kwargs)
        if name == "new-0" and events["injections"] == 0:
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(not workspace._workflow_complete and workspace._workflow_header is None)
                original_workspace = workspace
                events["injections"] += 1
            raise OSError("fixed incomplete workflow preparation injection")
        return value

    def recover(workspace):
        events["recoverCalls"] += 1
        return recover_original(workspace)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    with owned_lease(batch, root) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_write", write), patch.object(workspace_type, "recover", recover), \
             patch.object(workspace_type, "_unlink", unlink):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
    workflow_probe(batch)
    preparing = root / runtime.transaction.PREPARING
    observed = {"preparingRetained": stat.S_ISDIR(preparing.stat(follow_symlinks=False).st_mode),
                "completeProof": original_workspace is not None and original_workspace._workflow_complete,
                "numberedSlotRetained": workflow_read(preparing / "new-0", 16 * 1024) == runtime.workflow_bytes[0],
                **events}
    workflow_finish(batch, owner, result, ("not_started", "recovery_required", "settled", "filesystem_error"), observed,
        {"preparingRetained": True, "completeProof": False, "numberedSlotRetained": True,
         "recoverCalls": 0, "cleanupUnlinks": 0, "injections": 1})


def workflow_ready_corruption_cases(batch: Batch) -> None:
    """One original completed proof; disk controls cannot mint another roster."""
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    rollback_original, unlink_original = workspace_type._rollback, workspace_type._unlink
    for kind in ("wrong-roster-controls", "unowned-staging-slot"):
        root = batch.case_root(kind)
        workflow_seed(batch, root)
        events = {"completeProof": False, "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 0}
        mutated = None
        wrong_bytes = None
        consistent = False

        def install(workspace, fd, manifest):
            nonlocal mutated, wrong_bytes, consistent
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and not workspace._install_started and events["injections"] == 0)
                events["completeProof"] = workspace._workflow_complete
                journal = root / runtime.transaction.READY
                if kind == "wrong-roster-controls":
                    original = workflow_read(journal / "plan.json", runtime.transaction.MAX_CONTROL_BYTES)
                    require(original == workspace._workflow_plan)
                    changed = json.loads(original)
                    changed["files"][0]["path"] = ".github/workflows/unapproved.yml"
                    wrong_bytes = runtime.transaction._json(changed)
                    (journal / "plan.json").write_bytes(wrong_bytes)
                    for state, pending in (("COMMITTED", "commit.pending"), ("ROLLED_BACK", "rollback.pending")):
                        (journal / pending).write_bytes(runtime.transaction.InitWorkspace._marker(changed, state))
                    # This asserts self-consistent tampered DATA, not new native
                    # authority. Original _load must still reject its frozen proof.
                    actual = workflow_read(journal / "plan.json", runtime.transaction.MAX_CONTROL_BYTES)
                    markers = [json.loads(workflow_read(journal / pending, 4096))
                               for pending in ("commit.pending", "rollback.pending")]
                    consistent = (actual == wrong_bytes and all(
                        marker["transactionId"] == changed["transactionId"]
                        and marker["planSha256"] == hashlib.sha256(actual).hexdigest()
                        and marker["state"] == state
                        for marker, state in zip(markers, ("COMMITTED", "ROLLED_BACK"))))
                else:
                    with (journal / "new-17").open("xb") as stream:
                        stream.write(b"fixed unowned numbered slot; preserve\n")
                    (journal / "new-17").chmod(0o600)
                mutated = workflow_snapshot(batch, journal)
                events["injections"] += 1
            # Do not call original install: a retained journal can have a known
            # not-started effect. The real one-shot fixed recovery still runs.
            raise OSError("fixed completed workflow proof corruption injection")

        def rollback(workspace, *args):
            events["rollbackCalls"] += 1
            return rollback_original(workspace, *args)

        def unlink(workspace, *args, **kwargs):
            if events["injections"]:
                events["cleanupUnlinks"] += 1
            return unlink_original(workspace, *args, **kwargs)

        with owned_lease(batch, root) as owner:
            _, plan = workflow_prepare(batch, owner)
            with patch.object(workspace_type, "_install", install), patch.object(workspace_type, "_rollback", rollback), \
                 patch.object(workspace_type, "_unlink", unlink):
                result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
        retained = workflow_snapshot(batch, root / runtime.transaction.READY) == mutated
        if kind == "wrong-roster-controls":
            observed = {**events, "selfConsistentJournal": consistent,
                        "wrongRosterRetained": retained and workflow_read(root / runtime.transaction.READY / "plan.json",
                                                                          runtime.transaction.MAX_CONTROL_BYTES) == wrong_bytes}
            expected = {"completeProof": True, "selfConsistentJournal": True, "wrongRosterRetained": True,
                        "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 1}
        else:
            observed = {**events, "unownedSlotRetained": retained and workflow_read(
                root / runtime.transaction.READY / "new-17", 4096) == b"fixed unowned numbered slot; preserve\n"}
            expected = {"completeProof": True, "unownedSlotRetained": True,
                        "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 1}
        workflow_finish(batch, owner, result, ("not_started", "recovery_required", "settled", "filesystem_error"),
                        observed, expected)


def workflow_pending_replaced_case(batch: Batch, *, committed: bool) -> None:
    root = batch.case_root("commit-pending-replaced" if committed else "rollback-pending-replaced")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    install_original, publish_original, terminal_original = workspace_type._install, workspace_type._publish_terminal, workspace_type._terminal
    move_original, rollback_original = workspace_type._move, workspace_type._rollback
    unlink_original, recover_original = workspace_type._unlink, workspace_type.recover
    selected_state = "COMMITTED" if committed else "ROLLED_BACK"
    events = {"completeProof": False, "sameBytesNewInode": False, "terminalMoveCalls": 0,
              "rollbackCalls": 0, "cleanupUnlinks": 0, "injections": 0}
    active = None
    mutated = None
    retained_inside_original = False
    installed = False
    stopped_before_install = False

    def install(workspace, fd, manifest):
        nonlocal stopped_before_install
        if committed:
            return install_original(workspace, fd, manifest)
        with workflow_witness(batch):
            workflow_original(batch, owner, workspace)
            require(workspace._workflow_complete and not workspace._install_started and not stopped_before_install)
            stopped_before_install = True
        # Fixed prerequisite stop to reach the ORIGINAL rollback publisher.
        # "injections" counts the one pending-control replacement below.
        raise OSError("fixed pre-install stop for rollback marker injection")

    def publish(workspace, fd, manifest, state):
        nonlocal active
        with workflow_witness(batch):
            workflow_original(batch, owner, workspace)
            require(active is None)
            active = (workspace, fd, manifest, state)
        try:
            return publish_original(workspace, fd, manifest, state)
        finally:
            active = None

    def terminal(workspace, fd, manifest):
        nonlocal mutated, installed
        value = terminal_original(workspace, fd, manifest)
        if (active is not None and active[0] is workspace and active[1] == fd
                and active[2] is manifest and active[3] == selected_state and events["injections"] == 0):
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(value is None and workspace._workflow_complete
                        and workspace._install_started is committed)
                events["completeProof"] = workspace._workflow_complete
                if committed:
                    installed = workflow_installed(batch, root, workspace)
                    require(installed)
                else:
                    require(stopped_before_install)
                journal = root / runtime.transaction.READY
                pending = journal / ("commit.pending" if committed else "rollback.pending")
                data = workflow_read(pending, 4096)
                before = pending.stat(follow_symlinks=False)
                replacement = journal / "fixture-marker-replacement"
                with replacement.open("xb") as stream:
                    stream.write(data)
                replacement.chmod(stat.S_IMODE(before.st_mode))
                replacement.replace(pending)
                after = pending.stat(follow_symlinks=False)
                events["sameBytesNewInode"] = (workflow_read(pending, 4096) == data
                    and after.st_dev == before.st_dev and after.st_ino != before.st_ino
                    and after.st_mode == before.st_mode and after.st_nlink == before.st_nlink == 1)
                mutated = workflow_snapshot(batch, journal)
                events["injections"] += 1
            # Return the genuine proof's result. The untouched publisher must
            # re-bind pending and reject the replacement BEFORE its real _move.
        return value

    def move(workspace, source_fd, source, destination_fd, destination, expected, **kwargs):
        if destination in {"COMMITTED", "ROLLED_BACK"}:
            events["terminalMoveCalls"] += 1
        return move_original(workspace, source_fd, source, destination_fd, destination, expected, **kwargs)

    def rollback(workspace, *args):
        events["rollbackCalls"] += 1
        return rollback_original(workspace, *args)

    def unlink(workspace, *args, **kwargs):
        if events["injections"]:
            events["cleanupUnlinks"] += 1
        return unlink_original(workspace, *args, **kwargs)

    def recover(workspace):
        nonlocal retained_inside_original
        try:
            return recover_original(workspace)
        finally:
            if events["injections"]:
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    retained_inside_original = workflow_snapshot(batch, root / runtime.transaction.READY) == mutated

    with owned_lease(batch, root, expected_unknown=committed) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_install", install), patch.object(workspace_type, "_publish_terminal", publish), \
             patch.object(workspace_type, "_terminal", terminal), patch.object(workspace_type, "_move", move), \
             patch.object(workspace_type, "_rollback", rollback), patch.object(workspace_type, "_unlink", unlink), \
             patch.object(workspace_type, "recover", recover):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan),
                                  expected_unknown=committed)
        # No filesystem probes follow this result in either variant. In the
        # final committed variant the effect is Unknown, although these original
        # scope/lease resources settle. Never convert that into rolled-back.
    if committed:
        observed = {**events, "allFourInstalledBeforeRefusal": installed,
                    "remainingProofNotConsumed": retained_inside_original
                        and events["terminalMoveCalls"] == events["rollbackCalls"] == events["cleanupUnlinks"] == 0}
        expected = {"completeProof": True, "sameBytesNewInode": True, "allFourInstalledBeforeRefusal": True,
                    "terminalMoveCalls": 0, "rollbackCalls": 0, "cleanupUnlinks": 0,
                    "remainingProofNotConsumed": True, "injections": 1}
    else:
        observed = {**events, "remainingProofRetained": retained_inside_original}
        expected = {"completeProof": True, "sameBytesNewInode": True, "terminalMoveCalls": 0,
                    "rollbackCalls": 1, "cleanupUnlinks": 0, "remainingProofRetained": True, "injections": 1}
    workflow_finish(batch, owner, result,
        ("unknown" if committed else "not_started", "recovery_required", "settled", "filesystem_error"), observed, expected)


def workflow_cleanup_missing_cases(batch: Batch) -> None:
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    install_original, cleanup_original = workspace_type._install, workspace_type._cleanup
    terminal_original, unlink_original = workspace_type._terminal, workspace_type._unlink
    for committed in (True, False):
        root = batch.case_root("cleanup-committed-unused-missing" if committed else "cleanup-rolled-back-unused-missing")
        workflow_seed(batch, root)
        selected_state = "COMMITTED" if committed else "ROLLED_BACK"
        unused = "rollback.pending" if committed else "commit.pending"
        events = {"terminal": "UNKNOWN", "durable": False, "cleanupUnlinks": 0, "injections": 0}
        active_cleanup = None
        mutated = None

        def install(workspace, fd, manifest):
            if committed:
                return install_original(workspace, fd, manifest)
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and not workspace._install_started)
            raise OSError("fixed pre-install stop for rolled-back cleanup injection")

        def cleanup(workspace):
            nonlocal active_cleanup
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(active_cleanup is None)
                active_cleanup = workspace
            try:
                return cleanup_original(workspace)
            finally:
                active_cleanup = None

        def terminal(workspace, fd, manifest):
            nonlocal mutated
            value = terminal_original(workspace, fd, manifest)
            if active_cleanup is workspace and events["injections"] == 0:
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    require(value == selected_state and workspace._terminal_seen == selected_state
                            and workspace._terminal_durable and workspace._workflow_complete)
                    events["terminal"] = workspace._terminal_seen
                    events["durable"] = workspace._terminal_durable
                    journal = root / runtime.transaction.CLEANUP
                    # The original _cleanup has just validated all controls.
                    # Remove ONLY the unused marker before its entry capture;
                    # presence equivalence must reject, not adopt this suffix.
                    (journal / unused).unlink()
                    mutated = workflow_snapshot(batch, journal)
                    events["injections"] += 1
            return value

        def unlink(workspace, *args, **kwargs):
            if active_cleanup is workspace:
                events["cleanupUnlinks"] += 1
            return unlink_original(workspace, *args, **kwargs)

        with owned_lease(batch, root) as owner:
            _, plan = workflow_prepare(batch, owner)
            with patch.object(workspace_type, "_install", install), patch.object(workspace_type, "_cleanup", cleanup), \
                 patch.object(workspace_type, "_terminal", terminal), patch.object(workspace_type, "_unlink", unlink):
                result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
        journal = root / runtime.transaction.CLEANUP
        observed = {**events, "unusedPendingAbsent": workflow_absent(batch, journal / unused),
                    "remainingProofRetained": workflow_snapshot(batch, journal) == mutated}
        workflow_finish(batch, owner, result,
            ("committed" if committed else "not_started", "recovery_required", "settled", "filesystem_error"), observed,
            {"terminal": selected_state, "durable": True, "unusedPendingAbsent": True,
             "cleanupUnlinks": 0, "remainingProofRetained": True, "injections": 1})


def workflow_committed_fsync_case(batch: Batch) -> None:
    root = batch.case_root("committed-fsync-injection")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    fsync_original, rollback_original = workspace_type._fsync, workspace_type._rollback
    events = {"rollbackCalls": 0, "injections": 0}
    original_workspace = None

    def fsync(workspace, fd):
        nonlocal original_workspace
        if (workspace._publishing_terminal == "COMMITTED" and workspace._terminal_seen == "COMMITTED"
                and not workspace._terminal_durable and events["injections"] == 0):
            with workflow_witness(batch):
                workflow_original(batch, owner, workspace)
                require(workspace._workflow_complete and workspace._install_started)
                original_workspace = workspace
                events["injections"] += 1
            raise OSError("fixed workflow postdecision pre-fsync injection")
        return fsync_original(workspace, fd)

    def rollback(workspace, *args):
        events["rollbackCalls"] += 1
        return rollback_original(workspace, *args)

    with owned_lease(batch, root) as owner:
        _, plan = workflow_prepare(batch, owner)
        with patch.object(workspace_type, "_fsync", fsync), patch.object(workspace_type, "_rollback", rollback):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan))
    workflow_probe(batch)
    marker = root / runtime.transaction.READY / "COMMITTED"
    observed = {"committedObserved": original_workspace is not None and original_workspace._terminal_seen == "COMMITTED",
                "durabilityConfirmed": original_workspace is not None and original_workspace._terminal_durable,
                "allFourInstalled": workflow_installed(batch, root, original_workspace),
                "journalRetained": stat.S_ISREG(marker.stat(follow_symlinks=False).st_mode), **events}
    require(workflow_read(root / "release/mobile-release.json", 4096) == _WORKFLOW_DISK_CONFIG
            and workflow_read(root / ".gitignore", 4096) == _WORKFLOW_IGNORE)
    workflow_finish(batch, owner, result, ("committed", "recovery_required", "settled", "filesystem_error"), observed,
        {"committedObserved": True, "durabilityConfirmed": False, "rollbackCalls": 0,
         "allFourInstalled": True, "journalRetained": True, "injections": 1})


def workflow_committed_close_case(batch: Batch) -> None:
    root = batch.case_root("committed-close-return-injection")
    workflow_seed(batch, root)
    runtime = batch.runtime
    workspace_type = runtime.transaction.InitWorkspace
    close_original = runtime.custody.LockedInitScope.close
    publish_original, apply_original = workspace_type._publish_terminal, workspace_type.apply_workflows_typed
    events = {"actualScopeCloseReturned": False, "cancelledAfterCommit": 0, "committedCarrier": False, "injections": 0}
    with owned_lease(batch, root, expected_unknown=True) as owner:
        _, plan = workflow_prepare(batch, owner)

        def publish(workspace, fd, manifest, state):
            value = publish_original(workspace, fd, manifest, state)
            if state == "COMMITTED":
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    require(workspace._terminal_seen == "COMMITTED" and workspace._terminal_durable)
                    events["cancelledAfterCommit"] += 1
                    owner.guard.cancelled = True
                raise KeyboardInterrupt  # Labelled injection, never EOF evidence.
            return value

        def apply(workspace, changes):
            try:
                return apply_original(workspace, changes)
            except runtime.transaction.InitOperationFailure as error:
                with workflow_witness(batch):
                    workflow_original(batch, owner, workspace)
                    events["committedCarrier"] = (error.outcome.effect == "committed"
                        and error.outcome.journal == "clean" and error.outcome.reason == "cancelled")
                raise

        def close(scope):
            terminal = scope.workspace is not None and scope.workspace._terminal_seen == "COMMITTED"
            if scope.lease is owner.lease and terminal and events["injections"] == 0:
                close_original(scope)
                with workflow_witness(batch):
                    events["actualScopeCloseReturned"] = scope.closed is True
                    events["injections"] += 1
                raise OSError("fixed workflow positive scope-close return loss injection")
            return close_original(scope)

        with patch.object(workspace_type, "_publish_terminal", publish), \
             patch.object(workspace_type, "apply_workflows_typed", apply), \
             patch.object(runtime.custody.LockedInitScope, "close", close):
            result = batch.record(owner, runtime.workflow.apply_github_workflow_edit(owner.lease, plan), expected_unknown=True)
        # Nothing beyond original prearmed cleanup follows this resources-Unknown:
        # no filesystem observer, fresh owner, recovery or cleanup adoption.
    observed = {**events, "afterUnknownProbes": batch.workflow_after_unknown_probes}
    workflow_finish(batch, owner, result, ("committed", "clean", "unknown", "cancelled"), observed,
        {"actualScopeCloseReturned": True, "cancelledAfterCommit": 1, "committedCarrier": True,
         "injections": 1, "afterUnknownProbes": 0})


def hosted_parameters(argv: list[str]) -> tuple[Path, str]:
    if (not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or os.environ.get("MRK_DESKTOP_CONFIG_NATIVE") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise FixtureRefused()
    platform = "Linux" if sys.platform.startswith("linux") else "macOS" if sys.platform == "darwin" else None
    if platform is None or os.environ.get("RUNNER_OS") != platform:
        raise FixtureRefused()
    if len(argv) not in {2, 4} or argv[0] != "--task-root" or (len(argv) == 4 and argv[2] != "--case"):
        raise FixtureRefused()
    partition = argv[3] if len(argv) == 4 else "ordinary"
    if partition not in _PARTITIONS:
        raise FixtureRefused()
    root = Path(argv[1])
    temp_value = os.environ.get("RUNNER_TEMP")
    if not temp_value or not root.is_absolute() or str(root) != argv[1] or root.resolve(strict=True) != root:
        raise FixtureRefused()
    runner_temp = Path(temp_value).resolve(strict=True)
    if root == runner_temp or not root.is_relative_to(runner_temp):
        raise FixtureRefused()
    value = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or stat.S_IMODE(value.st_mode) != 0o700:
        raise FixtureRefused()
    return root, partition


def workflow_selection(argv: list[str]) -> tuple[str, str] | None:
    """Pure closed grammar; native admission additionally needs original facts."""
    if (type(argv) is not list or len(argv) != 6 or any(type(item) is not str for item in argv)
            or argv[0] != "--task-root" or argv[2:5] != ["--domain", "github_workflows", "--case"]
            or argv[5] not in _PARTITIONS):
        return None
    return argv[1], argv[5]


def workflow_hosted_parameters(argv: list[str]) -> tuple[Path, str, Path, str, dict[str, Any]]:
    selected = workflow_selection(argv)
    source_sha = os.environ.get("MRK_DESKTOP_WORKFLOW_SOURCE_SHA", "")
    if (selected is None or sys.version_info < (3, 11)
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode
            or sys.platform != "linux" or os.uname().machine != "x86_64"
            or os.getuid() == 0 or os.geteuid() != os.getuid()
            or threading.current_thread() is not threading.main_thread()
            or os.environ.get("MRK_DESKTOP_WORKFLOW_NATIVE") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("RUNNER_OS") != "Linux" or os.environ.get("RUNNER_ARCH") != "X64"
            or len(source_sha) != 40 or any(c not in "0123456789abcdef" for c in source_sha)
            or source_sha != os.environ.get("GITHUB_SHA")):
        raise FixtureRefused()
    root_text, partition = selected
    root = Path(root_text)
    fixture = Path(__file__)
    repository = fixture.parents[1]
    temp_value = os.environ.get("RUNNER_TEMP")
    workspace_value = os.environ.get("GITHUB_WORKSPACE")
    if (not temp_value or not workspace_value or not fixture.is_absolute()
            or fixture.resolve(strict=True) != fixture
            or fixture != repository / "tests/native_desktop_config.py"
            or str(repository) != workspace_value or repository.resolve(strict=True) != repository
            or not root.is_absolute() or str(root) != root_text or root.resolve(strict=True) != root):
        raise FixtureRefused()
    runner_temp = Path(temp_value)
    if (not runner_temp.is_absolute() or runner_temp.resolve(strict=True) != runner_temp
            or root == runner_temp or not root.is_relative_to(runner_temp)
            or root.is_relative_to(repository)):
        raise FixtureRefused()
    value = root.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
            or stat.S_IMODE(value.st_mode) != 0o700):
        raise FixtureRefused()
    # Only observed kernel/statvfs facts, NOT filesystem type, rename semantics,
    # runtime custody, ordinary startup, or a production capability qualification.
    release = os.uname().release
    filesystem = os.statvfs(root)
    if (not 0 < len(release.encode("utf-8")) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in release)
            or not 0 <= value.st_dev < 2**64
            or any(type(v) is not int or v <= 0 for v in (filesystem.f_bsize, filesystem.f_frsize, filesystem.f_namemax))
            or type(filesystem.f_flag) is not int or filesystem.f_flag < 0):
        raise FixtureRefused()
    host = {"kernelRelease": release, "machine": os.uname().machine, "nonRoot": os.geteuid() != 0,
            "filesystem": {"device": str(value.st_dev), "blockSize": filesystem.f_bsize,
                           "fragmentSize": filesystem.f_frsize, "nameMax": filesystem.f_namemax,
                           "flags": filesystem.f_flag}}
    return root, partition, repository, source_sha, host


def workflow_runtime(repository: Path, source_sha: str) -> tuple[Runtime, dict[str, Any]]:
    source = repository / "src"
    if not source.is_dir() or source.resolve(strict=True) != source:
        raise FixtureRefused()
    originals: dict[str, bytes] = {}
    for identity, relative in _WORKFLOW_SOURCES.items():
        path = repository / relative
        value = path.stat(follow_symlinks=False)
        if (path.resolve(strict=True) != path or not stat.S_ISREG(value.st_mode)
                or value.st_uid != os.geteuid() or value.st_mode & 0o022):
            raise FixtureRefused()
        originals[identity] = workflow_read(path, 1024 * 1024)
    # The exact source beside the admitted fixture is the sole subject import
    # path. There is no ZIP selector, ambient path or environment fallback here.
    sys.path.insert(0, str(source))
    runtime = Runtime(*(importlib.import_module("mobile_release." + name) for name in (
        "config_edit", "init_transaction", "init_workspace_custody", "build_inputs",
        "cancellation", "errors", "config_payloads")))
    runtime.workflow = importlib.import_module("mobile_release.github_workflow_edit")
    runtime.workflow_payloads = importlib.import_module("mobile_release.workflow_payloads")
    runtime.workflow_setup = importlib.import_module("mobile_release.api._github_setup")
    modules = ((runtime.edit, "config_edit.py"), (runtime.transaction, "init_transaction.py"),
               (runtime.custody, "init_workspace_custody.py"), (runtime.build, "build_inputs.py"),
               (runtime.cancellation, "cancellation.py"), (runtime.errors, "errors.py"),
               (runtime.payloads, "config_payloads.py"), (runtime.workflow, "github_workflow_edit.py"),
               (runtime.workflow_payloads, "workflow_payloads.py"), (runtime.workflow_setup, "api/_github_setup.py"))
    for module, relative in modules:
        require(Path(module.__file__).resolve(strict=True) == source / "mobile_release" / relative)
    require(runtime.workflow_payloads.GITHUB_WORKFLOWS == _WORKFLOW_FILES)
    draft = workflow_document()
    draft_bytes = json.dumps(draft, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    draft_digest = hashlib.sha256(draft_bytes).hexdigest()
    require(draft_digest == _WORKFLOW_DRAFT_SHA256)
    proposal = runtime.workflow_setup.propose_github_setup(draft, _WORKFLOW_REPOSITORY, _WORKFLOW_SHA, None)
    require(proposal["state"] == "proposed" and proposal["validation"]["valid"] is True
            and workflow_equal(proposal["templateSet"], _WORKFLOW_TEMPLATE_SET)
            and len(proposal["workflows"]) == 4)
    resource = json.loads(originals["resource"])
    require(hashlib.sha256(originals["resource"]).hexdigest() == proposal["templateSet"]["resourceSha256"])
    payloads = []
    payload_hashes = {}
    canonical_ids = ("canonicalPreflight", "canonicalCandidate", "canonicalExternalTesting", "canonicalProductionSubmit")
    for (identity, path), row, canonical, expected_digest in zip(
            _WORKFLOW_FILES, proposal["workflows"], canonical_ids, _WORKFLOW_PAYLOAD_SHA256):
        template = originals[canonical]
        require(template == resource["workflows"][identity].encode("utf-8"))
        rendered = runtime.workflow_payloads.render_workflow_caller(template, _WORKFLOW_REPOSITORY, _WORKFLOW_SHA)
        data = row["content"].encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        require(row["id"] == identity and row["path"] == path and row["comparison"] == "not-supplied"
                and data == rendered and 0 < len(data) <= 16 * 1024 and row["byteLength"] == len(data)
                and row["sha256"] == digest == expected_digest)
        payloads.append(data)
        payload_hashes[identity] = digest
    runtime.workflow_bytes = tuple(payloads)
    python = Path(sys.executable).resolve(strict=True)
    bindings = {"sourceSha": source_sha, "sourceKind": "source",
                "sourceHashes": {identity: hashlib.sha256(data).hexdigest() for identity, data in originals.items()},
                "pythonSha256": hashlib.sha256(workflow_read(python, 64 * 1024 * 1024)).hexdigest(),
                "draftSha256": draft_digest, "toolingRepository": _WORKFLOW_REPOSITORY,
                "toolingSha": _WORKFLOW_SHA, "templateSet": proposal["templateSet"], "payloadHashes": payload_hashes}
    return runtime, bindings


def workflow_main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
    batch = None
    bindings = host = None
    partition = "unadmitted"
    status, reason = "failed", "unexpected_failure"
    try:
        if _RUN_CLAIMED:
            raise FixtureRefused()
        _RUN_CLAIMED = True
        task_root, partition, repository, source_sha, host = workflow_hosted_parameters(argv)
        runtime, bindings = workflow_runtime(repository, source_sha)
        root = task_root / ("python-workflow-edit-" + partition)
        root.mkdir(mode=0o700)
        batch = Batch(runtime, root, partition)
        _RETAINED_BATCH = batch
        if partition == "ordinary":
            for case in (workflow_capture_case, workflow_conflict_case, workflow_observation_cases,
                         workflow_registered_root_case, workflow_stale_cases, workflow_pending_cases,
                         workflow_contention_cases, workflow_partial_rollback_case, workflow_incomplete_case,
                         workflow_ready_corruption_cases):
                if batch.blocked:
                    raise FixtureUnknown()
                case(batch)
            workflow_pending_replaced_case(batch, committed=False)
            workflow_cleanup_missing_cases(batch)
            workflow_pending_replaced_case(batch, committed=True)  # LAST: effect-Unknown.
        elif partition == "committed-fsync":
            workflow_committed_fsync_case(batch)
        else:
            workflow_committed_close_case(batch)  # LAST in the entire native lane.
        # Only retained original DATA is inspected after either uncertainty.
        # All workflow partitions intentionally retain their private trees. No
        # successful late wait/close supplies permission to adopt or delete them.
        require(tuple(batch.completed) == _WORKFLOW_CASES[partition]
                and len(batch.workflow_rows) == len(batch.completed)
                and not batch.workflow_fixture_failed and batch.retain
                and batch.blocked is (partition != "committed-fsync")
                and all(owner.closed and owner.restored for owner in batch.owners))
        require(all(not owner.fatal for owner in batch.owners) if partition != "committed-close"
                else len(batch.owners) == 1 and batch.owners[0].fatal)
        status, reason = "passed", "none"
    except FixtureRefused:
        reason = "hosted_guard_refused"
    except FixtureUnknown:
        reason = "original_custody_unknown"
    except AssertionError:
        reason = "fixed_case_failed"
    except BaseException:
        pass
    report = {
        "schemaVersion": 1, "suite": "desktop-workflow-native", "domain": "github_workflows",
        "partition": partition, "status": status, "reason": reason, "bindings": bindings, "host": host,
        "completed": batch.completed if batch is not None else [],
        "cases": batch.workflow_rows if batch is not None else [],
        "failedAt": batch.current if batch is not None and status != "passed" else None,
        "retained": batch is not None and (batch.retain or status != "passed"),
        "uncertaintyLatched": batch.blocked if batch is not None else False,
        "injection": {"ordinary": "fixed-original-workflow-boundaries", "committed-fsync": "postdecision-pre-fsync",
                      "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss"}.get(partition),
    }
    encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 32 * 1024:
        report.update(status="failed", reason="fixed_case_failed", bindings=None, host=None,
                      completed=[], cases=[], failedAt=batch.current if batch is not None else None,
                      retained=batch is not None)
        encoded = json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        status = "failed"
    print(encoded)
    return 0 if status == "passed" else 1


def main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
    if type(argv) is list and "--domain" in argv:
        return workflow_main(argv)
    batch = None
    status, reason = "failed", "unexpected_failure"
    partition = "unadmitted"
    try:
        if _RUN_CLAIMED:
            raise FixtureRefused()
        _RUN_CLAIMED = True  # No entrypoint replay in this interpreter, even on refusal.
        task_root, partition = hosted_parameters(argv)
        # -I -S excludes ambient PYTHONPATH/site packages. The only added path
        # is the exact source beside this reviewed fixed fixture, not a project.
        source = Path(__file__).resolve(strict=True).parents[1] / "src"
        require(source.is_dir() and not source.is_symlink())
        sys.path.insert(0, str(source))
        runtime = Runtime(*(importlib.import_module("mobile_release." + name) for name in (
            "config_edit", "init_transaction", "init_workspace_custody", "build_inputs",
            "cancellation", "errors", "config_payloads")))
        root = task_root / ("python-config-edit-" + partition)
        root.mkdir(mode=0o700)
        original = root.stat(follow_symlinks=False)
        batch = Batch(runtime, root, partition)
        _RETAINED_BATCH = batch  # Uncertainty/failure keeps original records to process exit.
        if partition == "ordinary":
            for case in (create_case, save_noop_ignore_cases, refusal_cases, stale_cases,
                         pending_cases, contention_cases, prepublication_rollback_case, legacy_public_apply_cases):
                if batch.blocked:
                    raise FixtureUnknown()
                case(batch)
            require(len(batch.completed) == 27)
        elif partition == "committed-fsync":
            committed_fsync_case(batch)
        else:
            committed_close_case(batch)
        if not batch.retain:
            require(not batch.blocked and all(owner.closed and owner.restored and not owner.fatal for owner in batch.owners))
            current = root.stat(follow_symlinks=False)
            require((current.st_dev, current.st_ino, current.st_mode) == (original.st_dev, original.st_ino, original.st_mode))
            shutil.rmtree(root)  # Only this exclusive fully settled synthetic root.
            _RETAINED_BATCH = None
        status, reason = "passed", "none"
    except FixtureRefused:
        reason = "hosted_guard_refused"
    except FixtureUnknown:
        reason = "original_custody_unknown"
    except AssertionError:
        reason = "fixed_case_failed"
    except BaseException:
        pass  # No exception text, private path, file bytes or native transcript.
    report = {
        "suite": "desktop-config-native", "partition": partition, "status": status, "reason": reason,
        "completed": batch.completed if batch is not None else [],
        "failedAt": batch.current if batch is not None and status != "passed" else None,
        "retained": batch is not None and (batch.retain or status != "passed"),
        "uncertaintyLatched": batch.blocked if batch is not None else False,
        "injection": {"ordinary": "precommit-publication", "committed-fsync": "postdecision-pre-fsync",
                      "committed-close": "postcommit-cancellation-and-positive-scope-close-return-loss"}.get(partition),
    }
    print(json.dumps(report, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
