"""Closed hosted-only configuration fixtures; never unittest discovery.

Source authoring is not execution approval. Each approved invocation uses
``python3 -I -S -B ... --task-root <original-private-root> --case <fixed-case>``.
There is no subprocess controller, credential input, recovery command or
alternative transaction engine. Uncertainty ends native admission in this
interpreter; the workflow disposes the retained synthetic case directory/VM.
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import stat
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import patch

_PARTITIONS = ("ordinary", "committed-fsync", "committed-close")
_GUARD_MESSAGE = "configuration fixture original ownership did not settle"
_RUN_CLAIMED = False
_RETAINED_BATCH: Any = None


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
def owned_lease(batch: Batch, root: Path, *, expected_unknown: bool = False):
    """Prearmed real guard/lease, with unconditional original cleanup dispatch."""
    if batch.blocked:
        raise FixtureUnknown()
    runtime = batch.runtime
    guard = runtime.cancellation.DefaultCancellation(runtime.errors.ValidationError, _GUARD_MESSAGE)
    lease = runtime.custody.InitRootLease(root, cancellation=guard)
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


def main(argv: list[str]) -> int:
    global _RUN_CLAIMED, _RETAINED_BATCH
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
