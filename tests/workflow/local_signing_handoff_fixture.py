"""Raw-fork syscall handoffs, using only a fictional private account.

The child continues the interrupted caller before normal interpreter exit. This
is deliberately stronger than exiting directly from the fork callback: handles
can be returned after registered at-fork cleanup has already run.
"""
from __future__ import annotations

import errno
import gc
import json
import os
import signal
import stat
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]

from mobile_release import build_inputs, credentials, ios_profiles, local_signing as signing
from mobile_release.errors import CredentialError, ValidationError
from unit.ios_entitlement_helpers import profile
from unit.local_signing_helpers import NativeSigningModel, fictional_signing_profile


_PROFILE_ROLE = "apple-profile"
_PROFILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _directory_facts(value):
    if not stat.S_ISDIR(value.st_mode):
        return None
    return dict(device=value.st_dev, inode=value.st_ino, uid=value.st_uid,
                gid=value.st_gid, mode=stat.S_IMODE(value.st_mode))


def _file_facts(value):
    if not stat.S_ISREG(value.st_mode):
        return None
    return dict(device=value.st_dev, inode=value.st_ino, uid=value.st_uid,
                gid=value.st_gid, mode=stat.S_IMODE(value.st_mode), links=value.st_nlink,
                size=value.st_size, mtime=value.st_mtime_ns, ctime=value.st_ctime_ns)


def _selected_profile_matches(selected):
    """Published object links only; never re-admit or re-read a selected input."""
    scratch, snapshot, owner = selected["scratch"], selected["snapshot"], selected["owner"]
    guard, record = selected["guard"], selected["record"]
    role = _PROFILE_ROLE
    return (scratch.cancellation is guard is owner.cancellation
            and owner is selected["lease"] and owner.locked and owner.active is None
            and owner.pid == scratch.pid == guard.pid == selected["pid"]
            and owner.owner_thread is scratch.thread is guard.owner_thread
            and scratch.active and not scratch.claimed and scratch.created
            and snapshot._owner is scratch and snapshot._role == role
            and scratch.snapshots.get(role) is snapshot and scratch.tokens.get(role) is snapshot._token
            and snapshot._token is selected["token"] and scratch.records.get(role) is record
            and record.get("binding") is selected["binding"]
            and selected["binding"] == {**selected["file"], "sha256": snapshot.sha256}
            and snapshot.size == selected["file"]["size"]
            and scratch.slot is selected["directory_slot"]
            and type(selected["directory_fd"]) is int and selected["directory_fd"] >= 0
            and scratch.slot.number == selected["directory_fd"]
            and scratch.slot.open_state == "OPEN" and scratch.slot.close_state == "NOT_ATTEMPTED"
            and scratch.identity is selected["original_directory_identity"]
            and scratch.identity == selected["directory"]
            and selected["path"] == scratch.parent.path / scratch.name / selected["leaf"]
            and build_inputs._LAYOUTS[scratch.layout][role].name == selected["leaf"])


def _profile_read_handoff_matches(selected, opening_frame, reader_frame, path, args, kwargs,
                                  parent_state, leaf_state, returned_state):
    """Inert selection predicate, not a process/finality or cleanup receipt."""
    if (selected is None or opening_frame is None or reader_frame is None
            or opening_frame.f_code is not ios_profiles._ProfileDescriptor.open.__code__
            or reader_frame.f_code is not ios_profiles.read_profile_bytes.__code__):
        return False
    opened, reader = opening_frame.f_locals, reader_frame.f_locals
    descriptor, scope, guard = opened.get("self"), reader.get("scope"), selected["guard"]
    if descriptor is None or scope is None or reader.get("entry") is None:
        return False
    return (_selected_profile_matches(selected)
            and opening_frame.f_back is reader_frame
            and path is selected["path"] is opened.get("path") is reader.get("path")
            and args == (_PROFILE_FLAGS, 0o600) and kwargs == {"dir_fd": None}
            and opened.get("flags") == _PROFILE_FLAGS and opened.get("mode") == 0o600
            and opened.get("dir_fd") is None
            and reader.get("descriptor") is descriptor
            and reader.get("guard") is guard is reader.get("cancellation")
            and scope.cancellation is guard and len(scope._descriptors) == 1
            and scope._descriptors[0] is descriptor
            and scope.pid == descriptor.pid == selected["pid"] and not scope.claimed
            and scope.owner_thread is descriptor.owner_thread is guard.owner_thread
            and descriptor.state == "ACQUIRING" and descriptor.number is None
            and not descriptor._child_close_claimed
            and _directory_facts(parent_state) == selected["directory"]
            and _file_facts(reader["entry"]) == _file_facts(leaf_state)
            == _file_facts(returned_state) == selected["file"])


def main(root: Path, mode: str) -> None:
    home = root / "home"
    home.mkdir(mode=0o700)
    project = root / "project"
    project.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    source, p12 = private / "profile", private / "identity.p12"
    source.write_bytes(b"fictional-profile")
    p12.write_bytes(b"fictional-p12")
    source.chmod(0o600); p12.chmod(0o600)
    original_inputs = {path: (path.read_bytes(), _file_facts(path.lstat())) for path in (source, p12)}
    parent = os.getpid()
    model = NativeSigningModel(home)
    fired, children, mutations, late_handles, entered = [], [], [], [], []
    selected_profile, account = None, None
    child_report = root / "child-result.json"
    real_open_dir, real_profile_dir, real_open = signing._open_dir, credentials._open_profile_directory, os.open
    real_close = os.close

    def authenticated_profile(path, *, cancellation):
        nonlocal selected_profile
        if mode == "profile-read":
            # Observe only the actual inner authentication call, after checked
            # external selection. No require(), new owner, or extra read here.
            frame = sys._getframe(1)
            try:
                assert frame.f_code is credentials._temporary_apple_signing_environment.__wrapped__.__code__
                values = frame.f_locals
                scratch, snapshot, owner = values["scratch"], values["profile"], values["owner"]
                assert selected_profile is None and type(scratch) is build_inputs.FiniteScratch
                assert type(snapshot) is build_inputs.InputSnapshot and scratch is values["directory"]
                assert owner is account is values["lease"] and cancellation is values["cancellation"]
                record = scratch.records[_PROFILE_ROLE]
                binding = record["binding"]
                selected_profile = {
                    "scratch": scratch, "snapshot": snapshot, "owner": owner, "lease": account,
                    "guard": cancellation, "pid": parent, "record": record, "binding": binding,
                    "token": snapshot._token, "path": path,
                    "leaf": build_inputs._LAYOUTS[scratch.layout][_PROFILE_ROLE].name,
                    "file": {key: value for key, value in binding.items() if key != "sha256"},
                    "directory_slot": scratch.slot, "directory_fd": scratch.slot.number,
                    "original_directory_identity": scratch.identity, "directory": dict(scratch.identity),
                    "close_attempts": 0, "close_binding": True, "close_returned": False,
                    "closed_before_return": False,
                }
                assert _selected_profile_matches(selected_profile)
            finally:
                del frame
        return fictional_signing_profile(path, cancellation=cancellation)

    def fork_handoff(descriptor):
        if fired:
            return
        fired.append(mode)
        # Remember the descriptor BEFORE fork, but its production owner has not
        # received it yet. The child must relinquish precisely this late handle.
        late_handles.append(descriptor)
        pid = os.fork()
        if pid == 0:
            return
        children.append(pid)
        expires = time.monotonic() + 5
        while time.monotonic() < expires:
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                children.remove(pid)
                assert os.waitstatus_to_exitcode(status) == 0
                result = json.loads(child_report.read_text())
                assert result["lateHandlesClosed"], result
                assert result["noChildMutations"], result
                assert result["inheritedCallerRejected"], result
                assert result["noChildBody"] and result["originalInputsUnchanged"], result
                if mode == "profile-read":
                    assert result["originalProfileLateClose"], result
                return
            time.sleep(.01)
        raise AssertionError("fork handoff child did not exit")

    def opening_directory(name, **kwargs):
        descriptor = real_open_dir(name, **kwargs)
        selected = ((mode == "lease-open" and str(name) == signing.LEASE_DIRECTORY)
                    or (mode == "session-open" and str(name).startswith("session-"))
                    or (mode == "native-open" and str(name) == "keychain"))
        if selected:
            fork_handoff(descriptor)
        return descriptor

    def opening_profile_directory(home):
        result = real_profile_dir(home)
        if mode == "profile-directory":
            fork_handoff(result[1])
        return result

    def opening(path, *args, **kwargs):
        descriptor = real_open(path, *args, **kwargs)
        if mode == "profile-stage" and str(path).startswith(".mobile-release-profile-"):
            fork_handoff(descriptor)
        elif mode == "profile-read" and selected_profile is not None and not fired:
            frame = sys._getframe(1)
            try:
                reader = frame.f_back
                if (frame.f_code is ios_profiles._ProfileDescriptor.open.__code__
                        and reader is not None and reader.f_code is ios_profiles.read_profile_bytes.__code__):
                    selected = selected_profile
                    assert type(descriptor) is int and descriptor >= 0
                    assert _profile_read_handoff_matches(selected, frame, reader, path, args, kwargs,
                        os.fstat(selected["directory_fd"]),
                        os.stat(selected["leaf"], dir_fd=selected["directory_fd"], follow_symlinks=False),
                        os.fstat(descriptor)), "original profile-reader handoff differs"
                    selected["descriptor"], selected["scope"] = frame.f_locals["self"], reader.f_locals["scope"]
                    selected["returned_fd"] = descriptor
                    # The real return is positive, but its preregistered slot
                    # remains ACQUIRING/None until this wrapper returns.
                    fork_handoff(descriptor)
            finally:
                del frame
        return descriptor

    def closing(descriptor):
        # Observe the product's own child-close call; never close a late FD on
        # the fixture's behalf or replace a failed production close attempt.
        selected = selected_profile
        frame = sys._getframe(1)
        try:
            observed = (os.getpid() != parent and selected is not None
                        and frame.f_code is ios_profiles._ProfileDescriptor.after_fork_child.__code__
                        and frame.f_locals.get("self") is selected.get("descriptor"))
        finally:
            del frame
        if not observed:
            return real_close(descriptor)
        slot = selected["descriptor"]
        selected["close_attempts"] += 1
        selected["close_binding"] &= (descriptor == selected["returned_fd"]
            and slot.state == "INHERITED" and slot.number is None and slot._child_close_claimed)
        try:
            selected["close_binding"] &= _file_facts(os.fstat(descriptor)) == selected["file"]
        except BaseException:
            selected["close_binding"] = False
        result = real_close(descriptor)
        selected["close_returned"] = True
        try:
            os.fstat(descriptor)
        except OSError as error:
            selected["closed_before_return"] = error.errno == errno.EBADF
        else:
            selected["closed_before_return"] = False
        return result

    def mutation(name, original):
        def call(*args, **kwargs):
            if os.getpid() != parent:
                mutations.append(name)
            return original(*args, **kwargs)
        return call

    error = None
    try:
        with ExitStack() as mocks:
            mocks.enter_context(patch.object(credentials, "_run_private", side_effect=model))
            mocks.enter_context(patch.object(credentials, "_authenticated_signing_profile", new=authenticated_profile))
            mocks.enter_context(patch.object(signing, "_open_dir", new=opening_directory))
            mocks.enter_context(patch.object(credentials, "_open_profile_directory", new=opening_profile_directory))
            mocks.enter_context(patch.object(os, "open", new=opening))
            mocks.enter_context(patch.object(os, "close", new=closing))
            for name in ("mkdir", "unlink", "link", "replace", "chmod", "rmdir"):
                mocks.enter_context(patch.object(os, name, new=mutation(name, getattr(os, name))))
            with signing.local_signing_lease(home=home) as lease:
                account = lease
                with credentials._temporary_apple_signing_environment(
                    p12=p12, password="fictional", profile=source, directory=private, lease=lease, project_root=project,
                ):
                    entered.append(os.getpid())
                    lease.assert_owner()
                    assert os.getpid() == parent, "inherited signing body was reached"
    except BaseException as caught:
        error = caught
    if os.getpid() != parent:
        closed = True
        for descriptor in late_handles:
            try:
                os.fstat(descriptor)
            except OSError as close_error:
                closed &= close_error.errno == errno.EBADF
            else:
                closed = False
        profile_late_close = False
        if mode == "profile-read" and selected_profile is not None and "descriptor" in selected_profile:
            selected, slot = selected_profile, selected_profile["descriptor"]
            profile_late_close = (selected["close_attempts"] == 1 and selected["close_binding"]
                and selected["close_returned"] and selected["closed_before_return"]
                and slot.state == "INHERITED" and slot.number is None and slot._child_close_claimed
                and len(selected["scope"]._descriptors) == 1 and selected["scope"]._descriptors[0] is slot
                and selected["scope"].fork_relinquished)
        unchanged = all((path.read_bytes(), _file_facts(path.lstat())) == value
                        for path, value in original_inputs.items())
        gc.collect()
        child_report.write_text(json.dumps({
            "lateHandlesClosed": closed, "noChildMutations": not mutations,
            "mutations": mutations,
            "inheritedCallerRejected": isinstance(error, (CredentialError, ValidationError)),
            "noChildBody": not entered, "originalInputsUnchanged": unchanged,
            "originalProfileLateClose": profile_late_close,
            "errorType": type(error).__name__,
        }))
        assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
        if (selected_profile is not None and profile_late_close and closed and unchanged
                and not mutations and not entered and isinstance(error, (CredentialError, ValidationError))):
            selected_profile.clear()
            selected_profile = None
        return  # Normal child interpreter shutdown, no os._exit shortcut.
    assert not children
    if error is not None:
        raise error
    assert fired == [mode] and entered == [parent] and child_report.is_file()
    assert all((path.read_bytes(), _file_facts(path.lstat())) == value for path, value in original_inputs.items())
    assert signing.signing_status(home=home)["status"] == "idle"
    assert model.preferences == model.original
    if mode == "profile-read":
        assert selected_profile is not None and "descriptor" in selected_profile
        scratch, descriptor = selected_profile["scratch"], selected_profile["descriptor"]
        assert descriptor.state == "CLOSED" and descriptor.number is None and descriptor.settled
        assert scratch.claimed and not scratch.active and not scratch.created
        assert scratch.creation["state"] == "RETIRED"
        assert all(slot.number is None and slot.close_state == "CLOSED"
                   for slot in (scratch.slot, *scratch.writer_slots, *scratch.parent.slots))
        assert not selected_profile["path"].parent.exists() and not selected_profile["path"].parent.is_symlink()
        selected_profile.clear()
        selected_profile = None
    print(json.dumps({"mode": mode, "childReaped": True, "checkedBeforeFallback": True}))


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2])
