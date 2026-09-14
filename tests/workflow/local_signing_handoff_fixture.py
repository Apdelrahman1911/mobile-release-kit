"""Raw-fork syscall handoffs, using only a fictional private account.

The child continues the interrupted caller before normal interpreter exit. This
is deliberately stronger than exiting directly from the fork callback: handles
can be returned after registered at-fork cleanup has already run.
"""
from __future__ import annotations

import gc
import json
import os
import signal
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == "__main__":
    sys.path[:0] = [sys.argv.pop(1), str(ROOT / "tests")]

from mobile_release import credentials, ios_profiles, local_signing as signing
from mobile_release.errors import CredentialError, ValidationError
from unit.ios_entitlement_helpers import profile
from unit.local_signing_helpers import NativeSigningModel, fictional_signing_profile


def main(root: Path, mode: str) -> None:
    home = root / "home"
    home.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    source, p12 = private / "profile", private / "identity.p12"
    source.write_bytes(b"fictional-profile")
    p12.write_bytes(b"fictional-p12")
    parent = os.getpid()
    model = NativeSigningModel(home)
    fired, children, mutations, late_handles = [], [], [], []
    child_report = root / "child-result.json"
    real_open_dir, real_profile_dir, real_open = signing._open_dir, credentials._open_profile_directory, os.open

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
        if ((mode == "profile-stage" and str(path).startswith(".mobile-release-profile-"))
                or (mode == "profile-read" and str(path) == str(source))):
            fork_handoff(descriptor)
        return descriptor

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
            mocks.enter_context(patch.object(credentials, "_authenticated_signing_profile", new=fictional_signing_profile))
            mocks.enter_context(patch.object(signing, "_open_dir", new=opening_directory))
            mocks.enter_context(patch.object(credentials, "_open_profile_directory", new=opening_profile_directory))
            mocks.enter_context(patch.object(os, "open", new=opening))
            for name in ("mkdir", "unlink", "link", "replace", "chmod"):
                mocks.enter_context(patch.object(os, name, new=mutation(name, getattr(os, name))))
            with signing.local_signing_lease(home=home) as lease:
                with credentials._temporary_apple_signing_environment(
                    p12=p12, password="fictional", profile=source, directory=private, lease=lease,
                ):
                    lease.assert_owner()
                    assert os.getpid() == parent, "inherited signing body was reached"
    except BaseException as caught:
        error = caught
    if os.getpid() != parent:
        closed = True
        for descriptor in late_handles:
            try:
                os.fstat(descriptor)
            except OSError:
                pass
            else:
                closed = False
        gc.collect()
        child_report.write_text(json.dumps({
            "lateHandlesClosed": closed, "noChildMutations": not mutations,
            "mutations": mutations,
            "inheritedCallerRejected": isinstance(error, (CredentialError, ValidationError)),
            "errorType": type(error).__name__,
        }))
        assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
        return  # Normal child interpreter shutdown, no os._exit shortcut.
    assert not children
    if error is not None:
        raise error
    assert fired and child_report.is_file()
    assert signing.signing_status(home=home)["status"] == "idle"
    assert model.preferences == model.original
    print(json.dumps({"mode": mode, "childReaped": True, "checkedBeforeFallback": True}))


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2])
