"""Isolated raw-fork regression for original command slots, not a Popen reaper.

The disposable verification owner must launch this fixture. The raw fork is an
explicit test cut; the child neither waits nor signals the parent's C/A/W roles.
Only a task-local cooperative marker releases the synthetic target.
"""
from __future__ import annotations

import gc
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

if __name__ == "__main__":
    sys.path.insert(0, sys.argv.pop(1))

from mobile_release import _command_process as command, local_signing, owned_process
from mobile_release.cancellation import OwnedTemporaryDirectory
from mobile_release.errors import MobileReleaseError


def main(root: Path, mode: str) -> None:
    if mode not in ("command-open", "command-active"):
        raise AssertionError("unknown original command fork edge")
    parent = os.getpid()
    ready, release, report = (root / name for name in ("ready", "release", "child.json"))
    contexts, forked, children = [], [], []
    original_child_pid = None
    scratch = OwnedTemporaryDirectory(prefix="parent-required-", dir=root)
    scratch.acquire()
    required = Path(scratch.name) / "required"
    required.write_bytes(b"fictional-parent-resource")
    target = ("import time\nfrom pathlib import Path\n"
              f"Path({str(ready)!r}).touch()\nend=time.monotonic()+12\n"
              f"while not Path({str(release)!r}).exists() and time.monotonic()<end:time.sleep(.01)\n")
    argv = [sys.executable, "-I", "-S", "-B", "-c", target]

    def fork_and_wait():
        forked.append(True)
        child = os.fork()
        if child == 0:
            return  # The original product stack must reject/unwind this copy.
        children.append(child)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            waited, status = os.waitpid(child, os.WNOHANG)
            if waited:
                children.remove(child)
                assert os.waitstatus_to_exitcode(status) == 0
                result = json.loads(report.read_bytes())
                assert result == {"workerStillAlive": True, "childHandlesClosed": True,
                                  "typedOwnershipRefusal": True, "parentScratchRetained": True}, result
                release.touch()
                return
            time.sleep(.01)
        raise AssertionError("original fork child did not settle")

    def event(role, name, **facts):
        nonlocal original_child_pid
        if role == "O" and name == "child_published":
            child = facts["child"]
            context = child._acquisition._failure_recorder.__self__
            assert context.role == "O" and context.pid == parent
            contexts.append(context)
            original_child_pid = child.pid  # Diagnostics only, before raw fork.
            if mode == "command-open" and not forked:
                fork_and_wait()

    original_read = command._Outer._read_outputs
    def read_outputs(engine):
        original_read(engine)
        if mode == "command-active" and ready.is_file() and not forked:
            assert contexts and engine.ctx is contexts[0]
            fork_and_wait()

    error = None
    try:
        with local_signing.local_signing_lease(home=root):
            with patch.object(command, "_command_event", new=event), \
                 patch.object(command._Outer, "_read_outputs", new=read_outputs):
                assert owned_process.run_owned(argv, timeout=20).returncode == 0
    except BaseException as caught:
        error = caught
    if os.getpid() != parent:
        alive = original_child_pid is not None
        if alive:
            try:
                os.kill(original_child_pid, 0)  # Non-mutating observation only.
            except ProcessLookupError:
                alive = False
        gc.collect()
        report.write_text(json.dumps({
            "workerStillAlive": alive,
            "childHandlesClosed": all(lease.state in ("NEW", "CLOSED", "INHERITED_CLOSED")
                                      for ctx in contexts for acq in ctx.acquisitions for lease in acq.leases),
            "typedOwnershipRefusal": isinstance(error, MobileReleaseError),
            "parentScratchRetained": required.read_bytes() == b"fictional-parent-resource",
        }))
        return
    try:
        assert not children
        if error is not None:
            raise error
        assert forked and contexts
        assert required.read_bytes() == b"fictional-parent-resource"
        for context in contexts:
            assert context.settled() and not context.cleanup_unknown
            assert context.child_acquisition.child.wait_state == "REAPED"
        print(json.dumps({"checkedBeforeFallback": True, "mode": mode}))
    finally:
        release.touch()
        # No retired numeric child/group route is reconstructed. Native failure
        # leaves original custody/evidence for the disposable case owner.
        if not children and contexts and all(context.settled() and not context.cleanup_unknown for context in contexts):
            scratch.cleanup()


if __name__ == "__main__":
    main(Path(sys.argv[1]), sys.argv[2])
