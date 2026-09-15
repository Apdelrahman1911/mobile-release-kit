"""Raw-fork ownership probes in an isolated interpreter and fictional account."""
from __future__ import annotations

import gc
import json
import math
import os
import signal
import sys
import time
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
if __name__ == '__main__':
    sys.path[:0] = [sys.argv.pop(1), str(ROOT/'tests')]

from mobile_release import credentials, ios_profiles, local_signing
from mobile_release.cancellation import OwnedTemporaryDirectory
from mobile_release.errors import CredentialError
from mobile_release.inspection import InspectionDeadline
from unit.ios_entitlement_helpers import profile
from unit.local_signing_helpers import NativeSigningModel, fictional_signing_profile
from workflow.local_signing_workload import worker_timeout


def _remaining(deadline):
    assert type(deadline) is float and math.isfinite(deadline), 'invalid original fixture cutoff'
    value = deadline - time.monotonic()
    assert value > 0, 'original fork fixture cutoff expired'
    return value


def _wait_released(path, deadline):
    while True:
        _remaining(deadline)
        released = path.exists()
        _remaining(deadline)  # A late positive filesystem observation cannot pass.
        if released:
            return
        time.sleep(min(.01, _remaining(deadline)))


def reap(pid, pending, deadline):
    assert type(pid) is int and pid > 0 and pending.count(pid) == 1, 'original child wait custody differs'
    while True:
        _remaining(deadline)
        pending.remove(pid)  # Retire BEFORE a call which may consume its status.
        observed = os.waitpid(pid, os.WNOHANG)
        assert type(observed) is tuple and len(observed) == 2 \
            and all(type(value) is int for value in observed), 'invalid original child wait return'
        if observed == (0, 0):
            pending.append(pid)  # Only a genuine no-result permits another wait.
            time.sleep(min(.01, _remaining(deadline)))
            continue
        result, status = observed
        assert result == pid, 'original child wait identity changed'
        _remaining(deadline)  # The consumed status is not a timely-success receipt.
        assert os.waitstatus_to_exitcode(status) == 0, 'owned fork child failed'
        _remaining(deadline)
        return


def _exit_context(owners, name, error_info=(None, None, None)):
    context = owners.pop(name, None)
    if context is not None:
        context.__exit__(*error_info)  # An ambiguous exit never restores this slot.


def _cleanup(primary, actions):
    errors = []
    for action in actions:
        try:
            action()
        except BaseException as error:
            errors.append(error)
    if errors:
        first = primary if primary is not None else errors[0]
        try:
            first.__dict__['fork_fixture_cleanup_errors'] = tuple(errors if primary is not None else errors[1:])
        except BaseException:
            pass  # Optional retention cannot replace the original failure.
        if primary is None:
            raise first
    return tuple(errors)


def main(root: Path, mode: str, deadline: float):
    assert _remaining(deadline) <= worker_timeout('account-native-flow'), 'fixture cutoff exceeds original budget'
    home = root/'home'; home.mkdir(mode=0o700)
    private = root/'private'; private.mkdir(mode=0o700)
    profile_input = private/'profile'; profile_input.write_bytes(b'fictional-profile')
    p12 = private/'identity.p12'; p12.write_bytes(b'fictional-p12')
    parent = os.getpid()
    children = []
    model = NativeSigningModel(home)
    native_events = root/'native-events'
    def before(argv, kwargs):
        with native_events.open('a') as events:
            events.write(str(os.getpid())+'\n')
    model.before = before
    owners = {}
    scratch = None
    try:
        owners['lease'] = local_signing.local_signing_lease(home=home)
        lease = owners['lease'].__enter__()
        scratch = OwnedTemporaryDirectory(prefix='fork-owned-', dir=root)
        scratch.acquire()
        required = Path(scratch.name)/'required'; required.write_bytes(b'parent-required')
        with ExitStack() as mocks:
            mocks.enter_context(patch.object(credentials, '_run_private', side_effect=model))
            mocks.enter_context(patch.object(credentials, '_authenticated_signing_profile', new=fictional_signing_profile))
            owners['signing'] = credentials._temporary_apple_signing_environment(p12=p12,password='fictional',profile=profile_input,directory=private,lease=lease)
            owners['signing'].__enter__()
            destination = home/'Library/MobileDevice/Provisioning Profiles'/(profile()['UUID']+'.mobileprovision')
            db_identity = model.keychain.stat().st_ino
            before_state = (lease.active.path/'state.json').read_bytes()
            if mode in {'explicit-exit','gc-exit','child-reentry'}:
                _remaining(deadline)
                pid = os.fork()
                if pid == 0:
                    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
                    if mode == 'explicit-exit':
                        _exit_context(owners, 'signing')
                        _exit_context(owners, 'lease')
                    else:
                        owners.clear()
                        scratch = None
                        gc.collect()
                    if mode == 'child-reentry':
                        _wait_released(root/'released', deadline)
                        with local_signing.local_signing_lease(home=home) as independent:
                            independent.assert_owner()
                            assert independent.cancellation.pid == os.getpid()
                    _remaining(deadline)
                    # Deliberate NORMAL interpreter exit/GC, not os._exit.
                    raise SystemExit(0)
                children.append(pid)
                if mode != 'child-reentry': reap(pid, children, deadline)
            else:
                def fork_and_check():
                    _remaining(deadline)
                    pid = os.fork()
                    if pid == 0:
                        gc.collect()
                        _remaining(deadline)
                        raise SystemExit(0)
                    children.append(pid); reap(pid, children, deadline)
                    lease.assert_owner()
                    assert destination.read_bytes() == b'fictional-profile'
                if mode == 'profile-read':
                    real_read = os.read
                    fired = []
                    def read(fd, count):
                        if not fired:
                            fired.append(True); fork_and_check()
                        return real_read(fd,count)
                    with patch.object(ios_profiles.os, 'read', new=read):
                        assert ios_profiles.read_profile_bytes(profile_input) == b'fictional-profile'
                    assert fired
                elif mode == 'profile-scratch':
                    def capture(directory, deadline, **kwargs):
                        fork_and_check()
                        assert (directory/'cms.der').read_bytes() == b'fictional-profile'
                        return b'fictional-verified'
                    with patch.object(ios_profiles, '_capture_profile', side_effect=capture):
                        assert ios_profiles.authenticate_cms(b'fictional-profile', deadline=InspectionDeadline()) == b'fictional-verified'
                else: raise AssertionError('unknown fork mode')
            if os.getpid() == parent:
                lease.assert_owner()
                assert local_signing.signing_status(home=home)['status'] == 'busy'
                assert destination.read_bytes() == b'fictional-profile'
                assert model.keychain.stat().st_ino == db_identity
                assert (lease.active.path/'state.json').read_bytes() == before_state
                assert required.read_bytes() == b'parent-required'
                assert all(int(pid)==parent for pid in native_events.read_text().splitlines())
                _exit_context(owners, 'signing')
                _exit_context(owners, 'lease')
                if mode == 'child-reentry':
                    _remaining(deadline)
                    (root/'released').touch()
                    _remaining(deadline)
                    for pid in children[:]: reap(pid, children, deadline)
                assert local_signing.signing_status(home=home)['status'] == 'idle'
                assert model.preferences == model.original
                assert not destination.exists()
    finally:
        if os.getpid() == parent:
            error_info = sys.exc_info()
            actions = [lambda: _exit_context(owners, 'signing', error_info),
                       lambda: _exit_context(owners, 'lease', error_info)]
            closing_scratch, scratch = scratch, None
            if closing_scratch is not None:
                actions.append(closing_scratch.cleanup)
            actions.extend(lambda child=pid: reap(child, children, deadline) for pid in children[:])
            cleanup_errors = _cleanup(error_info[1], actions)
    if os.getpid() == parent:
        _remaining(deadline)
        assert not children and not owners and not cleanup_errors, 'fork fixture cleanup remains'
        print(json.dumps({'parentResourcesUnchangedBeforeFallback': True, 'childReaped': True, 'mode':mode}))


if __name__ == '__main__': main(Path(sys.argv[1]),sys.argv[2],float(sys.argv[3]))
