"""Raw-fork ownership probes in an isolated interpreter and fictional account."""
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
if __name__ == '__main__':
    sys.path[:0] = [sys.argv.pop(1), str(ROOT/'tests')]

from mobile_release import credentials, ios_profiles, local_signing
from mobile_release.cancellation import OwnedTemporaryDirectory
from mobile_release.errors import CredentialError
from mobile_release.inspection import InspectionDeadline
from unit.ios_entitlement_helpers import profile
from unit.local_signing_helpers import NativeSigningModel, fictional_signing_profile


def reap(pid):
    for _ in range(300):
        result, status = os.waitpid(pid, os.WNOHANG)
        if result:
            assert os.waitstatus_to_exitcode(status) == 0
            return
        time.sleep(.01)
    raise AssertionError('owned fork child did not exit')


def main(root: Path, mode: str):
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
    lease_context = local_signing.local_signing_lease(home=home)
    lease = lease_context.__enter__()
    context = None
    scratch = OwnedTemporaryDirectory(prefix='fork-owned-', dir=root)
    scratch.acquire()
    required = Path(scratch.name)/'required'; required.write_bytes(b'parent-required')
    try:
        with ExitStack() as mocks:
            mocks.enter_context(patch.object(credentials, '_run_private', side_effect=model))
            mocks.enter_context(patch.object(credentials, '_authenticated_signing_profile', new=fictional_signing_profile))
            context = credentials._temporary_apple_signing_environment(p12=p12,password='fictional',profile=profile_input,directory=private,lease=lease)
            context.__enter__()
            destination = home/'Library/MobileDevice/Provisioning Profiles'/(profile()['UUID']+'.mobileprovision')
            db_identity = model.keychain.stat().st_ino
            before_state = (lease.active.path/'state.json').read_bytes()
            if mode in {'explicit-exit','gc-exit','child-reentry'}:
                pid = os.fork()
                if pid == 0:
                    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
                    if mode == 'explicit-exit':
                        context.__exit__(None,None,None)
                        lease_context.__exit__(None,None,None)
                    else:
                        context = lease_context = scratch = None
                        gc.collect()
                    if mode == 'child-reentry':
                        deadline = time.monotonic()+4
                        while not (root/'released').exists() and time.monotonic()<deadline: time.sleep(.01)
                        assert (root/'released').exists()
                        with local_signing.local_signing_lease(home=home) as independent:
                            independent.assert_owner()
                            assert independent.cancellation.pid == os.getpid()
                    # Deliberate NORMAL interpreter exit/GC, not os._exit.
                    raise SystemExit(0)
                children.append(pid)
                if mode != 'child-reentry': reap(pid); children.remove(pid)
            else:
                def fork_and_check():
                    pid = os.fork()
                    if pid == 0:
                        gc.collect()
                        raise SystemExit(0)
                    children.append(pid); reap(pid); children.remove(pid)
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
                context.__exit__(None,None,None); context=None
                lease_context.__exit__(None,None,None); lease_context=None
                if mode == 'child-reentry':
                    (root/'released').touch()
                    for pid in children[:]: reap(pid); children.remove(pid)
                assert local_signing.signing_status(home=home)['status'] == 'idle'
                assert model.preferences == model.original
                assert not destination.exists()
    finally:
        if os.getpid() == parent:
            if context is not None: context.__exit__(None,None,None)
            if lease_context is not None: lease_context.__exit__(None,None,None)
            scratch.cleanup()
            for pid in children: reap(pid)
    if os.getpid() == parent:
        print(json.dumps({'parentResourcesUnchangedBeforeFallback': True, 'childReaped': True, 'mode':mode}))


if __name__ == '__main__': main(Path(sys.argv[1]),sys.argv[2])
