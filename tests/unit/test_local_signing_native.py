"""Actual account flock/fork/ABI checks. Only isolated synthetic homes are used."""
from __future__ import annotations

import ctypes
import errno
import json
import os
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import mobile_release
from mobile_release import local_signing as signing
from mobile_release.errors import CredentialError
from mobile_release.owned_process import run_owned
from workflow import local_signing_bridge as bridge
from workflow.local_signing_workload import worker_timeout
from workflow.local_signing_regression_catalog import HANDOFF_MODES, inherited_modes
from .local_signing_helpers import completed_case_directory


def capture(argv, root, *, timeout):
    # Tests are already inside the reviewed original verification Session.
    # Preserve the fixture's real exec/normal-exit behavior and original bounded
    # timeout, without adopting any PID or treating wait() as family finality.
    return run_owned(argv, cwd=root, timeout=timeout, capture=True, output_limit=64 * 1024,
                     environ={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C",
                              "HOME": str(root), "TMPDIR": str(root)})


@unittest.skipUnless(os.name == 'posix', 'local signing lease requires POSIX')
class SigningAccountNativeTests(unittest.TestCase):
    def test_real_fork_during_resource_handoff_never_mutates_or_retains_parent_resources(self):
        for mode in HANDOFF_MODES:
            with self.subTest(mode=mode):
                self.run_handoff_variant(mode)

    def run_handoff_variant(self, mode):
        self.assertIn(mode, HANDOFF_MODES)
        fixture = Path(__file__).parents[1] / 'workflow/local_signing_handoff_fixture.py'
        with completed_case_directory(prefix='mrk-fork-handoff-') as root:
            result = capture(
                [sys.executable, '-I', '-S', '-B', str(fixture),
                 str(Path(mobile_release.__file__).resolve().parent.parent), str(root), mode],
                root, timeout=worker_timeout("account-native-flow"),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(result.stderr)
            self.assertTrue(json.loads(result.stdout)['checkedBeforeFallback'])

    def test_real_process_thread_and_independent_account_lock_lifetimes(self):
        with completed_case_directory(prefix='mrk-flock-account-') as home:
            other = home/'other'; other.mkdir(mode=0o700)
            package = str(Path(mobile_release.__file__).resolve().parent.parent)
            code = (f'import sys,json;sys.path.insert(0,{package!r});'
                    f'from pathlib import Path;from mobile_release.local_signing import signing_status;print(json.dumps(signing_status(home=Path({str(home)!r}))))')
            with signing.local_signing_lease(home=home) as lease:
                inode = (home/signing.LEASE_DIRECTORY).stat().st_ino
                result = capture([sys.executable,'-I','-S','-B','-c',code], home, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'],'busy')
                values=[]
                thread=threading.Thread(target=lambda:values.append(signing.signing_status(home=home)))
                thread.start();thread.join(timeout=5);self.assertFalse(thread.is_alive())
                self.assertEqual(values[0]['status'],'busy')
                with signing.local_signing_lease(home=other): lease.assert_owner()
            result = capture([sys.executable,'-I','-S','-B','-c',code], home, timeout=5)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'],'idle')
            self.assertEqual((home/signing.LEASE_DIRECTORY).stat().st_ino,inode)

    def test_inherited_fork_exit_gc_and_new_child_admission_cannot_cleanup_parent(self):
        for mode in inherited_modes('macos-26' if sys.platform == 'darwin' else 'ubuntu-24.04'):
            with self.subTest(mode=mode):
                self.run_inherited_variant(mode)

    def run_inherited_variant(self, mode):
        self.assertIn(mode, inherited_modes('macos-26' if sys.platform == 'darwin' else 'ubuntu-24.04'))
        fixture=Path(__file__).parents[1]/'workflow/local_signing_fork_fixture.py'
        with completed_case_directory(prefix='mrk-fork-account-') as root:
            process = capture([sys.executable,'-I','-S','-B',str(fixture),
                               str(Path(mobile_release.__file__).resolve().parent.parent),str(root),mode],
                              root, timeout=worker_timeout("account-native-flow"))
            self.assertEqual(process.returncode,0,process.stderr)
            self.assertFalse(process.stderr)
            result=json.loads(process.stdout)
            self.assertTrue(result['childReaped'] and result['parentResourcesUnchangedBeforeFallback'])

    def test_default_account_rejects_unsupported_host_and_conflicting_home_before_native_work(self):
        with patch.object(signing.sys,'platform','win32'), self.assertRaisesRegex(CredentialError,'require macOS'):
            signing.signing_status()
        if sys.platform == 'darwin':
            with patch.dict(os.environ,{'HOME':'/fictional-nonexistent-account-home'}),self.assertRaises((CredentialError,OSError)):
                signing.account_home()


@unittest.skipUnless(sys.platform == 'darwin','Darwin filesystem ABI requires macOS')
class SigningDarwinABITests(unittest.TestCase):
    def test_real_header_layout_and_local_volume_match_ctypes_without_private_state(self):
        source=r'''#define _DARWIN_C_SOURCE 1
#include <sys/mount.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdio.h>
_Static_assert(sizeof(mode_t)==2,"Darwin mode_t must be the public unsigned 16-bit slot");
_Static_assert((mode_t)-1>0,"Darwin mode_t must be unsigned");
_Static_assert(_Generic(&mkfifoat,int (*)(int,const char *,mode_t):1,default:0),"public mkfifoat signature differs");
int main(void){printf("%zu %zu %zu %u\n",sizeof(struct statfs),offsetof(struct statfs,f_flags),offsetof(struct statfs,f_fstypename),MNT_LOCAL);return 0;}
'''
        with completed_case_directory(prefix='mrk-fsabi-') as root:
            file=root/'abi.c';binary=root/'abi';file.write_text(source)
            built=capture(['/usr/bin/clang','-std=c11',str(file),'-o',str(binary)], root, timeout=30)
            self.assertEqual(built.returncode,0,built.stderr)
            run=capture([str(binary)], root, timeout=5)
            self.assertEqual(run.returncode,0,run.stderr)
            self.assertEqual([int(value) for value in run.stdout.split()],
                             [ctypes.sizeof(signing._Statfs64),signing._Statfs64.flags.offset,signing._Statfs64.fstypename.offset,0x1000])
            descriptor=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try: signing.require_local_volume(descriptor)
            finally: os.close(descriptor)
            # The same disposable native capture exercises the selected actual
            # Python/libSystem implementation, not a Linux/mock ABI substitute.
            namespace = bridge.Namespace(root / 'fifo-api', create=True)
            try:
                namespace.validate()  # Original private0700 dir, two0600 FIFOs.
                with self.assertRaises(OSError) as raised:
                    bridge._create_fifo(namespace.directory, bridge.NAMES[0])
                self.assertEqual(raised.exception.errno, errno.EEXIST)
                namespace.validate()  # Collision preserved every original identity.
                namespace.remove()
                self.assertIsNone(namespace.directory)
                self.assertFalse(namespace.close_errors)
            finally:
                # Only original still-owned descriptors; remove() has already
                # retired successful closes, so this never retries an FD.
                namespace.close()


if __name__ == '__main__': unittest.main()
