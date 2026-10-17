import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ci_xcode', Path(__file__).resolve().parents[2] / 'desktop/tools/prepare_ci_xcode.py')
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class ProtectedXcodeFixtureTests(unittest.TestCase):
    def test_physical_walk_preserves_bytes_execution_groups_and_external_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'selected'; root.mkdir(); root.chmod(0o775)
            sub = root / 'Contents'; sub.mkdir(); sub.chmod(0o775)
            executable = sub / 'tool'; executable.write_bytes(b'unchanged'); executable.chmod(0o775)
            external = Path(tmp) / 'outside'; external.write_bytes(b'outside'); external.chmod(0o777)
            (sub / 'alias').symlink_to(external)
            before = executable.stat()
            held = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            actual_fstat = os.fstat
            def administrative(fd):
                row = actual_fstat(fd)
                # Only owner identity is inert; real nofollow IO and mode writes
                # exercise our synthetic tree under the unprivileged test user.
                return SimpleNamespace(**{key: getattr(row, key) for key in dir(row) if key.startswith('st_')}, **{})
            def root_owned(fd):
                row = administrative(fd); row.st_uid = 0; return row
            try:
                expected = ci.walk(held, time.monotonic()+10, mutate=False, path_bytes=0)
                with patch.object(ci.os, 'fstat', root_owned), patch.object(ci.os, 'fchown', side_effect=AssertionError('must not change synthetic owner')):
                    actual = ci.walk(held, time.monotonic()+10, mutate=True, path_bytes=0)
            finally:
                os.close(held)
            self.assertEqual(actual, expected)
            self.assertEqual(actual, {'directories': 2, 'files': 1, 'symlinks': 1})
            self.assertEqual(executable.read_bytes(), b'unchanged')
            self.assertEqual(executable.stat().st_gid, before.st_gid)
            self.assertEqual(executable.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o777)
            self.assertEqual(os.readlink(sub/'alias'), str(external))

    def test_hardlink_and_bounds_refuse_in_preflight_without_permissions_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); leaf = root/'a'; leaf.write_bytes(b'data'); os.link(leaf, root/'b')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(ci, 'protect', side_effect=AssertionError('preflight effect')):
                    with self.assertRaises(ci.Refused):
                        ci.walk(fd, time.monotonic()+10, mutate=False, path_bytes=0)
                    (root/'b').unlink()
                    with patch.object(ci, 'MAX_ENTRIES', 1), self.assertRaises(ci.Refused):
                        ci.walk(fd, time.monotonic()+10, mutate=False, path_bytes=0)
                    with self.assertRaises(ci.Refused):
                        ci.walk(fd, time.monotonic()+10, mutate=False, path_bytes=ci.MAX_PATH+1)
                    with self.assertRaises(ci.Refused):
                        ci.walk(fd, time.monotonic()-1, mutate=False, path_bytes=0)
            finally:
                os.close(fd)

    def test_protection_changes_only_owner_and_forbidden_mode_bits(self):
        row = SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFREG|0o6775,st_nlink=1,
                              st_uid=501,st_gid=20,st_size=8,st_mtime_ns=9)
        calls=[]
        def chown(fd,uid,gid): calls.append(('chown',uid,gid)); row.st_uid=uid
        def chmod(fd,mode): calls.append(('chmod',mode)); row.st_mode=stat.S_IFREG|mode
        with patch.object(ci.os,'fstat',side_effect=lambda _:SimpleNamespace(**vars(row))), patch.object(ci.os,'fchown',side_effect=chown), patch.object(ci.os,'fchmod',side_effect=chmod):
            ci.protect(7)
        self.assertEqual(calls,[('chown',0,-1),('chmod',0o755)])
        self.assertEqual(row.st_gid,20)

    def test_exact_apple_signature_requirement_and_local_profile_refusal(self):
        with patch.object(ci.subprocess,'run') as run:
            ci.verify('/Applications/Xcode_26.app',time.monotonic()+10)
        argv=run.call_args.args[0]
        self.assertEqual(argv[:5],['/usr/bin/codesign','--verify','--deep','--strict','--all-architectures'])
        self.assertEqual(argv[5:],['--test-requirement','=identifier "com.apple.dt.Xcode" and anchor apple','/Applications/Xcode_26.app'])
        self.assertLessEqual(run.call_args.kwargs['timeout'],10)
        capture=io.StringIO()
        with patch.object(ci.sys,'platform','linux'), patch.object(ci,'open_original',side_effect=AssertionError('no local IO')), contextlib.redirect_stdout(capture):
            self.assertEqual(ci.main(),1)
        self.assertEqual(json.loads(capture.getvalue())['stage'],'ci-profile')

    def test_selected_alias_is_one_literal_sibling_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent=Path(tmp); alias=parent/'Xcode.app'; fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY)
            try:
                with patch.dict(os.environ,{'SUDO_UID':str(os.getuid())}):
                    for target in ('/private/SECRET_SENTINEL','../Xcode_26.app','Xcode.app','Xcode_26.app/Contents'):
                        alias.symlink_to(target)
                        with self.assertRaises(ci.Refused):ci.selected(fd)
                        alias.unlink()
                    alias.symlink_to('/Applications/Xcode_26.6.app')
                    name,_=ci.selected(fd)
                    self.assertEqual(name,'Xcode_26.6.app')
            finally:
                os.close(fd)


if __name__ == '__main__':
    unittest.main()
