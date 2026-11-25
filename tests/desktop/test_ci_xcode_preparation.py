import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('ci_xcode', Path(__file__).resolve().parents[2] / 'desktop/tools/prepare_ci_xcode.py')
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


class ProtectedXcodeFixtureTests(unittest.TestCase):
    def test_candidate_push_profile_is_closed_before_any_privileged_work(self):
        script='/Users/runner/work/mobile-release-kit/mobile-release-kit/.candidate-consumer-helper/desktop/tools/prepare_ci_xcode.py'
        ref='refs/heads/verify/desktop-macos-candidate-consume'
        env=dict(SUDO_UID='501',GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='macOS',
            GITHUB_EVENT_NAME='push',GITHUB_REPOSITORY='Apdelrahman1911/mobile-release-kit',GITHUB_REF=ref,
            GITHUB_WORKFLOW_REF='Apdelrahman1911/mobile-release-kit/.github/workflows/desktop-macos-candidate-consume.yml@'+ref,
            GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,MRK_CANDIDATE_MODE='ordinary-ios-ui')
        for mode in ('ordinary-ios-ui','ordinary-ios-archive-ui','ordinary-diagnostics-ui'):
            ci.ci_profile(['--candidate-consume'],dict(env,MRK_CANDIDATE_MODE=mode),'darwin',0,script)
        manual=dict(SUDO_UID='501',GITHUB_ACTIONS='true',RUNNER_ENVIRONMENT='github-hosted',RUNNER_OS='macOS',GITHUB_EVENT_NAME='workflow_dispatch')
        ci.ci_profile([],manual,'darwin',0,'unchanged manual path')
        for args in ([],['--candidate-consume','extra'],['--other']):
            with self.assertRaises(ci.Refused):ci.ci_profile(args,env,'darwin',0,script)
        for key,bad in [('GITHUB_EVENT_NAME','workflow_dispatch'),('GITHUB_REPOSITORY','foreign/repo'),
                ('GITHUB_REF','refs/heads/main'),('GITHUB_WORKFLOW_REF','foreign'),('GITHUB_SHA','0'*40),
                ('GITHUB_WORKFLOW_SHA','b'*40),('MRK_CANDIDATE_MODE','ordinary-ui'),('MRK_CANDIDATE_MODE','restore'),
                ('RUNNER_ENVIRONMENT','self-hosted'),('SUDO_UID','0')]:
            changed=dict(env,**{key:bad})
            with self.subTest(key=key,bad=bad),patch.dict(ci.os.environ,changed,clear=True),patch.object(ci.sys,'platform','darwin'),                 patch.object(ci.sys,'argv',['prepare','--candidate-consume']),patch.object(ci.os,'geteuid',return_value=0),                 patch.object(ci,'__file__',script),patch.object(ci,'native_clone') as clone,patch.object(ci,'open_original') as opened,                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(ci.main(),1);clone.assert_not_called();opened.assert_not_called()
        for foreign in (script.replace('.candidate-consumer-helper/',''),script.replace('prepare_ci_xcode.py','foreign.py')):
            with self.assertRaises(ci.Refused):ci.ci_profile(['--candidate-consume'],env,'darwin',0,foreign)
        with self.assertRaises(ci.Refused):ci.ci_profile(['--candidate-consume'],manual,'darwin',0,script)

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
            self.assertEqual(actual, {'directories': 2, 'files': 1, 'symlinks': 1, 'hardlinkedFiles': 0, 'cloneBytes': 0})
            self.assertEqual(executable.read_bytes(), b'unchanged')
            self.assertEqual(executable.stat().st_gid, before.st_gid)
            self.assertEqual(executable.stat().st_mtime_ns, before.st_mtime_ns)
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o777)
            self.assertEqual(os.readlink(sub/'alias'), str(external))

    def test_hardlinks_are_quoted_and_bounds_refuse_before_permissions_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); leaf = root/'a'; leaf.write_bytes(b'data'); os.link(leaf, root/'b')
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(ci, 'protect', side_effect=AssertionError('preflight effect')):
                    quote = ci.walk(fd, time.monotonic()+10, mutate=False, path_bytes=0)
                    self.assertEqual(quote['hardlinkedFiles'], 2)
                    self.assertEqual(quote['cloneBytes'], 8)
                    with patch.object(ci, 'MAX_CLONE_BYTES', 4), self.assertRaises(ci.Refused) as refused:
                        ci.walk(fd, time.monotonic()+10, mutate=False, path_bytes=0)
                    self.assertEqual(ci.failure_facts(refused.exception)['condition'], 'clone-byte-bound')
                    with patch.object(ci, 'MAX_QUEUED_NAME_BYTES', 1), self.assertRaises(ci.Refused):
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


    def test_independent_clone_preserves_external_alias_and_closes_collision(self):
        # Linux tests the original-bound replacement contract with an inert
        # copying adapter. macOS runs the real fclonefileat API on tiny own files.
        def portable_clone(source, parent, name):
            out = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600, dir_fd=parent)
            try:
                data = os.pread(source, 64, 0)
                self.assertEqual(os.write(out, data), len(data))
                row = os.fstat(source)
                os.fchmod(out, stat.S_IMODE(row.st_mode))
                os.utime(out, ns=(row.st_atime_ns, row.st_mtime_ns))
            finally:
                os.close(out)
        clone = ci.native_clone() if sys.platform == 'darwin' else portable_clone
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp); selected = parent/'selected'; selected.mkdir()
            original = parent/'other-xcode-file'; original.write_bytes(b'Apple test fixture'); original.chmod(0o775)
            os.link(original, selected/'tool')
            outside = original.stat()
            fd = os.open(selected, os.O_RDONLY | os.O_DIRECTORY)
            real_fstat = os.fstat
            def root_owned(n):
                row=real_fstat(n)
                values={key:getattr(row,key) for key in dir(row) if key.startswith('st_')}
                values['st_uid']=0
                return SimpleNamespace(**values)
            try:
                quoted=ci.walk(fd,time.monotonic()+10,mutate=False,path_bytes=0)
                self.assertEqual(quoted['hardlinkedFiles'],1)
                with patch.object(ci.os,'fstat',root_owned), patch.object(ci.os,'fchown',side_effect=AssertionError('no external permission writes')):
                    # Only ownership comparison is inert; clone, rename, mode
                    # changes, inode/link inspection and reads are genuine IO.
                    source=ci.open_original('tool',fd,False,allow_links=True)
                    # os.stat must report the same synthetic ownership at joins.
                    real_stat=ci.os.stat
                    def stat_root(*args,**kwargs):
                        row=real_stat(*args,**kwargs)
                        values={key:getattr(row,key) for key in dir(row) if key.startswith('st_')};values['st_uid']=0
                        return SimpleNamespace(**values)
                    try:
                        with patch.object(ci.os,'stat',side_effect=stat_root):
                            result=ci.split_link(source,fd,'tool',time.monotonic()+10,clone)
                        os.close(result)
                    finally:os.close(source)
                self.assertNotEqual((selected/'tool').stat().st_ino,original.stat().st_ino)
                self.assertEqual((selected/'tool').stat().st_nlink,1)
                self.assertEqual((selected/'tool').read_bytes(),original.read_bytes())
                self.assertEqual(stat.S_IMODE((selected/'tool').stat().st_mode),0o755)
                self.assertEqual(stat.S_IMODE(original.stat().st_mode),0o775)
                self.assertEqual(original.stat().st_uid,outside.st_uid)
                self.assertEqual(original.stat().st_gid,outside.st_gid)
                self.assertEqual(original.stat().st_mtime_ns,outside.st_mtime_ns)
                self.assertEqual(list(selected.iterdir()),[selected/'tool'])
                os.unlink(selected/'tool');os.link(original,selected/'tool')
                source=ci.open_original('tool',fd,False,allow_links=True)
                try:
                    with self.assertRaises(FileExistsError):
                        ci.split_link(source,fd,'tool',time.monotonic()+10,lambda *args:(_ for _ in ()).throw(FileExistsError()))
                finally:os.close(source)
                self.assertEqual((selected/'tool').stat().st_ino,original.stat().st_ino)
                self.assertEqual(list(selected.iterdir()),[selected/'tool'])
            finally:os.close(fd)

    def test_created_clone_failure_retires_only_its_own_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'other').write_bytes(b'data');os.link(root/'other',root/'tool')
            parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            source=ci.open_original('tool',parent,False,allow_links=True)
            def bad_clone(_source,fd,name):
                out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=fd)
                os.close(out)  # Positive creation, wrong size: no publication.
            try:
                with self.assertRaises(ci.Refused) as error:
                    ci.split_link(source,parent,'tool',time.monotonic()+10,bad_clone)
                self.assertEqual(error.exception.condition,'clone-result')
                self.assertEqual(sorted(p.name for p in root.iterdir()),['other','tool'])
                self.assertEqual((root/'other').stat().st_ino,(root/'tool').stat().st_ino)
                # A failed temporary retirement must not replace the cause of
                # rejection or cause publication of a wrong clone.
                with patch.object(ci.os,'unlink',side_effect=PermissionError(13,'fixture')), self.assertRaises(ci.Refused) as primary:
                    ci.split_link(source,parent,'tool',time.monotonic()+10,bad_clone)
                self.assertEqual(ci.failure_facts(primary.exception),{'kind':'precondition','condition':'clone-result','cleanupFailures':1})
                self.assertEqual((root/'other').stat().st_ino,(root/'tool').stat().st_ino)
            finally:
                os.close(source);os.close(parent)



if __name__ == '__main__':
    unittest.main()
