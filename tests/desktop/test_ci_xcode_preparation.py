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
        ci.ci_profile(['--candidate-consume'],env,'darwin',0,script)
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



class XcodeResourceObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('ci_xcode_resources', Path(__file__).resolve().parents[2] / 'desktop/tools/observe_ci_xcode_resources.py')
        cls.reader = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.reader)

    def state(self):
        return dict(end=time.monotonic()+10, closeFailures=0)

    def test_original_resource_opens_before_and_after_access_loss_or_clone(self):
        r=self.reader
        self.assertNotEqual(os.geteuid(),0)
        with tempfile.TemporaryDirectory() as tmp:
            app=Path(tmp)/'Xcode.app';resource=app/'Contents/Bundle/Resources/Defaults.properties'
            resource.parent.mkdir(parents=True);resource.write_bytes(b'never read by observer');resource.chmod(0o600)
            sibling=resource.with_name('private-other');sibling.write_bytes(b'not selected')
            outside=Path(tmp)/'outside';outside.mkdir();(outside/'Defaults.properties').write_bytes(b'not followed')
            (app/'Contents/alias').symlink_to(outside)
            state=self.state()
            with r.opened(str(app),None,True,state) as fd:
                paths,census=r.scan(fd,state)
                self.assertEqual(paths,['Contents/Bundle/Resources/Defaults.properties'])
                self.assertTrue(census['complete'])
                before=r.observe(fd,paths[0],state)
                self.assertTrue(before['opened']);self.assertIsNone(before['errno'])
                self.assertEqual(before['nodes'][-1]['mode'],stat.S_IFREG|0o600)
                resource.chmod(0)
                try:
                    refused=r.observe(fd,paths[0],state)
                    self.assertFalse(refused['opened']);self.assertEqual(refused['openErrno'],13)
                    self.assertEqual(refused['failedOperation'],'open')
                finally:resource.chmod(0o600)
                resource.parent.chmod(0)
                try:
                    refused=r.observe(fd,paths[0],state)
                    self.assertFalse(refused['opened']);self.assertEqual(refused['openErrno'],13)
                    self.assertEqual(refused['failedIndex'],3)
                finally:resource.parent.chmod(0o700)
                replacement=resource.with_name('replacement');replacement.write_bytes(b'never read by observer')
                os.replace(replacement,resource)
                after=r.observe(fd,paths[0],state)
                self.assertTrue(after['opened']);self.assertNotEqual(before['nodes'][-1]['inode'],after['nodes'][-1]['inode'])
            self.assertEqual(state['closeFailures'],0)
            self.assertEqual(resource.read_bytes(),b'never read by observer')

    def test_incomplete_scan_does_not_report_absence_and_bounds_are_finite(self):
        r=self.reader
        with tempfile.TemporaryDirectory() as tmp:
            app=Path(tmp);hidden=app/'Contents/Hidden';hidden.mkdir(parents=True)
            (hidden/'Defaults.properties').write_bytes(b'not read')
            hidden.chmod(0)
            state=self.state()
            with r.opened(str(app),None,True,state) as fd:
                try:
                    paths,census=r.scan(fd,state)
                    self.assertEqual(paths,[]);self.assertFalse(census['complete'])
                    self.assertEqual(census['errors'],[dict(depth=2,errno=13)])
                finally:hidden.chmod(0o700)
                for key,value in [('MAX_ENTRIES',1),('MAX_NAMES',1),('MAX_DEPTH',1),('MAX_MATCHES',0)]:
                    with self.subTest(key=key),patch.object(r,key,value),self.assertRaises(r.Refused):r.scan(fd,state)
                with self.assertRaises(r.Refused):r.scan(fd,dict(end=0,closeFailures=0))
            self.assertEqual(state['closeFailures'],0)

    def test_control_is_exclusive_bounded_closed_and_never_an_arbitrary_path(self):
        r=self.reader
        nomination=dict(schemaVersion=1,selection=dict(name='Xcode_26.app',alias=[1,2,stat.S_IFLNK],target='Xcode_26.app'),
            app=[1,3,stat.S_IFDIR],paths=['Contents/Resources/Defaults.properties'],scanComplete=True)
        with tempfile.TemporaryDirectory() as tmp:
            state=self.state()
            with r.opened(tmp,None,True,state) as fd:
                r.save_control(fd,nomination,state)
                self.assertEqual(r.load_control(fd,state),nomination)
                with self.assertRaises(FileExistsError):r.save_control(fd,nomination,state)
                with patch.object(r,'CONTROL_LIMIT',1),self.assertRaises(r.Refused):r.load_control(fd,state)
                (Path(tmp)/r.CONTROL).unlink();(Path(tmp)/r.CONTROL).symlink_to('/dev/null')
                with self.assertRaises(r.Refused):r.load_control(fd,state)
            for path in ('../Defaults.properties','Contents/../Defaults.properties','/etc/Defaults.properties','Contents/Other','Contents/\t/Defaults.properties'):
                with self.subTest(path=path),self.assertRaises(r.Refused):r.control_data(dict(nomination,paths=[path]))
            for value in (dict(nomination,schemaVersion=True),dict(nomination,paths=nomination['paths']*2),dict(nomination,extra=True)):
                with self.assertRaises(r.Refused):r.control_data(value)
            self.assertEqual(state['closeFailures'],0)

    def test_actual_before_after_main_control_and_same_selection_with_inert_host_boundary(self):
        r=self.reader
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);physical=root/'host';app=physical/'Applications/Xcode_26.app'
            resource=app/'Contents/Resources/Defaults.properties';resource.parent.mkdir(parents=True)
            resource.write_bytes(b'no content read');(physical/'Applications/Xcode.app').symlink_to('Xcode_26.app')
            work=root/'work';work.mkdir(mode=0o700)
            actual=r.opened
            def original(name,parent,directory,state):
                return actual(str(physical) if name=='/' and parent is None else name,parent,directory,state)
            values=[]
            with patch.object(r,'opened',side_effect=original):
                for phase in ('before','after'):
                    with patch.object(r,'profile',return_value=(phase,work)),contextlib.redirect_stdout(io.StringIO()) as stream:
                        self.assertEqual(r.main(),0)
                    values.append(json.loads(stream.getvalue()))
                (physical/'Applications/Xcode.app').unlink();(physical/'Applications/Xcode.app').symlink_to('Xcode_other.app')
                with patch.object(r,'profile',return_value=('after',work)),contextlib.redirect_stdout(io.StringIO()) as stream:
                    self.assertEqual(r.main(),1)
                self.assertEqual(json.loads(stream.getvalue())['outcome'],'unconfirmed')
            for value in values:
                self.assertTrue(value['originalClosesKnown']);self.assertFalse(value['qualification'])
                self.assertFalse(value['altoolSyscallErrno']);self.assertTrue(value['observations'][0]['opened'])
            self.assertEqual(values[0]['observations'],values[1]['observations'])
            self.assertTrue(values[1]['scan']['reusedBeforeNomination'])

    def test_unknown_close_is_recorded_and_foreign_entry_never_opens(self):
        r=self.reader
        with tempfile.TemporaryDirectory() as tmp:
            state=self.state();actual=os.close
            def uncertain(fd):actual(fd);raise OSError(5,'inert close uncertainty')
            with patch.object(r.os,'close',side_effect=uncertain):
                with r.opened(tmp,None,True,state):pass
            self.assertEqual(state['closeFailures'],1)
        for arguments in ([],['after','extra'],['before']):
            with patch.object(r.sys,'argv',['observer']+arguments),patch.object(r.sys,'platform','linux'), \
                    patch.object(r,'opened') as opened,contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(r.main(),1);opened.assert_not_called()
                value=json.loads(output.getvalue());self.assertFalse(value['qualification']);self.assertEqual(value['outcome'],'unconfirmed')


if __name__ == '__main__':
    unittest.main()
