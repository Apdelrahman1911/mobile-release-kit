"""Inert candidate UI composition tests; no native process, app or Store work."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from desktop.tools import macos_candidate_ui as U
from desktop.tools import macos_normal_ui_runner as N
from desktop.tools import macos_fixed_carrier_resume as R

WORK = Path('/Users/runner/work/_temp/mrk-macos-installed.ABCDEFGH')


def fixture(target=R.TARGETS[0]):
    selected = dict(source='a'*40, tree='b'*40, target=target, runId='17', runAttempt='2', jobId='19',
                    artifactId='23', artifactBytes=4096, artifactSha256='c'*64)
    context = dict(helperSource='d'*40, target=target, runId='31', runAttempt='1', work=WORK/'resume-carrier')
    install = dict(scope='candidate-fresh-installer-observation', target=target, producerSource=selected['source'],
        producerTree=selected['tree'], artifactId='23', artifactSha256='c'*64, producerRunId='17', producerRunAttempt='2',
        producerJobId='19', helperSource='d'*40, helperTree='e'*40, consumerRunId='31', consumerRunAttempt='1',
        originalInstallerReturnedZero=True, sameRequestReadback=True, originalMountDetached=True, originalClosesKnown=True,
        workloadsKnownSettled=True, privateOutputsRetired=True, productReady=False, uiQualified=False, p0Qualified=False)
    return selected, context, install


def persistence_body():
    method='-[MRKNormalAppUITests.NormalAppUITests testSyntheticPersistentCredentials]'
    return ('\n'.join(["Test Case '"+method+"' started.",
        'MRK_MACOS_PERSISTENCE_LIFETIME=phase=1'+U.LIFETIME_SUFFIX,
        'MRK_MACOS_PERSISTENCE_LIFETIME=phase=2'+U.LIFETIME_SUFFIX,
        U.PERSISTENCE_MARKER, "Test Case '"+method+"' passed (1.0 seconds).", ''])).encode()


def phase_fixture(name, target=R.TARGETS[0]):
    selected, context, install=fixture(target)
    args, req=U.phase_request(N,name,target,WORK)
    mode=req['phase']; result=None if req['result'] is None else req['result'].name
    out=(persistence_body() if name=='persistence-test' else
         R.canonical(dict(totalTestCount=2 if name=='project-summary' else 1,
            passedTests=2 if name=='project-summary' else 1,failedTests=0,skippedTests=0,expectedFailures=0))
         if mode=='summary' else b'inert returned native output\n')
    row=dict(scope='actual-generated-xctrunner-admission-only' if mode=='test' else 'normal-ui-original-command-admission-only',
        sourceCommit=selected['source'],target=target,sourcePrePostMatched=True,originalCommandReturned=True,
        resultBundle=result,receiptPolicy='exclusive0600-readback-consuming-close',sourceRosterSha256='f'*64,
        fileLimitBytes=[32<<30,32<<30] if mode=='build' else [1<<30,1<<30],
        phaseClock=dict(startNs='1',deadlineNs=str(1+req['phaseSeconds']*10**9),beforePublicationNs='2',postCloseDeadlineRequired=True))
    row['normalPhase' if mode=='test' else 'phase']=mode
    row['originalTestReturncode' if mode=='test' else 'originalReturncode']=0
    if mode=='test':
        row.update(originalClosesCompleted=True,originalProductsPrePostMatched=True,strictCodesignOriginalZero=True,reSignedOrRepaired=False)
        if name=='project-test':row.update(projectFieldAndEditMarkersObserved=True,androidToolSourceBrowseMarkerObserved=True)
        if name=='applications-test':row['applicationsLaunchObservationMarker']=True
    src=('normal-ui-source-roster',15,1048576)
    roles=([src,*[('normal-toolchain-'+k,15,4096) for k in ('xcode','sdkPath','sdkVersion','sdkBuild')],
        ('normal-ui-build',240,1048576),src] if mode=='build' else
        [src,('verify-generated-runner',30,1048576),('generated-runner-entitlements',30,1048576),
         ('one-admitted-ui-test',req['timeout'],1048576),src] if mode=='test' else
        [src,('normal-ui-summary',30,262144),src])
    commands=[]
    for index,(role,cap,limit) in enumerate(roles):
        stdout=out if index==len(roles)-2 else b'inert source roster'
        commands.append(dict(role=role,returncode=0,timeoutSeconds=cap,roleCapSeconds=cap,outputLimitBytes=limit,
            argvSha256='a'*64,stdoutBytes=len(stdout),stdoutSha256=R.sha(stdout),stderrBytes=0,stderrSha256=R.sha(b'')))
    row['commands']=commands
    return selected,context,install,args,req,row,out


class CandidateUITests(unittest.TestCase):
    def test_same_job_install_handoff_is_not_legacy_or_forged_finality(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            selected,context,value=fixture(target)
            self.assertEqual(U.install_admission_data(value,selected,context),value)
            for key,bad in [('originalClosesKnown',False),('originalInstallerReturnedZero',1),('uiQualified',True),
                ('producerSource','d'*40),('helperSource','a'*40),('consumerRunAttempt','2'),('helperTree','0'*40)]:
                changed=dict(value);changed[key]=bad
                with self.subTest(target=target,key=key),self.assertRaises(R.Refused):U.install_admission_data(changed,selected,context)
            with self.assertRaises(R.Refused):U.install_admission_data(dict(value,fixedCarrierResumeScope='fixed-ce644'),selected,context)

    def test_only_existing_same_source_phases_targets_and_clean_environment(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            selected,_,_=fixture(target)
            for name in U.PHASES:
                args,req=U.phase_request(N,name,target,WORK)
                self.assertEqual(N.normal_request(args,str(WORK/'normal-ui/tmp')+'/'),req)
                self.assertEqual(req['phaseSeconds'],450 if name=='build' else 90 if name.endswith('summary') else
                                 885 if name=='project-test' else 345 if name=='applications-test' else 585)
            env=U.clean_environment(N,selected,WORK)
            self.assertEqual(env['TEST_RUNNER_MRK_NORMAL_UI_APPLICATION_SOURCE'],selected['source'])
            self.assertEqual(env['TEST_RUNNER_MRK_NORMAL_UI_HARNESS_SOURCE'],selected['source'])
            self.assertNotIn('GITHUB_TOKEN',env);self.assertNotIn('GITHUB_SHA',env)
            self.assertFalse(any('FIXED' in k or 'CREDENTIAL' in k or 'SIGNING' in k for k in env))
        for name in ('remove','sign','ios-unsigned-archive-test','saved-version-recovery-test','--normal-build'):
            with self.assertRaises(R.Refused):U.phase_request(N,name,N.ARM_TARGET,WORK)

    def test_restart_requires_both_original_lifetimes_one_attempt_and_no_failure_cleanup(self):
        body=persistence_body();self.assertTrue(U.persistence_markers(body))
        changes=[body.replace(b'phase=1',b'phase=2'),body.replace(b'phase=2',b'phase=3'),
            body.replace(b'originalTerminated=1',b'originalTerminated=0',1),body+body,
            body+b'MRK_MACOS_UI_FAILURE_CLEANUP=1\n',body.replace(b' passed (',b' failed (')]
        for changed in changes:
            with self.assertRaises(R.Refused):U.persistence_markers(changed)

    def test_exact_native_admission_and_counts_do_not_accept_zero_test_or_fixed_profile(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            for name in U.PHASES:
                selected,_,_,_,req,row,out=phase_fixture(name,target)
                self.assertEqual(U.phase_admission_data(row,req,selected['source'],out,b''),'f'*64)
                for mutate in (lambda r:r.update(fixedCarrierResumeScope='fixed-ce644'),
                    lambda r:r.update(sourceCommit='d'*40),lambda r:r['commands'][-1].update(returncode=1),
                    lambda r:r['commands'][-2].update(stdoutSha256='0'*64),
                    lambda r:r['phaseClock'].update(deadlineNs='2'),lambda r:r.update(fileLimitBytes=[1,1])):
                    changed=deepcopy(row);mutate(changed)
                    with self.assertRaises(R.Refused):U.phase_admission_data(changed,req,selected['source'],out,b'')
                if name.endswith('summary'):
                    wrong=R.canonical(dict(totalTestCount=0,passedTests=0,failedTests=0,skippedTests=0,expectedFailures=0))
                    changed=deepcopy(row);changed['commands'][1].update(stdoutBytes=len(wrong),stdoutSha256=R.sha(wrong))
                    with self.assertRaises(R.Refused):U.phase_admission_data(changed,req,selected['source'],wrong,b'')

    def test_actual_owned_wrapper_known_nonzero_unknown_and_changed_post_never_publish_status(self):
        for fault in (None,'nonzero','unknown','post'):
            selected,context,_,_,req,row,out=phase_fixture('project-test')
            events=[]
            class Book:
                def __init__(self):self.entries=[];self.directories={WORK/'normal-ui':{}}
                def check(self):events.append('check')
                def publish(self,path,body):self.entries.append({'path':path});events.append(('publish',path.name))
                def file(self,path,limit,**kw):self.entries.append({'path':path});return self.entries[-1],R.canonical(row)
                def finish(self):return True
            class Owner:
                def run_owned(self,argv,**kw):
                    events.append('entered')
                    self.kw=kw;self.argv=argv
                    if fault=='unknown':raise RuntimeError('inert unknown native owner')
                    failure = R.canonical(dict(schemaVersion=1,scope='generated-ui-runner-refused',productReady=False,
                        error='runner-admission-or-owner-error',stage='execute',exceptionClass='Refused',
                        sourceFrames=[],commands=[],ownerFailure=dict(dispatched=True,contained=True,cleanupComplete=True),
                        unknownStateRetained=True)) if fault=='nonzero' else b''
                    return subprocess.CompletedProcess(argv,1 if fault=='nonzero' else 0,out,failure)
            count=0
            def verify():
                nonlocal count
                count+=1;events.append('source'+str(count))
                if fault=='post' and count==2:raise R.Refused('inert source POST')
            quota=R.OriginalQuota();book=quota.book(Book);owner=Owner()
            clock=N.PhaseClock(req['phaseSeconds']+180,now=lambda:1,started=1)
            call=lambda:U.run_phase(N,owner,book,quota,context,selected,'project-test',clock,verify)
            if fault is None:self.assertEqual(call(),'f'*64)
            else:
                with self.assertRaises((R.Refused,RuntimeError)):call()
            self.assertFalse(any(isinstance(e,tuple) and e[1].endswith('.status') for e in events))
            self.assertLess(events.index('source1'),events.index('entered'))
            if fault=='unknown':self.assertFalse(any(isinstance(e,tuple) for e in events))
            if fault=='nonzero':
                self.assertNotIn('source2',events)
                self.assertEqual(U.NATIVE_DIAGNOSTIC['status'],'observed-exception-only')
                self.assertEqual(U.NATIVE_DIAGNOSTIC['stage'],'execute')
                self.assertEqual(U.NATIVE_DIAGNOSTIC['exceptionClass'],'Refused')
            self.assertEqual(owner.kw['timeout'],req['phaseSeconds']+15)
            self.assertEqual(owner.kw['environ'],U.clean_environment(N,selected,WORK))
            self.assertEqual(owner.kw['cwd'],U.consumer.CANDIDATE_ROOT)

    def test_prior_caller_status_is_required_even_after_success_shaped_inner_receipt(self):
        selected,_,_,_,_,row,out=phase_fixture('build')
        contents={'build.status':b'0\n','build.command-admission.json':R.canonical(row),'build.stdout':out,'build.stderr':b''}
        read=lambda path,cap:contents[path.name]
        self.assertEqual(U.read_phase(read,N,'build',selected,WORK),'f'*64)
        for status in (b'1\n',b'',b'0',b'0\n1\n'):
            contents['build.status']=status
            with self.assertRaises(R.Refused):U.read_phase(read,N,'build',selected,WORK)

    def test_actual_main_refuses_handoff_before_loading_code_and_attempts_original_closes(self):
        selected,context,value=fixture();value['originalClosesKnown']=False
        book=SimpleNamespace(entries=[],directories={},finish=mock.Mock(return_value=False))
        def file(path,*a,**kw):
            return {},R.canonical({'schemaVersion':1,'targets':{selected['target']:selected}}) if path.name.endswith('selection.json') else R.canonical(value)
        book.file=file
        with mock.patch('resource.setrlimit'),mock.patch.object(U.consumer,'entry_context',return_value=context),mock.patch.object(U,'ROOT',U.consumer.HELPER_ROOT),\
             mock.patch.object(U.Path,'cwd',return_value=U.consumer.CANDIDATE_ROOT),mock.patch.object(U.resume,'bootstrap_originals',return_value=lambda:book),\
             mock.patch.object(U.resume.OriginalQuota,'call',side_effect=lambda b,m,p,*a,**kw:getattr(b,m)(p,*a,**kw)),\
             mock.patch.object(U.resume,'load_module') as load,mock.patch.object(sys,'argv',['candidate-ui','build']):
            with self.assertRaisesRegex(R.Refused,'candidate-ui-install-handoff') as caught:U.main()
            load.assert_not_called();book.finish.assert_called_once()
            self.assertIn('candidate-ui-original-final-closes',caught.exception.__notes__)



class CandidateUIMainTests(unittest.TestCase):
    def exercise(self, name, target, unknown_close=False):
        import os, stat
        selected,context,install=fixture(target)
        files={};directories=set();books=[];effects=[];modes={}
        root=U.consumer.HELPER_ROOT
        sources=tuple(dict.fromkeys((*U.consumer.HELPER_SOURCE_INPUTS,U.consumer.CONSUMER_PATH,
            U.consumer.LEGACY_PATH,U.consumer.PARSER_PATH,U.RUNNER,'desktop/tools/macos_candidate_ui.py')))
        for path in sources:
            actual=ROOT/path
            files[root/path]=actual.read_bytes() if actual.exists() else b'inert source\n'
            modes[root/path]=0o644
        files[root/U.consumer.SELECTION_PATH]=R.canonical({'schemaVersion':1,'targets':{target:selected}})
        modes[root/U.consumer.SELECTION_PATH]=0o644
        files[U.consumer.CANDIDATE_ROOT/U.RUNNER]=files[root/U.RUNNER];modes[U.consumer.CANDIDATE_ROOT/U.RUNNER]=0o644
        files[WORK/'consumer-result.json']=R.canonical(install)
        host=WORK/'host-python';base=Path('/inert-base/bin/python3');binary=b'inert python never executed'
        cfg=('home = /inert-base/bin\ninclude-system-site-packages = false\nversion = 3.14.7\n'
             'executable = /inert-base/bin/python3\ncommand = /inert-base/bin/python3 -m venv --copies '
             '--without-pip --without-scm-ignore-files '+str(host)+'\n').encode()
        for relative in (*R.HOST_FILES,R.HOST_OPTIONAL):
            executable=relative in ('bin/python','bin/python3','bin/python3.14',R.HOST_OPTIONAL)
            files[host/relative]=binary if executable else cfg if relative=='pyvenv.cfg' else b'inert activation'
            modes[host/relative]=0o755 if executable else 0o644
        files[base]=binary;modes[base]=0o755
        for relative in R.HOST_DIRS:directories.add(host/relative)
        files[Path('/usr/bin/git')]=b'inert system tool';modes[Path('/usr/bin/git')]=0o755
        def info(path):
            path=Path(path)
            return SimpleNamespace(st_dev=1,st_ino=int.from_bytes(__import__('hashlib').sha256(str(path).encode()).digest()[:6],'big'),
                st_mode=(stat.S_IFREG|modes.get(path,0o600)) if path in files else stat.S_IFDIR|0o700,
                st_uid=0 if str(path).startswith('/usr') else os.getuid(),st_gid=0 if str(path).startswith('/usr') else os.getgid(),
                st_nlink=1,st_size=len(files[path]) if path in files else 0,st_mtime_ns=1,st_ctime_ns=1)
        def children(path):
            return sorted({p.relative_to(path).parts[0] for p in (*files,*directories) if p!=path and p.is_relative_to(path)})
        basevalue=dict(launcherPath=str(base),executable=str(base),copyPath=str(base),copyExecutable=str(base),prefix='/inert-base',
                       identity=list(R.identity(info(base))),sha256=R.sha(binary))
        snapshot,_=R.host_snapshot(host,lambda p:(R.identity(info(p)),children(p)),lambda p,n:(R.identity(info(p)),files[p]))
        files[host/'host-binding.json']=R.canonical(dict(schemaVersion=1,source=context['helperSource'],runId='31',runAttempt='1',
            base=basevalue,prefix=str(host),basePrefix='/inert-base',baseExecutable=str(base),**snapshot,retainedUntilHostedTeardown=True))
        previous=U.PHASES if name=='result' else U.PHASES[:U.PHASES.index(name)]
        if name!='build':directories.add(WORK/'normal-ui');directories.add(WORK/'normal-ui/tmp')
        for phase in previous:
            _,_,_,_,_,row,out=phase_fixture(phase,target)
            for suffix,body in (('.status',b'0\n'),('.stdout',out),('.stderr',b'')):
                files[WORK/'normal-ui'/(phase+suffix)]=body
            files[WORK/'normal-ui'/U.admission_name(phase)]=R.canonical(row)
        class Book:
            def __init__(self):self.entries=[];self.directories={};self.attempts=[];books.append(self)
            def directory(self,path):
                path=Path(path)
                if path not in self.directories:
                    if path!=Path('/'):self.directory(path.parent)
                    directories.add(path);entry=dict(path=path,kind='directory',identity=R.identity(info(path))[:5],fd=len(self.entries)+100,closed=False)
                    self.entries.append(entry);self.directories[path]=entry
                return self.directories[path]
            def file(self,path,limit,**kw):
                path=Path(path);self.directory(path.parent)
                if len(files[path])>limit:raise R.Refused('inert cap')
                if 'modes' in kw and stat.S_IMODE(info(path).st_mode) not in kw['modes']:raise R.Refused('inert mode')
                entry=dict(path=path,kind='file',identity=R.identity(info(path)),fd=len(self.entries)+100,closed=False)
                self.entries.append(entry);return entry,files[path]
            def publish(self,path,body):
                if path in files:raise R.Refused('inert collision')
                self.directory(path.parent);files[path]=body;self.entries.append(dict(path=path,kind='output',identity=R.identity(info(path)),fd=None,closed=True))
            def check(self):pass
            def finish(self):
                for entry in self.entries:
                    if entry['fd'] is not None:
                        self.attempts.append(entry['path']);entry['fd']=None
                        entry['closed']=not(unknown_close and entry['path']==WORK/'consumer-result.json')
                return all(entry['closed'] for entry in self.entries)
        class Owner:
            def run_owned(self,argv,**kw):
                if argv[0]=='/usr/bin/git':
                    gitroot=Path(argv[argv.index('-C')+1]);helper=gitroot==root
                    if 'rev-parse' in argv:out=((context['helperSource']+'\n'+install['helperTree']) if helper else (selected['source']+'\n'+selected['tree'])).encode()+b'\n'
                    else:
                        names=argv[argv.index('--')+1:]
                        out=b''.join(b'100644 blob '+__import__('hashlib').sha1(b'blob '+str(len(files[gitroot/p])).encode()+b'\0'+files[gitroot/p]).hexdigest().encode()+b'\t'+p.encode()+b'\0' for p in names)
                    return subprocess.CompletedProcess(argv,0,out,b'')
                effects.append('native-cli')
                _,_,_,_,_,row,out=phase_fixture(name,target)
                files[WORK/'normal-ui'/U.admission_name(name)]=R.canonical(row)
                return subprocess.CompletedProcess(argv,0,out,b'')
        def mkdir(path,mode):
            if Path(path) in directories:raise FileExistsError()
            directories.add(Path(path))
        def listdir(fd):
            entry=next(e for b in books for e in b.entries if e['fd']==fd)
            return children(entry['path'])
        original_quota=R.OriginalQuota
        quotas=[]
        def quota_factory():
            q=original_quota();quotas.append(q);return q
        from contextlib import ExitStack
        with ExitStack() as stack:
            for patch in (mock.patch('resource.setrlimit'),mock.patch.object(U.consumer,'entry_context',return_value=context),
                mock.patch.object(U,'ROOT',root),mock.patch.object(U.Path,'cwd',return_value=U.consumer.CANDIDATE_ROOT),
                mock.patch.object(U.Path,'resolve',lambda p:p),mock.patch.object(U.resume,'bootstrap_originals',return_value=Book),
                mock.patch.object(U.resume,'load_module',return_value=N),mock.patch.object(U.resume,'OriginalQuota',side_effect=quota_factory),
                mock.patch.object(N,'load_normal_owner',return_value=Owner()),mock.patch.object(U.os,'stat',side_effect=lambda p,**kw:info(p)),
                mock.patch.object(U.os,'mkdir',side_effect=mkdir),mock.patch.object(U.os,'listdir',side_effect=listdir),
                mock.patch.object(sys,'argv',['candidate-ui',name]),mock.patch.object(sys,'executable',str(host/'bin/python3')),
                mock.patch.object(sys,'prefix',str(host)),mock.patch.object(sys,'base_prefix','/inert-base'),
                mock.patch.object(sys,'_base_executable',str(base))):stack.enter_context(patch)
            if unknown_close:
                with self.assertRaisesRegex(R.Refused,'candidate-ui-original-final-closes'):U.main()
                value=None
            else:value=U.main()
        self.assertLessEqual(quotas[0].reserved,96)
        self.assertEqual(len(books[0].attempts),len(set(books[0].attempts)))
        self.assertFalse(any(p.name==name+'.status' for p in files if name not in previous))
        return value,effects,quotas[0].reserved

    def test_actual_main_both_targets_first_and_full_result_with_lifetime_quota(self):
        for target in (N.ARM_TARGET,N.INTEL_TARGET):
            value,effects,_=self.exercise('build',target)
            self.assertEqual(effects,['native-cli']);self.assertTrue(value['originalClosesKnown'])
            value,effects,count=self.exercise('result',target)
            self.assertEqual(value['totalTests'],4);self.assertEqual(effects,[])
            self.assertGreaterEqual(count,80)

    def test_actual_main_late_consuming_close_prevents_success_and_status(self):
        value,effects,_=self.exercise('project-test',N.ARM_TARGET,unknown_close=True)
        self.assertIsNone(value);self.assertEqual(effects,['native-cli'])


class CandidateUICleanupTests(unittest.TestCase):
    def test_finite_failure_diagnostic_rejects_raw_secret_suffix_paths_and_foreign_exception(self):
        for error in (R.Refused('candidate-ui-original-cli-nonzero-PRIVATE_SENTINEL'),ValueError('/private/PRIVATE_SENTINEL'),
                      RuntimeError('PRIVATE_SENTINEL')):
            data=U.failure_data(error,'PRIVATE_SENTINEL')
            self.assertIsNone(data['reason']);self.assertIsNone(data['phase'])
            self.assertNotIn('PRIVATE_SENTINEL',R.canonical(data).decode())
        self.assertEqual(U.failure_data(R.Refused('candidate-ui-original-cli-nonzero'),'project-test')['reason'],
                         'candidate-ui-original-cli-nonzero')

    def test_real_inert_cleanup_only_known_outputs_and_foreign_link_refusal(self):
        import os,tempfile
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'normal-ui';root.mkdir(mode=0o700)
            for name in ('DerivedData','tmp','applications-test.xcresult','project-test.xcresult','persistence-test.xcresult'):
                (root/name).mkdir();(root/name/'inert').write_bytes(b'DATA')
            for phase in U.PHASES:
                for suffix in ('.stdout','.stderr'):(root/(phase+suffix)).write_bytes(b'inert')
            (root/'result.json').write_bytes(b'retained small observation')
            U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30))
            self.assertEqual([p.name for p in root.iterdir()],['result.json'])
            foreign=Path(d)/'foreign';foreign.mkdir();(foreign/'keep').write_bytes(b'unchanged')
            (root/'DerivedData').symlink_to(foreign,target_is_directory=True)
            with self.assertRaisesRegex(R.Refused,'candidate-ui-cleanup-directory'):
                U.cleanup_outputs(root,R.identity(root.stat())[:5],N.PhaseClock(30))
            self.assertEqual((foreign/'keep').read_bytes(),b'unchanged')


if __name__=='__main__':unittest.main()
