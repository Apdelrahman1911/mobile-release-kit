"""Real held source/host/control bootstrap; explicit inert native phase endpoints."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack, redirect_stderr
from types import SimpleNamespace
from collections import namedtuple
import test_macos_app_absence_fixture as fixture_tests
import unittest
from unittest import mock
from desktop.tools import macos_candidate_consumer as C
from desktop.tools import macos_android_helper_package as H
from desktop.tools import macos_app_absence_fixture as F
from desktop.tools import macos_fixed_carrier_resume as R
from desktop.tools import macos_normal_ui_runner as N
import test_macos_candidate_bootstrap as bootstrap
from test_macos_candidate_carrier import fixture

ROOT=Path(__file__).resolve().parents[2]

class CandidateFixtureBootstrapTests(unittest.TestCase):
    def exercise(self, fault=None, *, actual_builder=False, depth=8, diagnostics=None, diagnostic_fault=None, target=F.TARGETS[0]):
        with tempfile.TemporaryDirectory() as name:
            top=Path(name);root=top/'checkout';root.mkdir(mode=0o700)
            helper=root/'.candidate-consumer-helper';helper.mkdir(mode=0o700)
            work=top/'work';work.mkdir(mode=0o700)
            host,base,context,base_value=bootstrap.CandidateBootstrapTests().host_fixture(work)
            context['target']=target
            context['started']=time.monotonic_ns()
            target=context['target'];row,*_=fixture(target)
            paths=tuple(dict.fromkeys((*C.HELPER_SOURCE_INPUTS,C.CONSUMER_PATH,C.LEGACY_PATH,C.PARSER_PATH,C.FIXTURE_PATH,C.SELECTION_PATH,
                'desktop/tools/macos_android_helper_package.py','desktop/tools/macos_normal_ui_runner.py',C.STAGER_PATH,
                'desktop/src-tauri/src/macos_app_absence_fixture.rs','desktop/src-tauri/build.rs','desktop/src-tauri/Cargo.toml',
                'desktop/macos-installed-inputs/build-release.json','desktop/macos-installed-inputs/build-release-intel.json')))
            cpaths=(C.STAGER_PATH,*(p for p,cap in C.CANDIDATE_SOURCE_INPUTS))
            bodies={}
            for parent,names in ((helper,paths),(root,cpaths)):
                for leaf in names:
                    path=parent/leaf;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                    data=R.canonical({'schemaVersion':1,'targets':{target:row}}) if leaf==C.SELECTION_PATH else (ROOT/leaf).read_bytes()
                    path.write_bytes(data);path.chmod(0o644);bodies[path]=data
            snapshot,cfg=R.host_snapshot(host,lambda p:(R.identity(p.lstat()),os.listdir(p)),lambda p,limit:(R.identity(p.lstat()),p.read_bytes()))
            binding=dict(schemaVersion=1,source=context['helperSource'],runId='51',runAttempt='2',base=base_value,prefix=str(host),
                basePrefix=str(base.parent.parent),baseExecutable=str(base),**snapshot,retainedUntilHostedTeardown=True)
            (host/'host-binding.json').write_bytes(R.canonical(binding));(host/'host-binding.json').chmod(0o600)
            producer=work/'candidate-producer';producer.mkdir(mode=0o700)
            acquired=dict(schemaVersion=1,scope='candidate-closed-acquisition',nomination=row,helperSource=context['helperSource'],helperTree='e'*40,
                consumerRunId='51',consumerRunAttempt='2',runtimeManifestSha256='a'*64,nativeProducerSignatureVerified=True,
                originalMountDetached=True,originalClosesKnown=True,installerEntered=False,productReady=False)
            for key,leaf,data in (('package','Install.pkg',b'xar!'+b'X'*28),('descriptor','producer.json',b'closed-inert-descriptor'),
                                   ('signature','producer.sig',b'inert-signature'),('inventory','install-inventory.json',b'inert-inventory')):
                acquired[key]=dict(name=leaf,bytes=len(data),sha256=R.sha(data))
                if key!='inventory': (producer/leaf).write_bytes(data);(producer/leaf).chmod(0o444)
            data=b'inert exact app bytes'
            leaf='app/'+'d/'*(depth-1)+'leaf'
            app_rows={leaf:dict(size=len(data),sha256=R.sha(data),executable=False)}
            full_rows=dict(app_rows,**{'runtime/store/'+str(i):dict(size=1,sha256='a'*64,executable=False) for i in range(5000)})
            input_root=work/'input';input_root.mkdir(mode=0o700)
            (input_root/'runtime').mkdir(mode=0o555)
            app_path=input_root/leaf;app_path.parent.mkdir(parents=True,mode=0o700)
            app_path.write_bytes(data);app_path.chmod(0o444)
            for parent in reversed(list(app_path.parents)):
                if parent.is_relative_to(input_root) and parent!=input_root:parent.chmod(0o555)
            inventory=R.canonical(full_rows);(input_root/'install-inventory.json').write_bytes(inventory);(input_root/'install-inventory.json').chmod(0o444)
            input_root.chmod(0o555)
            acquired['inventory']=dict(name='install-inventory.json',bytes=len(inventory),sha256=R.sha(inventory))
            if fault=='acquisition': acquired['originalMountDetached']=False
            for leaf,data in (('candidate-acquisition.json',R.canonical(acquired)),('candidate-acquisition.status',b'0\n')):
                (work/leaf).write_bytes(data);(work/leaf).chmod(0o600)
            env=dict(GITHUB_SHA=context['helperSource'],GITHUB_WORKFLOW_SHA=context['helperSource'],GITHUB_RUN_ID='51',GITHUB_RUN_ATTEMPT='2',
                GITHUB_REF='refs/heads/'+C.BRANCH,GITHUB_EVENT_NAME='push',GITHUB_WORKFLOW_REF=R.REPOSITORY+'/'+C.WORKFLOW+'@refs/heads/'+C.BRANCH)
            operations=[];effects=[];calls=[];load=R.load_module;construct=H.Operation;register=H.Operation.register
            initialize, finish = construct.__init__, construct.finish
            native_error=RuntimeError('inert native original unknown')
            cleanup_error=RuntimeError('inert cleanup error with private text')
            class ProcessError(RuntimeError): pass
            owned_error=ProcessError('owned command exceeded its original deadline')
            owned_error.dispatched=True;owned_error.contained=False;owned_error.cleanup_complete=False
            capture=io.StringIO()
            def operation(value,*args,**kwargs):
                initialize(value,*args,**kwargs);operations.append(value)
            def finished(value):
                value.test_finish_calls=getattr(value,'test_finish_calls',0)+1
                finish(value)
                if fault=='cleanup': raise cleanup_error
                if fault=='terminal': value.app_absence['complete']=False
            def registered(op,*args,**kwargs):
                value=register(op,*args,**kwargs)
                op.test_peak=max(getattr(op,'test_peak',0),sum(e['fd'] is not None for e in op.entries))
                return value
            def owned(argv,**kwargs):
                self.assertNotIn('GITHUB_TOKEN',kwargs['environ']);calls.append(argv)
                if argv[0]=='/usr/bin/git':
                    source_root=Path(argv[argv.index('-C')+1]);is_helper=source_root==helper
                    if 'rev-parse' in argv:
                        source,tree=(context['helperSource'],'e'*40) if is_helper else (row['source'],row['tree'])
                        if fault=='source' and not is_helper: source='f'*40
                        out=(source+'\n'+tree+'\n').encode()
                    else:
                        out=b''
                        for leaf in argv[argv.index('--')+1:]:
                            data=bodies[source_root/leaf];digest=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
                            out+=b'100644 blob '+digest.encode()+b'\t'+leaf.encode()+b'\0'
                    if fault=='last-source' and len([a for a in calls if a[0]=='/usr/bin/git'])==8: raise RuntimeError('inert source original unknown')
                else:
                    effects.append(argv[-1]);out=b''
                    if actual_builder:
                        op=operations[0]
                        if 'build' in argv or 'test' in argv:
                            is_observer=argv[argv.index('--bin')+1]==F.FIXTURE_EXECUTABLE
                            expected_root=helper if is_observer else root
                            self.assertEqual(argv[argv.index('--manifest-path')+1],str(expected_root/'desktop/src-tauri/Cargo.toml'))
                            self.assertEqual(kwargs['cwd'],expected_root/'desktop/src-tauri')
                            self.assertEqual(kwargs['environ']['MRK_MACOS_INSTALL_SOURCE_COMMIT'],row['source'])
                            if is_observer:
                                self.assertEqual(kwargs['environ']['MRK_APP_ABSENCE_FIXTURE_SOURCE_COMMIT'],context['helperSource'])
                            else:
                                self.assertFalse(any(k.startswith('MRK_APP_ABSENCE_FIXTURE_') for k in kwargs['environ']))
                            self.assertEqual(op.checkout,root);self.assertEqual(op.stager.DESKTOP,root/'desktop')

                        if 'build' in argv and '--message-format=json-render-diagnostics' in argv:
                            selected=argv[argv.index('--bin')+1];feature=argv[argv.index('--features')+1]
                            op=operations[0];binary=work/op.target_name/target/'release'/selected
                            binary.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                            binary.write_bytes(b'inert compiler bytes never executed');binary.chmod(0o755)
                            rows=fixture_tests.cargo_rows(expected_root,work/op.target_name,target)
                            for item in rows[:2]:
                                item['features']=['macos-installed-app-absence-fixture',feature] if selected==F.FIXTURE_EXECUTABLE else ['macos-installed-installer',feature]
                            rows[0]['target']['name']=selected;rows[0]['executable']=str(binary);rows[0]['filenames']=[str(binary)]
                            out=fixture_tests.encoded_rows(rows)
                        elif 'test' in argv:
                            out=('running 6 tests\n'+''.join('test '+n+' ... ok\n' for n in F.NATIVE_DATA_TESTS)+
                                'test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.001s\n').encode()
                        elif argv[0]=='/usr/bin/pkgbuild':
                            path=Path(argv[-1]);path.write_bytes(b'inert original archive');path.chmod(0o644)
                        elif argv[0]=='/usr/bin/tar':
                            path=Path(argv[argv.index('-f')+1]);path.write_bytes(b'inert archive');path.chmod(0o644)
                        elif argv[0]=='/usr/bin/xar':
                            path=Path(argv[argv.index('-cf')+1]);path.write_bytes(b'inert compact archive');path.chmod(0o644)
                    if fault=='native' and len(effects)==2: raise native_error
                    if fault=='owned' and len(effects)==2: raise owned_error
                    if (fault in ('nonzero','cleanup') and len(effects)==2
                            or fault in ('cut-app-write','cut-own-attempt','cut-stage-move') and argv[-1]=='app-absence-'+fault+'-build'):
                        compiler_root=root if fault and fault.startswith('cut-') else helper
                        message=dict(reason='compiler-message',package_id='path+'+(compiler_root/'desktop/src-tauri').as_uri()+'#mobile-release-kit-desktop@0.1.2',
                            message=dict(level='error',code=dict(code='E0308'),message='private compiler text',rendered='private rendered text',
                                spans=[dict(is_primary=True,file_name='src/macos_app_absence_fixture.rs',line_start=123,column_start=4)]))
                        return subprocess.CompletedProcess(argv,101,R.canonical(message),b'private error text')
                return subprocess.CompletedProcess(argv,0,out,b'')
            def module(mod,path,body):
                if path.name=='macos_app_absence_fixture.py': return F
                if path.name=='macos_normal_ui_runner.py': return N
                if path.name=='macos_aqua_qualification.py': return SimpleNamespace(load_owner=lambda r:SimpleNamespace(run_owned=owned,ProcessError=ProcessError))
                if path.name=='macos_xcode_host_preparation.py': return SimpleNamespace(DarwinAPI=lambda *a,**k:SimpleNamespace(waitable_sigchld=lambda:None))
                if path.name=='stage_macos_installed.py':
                    is_helper=path.is_relative_to(helper)
                    release_path='desktop/macos-installed-inputs/build-release'+('-intel' if target==F.TARGETS[1] else '')+'.json'
                    release=json.loads(bodies[(helper if is_helper else root)/release_path])
                    def selection(selected_target):
                        if is_helper and fault=='selection-unknown':
                            operations[0].test_selection_error=native_error;raise native_error
                        return SimpleNamespace(target=selected_target,
                            release='wrong-release' if is_helper and fault=='release' else release['release'],
                            package_version='0.1.3' if is_helper and fault=='version' else release['packageVersion'])
                    return SimpleNamespace(DESKTOP=(helper if is_helper else root)/'desktop',source_build_selection=selection,MAX_BYTES=768<<20,
                        BuildSelection=namedtuple('BuildSelection','target package_version release'),build_release_data=lambda body,**k:json.loads(body),
                        CURRENT_PROTOCOL='c'*64 if is_helper and fault=='protocol' else 'b'*64,INSTALLATION_INVENTORY_NAME='install-inventory.json',INVENTORY_BYTES=12<<20,PACKAGE_ID='inert.fixture',
                        observation_inventory_bytes=lambda body,*a,**k:json.loads(body),macho=lambda *a,**k:None,
                        app_absence_original_command=lambda args,**kw:dict(originalPackageSha256=R.sha(args.original_package.read_bytes()),packageInfo=b'inert package info'),
                        app_absence_final_command=lambda args,compact,**kw:dict(packageSha256=R.sha(args.package.read_bytes()),packageSize=args.package.stat().st_size))
                return load(mod,path,body)
            def prepare(op):
                effects.append(('phase',len(op.entries),sum(e['fd'] is not None for e in op.entries)))
                for role in F.roles(op): op.package_call(role,['/inert/native-not-executed',role],timeout=20,limit=65536)
                op.app_absence['complete']=True;op.sha256='a'*64
            def preparation_handoff(prepared):
                # Actual completed builder bytes and actual prepared originals;
                # only the native baseline endpoint is replaced, never its reader.
                encoded=R.canonical(prepared)
                for leaf,data in (('app-absence-preparation.status',b'0\n'),
                                  ('android-helper-prepare-app-absence.json',encoded)):
                    path=work/leaf
                    with path.open('xb') as stream:stream.write(data)
                    path.chmod(0o600)
                prior=operations[0]
                class StopBeforeNativeBaseline(Exception):pass
                stopped=StopBeforeNativeBaseline()
                def state(owner):
                    now=time.monotonic_ns()
                    owner.app_absence=dict(started=now,observed=now,workSeconds=660,hardSeconds=720,
                        pendingRoot=None,pendingCut=None,mount=None,roots=[],outputs=[],future={},complete=False,
                        binding=dict(prior.app_absence['binding']))
                    owner.app_absence_module=F;owner.app_absence_api=H
                def baseline(owner,*args):
                    # Real current phase SOURCE/host/acquisition/producer roster,
                    # including optional host executable. Compile-only sources
                    # must not occupy the later original96 book.
                    self.assertIsNone(owner.app_absence)
                    self.assertEqual(sum(e['fd'] is not None for e in owner.entries),62)
                    self.assertEqual(owner.app_absence_live_limit(),96)
                    self.assertFalse(hasattr(owner,'candidate_fixture_source_original'))
                    state(owner)
                    program=F.preparation_input(owner)
                    self.assertEqual(owner.app_absence['preparation'],prepared['appAbsencePreparation'])
                    self.assertEqual(F.original_hash(owner,program),prepared['appAbsencePreparation']['fixturePackageSha256'])
                    live=sum(e['fd'] is not None for e in owner.entries)
                    self.assertEqual(live,76) # two receipt + four (directory, executable, package)
                    # Static next allocations, NOT a native image execution:
                    # carrier directory+nine copies, image, existing owner8.
                    self.assertEqual(live+1+len(F.carrier_names(owner))+1+8,95)
                    self.assertLessEqual(live+1+len(F.carrier_names(owner))+1+8,owner.app_absence_live_limit())
                    prior.test_later_phase_live=live
                    raise stopped
                fresh=dict(context,started=time.monotonic_ns())
                with mock.patch.object(F,'candidate_baseline',baseline):
                    try:H.candidate_fixture_phase(C,fresh,'restore-baseline',fresh['started'],(identity,bp,body))
                    except StopBeforeNativeBaseline as error:self.assertIs(error,stopped)
                    else:self.fail('inert baseline boundary did not stop')
                self.assertTrue(all(e['closed'] for e in operations[-1].entries))
                # Preserve immutable successful receipt/files. Changed DATA is
                # supplied at the existing small-input port only; the actual
                # receipt/binding reducers and retained prepared readers run.
                for change in ('cut-helper','cut-product-helper','observer-product-helper','observer-stale','observer-swapped'):
                    mutated=json.loads(encoded)
                    data=mutated['appAbsencePreparation']
                    if change=='cut-helper':data['restoreCuts'][F.CUTS[0]]['fixtureSource']=context['helperSource']
                    elif change=='cut-product-helper':data['restoreCuts'][F.CUTS[0]]['productSource']=context['helperSource']
                    elif change=='observer-product-helper':data['productSource']=context['helperSource']
                    elif change=='observer-stale':data['fixtureSource']='f'*40
                    else:data['fixtureSource'],data['productSource']=data['productSource'],data['fixtureSource']
                    owner=construct(None,root,work,'candidate-baseline',prior.environment,prior.stager,target=target)
                    owner.image_source=prior.image_source;owner.candidate_restore_context=dict(prior.candidate_restore_context)
                    state(owner)
                    fd=os.open(work,H.READ_FLAGS|os.O_DIRECTORY)
                    owner.work_entry=owner.register(fd,'work','directory')
                    owner.work_entry['identity']=H.directory_identity(os.fstat(fd))
                    def receipt(owner,parent,name,limit=16384,modes=(0o444,0o600)):
                        self.assertIs(parent,owner.work_entry)
                        self.assertIn(name,('app-absence-preparation.status','android-helper-prepare-app-absence.json'))
                        return b'0\n' if name.endswith('.status') else R.canonical(mutated)
                    try:
                        with mock.patch.object(F,'small',receipt),self.assertRaisesRegex(ValueError,
                            'restore-chain-cut-binding' if change.startswith('cut-') else 'app-absence-preparation-binding'):
                            F.preparation_input(owner)
                    finally:
                        for entry in reversed(owner.entries):owner.close(entry)
                    self.assertFalse(owner.app_absence['complete']);self.assertEqual(owner.calls,[])
                    self.assertTrue(all(e['closed'] for e in owner.entries));self.assertEqual(owner.errors,[])
                    self.assertEqual(R.canonical(prepared),encoded)
                    self.assertEqual((work/'android-helper-prepare-app-absence.json').read_bytes(),encoded)
                prior.test_preparation_refusals=5
            failure=result=None
            try:
                with ExitStack() as stack:
                    for obj,key,value in ((C,'ROOT',helper),(C,'HELPER_ROOT',helper),(C,'CANDIDATE_ROOT',root),
                        (C,'context_data',lambda *a:{k:v for k,v in context.items() if k!='started'}),(R,'load_module',module),
                        (construct,'__init__',operation),(construct,'register',registered),(construct,'finish',finished),(F,'prepare',F.prepare if actual_builder else prepare),
                        (os,'fstatvfs',lambda fd:SimpleNamespace(f_bavail=100*1024*1024,f_frsize=4096)),
                        (sys,'executable',str(host/'bin/python3')),(sys,'prefix',str(host)),(sys,'base_prefix',str(base.parent.parent)),(sys,'_base_executable',str(base))):
                        stack.enter_context(mock.patch.object(obj,key,value))
                    stack.enter_context(redirect_stderr(capture))
                    if diagnostic_fault=='write':
                        stack.enter_context(mock.patch.object(capture,'write',side_effect=OSError('private write failure')))
                    elif diagnostic_fault in ('capture','location'):
                        stack.enter_context(mock.patch.object(H,'failure_exception' if diagnostic_fault=='capture' else 'failure_stager_line',
                            side_effect=RuntimeError('private diagnostic parser fault')))
                    elif diagnostic_fault=='compiler':
                        stack.enter_context(mock.patch.object(H,'compiler_diagnostic',side_effect=RuntimeError('private compiler parser fault')))
                    stack.enter_context(mock.patch.dict(os.environ,env,clear=True))
                    bp=helper/'desktop/tools/macos_android_helper_package.py';identity,body=R.host_read(bp,1<<20)
                    result=H.candidate_fixture_phase(C,context,'prepare-restore',context['started'],(identity,bp,body))
                    if actual_builder:preparation_handoff(result)
            except BaseException as error: failure=error
            finally:
                if diagnostics is not None:
                    diagnostics.update(stderr=capture.getvalue(), native_error=native_error, owned_error=owned_error,
                        cleanup_error=cleanup_error, closes_before_test_cleanup=[all(e['closed'] for e in op.entries) for op in operations])
                for op in operations:
                    for e in reversed(op.entries):op.close(e)
            return result,failure,operations,effects,calls

    def test_real_bootstrap_sources_host_and_phase_originals(self):
        result,error,ops,effects,calls=self.exercise()
        self.assertIsNone(error,repr(error));self.assertTrue(result['passed'])
        self.assertEqual(result['candidateSource']['originalQueryCount'],8)
        self.assertEqual(len(ops[0].calls),25);self.assertLessEqual(ops[0].test_peak,96)
        self.assertTrue(all(e['closed'] for e in ops[0].entries))
        self.assertEqual(ops[0].credential_calls,[])
        print('INERT fixture bootstrap held/peak/lifetime',effects[0],ops[0].test_peak,len(ops[0].entries))

    def test_full_four_builders_use_same_input_original_and_fit_maximum_depth_real_ledger(self):
        for target in F.TARGETS:
            for depth in (8,15):
                with self.subTest(target=target,depth=depth):
                    self.check_four_builders(depth,target)

    def check_four_builders(self, depth, target):
        result,error,ops,effects,calls=self.exercise(actual_builder=True,depth=depth,target=target)
        self.assertIsNone(error,repr(error));op=ops[0]
        self.assertTrue(result['passed']);self.assertEqual(len(op.calls),25)
        self.assertLessEqual(op.test_peak,160)
        self.assertEqual(op.app_absence_live_limit(),160)
        self.assertEqual(len([e for e in op.entries if e.get('role')=='app-absence-retained-install-inventory.json']),1)
        self.assertEqual(len([e for e in op.entries if e.get('role')=='source-app-absence-data-tests']),0)
        preparation=result['appAbsencePreparation']
        self.assertEqual(set(preparation['restoreCuts']),set(F.CUTS))
        self.assertEqual(preparation['fixtureSource'],op.environment['GITHUB_SHA'])
        self.assertEqual(preparation['productSource'],op.image_source)
        self.assertNotEqual(preparation['fixtureSource'],preparation['productSource'])
        self.assertTrue(all(cut['fixtureSource']==cut['productSource']==op.image_source
            for cut in preparation['restoreCuts'].values()))
        self.assertEqual(result['candidateSource']['originalQueryCount'],8)
        self.assertEqual(op.test_later_phase_live,76)
        self.assertEqual(op.test_preparation_refusals,5)
        self.assertTrue(all(e['closed'] for owner in ops for e in owner.entries))
        print('INERT four-builder depth/peak/lifetime',depth,op.test_peak,len(op.entries),
              'actual later bootstrap/prepared',62,op.test_later_phase_live,'static image+owner quote',95)

    def test_source_and_handoff_refusal_before_phase_and_unknown_never_complete(self):
        for fault in ('source','acquisition','native','last-source','release','version','protocol','selection-unknown'):
            with self.subTest(fault=fault):
                result,error,ops,effects,calls=self.exercise(fault)
                self.assertIsNone(result);self.assertIsNotNone(error)
                if fault in ('source','acquisition','release','version','protocol','selection-unknown'):self.assertEqual(effects,[])
                if fault in ('native','last-source','release','version','protocol','selection-unknown'):self.assertFalse(ops[0].receipt['targetRetired'])
                if fault in ('release','version','protocol','selection-unknown'):
                    self.assertEqual(ops[0].stager_io_pending,'app-absence-source-selection')
                if fault=='selection-unknown':self.assertIs(error,ops[0].test_selection_error)
        # SAME real Operation class and bootstrap, only native execution is inert.
        # Read emitted facts before fixture-owned cleanup of unresolved originals.
        for fault in (None,'nonzero','native','owned','cleanup','terminal'):
            with self.subTest(diagnostic=fault):
                facts={};result,error,ops,effects,calls=self.exercise(fault,diagnostics=facts)
                op=ops[0];self.assertIs(type(op),H.Operation);self.assertEqual(op.test_finish_calls,1)
                if fault is None:
                    self.assertIsNone(error);self.assertTrue(result['passed']);self.assertEqual(facts['stderr'],'');continue
                self.assertIsNone(result);self.assertIsNotNone(error)
                lines=facts['stderr'].splitlines();self.assertEqual(len(lines),1)
                self.assertTrue(lines[0].isascii());self.assertLessEqual(len(lines[0])+1,4096)
                self.assertNotIn('private',lines[0]);self.assertNotIn('inert',lines[0])
                data=json.loads(lines[0]);native=data['lastRecordedNative']
                self.assertEqual(data['phase'],F.PREPARE);self.assertEqual(data['mainStage'],'operation-execute')
                self.assertFalse(data['productReady']);self.assertEqual(data['counts']['credential'],0)
                self.assertTrue(data['originalFailure']['recorded'])
                if fault=='terminal':
                    self.assertEqual(data['terminal']['reason'],'candidate-fixture-terminal')
                    self.assertEqual(native['role'],'app-absence-cut-stage-move-xar')
                    self.assertTrue(data['cleanup']['originalClosesKnown']);continue
                self.assertEqual(len(op.calls),1);self.assertEqual(native['role'],'app-absence-build')
                if fault in ('nonzero','cleanup'):
                    self.assertTrue(native['returned']);self.assertTrue(native['capturesSettled']);self.assertEqual(native['returncode'],101)
                    self.assertEqual(data['originalFailure']['reason'],'original-nonzero-app-absence-build')
                    self.assertTrue(data['cleanup']['originalClosesKnown']);self.assertEqual(facts['closes_before_test_cleanup'],[True])
                    self.assertEqual(data['compiler']['rows'],[dict(kind='rust',code='E0308',source='desktop/src-tauri/src/macos_app_absence_fixture.rs',line=123,column=4)])
                    if fault=='cleanup':self.assertIs(error,facts['cleanup_error']);self.assertEqual(data['terminal']['type'],'runtime-error')
                    else:self.assertIs(type(error),H.Refused)
                else:
                    self.assertFalse(native['returned']);self.assertFalse(native['capturesSettled']);self.assertIsNone(native['returncode'])
                    self.assertFalse(data['cleanup']['targetRetired'])
                    # Existing finish positively closes files but cannot retire an unknown native call.
                    self.assertTrue(data['cleanup']['originalClosesKnown']);self.assertEqual(facts['closes_before_test_cleanup'],[True])
                    self.assertIs(error,facts['owned_error' if fault=='owned' else 'native_error'])
                    if fault=='owned':
                        self.assertEqual(native['originalFailure']['classification'],'deadline')
                        self.assertEqual(native['originalFailure']['ownerErrorType'],'ProcessError')
                        self.assertFalse(native['contained']);self.assertFalse(native['cleanup_complete'])
        for fault in ('write','capture','location'):
            with self.subTest(diagnosticFault=fault):
                facts={};result,error,ops,effects,calls=self.exercise('native',diagnostics=facts,diagnostic_fault=fault)
                self.assertIs(error,facts['native_error']);self.assertIsNone(result)
                self.assertEqual(ops[0].test_finish_calls,1);self.assertEqual(len(ops[0].calls),1)
                self.assertFalse(ops[0].receipt['targetRetired'])
                if fault!='location':self.assertEqual(facts['stderr'],'')
        for cut,index in (('app-write',8),('own-attempt',14),('stage-move',20)):
            with self.subTest(compilerCut=cut):
                facts={};result,error,ops,effects,calls=self.exercise('cut-'+cut,diagnostics=facts)
                self.assertIs(type(error),H.Refused);self.assertIsNone(result)
                data=json.loads(facts['stderr']);native=data['lastRecordedNative']
                self.assertEqual(len(ops[0].calls),index);self.assertEqual(native['role'],'app-absence-cut-'+cut+'-build')
                self.assertEqual(native['returncode'],101);self.assertTrue(native['capturesSettled'])
                self.assertEqual(data['compiler']['rows'][0]['code'],'E0308')
                self.assertEqual(data['compiler']['rows'][0]['source'],'desktop/src-tauri/src/macos_app_absence_fixture.rs')
                self.assertNotIn('private',facts['stderr'])
        facts={};result,error,ops,effects,calls=self.exercise('nonzero',diagnostics=facts,diagnostic_fault='compiler')
        self.assertIs(type(error),H.Refused);self.assertEqual(str(error),'original-nonzero-app-absence-build')
        self.assertIsNone(json.loads(facts['stderr'])['compiler']);self.assertEqual(ops[0].test_finish_calls,1)
        # Only current closed roles/phases survive; similar private names do not.
        op.calls[-1]['role']='app-absence-cut-private-value'
        value=H.failure_diagnostic(error,phase='candidate-baseline',operation=op)
        self.assertEqual(value['phase'],'candidate-baseline')
        self.assertEqual(value['lastRecordedNative']['role'],'unclassified')

class CandidateChainHandoffTests(unittest.TestCase):
    def test_actual_native_status_original_not_wrapper_zero_controls_chain(self):
        result,error,_calls,_effects,_books,files=bootstrap.CandidateBootstrapTests().exercise(F.TARGETS[0],purpose='restore-install')
        self.assertIsNone(error,repr(error))
        body=next(data for path,data in files.items() if path.name==C.BASELINE_RECEIPT)
        baseline=R.decode(body);nomination=baseline['acquisition']['nomination']
        self.assertNotEqual(baseline['binding']['fixtureSource'],baseline['binding']['productSource'])
        for key,wrong in (('fixtureSource',nomination['source']),('productSource',baseline['helperSource'])):
            changed=R.decode(R.canonical(baseline));changed['binding'][key]=wrong
            with self.assertRaisesRegex(ValueError,'candidate-baseline-source-product'):
                F.candidate_baseline_receipt_data(changed,nomination,baseline['helperSource'],baseline['helperTree'],'51','2')
        for fault in (None,'caller','native-body','native-original','prior-source'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as name:
                work=Path(name);work.chmod(0o700)
                env=dict(GITHUB_SHA=baseline['helperSource'],GITHUB_WORKFLOW_SHA=baseline['helperSource'],
                    GITHUB_RUN_ID='51',GITHUB_RUN_ATTEMPT='2',GITHUB_WORKFLOW_REF='inert')
                op=H.Operation(None,work,work,F.RESTORE,env,None);op.open()
                now=time.monotonic_ns();op.app_absence_module=F;op.app_absence_api=H
                op.app_absence=dict(started=now,observed=now,workSeconds=660,hardSeconds=720,pendingRoot=None,pendingCut=None,
                    mount=None,roots=[],outputs=[],complete=False)
                op.candidate_restore_context=dict(nomination=nomination,helperSource=baseline['helperSource'],helperTree=baseline['helperTree'],runId='51',runAttempt='2')
                parent=F.mkdir(op,op.work_entry,'resume-carrier')
                native=F.output(op,parent,'installer-output.status',b'1\n' if fault=='native-body' else b'0\n',mode=0o600)
                installed=R.decode(R.canonical(result));installed['installerStatusOriginal']['identity']=list(C.resume_identity(native))
                if fault=='native-original':installed['installerStatusOriginal']['identity'][1]+=1
                if fault=='prior-source':installed['producerSource']='f'*40
                prior=F.output(op,parent,C.BASELINE_RECEIPT,body,mode=0o600)
                status=F.output(op,parent,C.BASELINE_STATUS,b'1\n' if fault=='caller' else b'0\n',mode=0o600)
                record=F.output(op,op.work_entry,'candidate-install.json',R.canonical(installed),mode=0o600)
                exit_status=F.output(op,op.work_entry,'candidate-install.status',b'0\n',mode=0o600)
                entered=[]
                def prepare(owner):owner.app_absence['preparationSha256']=baseline['preparationReceiptSha256']
                def chain(owner,previous,raw,*,initial_status):
                    entered.append(previous)
                    self.assertEqual(raw,body);self.assertEqual(initial_status,work/'resume-carrier/installer-output.status')
                    self.assertEqual(initial_status.read_bytes(),b'0\n')
                    self.assertNotIn('originalCalls',previous)
                    self.assertEqual(previous['initial'],installed['initial'])
                try:
                    with mock.patch.object(F,'preparation_input',prepare),mock.patch.object(F,'restore_from_initial',chain):
                        if fault:
                            with self.assertRaises(ValueError):C.candidate_restore(op,prior,status,record,exit_status,native)
                            self.assertEqual(entered,[])
                        else:
                            C.candidate_restore(op,prior,status,record,exit_status,native);self.assertEqual(len(entered),1)
                            self.assertEqual(op.read(record),R.canonical(installed))
                finally:
                    for e in reversed(op.entries):op.close(e)


class CandidateTransportRetirementTests(unittest.TestCase):
    def test_real_image_copy_last_use_closes_before_mount_and_unknown_blocks(self):
        for fault in (False,True):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as name:
                work=Path(name);work.chmod(0o700)
                env=dict(GITHUB_SHA='d'*40,GITHUB_WORKFLOW_SHA='d'*40,GITHUB_RUN_ID='51',GITHUB_RUN_ATTEMPT='2',
                    GITHUB_WORKFLOW_REF='inert',MRK_MACOS_PACKAGE_ROLE='ordinary-image')
                stage=SimpleNamespace()
                op=H.Operation(None,work,work,'candidate-baseline',env,stage)
                now=time.monotonic_ns();op.app_absence_module=F;op.app_absence_api=H;op.candidate_restore_context={}
                op.app_absence=dict(started=now,observed=now,workSeconds=660,hardSeconds=720,pendingRoot=None,pendingCut=None,
                    mount=None,roots=[],outputs=[],future=dict(F.OUTPUTS),complete=False,
                    binding=dict(fixtureSource='a'*40,productSource='a'*40,runId='51',runAttempt='2',target=op.target))
                op.package_started=op.package_observed=now;op.package_endpoint=now+660_000_000_000
                op.open();producer=F.mkdir(op,op.work_entry,'candidate-producer')
                op.candidate_producer_originals={}
                for leaf in ('Install.pkg','producer.json','producer.sig'):
                    e=F.output(op,producer,leaf,(b'closed inert '+leaf.encode()).ljust(64,b'X'))
                    op.candidate_producer_originals[leaf]=e
                for i in range(57):F.output(op,op.work_entry,'retained-'+str(i),b'inert source original')
                self.assertEqual(len(op.entries),63)
                events=[];peak=[63];register=op.register;close=op.close
                def registered(*args,**kwargs):
                    e=register(*args,**kwargs);peak[0]=max(peak[0],sum(e['fd'] is not None for e in op.entries));return e
                def input_phase(owner):
                    data=dict(owner.app_absence['binding'],fixtureExecutableSha256='1'*64,inventorySha256='2'*64,
                        runtimeManifestSha256='3'*64,protocolSha256='4'*64,restoreCuts={})
                    packages={}
                    for cut in (None,*F.CUTS):
                        prefix='app-absence' if cut is None else 'app-absence-cut-'+cut
                        root=F.mkdir(owner,owner.work_entry,prefix+'-prepared')
                        F.output(owner,root,F.FIXTURE_EXECUTABLE if cut is None else 'mrk-macos-install',b'inert binary',mode=0o555)
                        package=F.output(owner,root,'fixture.pkg',(b'inert package '+prefix.encode()).ljust(64,b'X'))
                        packages[cut]=package
                        row=dict(fixturePackageBytes=package['identity'][6],fixturePackageSha256=F.original_hash(owner,package))
                        if cut is None:data.update(row)
                        else:data['restoreCuts'][cut]=row
                    F.output(owner,owner.work_entry,'app-absence-preparation.status',b'0\n',mode=0o600)
                    F.output(owner,owner.work_entry,'android-helper-prepare-app-absence.json',b'inert already-admitted receipt',mode=0o600)
                    owner.app_absence.update(preparation=data,cutPackages={cut:packages[cut] for cut in F.CUTS})
                    owner.app_absence['future']['cutCopies']=sum(e['identity'][6] for c,e in packages.items() if c)
                    return packages[None]
                def native(argv,**kwargs):
                    events.append(argv[1])
                    if argv[1]=='create':
                        (work/'app-absence-fixture.dmg').write_bytes(b'inert image original');(work/'app-absence-fixture.dmg').chmod(0o644)
                    return subprocess.CompletedProcess(argv,0,b'',b'')
                op.owner=SimpleNamespace(run_owned=native)
                def attach(owner,role,rows):
                    # Explicit inert mount endpoint; no native/custody claim.
                    self.assertTrue(owner.app_absence['candidateCopiedOriginalsRetired'])
                    self.assertEqual(sum(e['fd'] is not None for e in owner.entries),67)
                    events.append('attach-boundary')
                    parent=F.mkdir(owner,owner.work_entry,'inert-mounted')
                    extra=F.mkdir(owner,parent,'placeholder')
                    for i in range(9):F.output(owner,parent,'leaf'+str(i),b'inert native input')
                    self.assertEqual(sum(e['fd'] is not None for e in owner.entries)+8,86)
                    F.post(owner)
                def closing(e):
                    close(e)
                    if fault and e.get('name')=='fixture.pkg':e['closed']=False;op.errors.append({'stage':'close','type':'OSError'})
                try:
                    with mock.patch.object(F,'preparation_input',input_phase),mock.patch.object(F,'attach',attach), \
                         mock.patch.object(op,'register',registered),mock.patch.object(op,'close',closing), \
                         mock.patch.object(os,'fstatvfs',return_value=SimpleNamespace(f_bavail=100*1024*1024,f_frsize=4096)):
                        if fault:
                            with self.assertRaisesRegex(ValueError,'candidate-carrier-close-unknown'):F.image_prepare(op,producer)
                            self.assertNotIn('attach-boundary',events)
                        else:F.image_prepare(op,producer)
                    self.assertLessEqual(peak[0],96)
                    self.assertTrue(all((work/'app-absence-carrier'/n).is_file() for n in F.carrier_names(op)))
                    self.assertTrue(all(e['fd'] is not None for e in op.candidate_producer_originals.values()))
                finally:
                    for e in reversed(op.entries):close(e)

if __name__=='__main__':unittest.main()
