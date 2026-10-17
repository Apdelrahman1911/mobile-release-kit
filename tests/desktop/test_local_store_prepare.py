"""Real saved engine/source/bundle/journal; native/Store transport is inert."""
from contextlib import ExitStack
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from mobile_release import local_store_prepare as S,_desktop_store_prepare_protocol as W
from mobile_release._desktop_store_prepare_engine import _Engine
from mobile_release._desktop_saved_command_engine import run_engine,_RETAINED
from mobile_release.local_release_journal import LocalReleaseJournal,canonical
from mobile_release import _command_process as process,build_inputs as B
from mobile_release._desktop_store_preflight_control import PREFIX,SUFFIX
from unit.test_desktop_store_preflight import account,request,encode
import unit.test_desktop_store_preflight as access_fixture
from unit.helpers import android_config,write_project
from mobile_release.tooling import REQUIRED_TOOLING_FILES
from test_local_release_history import ENROLLMENT,KEY
OP='33333333-3333-4333-8333-333333333333'

from unit.store_lane_model import StoreLaneModel,identity,write_exclusive
from mobile_release.owned_process import PRIVATE_OUTPUT_LIMIT
from mobile_release import _store_lane_files as lane_files
command=process
class LocalLaneModel(StoreLaneModel):
    def __call__(self, argv, *, cwd, environ, capture, timeout, cancellation, _evidence, **unused):
        assert type(_evidence) is command.CommandCallEvidence and _evidence._lane_reservation is not None
        assert 1 <= timeout <= 900 and capture is False
        assert _evidence._expected[5] == timeout and _evidence._desktop_readback_capped
        record = _evidence._lane_reservation[0]
        self.records.append(record)
        self.calls.append((tuple(argv), cwd, dict(environ), cancellation))
        _evidence._attempt(cancellation, timeout=timeout, ordinary=True)
        engine = command._Outer(cancellation, False, timeout, None, None,
                                suppress_cancel=False, evidence=_evidence)
        self.engines.append(engine)
        _evidence._bind(engine); engine.evidence = _evidence
        engine.frozen = command._freeze_command(argv, environ=environ, cwd=cwd, capture=capture,
            output_limit=PRIVATE_OUTPUT_LIMIT, nonce=engine.nonce)
        _evidence._match(engine)
        document, code = self.producer(argv, environ)
        # Deliberately modeled fields; no syscall, native receipt or child exists.
        engine.handlers_complete, engine.local_cleanup_complete = True, self.confirmed
        engine.create_route.attempted = engine.run_route.attempted = True
        engine.create_route.retired = engine.run_route.retired = True
        engine.wait = command.native.WaitReceipt(1001, "exit", command.HELPER_OK, 0)
        engine.child = SimpleNamespace(receipt=engine.wait)
        engine.sealed, engine.wire = True, SimpleNamespace(eof=True, poisoned=False)
        engine.readers, engine.output_eof = [object(), object()], [True, True]
        engine.terminal = {"producer": True, "no_target": None, "stdout": 0, "stderr": 0,
                           "result": True, "wait": {"kind": "exit", "code": code}}
        engine.publish()
        files, receipt = record._files_owner(), None
        if document is not None:
            data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            receipt = {**write_exclusive(Path(record._output), data), "size": len(data),
                       "sha256": hashlib.sha256(data).hexdigest()}
        if self.terminal:
            part = files.root_path / "terminal.part"
            number = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                value = {"version": 1, "nonce": record._nonce.hex(), "lane": record._lane,
                    "mode": files.mode, "output": record._output, "clock": files.timing.clock,
                    "run_deadline_ns": files.timing.run, "hard_deadline_ns": files.timing.hard,
                    "outcome": "success" if code == 0 else "failed", "launches_closed": True,
                    "adapter_settled": True, "nested_settled": True,
                    "terminal_identity": identity(os.fstat(number)), "receipt": receipt,
                    "inventory": []}
                data = (json.dumps(value, separators=(",", ":")) + "\n").encode("utf-8")
                view = memoryview(data)
                while view:
                    count = os.write(number, view)
                    if type(count) is not int or not 0 < count <= len(view):
                        raise OSError("synthetic terminal write made no progress")
                    view = view[count:]
                os.fsync(number)
            finally:
                os.close(number)
            os.link(part, part.with_name("terminal.json"))
        if self.after is not None:
            self.after(record)
        return subprocess.CompletedProcess(argv, code)


class LocalStorePrepareTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(),0)
        self.tmp=tempfile.TemporaryDirectory(dir=Path.home());self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'project';self.runtime=self.base/'runtime';self.home=self.base/'account'
        self.home.mkdir(mode=0o700)
        platform=getattr(self,'fixture_platform','android')
        config=(access_fixture.ios_config() if platform=='ios' else android_config());config['source']['localStoreEnabled']=True
        write_project(self.root,config,platform=platform)
        for name in ('ruby','bundle'):
            p=self.runtime/'store/bin'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'not executable payload');p.chmod(0o755)
        for name in REQUIRED_TOOLING_FILES:
            p=self.runtime/'store/tooling'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'inert source')
        for name,body in (('.git/config',b'[core]\nrepositoryformatversion=0\nbare=false\n'),('.git/HEAD',b'ref: refs/heads/main\n'),
                ('.git/refs/heads/main',b'a'*40+b'\n'),('.git/index',b'inert not executed')):
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);p.write_bytes(body);p.chmod(0o600)
        for name in ('.git/objects/info','.git/info'):(self.root/name).mkdir(parents=True,mode=0o700)
        self.rows=[]
        for name in ('release/mobile-release.json','release/version.properties'):
            body=(self.root/name).read_bytes();self.rows.append((name.encode(),hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest().encode()))
        raw=request(self.root,self.runtime);c=raw['context'];c.update(operation='local-store-prepare',candidateOperationId=OP,
            candidateSha256='b'*64,confirmation='candidate:%s:1.2.3:42'%platform,platform=platform)
        self.value=raw;raw['protocol']=W.PROTOCOL
        if platform=='ios':manifest=self.ios_bundle(config,c)
        else:
            self.bundle=self.root/'.mobile-release/desktop-android-build'/OP.replace('-','')/'artifacts'
            self.bundle.mkdir(parents=True,mode=0o700)
            p=self.bundle
            while p!=self.root:p.chmod(0o700);p=p.parent
            manifest=dict(schemaVersion=1,scope='local-android-candidate-inputs',operationId=OP,enrollment=ENROLLMENT,
                sourceCommit='a'*40,sourceTree='b'*40,savedConfig=c['savedConfig'],savedVersion=c['savedVersion'],
                applicationId=config['android']['applicationId'],signerSha256=config['android']['uploadCertificateSha256'].replace(':','').lower(),files=[])
            for name,body in [('app-release.aab',b'not an AAB'),('store-metadata.zip',b'not ZIP'),('validation-report.json',b'{}')]:
                p=self.bundle/name;p.write_bytes(body);p.chmod(0o600)
                manifest['files'].append(dict(fileName=name,bytes=len(body),sha256=hashlib.sha256(body).hexdigest()))
        m=canonical(manifest)+b'\n';p=self.bundle/'candidate-inputs.json';p.write_bytes(m);p.chmod(0o600)
        c['candidateSha256']=hashlib.sha256(m).hexdigest();self.manifest=manifest
        j=LocalReleaseJournal(str(self.home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open()
        v=self.root.stat();j._append(expected_head=j.head(),operation_id=None,phase='genesis',payload={'rootIdentity':dict(device=v.st_dev,inode=v.st_ino,mode=v.st_mode&0o7777,uid=v.st_uid,gid=v.st_gid)})
        j._append(expected_head=j.head(),operation_id=OP,phase='inputs-pending',payload=dict(configurationSha256=c['savedConfig']['sha256'],versionSha256=c['savedVersion']['sha256'],sourceCommit='a'*40,sourceTree='b'*40))
        j._append(expected_head=j.head(),operation_id=OP,phase='inputs-ready',payload=dict(candidateSha256=c['candidateSha256']));j.close()
    def current_phase(self):
        j=LocalReleaseJournal(str(self.home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing()
        try:return j._rows[-1][0]['phase']
        finally:j.close()
    def run_original(self,*,fault=None,_execute=False,_reconcile=False):
        # One existing real Engine fixture, two explicit closed local variants.
        # Only native/provider boundaries are inert; no ordinary lifetime facts
        # or call counts are changed to simulate the new operation.
        if _reconcile:
            from mobile_release import local_store_execute as S,_desktop_store_reconcile_protocol as W
            from mobile_release._desktop_store_reconcile_engine import _Engine
            from mobile_release.local_store_reconcile import LocalStoreReconcileRun
            owner_type=LocalStoreReconcileRun
        elif _execute:
            from mobile_release import local_store_execute as S,_desktop_store_execute_protocol as W
            from mobile_release._desktop_store_execute_engine import _Engine
            owner_type=S.LocalStoreExecuteRun
        else:
            from mobile_release import local_store_prepare as S,_desktop_store_prepare_protocol as W
            from mobile_release._desktop_store_prepare_engine import _Engine
            owner_type=S.LocalStorePrepareRun
        readiness=_reconcile and W.readiness(self.value["context"])
        settlement=_reconcile and W.settling(self.value["context"])
        pending,settled=("history-head","external-ready" if readiness else "recovery-settled" if settlement else None) if _reconcile else W.PHASES[2:]
        later=self.value['context'].get('stage') is not None or readiness
        pending_row='promotion-pending' if later and not _execute else pending
        initial_phase=self.current_phase() if _reconcile or later else 'prepared' if _execute else 'inputs-ready'
        final_phase='external-ready' if readiness else 'target-reconciled' if settlement else 'settled-success' if _execute else 'prepared'
        parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC);fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
        loan=os.dup(parent);os.set_inheritable(loan,True)
        value=copy.deepcopy(self.value);now=time.monotonic_ns();value['native'].update(home=str(self.home),leaseFd=loan,
            nonce='e'*32,clock=dict(workEndNs=str(now+1200_000_000_000),hardEndNs=str(now+1210_000_000_000)),
            authorizationId=getattr(self,'readiness_authorization','66666666-6666-4666-8666-666666666666') if _reconcile else '55555555-5555-4555-8555-555555555555' if _execute else '44444444-4444-4444-8444-444444444444',tooling=dict(version='0.3.0',commit='c'*40))
        if _reconcile and fault=='same-authorization':value['native']['authorizationId']='55555555-5555-4555-8555-555555555555'
        if fault=='saved':value['native']['credentialConfig']={'bytes':2,'sha256':hashlib.sha256(b'{}').hexdigest()}
        old=[os.dup(n) for n in (0,1,2)];ir,iw=os.pipe();orr,ow=os.pipe();er,ew=os.pipe()
        os.dup2(ir,0);os.dup2(ow,1);os.dup2(ew,2)
        for fd in(ir,ow,ew):os.close(fd)
        os.write(iw,encode(value));oldcwd=Path.cwd();os.chdir(self.runtime)
        e=_Engine(time.monotonic());events=[];calls=[];high=[0];lost_target=[None];original_event=_Engine.local_event
        apple=value['context']['platform']=='ios'
        fixture=json.loads((Path(access_fixture.__file__).resolve().parents[1]/('fixtures/local-intent-ios-candidate-valid.json' if apple else 'fixtures/local-intent-candidate-valid.json')).read_bytes())['storePrecondition']
        if later:fixture=copy.deepcopy(self.stage_precondition)
        fixture['appIdentity']=self.manifest['bundleId' if apple else 'applicationId']
        if fault=='snapshot-platform':fixture['platform']='android'
        if fault=='snapshot-missing':fixture=None
        model=LocalLaneModel(self.execution_receipt if _execute or _reconcile else lambda argv,env:self.stage_snapshot(argv,env,fixture) if later else (fixture,0),terminal=fault!='nested-terminal')
        self.addCleanup(model.close)
        def peak():high[0]=max(high[0],len(os.listdir('/dev/fd' if sys.platform=='darwin' else '/proc/self/fd')))
        def parent_reply(engine,kind,payload):
            peak();original_event(engine,kind,payload);events.append(kind)
            self.assertEqual(engine.service.journals[-1]._rows[-1][0]['phase'] if engine.service.journals and not engine.service.journals[-1].closed else self.current_phase(),final_phase if kind==settled else initial_phase if _reconcile else pending_row if kind==pending else initial_phase)
            reply=dict(protocol=W.PROTOCOL,operationId=engine.request.operation_id,ownerGeneration=engine.request.owner_generation,
                nonce=engine.request.native['nonce'],requestSha256=engine.request.digest,kind='key-material' if kind=='lease-ready' else 'checkpoint-settled',
                step=engine.input.reply_step,payload=ENROLLMENT if kind=='lease-ready' else {})
            if fault==kind:reply['nonce']='f'*32
            if (_execute or _reconcile) and kind==pending and fault=='cancel-after-pending':engine.input.stop('cancelled')
            data=encode(reply)
            if kind=='lease-ready':data+=W.KEY_PREFIX+KEY+W.KEY_SUFFIX
            if kind==pending:
                if apple:
                    parts=access_fixture.apple_material()
                    roles=('asc-p8','asc-key-id','asc-issuer-id')
                    if later:
                        parts+=(b'Ada',b'Example',b'ada@example.test',b'+12025550123',__import__('base64').b64encode(b'k'*32),b'v1')
                        roles+=('contact-first-name','contact-last-name','contact-email','contact-phone','commitment-key-base64','commitment-version')
                        if value['context']['supplementalAssignments']['reviewDemo'] is not None:
                            parts+=(b'demo-user',b'demo-password');roles+=('demo-username','demo-password')
                    data+=PREFIX+encode(dict(schemaVersion=1,files=[dict(role=role,bytes=len(body))
                        for role,body in zip(roles,parts)]))+b''.join(parts)+SUFFIX
                else:
                    body=encode(account());data+=PREFIX+encode(dict(schemaVersion=1,files=[dict(role='google-service-account',bytes=len(body))]))+body+SUFFIX
            os.write(iw,data)
            if kind==settled and fault=='ack-stop':engine.input.stop('cancelled')
            if kind==settled and fault=='ack-time':engine.input.work_end=time.monotonic()-1
            if kind==settled and fault=='publication-close':lost_target[0]=engine.service.publishers[-1].slots[-1].number
            if kind=='recovery-settled' and hasattr(self,'recovery_after_ack'):self.recovery_after_ack(engine)
            if kind=='recovery-settled' and fault=='recovery-marker-close':lost_target[0]=engine.service.fence_readers[0].fd
            if kind==settled and fault=='publication-post':
                target=Path(engine.service.record._output)
                if not _execute:target=target.with_name('operation-intent.json')
                target.write_bytes(b'changed after prepared checkpoint')
        def command(argv,**kwargs):
            peak();calls.append(tuple(argv));self.assertIs(kwargs['cancellation'],e.guard)
            if argv[0]=='/usr/bin/git':
                self.assertLessEqual(kwargs['timeout'],10)
                if fault=='source' and len(calls)==1:
                    e.guard.lifetime_ledger._commands+=1;e.guard.lifetime_ledger._command_dispatched=True
                    return subprocess.CompletedProcess(argv,9,stdout=b'',stderr=b'PRIVATE')
                if 'config' in argv:out=b'core.repositoryformatversion\n0\0core.bare\nfalse\0'
                elif 'rev-parse' in argv:out=b'a'*40+b'\n'+b'b'*40+b'\n'
                elif '--stage' in argv:out=b''.join(b'100644 '+sha+b' 0\t'+name+b'\0' for name,sha in self.rows)
                elif 'ls-files' in argv:out=b''.join(b'H '+name+b'\0' for name,_ in self.rows)
                elif 'ls-tree' in argv:out=b''.join(b'100644 blob '+sha+b'\t'+name+b'\0' for name,sha in self.rows)
                else:
                    out=b''
                    if _reconcile and settlement and hasattr(self,'recovery_final_source') and len(e.service._source_rows)==8:self.recovery_final_source(e)
                    if later and hasattr(self,'stage_final_source') and len(e.service._source_rows)==8:self.stage_final_source(e)
                    if (_execute or _reconcile) and fault=='last-source' and len(e.service._source_rows)==8:
                        (self.root/'.mobile-release/store/local'/OP.replace('-','')/'operation-intent.json').write_bytes(b'changed at last source status')
                e.guard.lifetime_ledger._commands+=1;e.guard.lifetime_ledger._command_dispatched=True
                return subprocess.CompletedProcess(argv,0,stdout=out,stderr=b'')
            if apple and _execute and not later and e.service._pending['kind']=='tool-resolution':
                self.assertNotIn(pending,events);self.assertFalse(e.input._material_read)
                self.assertEqual(e.service.journals[-1]._rows[-1][0]['phase'],'prepared')
                return self.resolve_tool(argv,kwargs,e,fault)
            self.assertIn(pending,events);self.assertEqual(e.service.journals[0]._rows[-1][0]['phase'] if later and not e.service.journals[0].closed else self.current_phase(),initial_phase if _reconcile else pending_row)
            for name in ('GITHUB_ACTIONS','MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON','RUBYOPT'):self.assertNotIn(name,kwargs['environ'])
            if kwargs['capture']:
                i=len(e.service._runtime_rows)-1-(1 if apple and _execute and not later else 0)
                if apple and i==5:
                    from mobile_release.credentials import APPLE_P8_CHECK
                    self.assertEqual(tuple(argv[:6]),('bundle','exec','ruby','-ropenssl','-e',APPLE_P8_CHECK))
                    self.assertEqual(Path(argv[-1]).read_bytes(),access_fixture.apple_material()[0])
                    self.assertLessEqual(kwargs['timeout'],30);self.assertEqual(kwargs['output_limit'],4096)
                    out=''
                else:out=('3.3.12','4.0.16','','MRK_RUNTIME_3.3.12_FIDDLE_1.1.2','MRK_RUNTIME_3.3.12_FIDDLE_1.1.2')[i]
                e.guard.lifetime_ledger._commands+=1;e.guard.lifetime_ledger._command_dispatched=True
                return subprocess.CompletedProcess(argv,1 if apple and i==5 and fault=='bad-p8' else 0,stdout=out,stderr='')
            self.assertEqual(argv[-1],__import__('mobile_release.stores',fromlist=['LANES']).LANES[('external-testing' if readiness else value['context'].get('stage','candidate'),'ios' if apple else 'android')]);self.assertLessEqual(kwargs['timeout'],900)
            if apple:
                self.assertEqual(kwargs['environ']['MOBILE_RELEASE_STORE_MODE'],'execute' if _execute or _reconcile else 'prepare')
                self.assertEqual(e.service.record._files_owner().mode,'execute' if _execute or _reconcile else 'prepare')
                self.assertNotIn('MOBILE_RELEASE_LOCAL_EXECUTE_AUTHORITY_JSON',kwargs['environ'])
            timing=e.service.record._files_owner().timing
            self.assertEqual(timing.run,__import__('math').floor(e.input.work_end*1e9))
            self.assertEqual(timing.hard-timing.run,3_000_000_000)
            self.assertLessEqual(timing.hard,__import__('math').floor(e.input.hard_end*1e9))
            answer=model(argv,**kwargs)
            if later and fault=='stage-tree-close':lost_target[0]=e.service.metadata_tree.slots[-1].number
            if _reconcile and fault=='prepared-close':lost_target[0]=e.service.prepared_out.fd
            if _execute and fault=='tool-close-cancel':lost_target[0]=e.service.tool_manifest.slot.number
            if _execute and not apple and fault=='tool-manifest-post':
                path=self.tools/'android-toolchain.json';path.chmod(0o600);path.write_bytes(b'changed original manifest')
            if apple and _execute and not later and hasattr(self,'after_lane'):self.after_lane(e,fault)
            if fault=='bundle-post':(self.bundle/('export/App.ipa' if apple else 'app-release.aab')).write_bytes(b'changed during original lane')
            return answer
        original_begin=owner_type._begin
        def begin(op):
            try:return original_begin(op)
            except BaseException as error:
                e.inert_debug=''.join(__import__('traceback').format_exception(error));raise
        original_complete=S.complete_store_operation
        def complete(*args,**kwargs):
            result=original_complete(*args,**kwargs)
            if fault=='publication-root':
                target=Path(e.service.record._output);relative=target.relative_to(self.root)
                moved=self.base/'original-project';self.root.rename(moved)
                self.root.mkdir(mode=0o700)
                parent=self.root
                for part in relative.parts[:-1]:
                    parent=parent/part;parent.mkdir(mode=0o700)
                target.write_bytes((moved/relative).read_bytes());target.chmod(0o600)
            return result
        native_open=os.open;native_close=os.close;lost=[]
        def opened(*args,**kwargs):
            number=native_open(*args,**kwargs);peak();return number
        def closed(number):
            target=None
            if fault=='publication-close' and not lost and e.service is not None and e.service.publishers and settled in events:
                target=lost_target[0]
            if (_execute and fault=='tool-close-cancel' or _reconcile and fault in {'prepared-close','recovery-marker-close'}) and not lost:target=lost_target[0]
            if later and fault=='stage-tree-close' and not lost:target=lost_target[0]
            native_close(number)
            if number==target and fault=='tool-close-cancel':e.input.stop('cancelled')
            if number==target:lost.append(number);raise RuntimeError('inert lost original close')
        def scratch(**kwargs):
            if kwargs.get('parent')==Path('/private/tmp'):kwargs['parent']=self.base
            return B.finite_scratch(**kwargs)
        try:
            with (patch.object(time,'CLOCK_UPTIME_RAW',time.CLOCK_MONOTONIC,create=True),patch.object(_Engine,'local_event',parent_reply),patch.object(S,'sys',SimpleNamespace(platform='darwin')),
                    patch.object(os,'open',side_effect=opened),patch.object(os,'close',side_effect=closed),patch.object(owner_type,'_begin',begin),patch.object(S,'complete_store_operation',side_effect=complete),patch.object(S,'finite_scratch',side_effect=scratch),patch.object(process,'run_command',side_effect=command),patch.object(subprocess,'Popen',side_effect=AssertionError('no native process'))):
                code=run_engine(e)
        finally:
            os.chdir(oldcwd)
            for n,fd in enumerate(old):os.dup2(fd,n);os.close(fd)
            os.close(iw);os.close(parent)
        output=b''
        while True:
            data=os.read(orr,65536)
            if not data:break
            output+=data
        error=os.read(er,65536);os.close(orr);os.close(er)
        self.assertEqual(error,b'');self.assertEqual(code,0,repr(e.primary))
        frames=[json.loads(line) for line in output.splitlines()]
        self.assertEqual(frames[-1]['kind'],'terminal',repr(e.primary))
        terminal=frames[-1]['payload']
        if e in _RETAINED:_RETAINED.remove(e) # Only synthetic fixture; original closes asserted by each case.
        return terminal,e,events,calls,high[0]
    def test_actual_engine_saved_refusal_has_no_phase_material_or_command(self):
        terminal,e,events,calls,high=self.run_original(fault='saved')
        self.assertEqual(terminal['outcome'],'refused',repr(e.primary));self.assertEqual(events,[]);self.assertEqual(calls,[])
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed());self.assertEqual(self.current_phase(),'inputs-ready')
    def test_actual_pending_checkpoint_refusal_prevents_material_and_store(self):
        terminal,e,events,calls,high=self.run_original(fault='prepare-pending')
        self.assertNotEqual(terminal['outcome'],'complete',repr(e.primary));self.assertIsNone(terminal['result'])
        self.assertEqual(events,list(W.PHASES[:3]),getattr(e,'inert_debug','')+''.join(__import__('traceback').format_exception(e.primary)));self.assertEqual(len(calls),6)
        self.assertFalse(e.input._material_read);self.assertEqual(self.current_phase(),'prepare-pending')
        self.assertTrue(e.service.closed(),repr(e.primary));self.assertTrue(e.input.material_closed())

    def test_actual_complete_engine_store_originals_and_prepared_journal(self):
        t,e,events,calls,high=self.run_original()
        self.assertEqual(t['outcome'],'complete',getattr(e,'inert_debug','')+''.join(__import__('traceback').format_exception(e.primary)) if e.primary else '')
        self.assertEqual(events,list(W.PHASES));self.assertEqual(len(calls),14)
        self.assertEqual(t['lifetime']['commands'],14);self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
        self.assertEqual(self.current_phase(),'prepared');self.assertTrue(e.service.store_completed)
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        print('Prepare actual opened-FD high',high,'quoted Python originals',e.service.quote['total'])
        p=Path(e.service.record._output).parent
        self.assertEqual(set(x.name for x in p.iterdir()),{'store-precondition.json','operation-intent.json'})
        from mobile_release.local_release_intent import decode_local_operation_intent
        d=decode_local_operation_intent((p/'operation-intent.json').read_bytes())
        self.assertEqual(d['integrity']['sha256'],t['result']['preparedIntent']['intentSha256'])
        self.assertNotIn('client_email',json.dumps(t));self.assertNotIn(str(self.root),json.dumps(t))

    def test_source_nonzero_cannot_request_key_material_or_append_pending(self):
        t,e,events,calls,high=self.run_original(fault='source')
        self.assertEqual(len(calls),1);self.assertEqual(events,[]);self.assertNotEqual(t['outcome'],'complete')
        self.assertEqual(t['lifetime']['commands'],1);self.assertIsNone(t['result']);self.assertTrue(e.service.closed())
        self.assertEqual(self.current_phase(),'inputs-ready');self.assertNotIn('PRIVATE',json.dumps(t))
    def test_nested_missing_terminal_cannot_turn_outer_success_into_prepared(self):
        t,e,events,calls,high=self.run_original(fault='nested-terminal')
        self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertFalse(e.service.store_completed)
        self.assertEqual(self.current_phase(),'prepare-pending');self.assertNotIn('prepare-settled',events)
    def test_late_bundle_drift_vetoes_complete_store_and_prepared_publication(self):
        t,e,events,calls,high=self.run_original(fault='bundle-post')
        self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertFalse(e.service.store_completed)
        self.assertEqual(self.current_phase(),'prepare-pending');self.assertNotIn('prepare-settled',events)
    def test_replaced_publication_root_cannot_adopt_precondition_or_prepare_history(self):
        t,e,events,calls,high=self.run_original(fault='publication-root')
        self.assertTrue(e.service.store_completed);self.assertEqual(len(calls),14)
        self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result'])
        self.assertEqual(self.current_phase(),'prepare-pending');self.assertNotIn('prepare-settled',events)
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
        target=Path(e.service.record._output)
        self.assertEqual(set(p.name for p in target.parent.iterdir()),{'store-precondition.json'})
        original=self.base/'original-project'/target.relative_to(self.root)
        self.assertEqual(original.read_bytes(),target.read_bytes())
        self.assertFalse(original.with_name('operation-intent.json').exists())
    def test_durable_prepared_ack_failure_retains_files_without_complete_result(self):
        t,e,events,calls,high=self.run_original(fault='prepare-settled')
        self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertTrue(e.service.store_completed)
        self.assertEqual(self.current_phase(),'prepared');self.assertEqual(len(calls),14)
        self.assertTrue(Path(e.service.record._output).with_name('operation-intent.json').exists())
    def test_prepared_callback_document_drift_is_not_current_success(self):
        t,e,events,calls,high=self.run_original(fault='publication-post')
        self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertEqual(self.current_phase(),'prepared')
        self.assertEqual(Path(e.service.record._output).with_name('operation-intent.json').read_bytes(),b'changed after prepared checkpoint')
    def test_prepared_publication_original_unknown_close_retains_unknown(self):
        t,e,events,calls,high=self.run_original(fault='publication-close')
        self.assertEqual(t['outcome'],'unknown');self.assertIsNone(t['result']);self.assertEqual(self.current_phase(),'prepared')
        self.assertFalse(e.service.closed());self.assertTrue(e.input.material_closed())
    def test_closed_context_and_bounded_result_reject_hybrid_or_raw_details(self):
        value=copy.deepcopy(self.value)
        for key,bad in [('operation','local-store-preflight'),('executionMode','github'),('candidateOperationId','a'*32),('candidateSha256',True),('confirmation','candidate:android:other:42')]:
            row=copy.deepcopy(value['context']);row[key]=bad
            with self.subTest(key=key),self.assertRaises(W.ProtocolError):W.context(row)
        self.assertEqual(W.context(value['context']),value['context'])
        with self.assertRaises(W.ProtocolError):W.context({**value['context'],'authority':{'GITHUB_ACTIONS':'true'}})
    def test_quote_actual_depth_and_failure_overlap_do_not_raise256(self):
        self.assertEqual(S.resource_quote(project_depth=8,version_parent_depth=9,source=48,history_depth=8)['total'],178)
        with self.assertRaises(W.ProtocolError):S.resource_quote(project_depth=24,version_parent_depth=25,source=96,history_depth=8)
