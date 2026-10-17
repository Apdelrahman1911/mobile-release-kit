"""Real source/journal/metadata/retained iOS publication, inert signing/native.

Reuses original handoff fixture. Actual command slots carry explicit finality
DATA at the native boundary; no process, Keychain, Xcode or Store is entered.
"""
from contextlib import nullcontext
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import test_local_ios_candidate as old
import test_local_ios_candidate_protocol as data
from mobile_release import build_inputs as B, _command_process as commands
from mobile_release import local_release_source as S
from mobile_release import local_ios_candidate_create as C
from mobile_release._desktop_ios_archive_engine import _Engine
from mobile_release.local_release_journal import LocalReleaseJournal

ENROLLMENT=dict(projectLocator='a'*64,projectBinding='b'*64,projectId='11111111-1111-4111-8111-111111111111',keyId='22222222-2222-4222-8222-222222222222',keyRevision=1)
KEY=b'K'*32
class IOSCandidateCreateTests(unittest.TestCase):
    setUp=old.LocalIOSHandoffTests.setUp
    patch=old.LocalIOSHandoffTests.patch
    def subject(self, *, fault=None, ipa_body=None):
        self.patch(time,'CLOCK_UPTIME_RAW',new=time.CLOCK_MONOTONIC,create=True)
        from mobile_release.checked_files import _Reader
        self.patch(_Reader,'_physical_role',return_value=None)  # Linux originals; no Darwin alias claim.
        home=Path.home()/Path(self.temp).name;home.mkdir(mode=0o700)
        self.stack.callback(__import__('shutil').rmtree,home)
        config=old.signed.signed_configuration();config['source']['localStoreEnabled']=True
        def transform(root,value):
            parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY);self.stack.callback(os.close,parent)
            fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
            loan=os.dup(parent);os.set_inheritable(loan,True)
            st=root.stat();now=time.monotonic_ns()
            value.update(protocol=data.wire.CANDIDATE_PROTOCOL,operationId=data.OP)
            value['context'].update(operation='ios-candidate-inputs',action='create')
            value['native'].update(rootIdentity=dict(device=str(st.st_dev),inode=str(st.st_ino),mode=st.st_mode,uid=st.st_uid,gid=st.st_gid),
                candidateHistory=dict(home=str(home),leaseFd=loan,nonce='e'*32,clock=dict(
                    workEndNs=str(now+500_000_000_000),cleanupEndNs=str(now+620_000_000_000),hardEndNs=str(now+630_000_000_000))))
            return value
        box={}
        def register(run):
            e=_Engine(time.monotonic());e.input=run.source;e.guard=run.guard;e.service=run;e.request=run.request
            run.source._engine=e;box['owner']=C.IOSCandidateCreateRun(e)
            self.stack.callback(lambda:run.source.candidate_input.close() if not run.source.candidate_input.close_claimed else None)
        def invocation_factory(op,project,lease):
            project.fd=project.directory.fd;project.guard=op.guard;project.root=op.root
            inv=B.InvocationCustody(op.root,'build',op.guard)
            inv._original_project=inv.project_owner=project;inv.signing_lease=lease
            inv.active=inv.reserved=True;inv.closed=False
            self.patch(inv,'require',return_value=None)  # Existing environment/account admission boundary.
            return inv
        f=old.LocalIOSHandoffTests.fixture(self,configuration=config,request_map=transform,register=register,
                                           invocation_factory=invocation_factory,ipa_body=ipa_body)
        owner=box['owner'];adapter=f.source.candidate_input
        f.project.meta.open(f.op.root/'.mobile-release',os.O_RDONLY|os.O_DIRECTORY)
        root=f.op.root;st=root.stat()
        journal=LocalReleaseJournal(str(home),end=f.source.work_end,enrollment=ENROLLMENT,key=KEY)
        journal.open();journal._append(expected_head=journal.head(),operation_id=None,phase='genesis',payload=dict(
            rootIdentity=dict(device=st.st_dev,inode=st.st_ino,mode=st.st_mode&0o7777,uid=st.st_uid,gid=st.st_gid)))
        journal.close();phases=[]
        def exchange(kind,payload):
            adapter.post();self.assertEqual(kind,data.C.PHASES[adapter.reply_step]);adapter.reply_step+=1
            phases.append(kind)
            if fault=='mutate-ready' and kind=='inputs-ready':
                (f.path/'store-metadata.zip').write_bytes(b'changed after original ready ACK')
            if fault==kind:raise C.LocalCandidateError('Inert checkpoint refuses')
            return (dict(ENROLLMENT),bytearray(KEY)) if kind=='lease-ready' else (None,None)
        self.patch(adapter,'exchange',side_effect=exchange)
        def receive(op):
            self.assertIs(op,f.op);self.assertEqual(phases,['lease-ready','history-head','inputs-pending'])
            self.assertEqual(adapter.reply_step,3);self.assertEqual(owner.composition.source.calls,6)
            self.assertTrue(all(j.closed for j in owner.journals));f.events.append('material')
        self.patch(f.source,'receive_material',side_effect=receive)
        # Same exact saved/source files and real original metadata ZIP writer.
        bodies={S.CONFIG_PATH:f.config_raw,f.bound.saved.configuration.source:f.version_raw,
            'release/store/ios/en-US/name.txt':b'Original iOS metadata\n'}
        controls={'.git/config':b'[core]\nrepositoryformatversion=0\nbare=false\n',
            '.git/HEAD':b'ref: refs/heads/main\n','.git/refs/heads/main':b'a'*40+b'\n',
            '.git/index':b'inert index no Git process'}
        for name,body in {**bodies,**controls}.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);p.write_bytes(body);p.chmod(0o600)
        for name in ('.git/objects/info','.git/info'):(root/name).mkdir(parents=True,exist_ok=True,mode=0o700)
        rows=[(name.encode(),hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest().encode()) for name,body in bodies.items()]
        calls=[]
        def command(argv,**kw):
            self.assertIs(kw['cancellation'],f.guard);self.assertEqual(argv[0],'/usr/bin/git')
            self.assertNotIn('producer-close',f.events);self.assertIsNone(kw['execution_scope'])
            calls.append(tuple(argv))
            if 'config' in argv:out=b'core.repositoryformatversion\n0\0core.bare\nfalse\0'
            elif 'rev-parse' in argv:out=b'a'*40+b'\n'+b'b'*40+b'\n'
            elif '--stage' in argv:out=b''.join(b'100644 '+sha+b' 0\t'+name+b'\0' for name,sha in rows)
            elif 'ls-files' in argv:out=b''.join(b'H '+name+b'\0' for name,_ in rows)
            elif 'ls-tree' in argv:out=b''.join(b'100644 blob '+sha+b'\t'+name+b'\0' for name,sha in rows)
            else:self.assertIn('status',argv);out=b''
            engine=commands._Outer(f.guard,False,kw['timeout'],None,None,suppress_cancel=False)
            code=7 if fault=='source-first' and len(calls)==1 else 0
            wait=SimpleNamespace(status_kind='exit',status_code=0) # Original helper joined; target exit is separate.
            engine.child,engine.wait=SimpleNamespace(receipt=wait),wait
            engine.terminal={'producer':True,'stdout':len(out),'stderr':0}
            engine.sealed=True;engine.wire=SimpleNamespace(eof=True,poisoned=False)
            engine.readers=[object(),object()];engine.output_eof=[True,True]
            engine.handlers_complete=engine.local_cleanup_complete=True
            engine.outputs[0].extend(out);engine.decoded=(out,b'')
            final=object.__new__(commands.OriginalCommandFinality);final._engine=engine
            result=commands.OriginalCommandOutcome(engine,engine.nonce,commands.RouteHistory(True,True),
                commands.RouteHistory(True,True),None,'normal-exit',code,'complete',final)
            engine.phase='CLOSED';engine.slot._publish(engine,result)
            f.guard.lifetime_ledger._finish_command(engine.slot,dispatched=True,contained=True,cleanup_complete=True)
            return SimpleNamespace(args=argv,returncode=code,stdout=out,stderr=b'PRIVATE_INERT' if code else b'')
        self.patch(commands,'run_command',side_effect=command)
        # Original signed native body boundary retains its variable command
        # ledger, separately from the actual eight source command records.
        signed_body=f.run._signed_body.side_effect
        def body(bound):
            before=f.guard.lifetime_ledger.verdict().commands
            self.assertEqual(before,6);self.assertEqual(phases[-1],'inputs-pending')
            signed_body(bound)
            # Authenticated native IPA validation is the explicit inert boundary
            # in this whole-chain fixture. Separate tests call the actual deposit.
            from mobile_release.local_release_journal import canonical
            owner.composition.signing_record=(f.op._ipa,dict(f.op._ipa.original.identity),f.op._ipa.inventory,
                canonical(dict(platform='ios',kind='apple-distribution',certificateSha256=f.run.request.context['signing']['distributionCertificateSha256'],
                    teamId=f.run.request.context['signing']['teamId'],profileUuid='12345678-1234-1234-1234-123456789abc',
                    profileExpiresAt='2030-01-01T00:00:00Z')))
            native=f.guard.lifetime_ledger.verdict().commands
            f.guard.lifetime_ledger._commands+=before
            f.op.signing.commands=[object() for _ in range(native)]
            f.op.signing.profiles=[object() for _ in range(3)]
        self.patch(f.run,'_signed_body',side_effect=body)
        self.patch(f.op.signing,'commands_settled',return_value=True)  # Explicit native-only finality fixture.
        self.patch(f.op,'command_dispatch',side_effect=lambda:f.guard.lifetime_ledger.verdict().command_dispatched)
        f.owner=owner;f.adapter=adapter;f.phases=phases;f.home=home;f.calls=calls
        return f
    def finish(self,f):
        try:f.execute();f.owner.finish_build()
        except BaseException as error:f.run.remember(error)
        finally:
            try:f.run.close()
            except BaseException as error:f.run.remember(error)
            try:f.owner.close()
            except BaseException as error:f.run.remember(error)
            f.adapter.close()
            f.source.close_claimed=f.source.closed=True
            f.guard._saved_command_source=None;f.guard._saved_command_source_removed=True
            f.guard._restoration='RESTORED'  # Original outer input/handler boundary only.
        return f.run.terminal()
    def test_actual_source_journal_metadata_same_archive_ipa_and_final_closes(self):
        f=self.subject();before=f.ipa.stat().st_ino
        result=self.finish(f)
        self.assertEqual(result['outcome'],'complete',repr(f.run.primary))
        self.assertEqual(result['lifetime']['sourceCommands'],8)
        self.assertEqual(len(f.calls),8);self.assertEqual(f.phases,list(data.C.PHASES))
        self.assertEqual(f.ipa.stat().st_ino,before);self.assertEqual(f.ipa.read_bytes(),f.body)
        self.assertEqual({p.name for p in f.path.iterdir()},{'archive.xcarchive','export','store-metadata.zip','validation-report.json','candidate-inputs.json'})
        self.assertTrue(f.owner.originals_closed());self.assertFalse(f.owner.composition.handoff.producer_joined)
        self.assertLessEqual(f.owner.fd_peak,256);self.assertGreater(f.owner.fd_peak,64)

    def test_pending_refusal_prevents_material_and_keeps_durable_row(self):
        f=self.subject(fault='inputs-pending');result=self.finish(f)
        self.assertNotEqual(result['outcome'],'complete');self.assertIsNone(result['result'])
        self.assertNotIn('material',f.events);f.run._signed_body.assert_not_called()
        self.assertEqual(result['lifetime']['sourceCommands'],6);self.assertEqual(f.phases,list(data.C.PHASES[:3]))
        self.assertTrue(f.owner.originals_closed());self.assertTrue(f.adapter.closed)
        self.assertFalse((f.path/'candidate-inputs.json').exists());self.assertEqual(f.ipa.read_bytes(),f.body)
        j=LocalReleaseJournal(str(f.home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing()
        self.assertEqual(j._rows[-1][0]['phase'],'inputs-pending');j.close()
    def test_ready_checkpoint_refusal_or_mutation_preserves_originals_without_result(self):
        for fault in ('inputs-ready','mutate-ready'):
            with self.subTest(fault=fault):
                if fault=='mutate-ready':self.doCleanups();self.setUp()
                f=self.subject(fault=fault);result=self.finish(f)
                self.assertNotEqual(result['outcome'],'complete');self.assertIsNone(result['result'])
                self.assertEqual(result['lifetime']['sourceCommands'],8);self.assertTrue(f.owner.originals_closed())
                self.assertEqual(len(list(f.path.iterdir())),5);self.assertEqual(f.ipa.read_bytes(),f.body)
                j=LocalReleaseJournal(str(f.home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing()
                self.assertEqual(j._rows[-1][0]['phase'],'inputs-ready');j.close()
    def test_source_failure_keeps_actual_one_call_and_no_journal_or_signing(self):
        f=self.subject(fault='source-first');result=self.finish(f)
        self.assertNotEqual(result['outcome'],'complete');self.assertIsNone(result['result'])
        self.assertEqual(result['lifetime']['sourceCommands'],1);self.assertEqual(result['lifetime']['commands'],1)
        self.assertEqual(f.phases,[]);self.assertEqual(f.owner.journals,[]);f.run._signed_body.assert_not_called()
        self.assertTrue(f.owner.originals_closed());self.assertNotIn('PRIVATE_INERT',json.dumps(result))
    def test_publisher_unknown_consuming_close_is_absorbing_and_others_close(self):
        f=self.subject();original=B._FD.close;lost=[]
        def close(slot):
            p=f.owner.publisher
            if p is not None and p.closed and p.files and slot is p.files[0][1] and not lost:
                lost.append(slot.number);native=os.close
                def consume(number):
                    native(number)
                    if number==lost[0]:raise RuntimeError('inert lost original close')
                with patch.object(os,'close',side_effect=consume):return original(slot)
            return original(slot)
        self.patch(B._FD,'close',new=close);result=self.finish(f)
        self.assertEqual(result['outcome'],'unknown');self.assertIsNone(result['result'])
        self.assertEqual(len(lost),1);self.assertFalse(result['lifetime']['candidateInputsClosed'])
        self.assertEqual(f.owner.publisher.files[0][1].close_state,'UNKNOWN');self.assertTrue(f.adapter.closed)
        self.assertEqual(f.ipa.read_bytes(),f.body);self.assertEqual(len(list(f.path.iterdir())),5)
    def test_account_contention_refuses_before_source_journal_and_material(self):
        from mobile_release import local_signing
        from contextlib import contextmanager
        f=self.subject()
        @contextmanager
        def busy(**_):
            raise BlockingIOError('inert account is already held')
            yield
        self.patch(local_signing,'local_signing_lease',new=busy)
        result=self.finish(f)
        self.assertNotEqual(result['outcome'],'complete');self.assertIsNone(result['result'])
        self.assertEqual(f.calls,[]);self.assertEqual(f.phases,[]);self.assertNotIn('material',f.events)
        self.assertEqual(f.owner.journals,[]);self.assertTrue(f.owner.originals_closed())
        f.run._signed_body.assert_not_called()

    def test_unarmed_source_is_not_a_signed_command_or_new_execution_scope(self):
        from mobile_release import owned_process
        f=self.subject();comp=f.owner.composition
        with self.assertRaises(C.LocalCandidateError):
            comp.source_command(['/usr/bin/git','status'],environ={},cwd=f.op.root,timeout=1,
                capture=True,text=False,cleanup=False,scope=None,binding=None,evidence=None,on_start=None)
        # The actual normal dispatcher still chooses its original SignedIOS
        # command owner when no exact source row is armed; it does not dispatch.
        with self.assertRaises((ValueError,C.LocalCandidateError)):
            owned_process.run_owned(['/usr/bin/git','status'],cancellation=f.guard,
                cwd=f.op.root,timeout=1,capture=True,text=False,environ={})
        self.assertEqual(f.calls,[]);self.assertEqual(comp._source_rows,[])
        self.assertFalse(f.guard.lifetime_ledger.verdict().command_dispatched)
        f.owner.close();f.adapter.close()

    def test_aggregate_preopen_exact_fit_and_unknown_never_refunded(self):
        f=self.subject();slot=B._FD(f.guard)
        live=sum(s.open_state!='NEW' and s.close_state!='CLOSED' for s in f.owner.descriptors)
        f.owner.non_fd_reserve=255-live
        slot.open('/dev/null',os.O_RDONLY);self.assertEqual(f.owner.fd_peak,256)
        later=B._FD(f.guard)
        with self.assertRaises(C.LocalCandidateError):later.open('/dev/null',os.O_RDONLY)
        self.assertEqual(later.open_state,'NEW');self.assertIsNone(later.number)
        number=slot.number;native=os.close
        def consumed(fd):
            native(fd)
            if fd==number:raise RuntimeError('inert lost close')
        with patch.object(os,'close',side_effect=consumed),self.assertRaises(old.service.ProcessError):slot.close()
        self.assertEqual(slot.close_state,'UNKNOWN')
        with self.assertRaises(C.LocalCandidateError):later.open('/dev/null',os.O_RDONLY)
        f.owner.close();f.adapter.close()

if __name__=='__main__':unittest.main()
