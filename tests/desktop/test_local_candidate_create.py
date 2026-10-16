"""Actual source14/AAB/metadata/journal/publisher chain; native effects inert.

Reuses existing original Gradle/signature/outer boundary fixture. IO/lease and
wire are covered separately; no native build, signing, Keychain or Store call.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from mobile_release import local_candidate_create as C
from mobile_release._desktop_android_build_engine import _Engine
from mobile_release._desktop_candidate_input_control import CandidateCreateInput
from mobile_release.local_release_journal import LocalReleaseJournal
from mobile_release.local_candidate_bundle import MANIFEST
from mobile_release import _desktop_android_build_protocol as wire
import test_local_candidate_composition as composition
import test_android_build_service as service
import test_android_build_protocol as old
import test_local_candidate_create_protocol as data
from test_local_release_history import ENROLLMENT,KEY

class CandidateCreateChainTests(unittest.TestCase):
    setUp=composition.LocalCandidateCompositionTests.setUp
    patched=composition.LocalCandidateCompositionTests.patched
    forbidden=composition.LocalCandidateCompositionTests.forbidden
    close_sources=composition.LocalCandidateCompositionTests.close_sources
    def subject(self,fault=None):
        ordinary=service.values
        self.patched(service,'values',side_effect=lambda **kw:(replace(ordinary(**kw)[0],operation_id=data.OP),ordinary(**kw)[1]))
        signed=old.signed_request_data
        def selected(**kw):d=signed(**kw);d['operationId']=data.OP;return d
        self.patched(old,'signed_request_data',side_effect=selected)
        f,path,body=composition.LocalCandidateCompositionTests.subject(self)
        self.home_tmp=tempfile.TemporaryDirectory(dir=Path.home());self.addCleanup(self.home_tmp.cleanup)
        home=Path(self.home_tmp.name);native=dict(f.request.native);root=f.operation.root.stat()
        parent=f.invocation._original_project.fd
        import fcntl
        fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
        loan=os.dup(parent);os.set_inheritable(loan,True)
        native['rootIdentity']=dict(device=str(root.st_dev),inode=str(root.st_ino),mode=root.st_mode,uid=root.st_uid,gid=root.st_gid)
        now=time.monotonic_ns();native['candidateHistory']=dict(home=str(home),leaseFd=loan,nonce='e'*32,
            clock=dict(workEndNs=str(now+500_000_000_000),hardEndNs=str(now+510_000_000_000)))
        request=wire.parse_request(old.encoded(dict(protocol=wire.CANDIDATE_PROTOCOL,operationId=data.OP,
            ownerGeneration=f.request.owner_generation,context={**f.request.context,'operation':'android-candidate-inputs','action':'create'},native=native)))
        f.request=f.run.request=f.operation.request=request
        f.run._candidate_inputs=None;f.source.candidate_input=None
        e=_Engine(time.monotonic());e.input=f.source;e.guard=f.guard;e.service=f.run;e.request=request;f.source._engine=e
        adapter=CandidateCreateInput(f.source,request)
        self.patched(time,'CLOCK_UPTIME_RAW',time.CLOCK_MONOTONIC,create=True);adapter.acquire()
        self.addCleanup(lambda:adapter.close() if not adapter.close_claimed else None)
        owner=C.CandidateCreateRun(e)
        journal=LocalReleaseJournal(str(home),end=f.source.work_end,enrollment=ENROLLMENT,key=KEY)
        journal.open();journal._append(expected_head=journal.head(),operation_id=None,phase='genesis',
            payload=dict(rootIdentity=dict(device=root.st_dev,inode=root.st_ino,mode=root.st_mode&0o7777,uid=root.st_uid,gid=root.st_gid)))
        journal.close()
        phases=[]
        def exchange(kind,payload):
            adapter.post();self.assertEqual(kind,data.C.PHASES[adapter.reply_step]);adapter.reply_step+=1
            phases.append((kind,json.loads(json.dumps(payload))))
            if fault==kind:raise C.LocalCandidateError('Inert checkpoint refuses')
            return (dict(ENROLLMENT),bytearray(KEY)) if kind=='lease-ready' else (None,None)
        self.patched(adapter,'exchange',side_effect=exchange)
        f.signed_bytes=b'actually changed signed AAB stand-in\n'
        return f,path,owner,adapter,phases,home
    def finish(self,f,owner,adapter):
        try:f.run.run();owner.finish_build()
        except BaseException as error:
            f.run.remember(error)
        finally:
            try:owner.close()
            except BaseException as error:f.run.remember(error)
            adapter.close();f.settle_outer()
        return f.run.terminal()
    def test_complete_same_aab_retained_metadata_journal_and_actual14(self):
        f,path,owner,adapter,phases,home=self.subject()
        terminal=self.finish(f,owner,adapter)
        self.assertEqual(terminal['outcome'],'complete',repr(f.run.primary))
        self.assertEqual(terminal['lifetime']['commands'],14)
        self.assertEqual([p[0] for p in phases],list(data.C.PHASES))
        self.assertTrue(owner.originals_closed());self.assertFalse(owner.composition.handoff.producer_joined)
        self.assertEqual(owner.composition.handoff._completed_reads,3)
        self.assertEqual(path.read_bytes(),f.signed_bytes)
        self.assertEqual(set(p.name for p in path.parent.iterdir()),{'app-release.aab','store-metadata.zip','validation-report.json',MANIFEST})
        manifest=json.loads((path.parent/MANIFEST).read_bytes())
        self.assertEqual(manifest['sourceCommit'],'a'*40)
        summary=terminal['result']['candidateInputs']
        for row in summary['files']:
            body=(path.parent/row['fileName']).read_bytes()
            self.assertEqual((len(body),hashlib.sha256(body).hexdigest()),(row['bytes'],row['sha256']))
        self.assertFalse(owner.composition.metadata_scratch._path.exists())
        self.assertEqual([j.closed for j in owner.journals],[True,True])
        self.assertLessEqual(owner.quote['total'],256)
        j=LocalReleaseJournal(str(home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing()
        self.assertEqual([r['phase'] for r,_ in j._rows],['genesis','inputs-pending','inputs-ready'])
        self.assertEqual(j._rows[-1][0]['payload']['candidateSha256'],summary['candidateSha256']);j.close()
    def test_pending_checkpoint_refusal_stops_before_build_preserves_pending_and_closes(self):
        f,path,owner,adapter,phases,home=self.subject(fault='inputs-pending')
        terminal=self.finish(f,owner,adapter)
        self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])
        f.run._signed_body.assert_not_called();self.assertEqual(terminal['lifetime']['commands'],6)
        self.assertFalse(path.exists());self.assertTrue(owner.originals_closed())
        self.assertEqual(len(owner.journals),1)
        j=LocalReleaseJournal(str(home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing()
        self.assertEqual(j._rows[-1][0]['phase'],'inputs-pending');j.close()
    def test_ready_checkpoint_refusal_preserves_four_files_no_positive_result(self):
        f,path,owner,adapter,phases,home=self.subject(fault='inputs-ready')
        terminal=self.finish(f,owner,adapter)
        self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])
        self.assertEqual(terminal['lifetime']['commands'],14)
        self.assertEqual(len(list(path.parent.iterdir())),4)
        self.assertTrue(owner.originals_closed());self.assertFalse(owner.composition.handoff.producer_joined)
        self.assertEqual((path.parent/'app-release.aab').read_bytes(),f.signed_bytes)

    def test_actual_new_leaf_close_unknown_preserves_bundle_and_blocks_result(self):
        f,path,owner,adapter,phases,home=self.subject()
        from mobile_release.build_inputs import _FD
        original=_FD.close;lost=[]
        def close(slot):
            publisher=owner.publisher
            if publisher is not None and publisher.closed and publisher.files and slot is publisher.files[0][1] and not lost:
                lost.append(slot.number)
                # The real _FD retirement consumes close; lose its return at
                # os.close rather than counterfeit a projected close flag.
                builtin=os.close
                def consume(number):
                    builtin(number)
                    if number==lost[0]:raise RuntimeError('inert-lost-close-return')
                with __import__('unittest').mock.patch.object(os,'close',side_effect=consume):
                    return original(slot)
            return original(slot)
        self.patched(_FD,'close',new=close)
        terminal=self.finish(f,owner,adapter)
        self.assertEqual(terminal['outcome'],'unknown');self.assertIsNone(terminal['result'])
        self.assertFalse(terminal['lifetime']['candidateInputsClosed']);self.assertFalse(owner.originals_closed())
        self.assertEqual(len(lost),1);self.assertEqual(len(list(path.parent.iterdir())),4)
        self.assertEqual(owner.publisher.files[0][1].close_state,'UNKNOWN')
        self.assertFalse(owner.composition.handoff.producer_joined)
    def test_exact_candidate_resource_boundary_preserves_ordinary_quote(self):
        f,path,owner,adapter,phases,home=self.subject()
        quote=dict(project=10,source=10,normalFiles=10,namespace=3,baseline=8,normalIterators=2,handoff=12,total=255)
        admitted=owner.reserve(quote);self.assertEqual(admitted['total'],256);self.assertEqual(quote['total'],255)
        with self.assertRaises(C.LocalCandidateError):owner.reserve({**quote,'total':256})
        owner.close();adapter.close();self.assertTrue(owner.originals_closed())
        f.run._signed_body.assert_not_called();self.assertEqual(owner.journals,[])

    def test_actual_source_only_failure_has_no_journal_or_build_effect(self):
        f,path,owner,adapter,phases,home=self.subject()
        original=f.command.side_effect
        def refused(argv,**kwargs):
            answer=original(argv,**kwargs);answer.returncode=7;answer.stderr=b'PRIVATE_SOURCE_OUTPUT';return answer
        f.command.side_effect=refused
        terminal=self.finish(f,owner,adapter)
        self.assertEqual(terminal['outcome'],'refused');self.assertIsNone(terminal['result'])
        self.assertEqual(terminal['lifetime']['commands'],1)
        self.assertTrue(terminal['lifetime']['commandDispatched'])
        self.assertEqual(terminal['activity']['command']['outcome'],'not-dispatched')
        self.assertEqual(owner.journals,[]);self.assertEqual(phases,[]);f.run._signed_body.assert_not_called()
        self.assertTrue(owner.originals_closed());self.assertNotIn('PRIVATE_SOURCE',json.dumps(terminal))
    def test_metadata_drift_after_ready_checkpoint_vetoes_current_create_result(self):
        f,path,owner,adapter,phases,home=self.subject()
        exchange=adapter.exchange.side_effect
        def change(kind,payload):
            answer=exchange(kind,payload)
            if kind=='inputs-ready':
                p=path.parent/'store-metadata.zip';p.write_bytes(b'changed after durable ready')
            return answer
        adapter.exchange.side_effect=change
        terminal=self.finish(f,owner,adapter)
        self.assertNotEqual(terminal['outcome'],'complete');self.assertIsNone(terminal['result'])
        self.assertEqual(terminal['lifetime']['commands'],14);self.assertTrue(owner.originals_closed())
        self.assertEqual((path.parent/'store-metadata.zip').read_bytes(),b'changed after durable ready')
        self.assertEqual(len(list(path.parent.iterdir())),4)
        j=LocalReleaseJournal(str(home),end=time.monotonic()+30,enrollment=ENROLLMENT,key=KEY);j.open_existing()
        self.assertEqual(j._rows[-1][0]['phase'],'inputs-ready');j.close()

if __name__=='__main__':unittest.main()
