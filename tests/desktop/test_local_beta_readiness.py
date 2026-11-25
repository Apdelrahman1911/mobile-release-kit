"""Actual existing Store/History owners; provider/native dispatch modeled only."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from uuid import UUID
from unittest.mock import patch
from mobile_release import _desktop_store_reconcile_protocol as wire
from mobile_release.local_release_journal import canonical
from mobile_release.local_release_receipt import validate_local_readiness_receipt
import test_local_store_stage_execute as stage_fixture
import test_local_release_history as history_fixture

STAGE='77777777-7777-4777-8777-777777777777'
class LocalBetaReadinessTests(unittest.TestCase):
    def prepare(self):
        case=stage_fixture.LocalStoreStageExecuteTests(methodName='runTest');self.addCleanup(case.doCleanups)
        f,intent,_,sourcecase=case.prepare('ios')
        old=f.execution_receipt
        def submitted(argv,env):
            receipt,code=old(argv,env)
            receipt.update(state='submitted-for-review',betaReviewState='WAITING_FOR_REVIEW')
            return receipt,code
        f.execution_receipt=submitted
        t,e,_,_,_=f.run_original(_execute=True);self.assertEqual(t['outcome'],'complete',sourcecase.detail(e,t))
        previous=Path(e.service.record._output).read_bytes();self.assertEqual(json.loads(previous)['state'],'submitted-for-review')
        c=f.value['context'];f.value['protocol']=wire.PROTOCOL
        c.update(operation='local-store-reconcile',action='external-readiness',executionReceiptSha256=hashlib.sha256(previous).hexdigest())
        for k in ('stage','predecessorOperationId','predecessorReceiptSha256'):c.pop(k)
        observed=[]
        def readback(argv,env):
            ctx=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_READINESS']);observed.append(ctx)
            self.assertEqual(set(ctx),{'authority','expectedIntentSha256','executionReceiptSha256','metadataInputs'})
            self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE',env);self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_RECONCILE',env)
            self.assertNotIn('MOBILE_RELEASE_IOS_IPA_PATH',env)
            self.assertEqual((Path(ctx['metadataInputs']['root'])/'ios/en-US/title.txt').read_bytes(),b'Original stage title\n')
            receipt=dict(documentType='local-store-external-readiness-receipt',schemaVersion=1,origin='local-desktop',
                operation='ios_testflight_external',platform='ios',stage='external-testing',project=intent['project'],operationId=STAGE,
                candidateOperationId=intent['candidateOperationId'],candidateSha256=intent['candidateSha256'],operationIntentSha256=intent['integrity']['sha256'],
                executionReceiptSha256=c['executionReceiptSha256'],preparedBy=intent['preparedBy'],observedBy=ctx['authority'],
                appIdentity=intent['application']['id'],appStoreAppId=intent['application']['storeAppId'],marketingVersion='1.2.3',buildNumber=42,
                observedAt='2026-10-17T00:00:00Z',result='ready',state='available-to-testers',buildResourceId=intent['storePrecondition']['snapshot']['build']['id'],
                processingState='VALID',externalGroup=intent['storePrecondition']['snapshot']['external']['groupName'],autoNotifyEnabled=False,
                betaReviewState='APPROVED',priorExecutionFinality='not-established')
            if hasattr(self,'mutate_receipt'):self.mutate_receipt(receipt)
            return receipt,0
        f.execution_receipt=readback
        return f,intent,observed,sourcecase
    def test_original_external_receipt_preserved_new_readonly_checkpoint(self):
        f,intent,observed,case=self.prepare();before={p:p.read_bytes() for p in (f.root/'.mobile-release/store/local').rglob('*') if p.is_file()}
        t,e,events,calls,high=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(events,['lease-ready','history-head','external-ready'])
        self.assertEqual(len(calls),15);self.assertEqual(e.service.observation.calls,8);self.assertEqual(len(observed),1)
        self.assertEqual(t['result']['headSequence'],12);self.assertEqual(len(t['result']['readinessReceipt']),19)
        self.assertEqual(f.current_phase(),'external-ready');self.assertTrue(e.service.closed());self.assertTrue(e.service.metadata_tree.retired)
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        self.assertEqual(before,{p:p.read_bytes() for p in before});wire.validate_readiness_result(t['result'])
    def test_unavailable_readback_cannot_append_or_replace_prior_execution(self):
        f,_,_,case=self.prepare();self.mutate_receipt=lambda r:r.update(state='submitted-for-review')
        t,e,events,calls,_=f.run_original(_reconcile=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result']);self.assertEqual(len(calls),13)
        self.assertNotIn('external-ready',events);self.assertEqual(f.current_phase(),'settled-success')
    def test_exact_original_execution_digest_refuses_before_material(self):
        f,_,observed,case=self.prepare();f.value['context']['executionReceiptSha256']='0'*64
        t,e,events,calls,_=f.run_original(_reconcile=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(events,['lease-ready'])
        self.assertEqual(len(calls),6);self.assertFalse(e.input._material_read);self.assertEqual(observed,[]);self.assertTrue(e.service.closed())
    def test_final_ack_loss_preserves_new_row_but_attempt_has_no_success(self):
        f,_,_,case=self.prepare();t,e,events,calls,_=f.run_original(_reconcile=True,fault='external-ready')
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result']);self.assertEqual(len(calls),15)
        self.assertEqual(f.current_phase(),'external-ready');self.assertTrue(e.service.store_completed)
    def test_closed_request_cannot_select_tools_settlement_or_other_platform(self):
        f,_,_,_=self.prepare();c=f.value['context'];self.assertEqual(wire.context(c),c)
        for changes in ({'platform':'android'},{'stage':'external-testing'},{'settlement':'record-current-target'},{'action':'recover'},{'stageOperationId':c['candidateOperationId']}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):wire.context(dict(c,**changes))

    def request(self,fd,action):
        value=history_fixture.LocalHistoryTests.request(self,fd,action)
        value['context'].update(platform='ios',stageOperationId=STAGE);return value
    def history(self,f,**kwargs):
        self.root,self.home,self.base=f.root,f.home,f.base
        return history_fixture.LocalHistoryTests.run_original(self,'review-external-readiness',**kwargs)
    def test_restart_observation_retains_previous_finality_warning(self):
        f,_,_,case=self.prepare();t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t));raw=Path(e.service.record._output).read_bytes()
        t,events,e=self.history(f);self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        r=t['result']['readinessReceipt'];self.assertEqual(r['receiptSha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(r['observation'],'current-external-readiness-files-only');self.assertEqual(r['priorExecutionFinality'],'not-established')
        self.assertEqual(len(r),19);self.assertEqual(t['lifetime']['commands'],0)
        self.assertEqual([v[0] for v in events],['lease-ready','history-head']);self.assertTrue(e.service.stage_inputs.closed)
    def test_fresh_restart_can_observe_anchored_readonly_row_after_ack_loss(self):
        f,_,_,case=self.prepare();t,e,_,_,_=f.run_original(_reconcile=True,fault='external-ready')
        self.assertNotEqual(t['outcome'],'complete');t,_,e=self.history(f)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(t['result']['readinessReceipt']['priorExecutionFinality'],'not-established')
    def test_changed_raw_readiness_is_not_adopted_from_its_own_authority(self):
        f,_,_,case=self.prepare();t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t));path=Path(e.service.record._output)
        body=json.loads(path.read_bytes());body['observedBy']['authorizationId']='99999999-9999-4999-8999-999999999999';path.write_bytes(canonical(body))
        t,_,e=self.history(f);self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertTrue(e.service.closed())
    def test_last_source_original_change_prevents_readiness_publication(self):
        f,_,_,case=self.prepare()
        def change(engine):
            (f.root/'.mobile-release/store/local'/UUID(STAGE).hex/'operation-intent.json').write_bytes(b'changed across eighth original status')
        f.stage_final_source=change;t,e,events,calls,_=f.run_original(_reconcile=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(len(calls),15)
        self.assertNotIn('external-ready',events);self.assertEqual(f.current_phase(),'settled-success')
    def test_consumed_tree_close_unknown_cannot_publish_or_fund_final_tree(self):
        f,_,_,case=self.prepare();t,e,events,_,_=f.run_original(_reconcile=True,fault='stage-tree-close')
        self.assertEqual(t['outcome'],'unknown',case.detail(e,t));self.assertIsNone(t['result']);self.assertFalse(e.service.closed())
        self.assertNotIn('external-ready',events);self.assertEqual(f.current_phase(),'settled-success')
    def test_production_uses_separate_readiness_digest_not_replacement_execution(self):
        f,_,_,case=self.prepare();external_hash=f.value['context']['executionReceiptSha256']
        t,e,_,_,_=f.run_original(_reconcile=True);self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        self.production(f,case,external_hash,t['result']['readinessReceipt']['receiptSha256'])
    def production(self,f,case,external_hash,readiness_hash,*,blocked=False):
        from test_local_store_stages import documents,raw_receipt
        from mobile_release import _desktop_store_prepare_protocol as prepare_wire,_desktop_store_execute_protocol as execute_wire
        stage='88888888-8888-4888-8888-888888888888'
        c=f.value['context'];c.update(operation='local-store-prepare',stage='production-submit',predecessorOperationId=STAGE,
            predecessorReceiptSha256=external_hash,confirmation='production-submit:ios:1.2.3:42')
        for k in ('action','stageOperationId','intentSha256','executionReceiptSha256'):c.pop(k)
        f.value['protocol']=prepare_wire.PROTOCOL;f.value['operationId']=UUID(stage).hex
        value,_,_=documents('ios','production-submit');f.stage_precondition=value['storePrecondition'];f.stage_precondition['appIdentity']=f.manifest['bundleId']
        f.stage_snapshot=lambda argv,env,value:(value,0)
        t,e,_,calls,_=f.run_original();self.assertEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(t['result']['headSequence'],14)
        intent=json.loads((f.root/'.mobile-release/store/local'/UUID(stage).hex/'operation-intent.json').read_bytes())
        self.assertEqual(intent['predecessors']['externalReceiptSha256'],external_hash)
        self.assertEqual(intent['predecessors']['externalReadinessReceiptSha256'],readiness_hash)
        c.update(operation='local-store-execute',stageOperationId=stage,intentSha256=intent['integrity']['sha256']);f.value['protocol']=execute_wire.PROTOCOL
        def execute(argv,env):
            ctx=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE']);receipt=raw_receipt(dict(intent,authorizedBy={}))
            for key in ('authorizedBy','executedBy'):receipt.pop(key)
            receipt.update(documentType='local-store-execution-receipt',schemaVersion=1,origin='local-desktop',project=intent['project'],operationId=stage,
                candidateOperationId=intent['candidateOperationId'],candidateSha256=intent['candidateSha256'],stage='production-submit',preparedBy=intent['preparedBy'],executedBy=ctx['authority'])
            return receipt,0
        f.execution_receipt=execute;t,e,_,calls,_=f.run_original(_execute=True)
        if blocked:
            self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result'])
            self.assertEqual(len(calls),6);self.assertEqual(f.current_phase(),'prepared');return
        self.assertEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(t['result']['headSequence'],16);self.assertEqual(len(calls),15)

    def test_final_ack_stop_joins_reply_without_reporting_old_or_new_success(self):
        f,_,_,case=self.prepare();t,e,events,calls,_=f.run_original(_reconcile=True,fault='ack-stop')
        self.assertEqual(t['outcome'],'cancelled',case.detail(e,t));self.assertIsNone(t['result']);self.assertEqual(len(calls),15)
        self.assertEqual(e.input.reply_step,3);self.assertFalse(e.input.material_receiving);self.assertFalse(e.input.reading)
        self.assertEqual(f.current_phase(),'external-ready');self.assertTrue(e.service.closed())
    def test_readiness_is_not_a_second_refresh_or_loose_file_adoption(self):
        f,_,observed,case=self.prepare();t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        # Current new invocation AUTH differs, so original output collision is
        # not what protects the one allowed journal suffix.
        f.readiness_authorization='99999999-9999-4999-8999-999999999999'
        t,e,events,calls,_=f.run_original(_reconcile=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertEqual(events,['lease-ready'])
        self.assertEqual(len(calls),6);self.assertFalse(e.input._material_read);self.assertEqual(len(observed),1)
        self.assertEqual(f.current_phase(),'external-ready');self.assertTrue(e.service.closed())

    def test_same_byte_replacement_between_predecessor_reads_is_not_adopted(self):
        from mobile_release.local_store_predecessor import StorePredecessorInputs
        f,_,_,case=self.prepare();t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        original=StorePredecessorInputs._readiness_receipt;seen=[]
        def replace(owner,rows,facts):
            entry=next(v for v in owner.bindings if v[0].path.name==UUID(STAGE).hex)
            path=entry[0].path/'operation-intent.json';binding=copy.deepcopy(entry[2]['operation-intent.json'])
            old=path.stat();replacement=path.with_name('replacement-fixture')
            replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);replacement.replace(path)
            seen.append([old.st_ino,path.stat().st_ino,binding,None])
            try:return original(owner,rows,facts)
            finally:seen[-1][3]=copy.deepcopy(entry[2]['operation-intent.json'])
        with patch.object(StorePredecessorInputs,'_readiness_receipt',replace):t,_,e=self.history(f)
        self.assertTrue(seen);self.assertNotEqual(seen[0][0],seen[0][1]);self.assertEqual(seen[0][2],seen[0][3])
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result'])
        self.assertTrue(e.service.closed())

    def capture_marker(self,f):
        paths=list((f.root/'.mobile-release/store/lane-attempts-v1').glob('*.pending'))
        self.assertEqual(len(paths),1)
        path=paths[0];return path,path.stat().st_ino,path.read_bytes()
    def fresh_success(self,f,case,readback):
        f.execution_receipt=readback;f.readiness_authorization='99999999-9999-4999-8999-999999999999'
        t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t));return t
    def test_known_failed75_retires_only_current_marker_then_fresh_auth_can_reach_production(self):
        f,_,_,case=self.prepare();readback=f.execution_receipt;markers=[]
        old_files={p:p.read_bytes() for p in (f.root/'.mobile-release/store/local').rglob('*') if p.is_file()}
        def unavailable(argv,env):
            readback(argv,env);markers.append(self.capture_marker(f));return None,75
        f.execution_receipt=unavailable;t,e,events,calls,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'refused',case.detail(e,t));self.assertIsNone(t['result']);self.assertEqual(len(calls),13)
        self.assertEqual(events,['lease-ready','history-head']);self.assertEqual(f.current_phase(),'settled-success')
        pending=e.service.record._pending_attempt;self.assertEqual(pending.phase,'RETIRED');self.assertTrue(pending.handles_closed())
        self.assertTrue(e.service.closed());self.assertFalse(markers[0][0].exists())
        self.assertEqual(old_files,{p:p.read_bytes() for p in old_files})
        # Retired marker is not permission to reuse its already created output.
        t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertNotEqual(t['outcome'],'complete');self.assertIsNone(t['result']);self.assertEqual(len(markers),1)
        t=self.fresh_success(f,case,readback)
        self.production(f,case,f.value['context']['executionReceiptSha256'],t['result']['readinessReceipt']['receiptSha256'])
    def test_semantic_bad_receipt_retires_own_known_closed_marker_without_success(self):
        f,_,_,case=self.prepare();readback=f.execution_receipt;markers=[]
        self.mutate_receipt=lambda r:r.update(state='submitted-for-review')
        def bad(argv,env):markers.append(self.capture_marker(f));return readback(argv,env)
        f.execution_receipt=bad;t,e,_,calls,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'refused',case.detail(e,t));self.assertIsNone(t['result']);self.assertEqual(len(calls),13)
        self.assertEqual(f.current_phase(),'settled-success');self.assertEqual(e.service.record._pending_attempt.phase,'RETIRED')
        self.assertTrue(e.service.record._pending_attempt.handles_closed());self.assertFalse(markers[0][0].exists())
        del self.mutate_receipt;self.fresh_success(f,case,readback)
    def test_unknown_tree_close_preserves_marker_and_blocks_later_production(self):
        f,_,_,case=self.prepare();readback=f.execution_receipt;markers=[]
        def observe(argv,env):markers.append(self.capture_marker(f));return readback(argv,env)
        f.execution_receipt=observe;t,e,_,_,_=f.run_original(_reconcile=True,fault='stage-tree-close')
        self.assertEqual(t['outcome'],'unknown',case.detail(e,t));self.assertIsNone(t['result'])
        pending=e.service.record._pending_attempt;self.assertEqual(pending.phase,'PENDING');self.assertTrue(pending.handles_closed())
        path,inode,raw=markers[0];self.assertEqual((path.stat().st_ino,path.read_bytes()),(inode,raw))
        t=self.fresh_success(f,case,readback)
        self.production(f,case,f.value['context']['executionReceiptSha256'],t['result']['readinessReceipt']['receiptSha256'],blocked=True)
        self.assertEqual((path.stat().st_ino,path.read_bytes()),(inode,raw))
    def test_missing_original_terminal_never_retires_marker(self):
        f,_,_,case=self.prepare();readback=f.execution_receipt;markers=[]
        def observe(argv,env):markers.append(self.capture_marker(f));return readback(argv,env)
        f.execution_receipt=observe;t,e,_,_,_=f.run_original(_reconcile=True,fault='nested-terminal')
        self.assertEqual(t['outcome'],'unknown',case.detail(e,t));self.assertIsNone(t['result'])
        pending=e.service.record._pending_attempt;self.assertEqual(pending.phase,'PENDING');self.assertTrue(pending.handles_closed())
        path,inode,raw=markers[0];self.assertEqual((path.stat().st_ino,path.read_bytes()),(inode,raw))
    def test_changed_current_marker_refuses_retirement_and_closes_its_original_handles(self):
        f,_,_,case=self.prepare();readback=f.execution_receipt;markers=[]
        def changed(argv,env):
            readback(argv,env);path,inode,raw=self.capture_marker(f)
            path.write_bytes(raw+b' ');markers.append((path,inode,raw+b' '));return None,75
        f.execution_receipt=changed;t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result'])
        pending=e.service.record._pending_attempt;self.assertNotEqual(pending.phase,'RETIRED');self.assertTrue(pending.handles_closed())
        path,inode,raw=markers[0];self.assertEqual((path.stat().st_ino,path.read_bytes()),(inode,raw))
    def test_foreign_marker_survives_known_failure_fresh_readiness_and_production_refusal(self):
        f,_,_,case=self.prepare();readback=f.execution_receipt
        path=f.root/'.mobile-release/store/lane-attempts-v1'/('f'*64+'.pending')
        path.write_bytes(b'foreign unknown mutation marker\n');path.chmod(0o600);inode=path.stat().st_ino;raw=path.read_bytes()
        def unavailable(argv,env):readback(argv,env);return None,75
        f.execution_receipt=unavailable;t,e,_,_,_=f.run_original(_reconcile=True)
        self.assertEqual(t['outcome'],'refused',case.detail(e,t));self.assertEqual(e.service.record._pending_attempt.phase,'RETIRED')
        self.assertEqual((path.stat().st_ino,path.read_bytes()),(inode,raw))
        t=self.fresh_success(f,case,readback)
        self.production(f,case,f.value['context']['executionReceiptSha256'],t['result']['readinessReceipt']['receiptSha256'],blocked=True)
        self.assertEqual((path.stat().st_ino,path.read_bytes()),(inode,raw))
