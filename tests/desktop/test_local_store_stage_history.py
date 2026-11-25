"""Actual History restart over original positive later-stage Engine outputs."""
import copy
import hashlib
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import patch
from uuid import UUID
from mobile_release import _desktop_local_history_protocol as wire
from mobile_release.local_release_journal import LocalReleaseJournal
import test_local_release_history as history_fixture
import test_local_store_stage_execute as execute_fixture

STAGE='77777777-7777-4777-8777-777777777777'
class LocalStoreStageHistoryTests(unittest.TestCase):
    def prepare(self,platform,execution):
        case=execute_fixture.LocalStoreStageExecuteTests(methodName='runTest');self.addCleanup(case.doCleanups)
        f,intent,_,sourcecase=case.prepare(platform)
        if execution:
            t,e,_,_,_=f.run_original(_execute=True);self.assertEqual(t['outcome'],'complete',sourcecase.detail(e,t))
        self.root,self.home,self.base=f.root,f.home,f.base;self.platform=platform
        return f,intent
    def request(self,fd,action):
        value=history_fixture.LocalHistoryTests.request(self,fd,action)
        value['context'].update(platform=self.platform,stageOperationId=STAGE)
        return value
    def run_history(self,execution,**kwargs):
        return history_fixture.LocalHistoryTests.run_original(self,'review-stage-execution' if execution else 'review-stage-prepared',**kwargs)
    def positive(self,platform,execution):
        f,intent=self.prepare(platform,execution)
        before={p:p.read_bytes() for p in f.base.rglob('*') if p.is_file()}
        t,events,e=self.run_history(execution)
        self.assertEqual(t['outcome'],'complete',''.join(__import__('traceback').format_exception(e.primary)))
        self.assertEqual([r[0] for r in events],['lease-ready','history-head']);self.assertEqual(t['lifetime']['commands'],0)
        key='executionReceipt' if execution else 'preparedIntent';summary=t['result'][key]
        self.assertEqual(summary['operationId'],STAGE);self.assertEqual(summary['candidateOperationId'],intent['candidateOperationId'])
        self.assertEqual(summary['intentSha256'],intent['integrity']['sha256']);self.assertEqual(len(summary),(20 if execution else 17)+(platform=='ios'))
        self.assertEqual(summary['observation'],'current-execution-files-only' if execution else 'current-prepared-files-only')
        self.assertEqual(summary['priorExecutionFinality' if execution else 'priorPrepareFinality'],'not-established')
        self.assertTrue(e.service.closed());self.assertTrue(e.service.stage_inputs.closed)
        self.assertEqual(before,{p:p.read_bytes() for p in f.base.rglob('*') if p.is_file()})
    def test_android_prepared_restart_has_no_tool_or_store_authority(self):self.positive('android',False)
    def test_ios_prepared_restart_preserves_supplemental_prepared_binding(self):self.positive('ios',False)
    def test_android_completed_restart_is_current_files_not_old_finality(self):self.positive('android',True)
    def test_ios_completed_restart_is_current_files_not_old_finality(self):self.positive('ios',True)
    def test_foreign_current_stage_zip_refuses_without_mutating_history(self):
        f,_=self.prepare('android',False);path=f.root/'.mobile-release/store/local'/UUID(STAGE).hex/'store-metadata.zip'
        body=path.read_bytes()+b'foreign';path.write_bytes(body)
        t,events,e=self.run_history(False);self.assertEqual(t['outcome'],'refused');self.assertIsNone(t['result'])
        self.assertEqual(path.read_bytes(),body);self.assertTrue(e.service.closed());self.assertEqual(f.current_phase(),'prepared')
    def test_previous_completed_stage_remains_observable_after_new_operation(self):
        f,_=self.prepare('ios',True)
        j=LocalReleaseJournal(str(f.home),end=time.monotonic()+10,enrollment=history_fixture.ENROLLMENT,key=history_fixture.KEY);j.open_existing()
        try:
            original=j._rows[1][0]['payload']
            j._append(expected_head=j.head(),operation_id='99999999-9999-4999-8999-999999999999',phase='inputs-pending',payload=original)
        finally:j.close()
        t,_,e=self.run_history(True);self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(t['result']['headSequence'],12)
        self.assertEqual(t['result']['executionReceipt']['operationId'],STAGE)
    def test_closed_context_forbids_candidate_alias_and_foreign_platform(self):
        value=dict(projectId='current',executionMode='local',action='review-stage-prepared',platform='ios',stageOperationId=STAGE)
        self.assertEqual(wire.context(value),value)
        for change in (lambda v:v.update(candidateOperationId=STAGE),lambda v:v.pop('stageOperationId'),lambda v:v.update(platform='macos'),lambda v:v.update(stageOperationId='0'*32)):
            v=copy.deepcopy(value);change(v)
            with self.assertRaises(wire.ProtocolError):wire.context(v)

    def test_consumed_original_close_lost_return_stays_unknown_not_historical_success(self):
        f,_=self.prepare('android',True)
        from mobile_release.local_store_predecessor import StorePredecessorInputs
        original_read=StorePredecessorInputs._read;original_close=os.close;target=[None];lost=[]
        def read(reader,out,bindings,name,limit,**kwargs):
            result=original_read(reader,out,bindings,name,limit,**kwargs)
            if name=='raw-store-receipt.json' and out.path.name.startswith(UUID(STAGE).hex+'-execute-'):target[0]=out.fd
            return result
        def close(number):
            original_close(number)
            if number==target[0] and not lost:lost.append(number);raise OSError('inert lost original close result')
        with patch.object(StorePredecessorInputs,'_read',read),patch.object(os,'close',close):
            t,events,e=self.run_history(True,expect_unknown=True)
        self.assertEqual(len(lost),1);self.assertEqual(t['outcome'],'unknown');self.assertIsNone(t['result'])
        self.assertFalse(e.service.closed());self.assertEqual(f.current_phase(),'settled-success')
        self.assertEqual([r[0] for r in events],['lease-ready','history-head'])
