"""Actual local Engine + original disk/source/lane/receipt owners, inert sends."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest.mock import patch
from dataclasses import replace
from mobile_release import _desktop_store_execute_protocol as W
from mobile_release.local_release_receipt import validate_local_execution_receipt
from mobile_release.local_release_journal import canonical
from mobile_release.android_build_tools import MANIFEST_NAME
import test_local_store_prepare as prepare_fixture
OP=prepare_fixture.OP

class LocalStoreExecuteTests(unittest.TestCase):
    def setUp(self):
        self.f=prepare_fixture.LocalStorePrepareTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        t,e,_,_,_=self.f.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        self.prepared=self.f.root/'.mobile-release/store/local'/OP.replace('-','')
        self.intent=json.loads((self.prepared/'operation-intent.json').read_bytes())
        self.f.value['protocol']=W.PROTOCOL;c=self.f.value['context']
        # The native protected-root admission is modeled, not qualified on
        # this host. All manifest bytes/FDs/names/hash/POST/closes stay actual.
        from mobile_release import android_build_tools_macos as mac,_desktop_android_build_protocol as android_wire
        prefix=self.f.base/'registered';tools=prefix/str(os.getuid())/('1'*32)
        tools.mkdir(parents=True,mode=0o700)
        raw=canonical({'schemaVersion':1,'profile':'android-registered-macos-arm64-v1','instance':'1'*32,
            'roles':{'java':'jdk/inert.jdk/Contents/Home/bin/java','bundletool':'bundletool/bundletool.jar'}})
        (tools/MANIFEST_NAME).write_bytes(raw);(tools/MANIFEST_NAME).chmod(0o444);tools.chmod(0o555)
        self.addCleanup(tools.chmod,0o700)
        self.f.tools=tools;st=tools.stat()
        selection=dict(instance='1'*32,ownerUid=os.getuid(),catalogGeneration=1,recordSha256='2'*64,
            inventorySha256=hashlib.sha256(raw).hexdigest(),osProviderSha256='3'*64)
        binding=dict(schemaVersion=2,profile='android-registered-macos-arm64-v1',root=str(tools),
            rootIdentity=dict(device=str(st.st_dev),inode=str(st.st_ino),mode=stat.S_IFDIR|0o555,uid=0,gid=0),
            inventorySha256=selection['inventorySha256'],selection=selection)
        original_binding=mac.binding
        def native_root_model(value):
            admitted=original_binding(value) # Keep actual closed wire grammar.
            return replace(admitted,identity=(st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid))
        for boundary in (patch.object(mac,'PREFIX',str(prefix)),patch.object(android_wire,'MAC_TOOLCHAIN_PREFIX',str(prefix)),
                         patch.object(mac,'binding',side_effect=native_root_model)):
            boundary.start();self.addCleanup(boundary.stop)
        c.update(operation='local-store-execute',intentSha256=self.intent['integrity']['sha256'],toolchainSelection=selection)
        self.f.value['native']['toolchain']=binding
        self.f.execution_receipt=self.receipt
    def receipt(self,argv,env):
        from pathlib import Path
        value=json.loads((Path(__file__).resolve().parents[1]/'fixtures/local-execution-receipt-valid.json').read_bytes())
        ctx=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE']);authority=ctx['authority'];i=self.intent
        value.update(project=i['project'],operationId=i['operationId'],candidateSha256=i['candidateSha256'],
            operationIntentSha256=i['integrity']['sha256'],preparedBy=i['preparedBy'],executedBy=authority,
            appIdentity=i['application']['id'],marketingVersion=i['version']['marketing'],buildNumber=i['version']['build'],versionCode=i['version']['build'])
        # Existing platform fixture carries full exact target/digests, not only a
        # claimed versionCode. Local envelope binds our actual prepared original.
        from mobile_release.provenance import _play_digest
        snapshot=i['storePrecondition']['snapshot'];state=value['storeState']
        before,target=snapshot['destinationState'],snapshot['destinationTargetState']
        without=lambda track:[r for r in track['releases'] if str(i['version']['build']) not in r['versionCodes']]
        state.update(destinationBeforeSha256=_play_digest(before),destinationExpectedSha256=_play_digest(target),
            destinationCommittedSha256=_play_digest(target),unrelatedBeforeSha256=_play_digest(without(before),'release-set'),
            unrelatedCommittedSha256=_play_digest(without(target),'release-set'),targetReleaseSha256=_play_digest(snapshot['targetRelease'],'release'))
        if hasattr(self,'mutate_receipt'):self.mutate_receipt(value)
        return value,0
    def test_real_execute_joins_originals_and_preserves_prepared(self):
        original={p.name:p.read_bytes() for p in self.prepared.iterdir()}
        t,e,events,calls,high=self.f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',getattr(e,'inert_debug','')+''.join(__import__('traceback').format_exception(e.primary)) if e.primary else '')
        self.assertEqual(events,list(W.PHASES));self.assertEqual(len(calls),14);self.assertEqual(t['lifetime']['commands'],14)
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed());self.assertTrue(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'settled-success');self.assertEqual(t['result']['headSequence'],7)
        self.assertEqual(original,{p.name:p.read_bytes() for p in self.prepared.iterdir()})
        self.assertEqual(list((self.f.root/'.mobile-release/store/lane-attempts-v1').iterdir()),[])
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        self.assertNotIn('client_email',json.dumps(t));self.assertNotIn(str(self.f.root),json.dumps(t))
        for mutate in (lambda r:r.update(headSequence=6),lambda r:r.update(preparedIntent={}),
                       lambda r:r['executionReceipt'].update(destination={'channel':'production','releaseStatus':'completed'})):
            value=copy.deepcopy(t['result']);mutate(value)
            with self.assertRaises(W.ProtocolError):W.validate_result(value)
    def test_pending_ack_failure_sends_no_google_or_store(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='execute-pending')
        self.assertIsNone(t['result']);self.assertEqual(events,list(W.PHASES[:3]));self.assertEqual(len(calls),6)
        self.assertFalse(e.input._material_read);self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())
        self.assertEqual(self.f.current_phase(),'execute-pending')
    def test_retained_old_marker_refuses_before_pending_material_or_store(self):
        path=self.f.root/'.mobile-release/store/lane-attempts-v1/old.pending';path.write_bytes(b'old original evidence');path.chmod(0o600)
        t,e,events,calls,_=self.f.run_original(_execute=True)
        self.assertIsNone(t['result']);self.assertEqual(events,['lease-ready']);self.assertEqual(len(calls),6)
        self.assertFalse(e.input._material_read);self.assertTrue(e.service.closed());self.assertEqual(path.read_bytes(),b'old original evidence')
        self.assertEqual(self.f.current_phase(),'prepared')
    def test_last_real_source_call_drift_cannot_publish_success(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='last-source')
        self.assertIsNone(t['result']);self.assertEqual(len(calls),14);self.assertNotIn('execute-settled',events)
        self.assertFalse(e.service.store_completed);self.assertEqual(self.f.current_phase(),'execute-pending')
        self.assertTrue(list((self.f.root/'.mobile-release/store/lane-attempts-v1').iterdir()))
    def test_foreign_current_receipt_cannot_settle_attempt(self):
        self.mutate_receipt=lambda value:value.update(executedBy=value['preparedBy'])
        t,e,events,calls,_=self.f.run_original(_execute=True)
        self.assertIsNone(t['result']);self.assertNotIn('execute-settled',events);self.assertFalse(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'execute-pending');self.assertTrue(list((self.f.root/'.mobile-release/store/lane-attempts-v1').iterdir()))

    def test_entered_final_ack_failure_preserves_settled_semantics_not_native_success(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='execute-settled')
        self.assertIsNone(t['result']);self.assertEqual(events,list(W.PHASES));self.assertEqual(len(calls),14)
        self.assertTrue(e.service.closed());self.assertTrue(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'settled-success')
        self.assertEqual(list((self.f.root/'.mobile-release/store/lane-attempts-v1').iterdir()),[])
        self.assertTrue(Path(e.service.record._output).is_file())
    def test_closed_execute_context_rejects_other_origin_or_selection_types(self):
        self.assertEqual(W.context(self.f.value['context']),self.f.value['context'])
        for mutate in (lambda v:v.update(operation='local-store-prepare'),
                       lambda v:v['toolchainSelection'].update(ownerUid=True),
                       lambda v:v.update(intentSha256=''),lambda v:v.update(authority={})):
            value=copy.deepcopy(self.f.value['context']);mutate(value)
            with self.assertRaises((W.ProtocolError,ValueError)):W.context(value)
    def test_known_cancel_before_material_preserves_pending_and_actual_stop(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='cancel-after-pending')
        self.assertEqual((t['outcome'],t['reason'],t['lifetime']['stopObserved']),('cancelled','cancelled','cancelled'),repr(t['lifetime'])+repr(e.service.closed())+''.join(__import__('traceback').format_exception(e.primary)))
        self.assertIsNone(t['result']);self.assertEqual(len(calls),6);self.assertEqual(self.f.current_phase(),'execute-pending')
        self.assertFalse(e.input._material_read);self.assertTrue(e.service.closed())
    def test_unknown_original_close_preserves_observed_cancel_and_other_closes(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='tool-close-cancel')
        self.assertEqual((t['outcome'],t['reason'],t['lifetime']['stopObserved']),('unknown','cleanup-unknown','cancelled'))
        self.assertIsNone(t['result']);self.assertEqual(len(calls),14);self.assertFalse(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'execute-pending');self.assertTrue(e.input.material_closed())
        self.assertFalse(e.service.closed());self.assertTrue(all(p.closed() for p in (*e.service.prepared_readers,*e.service.fence_readers)))
        self.assertTrue(all(s.number is None for s in e.service.tool_reader.descriptors))
    def test_actual_manifest_original_change_vetoes_settlement(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='tool-manifest-post')
        self.assertIsNone(t['result']);self.assertEqual(len(calls),14);self.assertFalse(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'execute-pending');self.assertNotIn('execute-settled',events)
        self.assertTrue(e.service.closed());self.assertEqual((self.f.tools/MANIFEST_NAME).read_bytes(),b'changed original manifest')
