"""Same original Engine later Execute consumes the retained stage metadata."""
import json
from pathlib import Path
from uuid import UUID
import unittest
from mobile_release import _desktop_store_execute_protocol as wire
from mobile_release.local_release_receipt import validate_local_execution_receipt
from mobile_release.local_release_journal import canonical
import test_local_store_stage_prepare as prepare_fixture
from test_local_store_stages import raw_receipt

class LocalStoreStageExecuteTests(unittest.TestCase):
    def prepare(self,platform):
        case=prepare_fixture.LocalStoreStagePrepareTests(methodName='runTest');self.addCleanup(case.doCleanups)
        f,_,_=case.prepare(platform);t,e,_,_,_=f.run_original()
        self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        out=f.root/'.mobile-release/store/local'/UUID(prepare_fixture.STAGE).hex
        intent=json.loads((out/'operation-intent.json').read_bytes());observed=[]
        f.value['protocol']=wire.PROTOCOL;f.value['context'].update(operation='local-store-execute',
            stageOperationId=prepare_fixture.STAGE,intentSha256=intent['integrity']['sha256'])
        def receipt(argv,env):
            ctx=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE']);observed.append(ctx)
            self.assertEqual(set(ctx),{'authority','expectedIntentSha256','metadataInputs'})
            self.assertEqual((Path(ctx['metadataInputs']['root'])/platform/'en-US/title.txt').read_bytes(),b'Original stage title\n')
            self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_STAGE',env)
            body=raw_receipt(dict(intent,authorizedBy={}))
            for key in ('authorizedBy','executedBy'):body.pop(key)
            body.update(documentType='local-store-execution-receipt',schemaVersion=1,origin='local-desktop',
                project=intent['project'],operationId=intent['operationId'],candidateSha256=intent['candidateSha256'],
                candidateOperationId=intent['candidateOperationId'],stage=intent['stage'],preparedBy=intent['preparedBy'],executedBy=ctx['authority'])
            validate_local_execution_receipt(canonical(body),intent_data=canonical(intent),authority_data=canonical(ctx['authority']),
                purpose='execute',expected_intent_sha256=intent['integrity']['sha256'],platform=platform,stage=intent['stage'])
            return body,0
        f.execution_receipt=receipt
        return f,intent,observed,case
    def check(self,platform):
        f,intent,observed,case=self.prepare(platform)
        t,e,events,calls,high=f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        self.assertEqual(len(calls),15 if platform=='ios' else 14);self.assertEqual(e.service.observation.calls,8)
        self.assertEqual(events,list(wire.PHASES));self.assertEqual(len(observed),1)
        self.assertIsNone(e.service.tool_reader);self.assertEqual(e.service.transport_tools,None)
        self.assertTrue(e.service.closed());self.assertTrue(e.service.metadata_tree.retired)
        self.assertFalse(e.service.metadata_scratch._path.exists());self.assertEqual(f.current_phase(),'settled-success')
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        self.assertEqual(t['result']['headSequence'],11)
        self.assertEqual(t['result']['executionReceipt']['operationId'],prepare_fixture.STAGE)
        self.assertEqual(t['result']['executionReceipt']['stage'],'external-testing')
        wire.validate_result(t['result'],platform=platform,selected='external-testing')
    def test_actual_android_stage_execute_uses_same_snapshot_no_tools_or_build(self):self.check('android')
    def test_actual_ios_stage_execute_uses_same_snapshot_and_private_supplementals(self):self.check('ios')

    def test_entered_stage_ack_refusal_never_reads_material_or_store(self):
        f,_,observed,case=self.prepare('android')
        t,e,events,calls,_=f.run_original(_execute=True,fault='execute-pending')
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result'])
        self.assertEqual(events,list(wire.PHASES[:3]));self.assertEqual(len(calls),6);self.assertFalse(e.input._material_read)
        self.assertEqual(observed,[]);self.assertEqual(f.current_phase(),'execute-pending');self.assertTrue(e.service.closed(),case.detail(e,t))

    def test_changed_prepared_metadata_refuses_without_tools_or_material(self):
        f,_,observed,case=self.prepare('ios')
        path=f.root/'.mobile-release/store/local'/UUID(prepare_fixture.STAGE).hex/'store-metadata.zip'
        original=path.read_bytes();path.write_bytes(original+b'foreign trailing bytes')
        t,e,events,calls,_=f.run_original(_execute=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result'])
        self.assertEqual(events,['lease-ready']);self.assertEqual(len(calls),6);self.assertFalse(e.input._material_read)
        self.assertEqual(observed,[]);self.assertEqual(f.current_phase(),'prepared');self.assertTrue(e.service.closed(),case.detail(e,t))
        self.assertEqual(path.read_bytes(),original+b'foreign trailing bytes')

    def test_last_source_stage_original_change_cannot_settle_current_attempt(self):
        f,_,observed,case=self.prepare('android')
        def change(engine):
            path=f.root/'.mobile-release/store/local'/UUID(prepare_fixture.STAGE).hex/'operation-intent.json'
            path.write_bytes(b'changed after actual last status')
        f.stage_final_source=change
        t,e,events,calls,_=f.run_original(_execute=True)
        self.assertNotEqual(t['outcome'],'complete',case.detail(e,t));self.assertIsNone(t['result'])
        self.assertEqual(len(calls),14);self.assertEqual(len(observed),1);self.assertNotIn('execute-settled',events)
        self.assertEqual(f.current_phase(),'execute-pending');self.assertTrue(list((f.root/'.mobile-release/store/lane-attempts-v1').iterdir()))

    def test_original_stage_tree_close_unknown_never_publishes_success(self):
        f,_,_,case=self.prepare('ios')
        t,e,events,_,_=f.run_original(_execute=True,fault='stage-tree-close')
        self.assertEqual(t['outcome'],'unknown',case.detail(e,t));self.assertIsNone(t['result'])
        self.assertFalse(e.service._source_final);self.assertFalse(e.service.closed());self.assertNotIn('execute-settled',events)
        self.assertEqual(f.current_phase(),'execute-pending')

    def production(self,platform):
        import hashlib
        from mobile_release.metadata import PLATFORM_METADATA_ROOTS
        from test_local_store_stages import documents
        f,intent,observed,case=self.prepare(platform)
        t,e,_,_,_=f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        prior=Path(e.service.record._output).read_bytes()
        # The accepted external receipt supplies available-to-testers, not a
        # guessed approval or readiness inferred from local native finality.
        self.assertEqual(json.loads(prior)['state'],'available-to-testers')
        stage_id='88888888-8888-4888-8888-888888888888'
        f.value['protocol']=prepare_fixture.wire.PROTOCOL;f.value['operationId']=UUID(stage_id).hex
        c=f.value['context'];c.update(operation='local-store-prepare',stage='production-submit',
            predecessorOperationId=prepare_fixture.STAGE,predecessorReceiptSha256=hashlib.sha256(prior).hexdigest(),
            confirmation=f'production-submit:{platform}:1.2.3:42')
        c.pop('stageOperationId');c.pop('intentSha256')
        value,_,_=documents(platform,'production-submit');f.stage_precondition=value['storePrecondition']
        f.stage_precondition['appIdentity']=f.manifest['bundleId' if platform=='ios' else 'applicationId']
        if platform=='android':
            f.stage_precondition['snapshot']['bundles'][0]['sha256']=f.manifest['files'][0]['sha256']
            notes=f.stage_precondition['snapshot']['targetRelease']['releaseNotes']
            for note in notes:
                p=f.root/'release/store/android'/note['language']/'changelogs/42.txt';p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(note['text'].encode());p.chmod(0o644)
        # Actual final source roster updates only inert Git responses, never
        # reuses prior source hashes as authority over changed production notes.
        f.rows=[row for row in f.rows if not row[0].startswith(b'release/store/')]
        for selected in PLATFORM_METADATA_ROOTS[platform]:
            for p in sorted((f.root/'release/store'/selected).rglob('*')):
                if p.is_file():
                    raw=p.read_bytes();f.rows.append((p.relative_to(f.root).as_posix().encode(),hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest().encode()))
        f.rows.sort()
        def snapshot(argv,env,value):
            ctx=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_STAGE'])
            self.assertEqual(ctx['stage'],'production-submit');self.assertNotIn('MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE',env)
            return value,0
        f.stage_snapshot=snapshot
        t,e,_,calls,_=f.run_original();self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        self.assertEqual(t['result']['headSequence'],13);self.assertEqual(len(calls),15 if platform=='ios' else 14)
        out=f.root/'.mobile-release/store/local'/UUID(stage_id).hex
        current=json.loads((out/'operation-intent.json').read_bytes());intent.clear();intent.update(current)
        self.assertEqual(current['predecessors']['externalReceiptSha256'],hashlib.sha256(prior).hexdigest())
        f.value['protocol']=wire.PROTOCOL;c.update(operation='local-store-execute',stageOperationId=stage_id,intentSha256=current['integrity']['sha256'])
        t,e,_,calls,high=f.run_original(_execute=True);self.assertEqual(t['outcome'],'complete',case.detail(e,t))
        self.assertEqual(t['result']['headSequence'],15);self.assertEqual(len(calls),15 if platform=='ios' else 14)
        self.assertEqual(t['result']['executionReceipt']['stage'],'production-submit');self.assertIsNone(e.service.tool_reader)
        self.assertTrue(e.service.closed());self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
    def test_actual_android_external_then_production_reuses_original_binary(self):self.production('android')
    def test_actual_ios_external_then_production_reuses_original_archive(self):self.production('ios')
