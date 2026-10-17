"""Actual saved iOS Execute/input/source/journal/files, inert native/ASC only."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from mobile_release import local_store_execute as S,_desktop_store_execute_protocol as W
from mobile_release.local_release_journal import canonical
from test_local_store_prepare import OP
import test_local_ios_store_prepare as prepare_fixture


class IOSStoreExecuteBudgetTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path.home());self.addCleanup(self.tmp.cleanup)
        home=Path(self.tmp.name)/'nested'/'workspace'/'account'/'home'
        home.mkdir(parents=True,mode=0o700)
        env=patch.dict(os.environ,{'HOME':str(home)})
        env.start();self.addCleanup(env.stop)
        self.f=IOSStoreExecuteTests(methodName='runTest')
        self.f.setUp();self.addCleanup(self.f.doCleanups)

    def test_deep_project_uses_actual_source_topology_without_raising256(self):
        self.assertGreaterEqual(len(self.f.f.root.parts),9)
        t,e,_,calls,high=self.f.f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',''.join(__import__('traceback').format_exception(e.primary)))
        self.assertEqual(len(calls),16);self.assertEqual(self.f.f.current_phase(),'settled-success')
        self.assertEqual(e.service.observation.descriptor_quote(),
            S.source_descriptor_quote(self.f.f.root,'release/version.properties','main'))
        self.assertLess(e.service.observation.descriptor_quote(),96)
        self.assertLessEqual(high,e.service.quote['total']);self.assertLessEqual(e.service.quote['total'],256)
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed())

    def test_full_phase_overflow_or_bad_saved_input_never_opens_invocation(self):
        for fault in ('full-quote','saved'):
            with self.subTest(fault=fault), patch.object(S,'invocation_custody',side_effect=AssertionError('no invocation before full quote')):
                with patch.object(S,'source_descriptor_quote',return_value=96):
                    t,e,events,calls,_=self.f.f.run_original(_execute=True,fault='saved' if fault=='saved' else None)
                self.assertEqual(t['outcome'],'refused');self.assertEqual(calls,[]);self.assertEqual(events,[])
                self.assertIsNone(e.service.invocation);self.assertIsNone(e.service.quote)
                self.assertFalse(e.input._material_read);self.assertTrue(e.service.closed())
                self.assertTrue(e.input.material_closed());self.assertEqual(self.f.f.current_phase(),'prepared')
                if fault=='full-quote':self.assertIsNotNone(e.service.config)

    def test_shared_source_quote_bounds_and_validation_are_preserved(self):
        from mobile_release.local_release_source import LocalSourceError,LocalSourceObservation,MAX_HELD
        from types import SimpleNamespace
        root=self.f.f.root
        for depth in range(1,100):
            branch='/'.join(['b']*depth)
            try:count=S.source_descriptor_quote(root,'release/version.properties',branch)
            except LocalSourceError:
                self.assertEqual(previous,MAX_HELD);break
            self.assertEqual(LocalSourceObservation.descriptor_quote(SimpleNamespace(root=root,
                version_path='release/version.properties',branch=branch)),count)
            previous=count
        else:self.fail('source bound was not enforced')
        for version,branch in [('../outside','main'),('.git/index','main'),('release/version.properties','../main')]:
            with self.subTest(version=version,branch=branch),self.assertRaises(LocalSourceError):
                S.source_descriptor_quote(root,version,branch)

class IOSStoreExecuteTests(unittest.TestCase):
    def setUp(self):
        self.f=prepare_fixture.IOSStorePrepareTests(methodName='runTest');self.f.setUp();self.addCleanup(self.f.doCleanups)
        t,e,_,_,_=self.f.run_original();self.assertEqual(t['outcome'],'complete',repr(e.primary))
        self.prepared=self.f.root/'.mobile-release/store/local'/OP.replace('-','')
        self.intent=json.loads((self.prepared/'operation-intent.json').read_bytes())
        self.apps=self.f.base/'Applications';self.app=self.apps/'Xcode.app';self.dev=self.app/'Contents/Developer'
        self.dev.mkdir(parents=True);self.altool=self.app/'Contents/Tools/altool';self.altool.parent.mkdir()
        self.altool.write_bytes(b'inert executable');self.altool.chmod(0o755)
        self.xcrun=self.f.base/'xcrun';self.xcrun.write_bytes(b'inert resolver');self.xcrun.chmod(0o755)
        from mobile_release import ios_current_tools_macos as current
        original_tool=current.tool_data;original_root=S.LocalStoreExecuteRun._root_data
        # Model only protected system UID/platform nomination. All actual file
        # descriptors, nofollow walks, identity/bytes/closes and ledger stay real.
        def tool(st):return dict(original_tool(st),uid=0,gid=0)
        def root(st):return dict(original_root(st),uid=0,gid=0)
        def protected(st,directory=False):
            self.assertTrue(stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))
            self.assertIn(st.st_uid,(0,os.getuid()))
            if not directory:self.assertEqual(st.st_nlink,1);self.assertTrue(st.st_mode&0o111)
        for boundary in (patch.object(W,'APPLICATIONS',self.apps),patch.object(S,'XCRUN',self.xcrun),
                patch.object(current,'tool_data',tool),patch.object(S.LocalStoreExecuteRun,'_root_data',staticmethod(root)),
                patch.object(S.LocalStoreExecuteRun,'_upload_protected',staticmethod(protected))):
            boundary.start();self.addCleanup(boundary.stop)
        self.f.value['protocol']=W.PROTOCOL;self.f.value['context'].update(operation='local-store-execute',intentSha256=self.intent['integrity']['sha256'])
        self.f.value['native'].update(signingTools={k:tool(self.xcrun.stat()) for k in ('security','codesign','openssl')},
            uploadSelection=dict(schemaVersion=1,developerDirectory=str(self.dev),appIdentity=root(self.app.stat()),
                developerIdentity=root(self.dev.stat()),xcrun=tool(self.xcrun.stat())))
        self.f.execution_receipt=self.receipt;self.f.resolve_tool=self.resolve;self.f.after_lane=self.after_lane
        self.resolutions=[];self.contexts=[]
    def resolve(self,argv,kw,e,fault):
        self.assertEqual(tuple(argv),(str(self.xcrun),'--no-cache','--find','altool'))
        self.assertEqual(kw['environ'],dict(PATH='/usr/bin:/bin:/usr/sbin:/sbin',LANG='C',LC_ALL='C',DEVELOPER_DIR=str(self.dev)))
        self.assertLessEqual(kw['timeout'],10);self.assertEqual(kw['output_limit'],4097)
        self.resolutions.append(tuple(argv));e.guard.lifetime_ledger._commands+=1;e.guard.lifetime_ledger._command_dispatched=True
        output=(str(self.altool)+'\n').encode()
        if fault=='resolve-outside':output=(str(self.xcrun)+'\n').encode()
        if fault=='resolve-extra':output+=b'/private/other/altool\n'
        if fault=='resolve-link':self.altool.unlink();self.altool.symlink_to(self.xcrun)
        if fault=='resolve-parent':self.app.rename(self.apps/'Old.app');self.dev.mkdir(parents=True)
        return subprocess.CompletedProcess(argv,9 if fault=='resolve-nonzero' else 0,stdout=output,stderr=b'')
    def receipt(self,argv,env):
        i=self.intent;context=json.loads(env['MOBILE_RELEASE_STORE_LANE_LOCAL_EXECUTE']);self.contexts.append(context)
        self.assertEqual(set(context),{'authority','expectedIntentSha256','signingTools','transportTools'})
        self.assertEqual(context['signingTools'],self.f.value['native']['signingTools'])
        self.assertEqual(context['transportTools']['selection'],self.f.value['native']['uploadSelection'])
        self.assertEqual(context['transportTools']['altoolPath'],str(self.altool))
        self.assertEqual(env['DEVELOPER_DIR'],str(self.dev));self.assertNotIn('JAVA_HOME',env)
        self.assertEqual(env['MOBILE_RELEASE_IOS_IPA_PATH'],str(self.f.bundle/'export/App.ipa'))
        self.assertEqual(env['MOBILE_RELEASE_IOS_ARCHIVE_PATH'],str(self.f.bundle/'archive.xcarchive'))
        value=dict(documentType='local-store-execution-receipt',schemaVersion=1,origin='local-desktop',
            project=i['project'],operationId=i['operationId'],candidateSha256=i['candidateSha256'],
            operationIntentSha256=i['integrity']['sha256'],preparedBy=i['preparedBy'],executedBy=context['authority'],
            operation='ios_testflight_internal',platform='ios',appIdentity=i['application']['id'],
            marketingVersion=i['version']['marketing'],buildNumber=i['version']['build'],observedAt='2026-10-17T00:00:00Z',
            result='accepted',state='processed',appStoreAppId=i['application']['storeAppId'],buildResourceId='12345678-1234-1234-1234-123456789abc',
            processingState='VALID',autoNotifyEnabled=False)
        if hasattr(self,'change_receipt'):self.change_receipt(value)
        return value,0
    def after_lane(self,e,fault):
        if fault=='tool-post':self.altool.write_bytes(b'changed executable')
    def test_actual16_and_pending_before_material_current_receipt_and_original_closes(self):
        before={p:p.read_bytes() for p in self.prepared.iterdir()}
        t,e,events,calls,high=self.f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',''.join(__import__('traceback').format_exception(e.primary)))
        self.assertEqual(len(calls),16);self.assertEqual(t['lifetime']['commands'],16);self.assertEqual(events,list(W.PHASES))
        self.assertEqual(len(self.resolutions),1);self.assertEqual(len(e.service._source_rows),8)
        self.assertEqual([r['kind'] for r in e.service._runtime_rows],['tool-resolution']+['probe']*5+['apple-key','lane'])
        self.assertEqual(e.service.bundle.tree_reads,2);self.assertTrue(e.service.bundle.tree_closed())
        self.assertTrue(e.service.closed());self.assertTrue(e.input.material_closed());self.assertTrue(e.service.store_completed)
        self.assertEqual(self.f.current_phase(),'settled-success');self.assertLessEqual(high,e.service.quote['total'])
        self.assertLessEqual(e.service.quote['total'],256);self.assertEqual(before,{p:p.read_bytes() for p in self.prepared.iterdir()})
        r=t['result'];W.validate_result(r,platform='ios');self.assertEqual(r['scope'],'local-ios-store-execute')
        self.assertEqual(len(r['executionReceipt']),14);self.assertEqual(r['headSequence'],7)
        self.assertEqual(r['executionReceipt']['destination'],{'channel':'testflight-internal'})
        with self.assertRaises(ValueError):W.validate_result(r)
        self.assertNotIn(str(self.f.root),json.dumps(t));self.assertNotIn('PRIVATE',json.dumps(t))
    def test_resolution_refusal_precedes_pending_material_and_lane(self):
        for index,fault in enumerate(('resolve-nonzero','resolve-outside','resolve-extra','resolve-link','resolve-parent')):
            with self.subTest(fault=fault):
                if index:self.doCleanups();self.setUp()
                t,e,events,calls,_=self.f.run_original(_execute=True,fault=fault)
                self.assertIsNone(t['result']);self.assertEqual(len(calls),7);self.assertEqual(events,['lease-ready'])
                self.assertEqual(self.f.current_phase(),'prepared');self.assertFalse(e.input._material_read)
                self.assertTrue(e.input.material_closed());self.assertTrue(e.service.closed(),repr(e.primary))
    def test_pending_and_bad_asc_refuse_without_lane(self):
        for index,(fault,count) in enumerate((('execute-pending',7),('bad-p8',13))):
            with self.subTest(fault=fault):
                if index:self.doCleanups();self.setUp()
                t,e,events,calls,_=self.f.run_original(_execute=True,fault=fault)
                self.assertIsNone(t['result']);self.assertEqual(len(calls),count);self.assertEqual(self.f.current_phase(),'execute-pending')
                self.assertFalse(self.contexts);self.assertTrue(e.input.material_closed());self.assertTrue(e.service.closed())
    def test_late_tool_source_receipt_or_nested_failure_preserves_pending(self):
        for index,fault in enumerate(('tool-post','last-source','bundle-post','nested-terminal')):
            with self.subTest(fault=fault):
                if index:self.doCleanups();self.setUp()
                t,e,events,calls,_=self.f.run_original(_execute=True,fault=fault)
                self.assertIsNone(t['result']);self.assertFalse(e.service.store_completed);self.assertEqual(self.f.current_phase(),'execute-pending')
                self.assertNotIn('execute-settled',events);self.assertTrue(list((self.f.root/'.mobile-release/store/lane-attempts-v1').iterdir()))
                self.assertTrue(e.input.material_closed())
    def test_ack4_stop_and_work_timeout_are_drained_but_not_success(self):
        for index,(fault,stop) in enumerate((('ack-stop','cancelled'),('ack-time','timed-out'))):
            with self.subTest(fault=fault):
                if index:self.doCleanups();self.setUp()
                parsed=[];reply=W.reply
                def receive(raw,request,kind,step):
                    value=reply(raw,request,kind,step)
                    if step==4:parsed.append(step)
                    return value
                with patch.object(W,'reply',receive):t,e,events,calls,_=self.f.run_original(_execute=True,fault=fault)
                self.assertEqual(parsed,[4]);self.assertIsNone(t['result']);self.assertEqual(t['lifetime']['stopObserved'],stop)
                self.assertEqual(len(calls),16);self.assertTrue(e.service.store_completed);self.assertEqual(self.f.current_phase(),'settled-success')
                self.assertTrue(e.input.material_closed());self.assertTrue(e.service.closed())
    def test_original_unknown_tool_close_preserves_cancel_and_blocks_final_tree(self):
        t,e,events,calls,_=self.f.run_original(_execute=True,fault='tool-close-cancel')
        self.assertEqual((t['outcome'],t['reason'],t['lifetime']['stopObserved']),('unknown','cleanup-unknown','cancelled'))
        self.assertIsNone(t['result']);self.assertEqual(len(calls),16);self.assertFalse(e.service.store_completed)
        self.assertEqual(e.service.bundle.tree_reads,1);self.assertFalse(e.service.closed());self.assertTrue(e.input.material_closed())
        self.assertTrue(all(p.closed() for p in (*e.service.prepared_readers,*e.service.fence_readers)))
    def test_exact_context_native_selection_and_receipt_grammars_remain_platform_closed(self):
        self.assertEqual(W.context(self.f.value['context']),self.f.value['context'])
        self.assertEqual(W.upload_selection(self.f.value['native']['uploadSelection']),self.f.value['native']['uploadSelection'])
        for change in (lambda c:c.update(toolchainSelection={}),lambda c:c.update(operation='local-store-reconcile'),
                       lambda c:c.update(confirmation='candidate:android:1.2.3:42'),lambda c:c.update(platform='android')):
            c=copy.deepcopy(self.f.value['context']);change(c)
            with self.assertRaises(ValueError):W.context(c)
        for change in (lambda n:n.update(schemaVersion=True),lambda n:n['xcrun'].update(uid=1),
                       lambda n:n['developerIdentity'].update(mode=stat.S_IFDIR|0o777),
                       lambda n:n.update(developerDirectory=str(self.dev/'wrong')),lambda n:n.update(altoolPath=str(self.altool))):
            n=copy.deepcopy(self.f.value['native']['uploadSelection']);change(n)
            with self.assertRaises(ValueError):W.upload_selection(n)
        from mobile_release import _desktop_local_history_protocol as h
        row=dict(projectId='p',executionMode='local',action='review-execution',platform='ios',candidateOperationId=OP)
        self.assertEqual(h.context(row),row)
        for action in ('review-recovery',):
            with self.assertRaises(ValueError):h.context({**row,'action':action})
    def test_actual_resolved_original_quote_exact_fit_and_pre_effect_overflow(self):
        # Exact three independently held walks: initial xcrun, selectedDeveloper,
        # resolved altool; the reader never deduplicates numeric/inode slots.
        needed=len(self.xcrun.parts)+len(self.dev.parts)-1+len(self.altool.parts)-1
        with patch.object(S,'UPLOAD_TOOL_SLOTS',needed):t,e,_,_,_=self.f.run_original(_execute=True)
        self.assertEqual(t['outcome'],'complete',repr(e.primary));self.assertEqual(len(e.service.tool_reader.descriptors),needed)
        self.doCleanups();self.setUp()
        with patch.object(S,'UPLOAD_TOOL_SLOTS',needed-1):t,e,events,calls,_=self.f.run_original(_execute=True)
        self.assertIsNone(t['result']);self.assertEqual(len(calls),7);self.assertEqual(events,['lease-ready'])
        self.assertEqual(self.f.current_phase(),'prepared');self.assertFalse(e.input._material_read);self.assertTrue(e.service.closed())
    def test_invalid_processing_receipt_and_publication_unknown_do_not_authorize_retry(self):
        for index,kind in enumerate(('processing','notify','foreign-auth','publication-post','publication-close')):
            with self.subTest(kind=kind):
                if index:self.doCleanups();self.setUp()
                if hasattr(self,'change_receipt'):del self.change_receipt
                if kind=='processing':self.change_receipt=lambda r:r.update(processingState='PROCESSING')
                elif kind=='notify':self.change_receipt=lambda r:r.update(autoNotifyEnabled=True)
                elif kind=='foreign-auth':self.change_receipt=lambda r:r.update(executedBy=r['preparedBy'])
                t,e,events,calls,_=self.f.run_original(_execute=True,fault=kind if kind.startswith('publication-') else None)
                self.assertIsNone(t['result']);self.assertEqual(len(calls),16 if kind.startswith('publication-') else 14)
                self.assertEqual(self.f.current_phase(),'settled-success' if kind.startswith('publication-') else 'execute-pending')
                if kind=='publication-close':self.assertEqual(t['outcome'],'unknown');self.assertFalse(e.service.closed())
                self.assertTrue(e.input.material_closed())
                if hasattr(self,'change_receipt'):del self.change_receipt
    def test_restart_current_receipt_review_does_not_reconstruct_old_finality(self):
        from test_local_release_history import LocalHistoryTests
        t,e,_,calls,_=self.f.run_original(_execute=True,fault='execute-settled')
        self.assertIsNone(t['result']);self.assertEqual(len(calls),16);self.assertEqual(self.f.current_phase(),'settled-success')
        target=Path(e.service.record._output);before=target.read_bytes()
        t,events,h=LocalHistoryTests.run_original(self.f,'review-execution')
        self.assertEqual(t['outcome'],'complete',repr(h.primary));summary=t['result']['executionReceipt']
        self.assertEqual(len(summary),16);self.assertEqual(summary['receiptSha256'],hashlib.sha256(before).hexdigest())
        self.assertEqual(summary['bundleId'],self.intent['application']['id']);self.assertEqual(summary['appStoreAppId'],self.intent['application']['storeAppId'])
        self.assertEqual(summary['observation'],'current-execution-files-only');self.assertEqual(summary['priorExecutionFinality'],'not-established')
        self.assertEqual(t['lifetime']['commands'],0);self.assertEqual([v[0] for v in events],['lease-ready','history-head'])
        self.assertTrue(h.service.bundle.tree_closed());self.assertEqual(target.read_bytes(),before)
        target.write_bytes(before+b' ')
        t,_,h=LocalHistoryTests.run_original(self.f,'review-execution')
        self.assertEqual(t['outcome'],'refused');self.assertIsNone(t['result']);self.assertEqual(target.read_bytes(),before+b' ')
