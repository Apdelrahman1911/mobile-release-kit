"""Fresh target-only Store readback; preserves prior journal, outputs and fences."""
import hashlib
from contextlib import ExitStack
import os
from pathlib import Path
from . import _desktop_store_reconcile_protocol as wire
from ._desktop_store_reconcile_protocol import require
from .local_store_execute import LocalStoreExecuteRun
from .local_store_prepare import resource_quote,canonical
from .build_inputs import _app_private_directory,_read_file
from .local_release_journal import recovery_chain
from . import local_recovery_fence as fence
from .local_release_receipt import validate_local_execution_receipt

class LocalStoreReconcileRun(LocalStoreExecuteRun):
    def __init__(self,request,guard,source):
        self.observed_head=None
        self.marker_scope=ExitStack();self.preserved_attempt=None;self.execution_pending=None
        super().__init__(request,guard,source)
    @property
    def readiness(self):return wire.readiness(self.request.context)
    @property
    def stage(self):return 'external-testing' if self.readiness else super().stage
    @property
    def settlement(self):return wire.settling(self.request.context)
    @property
    def apple_reconcile(self):
        return type(self) is LocalStoreReconcileRun and self.request.context['platform']=='ios' and not self.settlement
    @property
    def runtime_count(self):return 7 if self.apple_reconcile else 6
    @property
    def material_head(self):return self.observed_head
    @property
    def authority_purpose(self):return 'external-readiness' if self.readiness else 'recover'
    def _quote(self,source=96):
        if self.readiness:
            from .local_store_stage import execute_quote
            return execute_quote(self,source)
        self.checkpoint()
        q=resource_quote(project_depth=len(self.root.parts),version_parent_depth=len((self.root/self.request.context['savedVersion']['source']).parent.parts),
            source=source,history_depth=len(Path(self.request.native['home']).parts),platform=self.platform)
        # Same prepared/fence original walks as Execute; no Android tool Book,
        # manifest or native current-validator subprocess is acquired.
        extra=(3*len(self.root.parts)+18 if self.settlement else 2*len(self.root.parts)+12)
        if self.apple_reconcile:
            # Initial archive traversal precedes the prepared/fence walks; final
            # traversal follows their actual positive closes, never close credit.
            extra=2*len(self.root.parts)+7
            for key in ('pending','material','lane','source'):q[key]+=extra
            q['total']=max(v for k,v in q.items() if k!='total')
        else:q={k:v+extra for k,v in q.items()}
        require(q['total']<=256)
        if self.quote is not None:require(q['total']<=self.quote['total'])
        self.quote=q;return q
    def _begin(self):
        if self.readiness:
            from .local_store_stage import execute_begin
            return execute_begin(self)
        self.checkpoint();require(self.observation.calls==6 and not self.journals)
        self.enrollment,self.key=self.source.exchange('lease-ready',{})
        require(type(self.key) is bytearray and len(self.key)==32)
        j=self._open_journal();head=j.head();c=self.request.context
        require(j._rows[-1][0]['operationId']==c['candidateOperationId'] and 6<=head['sequence']<=513)
        rows=wire.execution_chain([r for r,_ in j._rows if r['operationId']==c['candidateOperationId']],c['candidateOperationId'])
        if self.settlement:
            recovery_chain(rows,c['candidateOperationId']);require(head['sequence']<=512)
            self.preserved_markers=fence.prior_markers(self,[r for r,_ in j._rows])
        self._admit_prepared(rows[:4]);pending=rows[4]['payload'];i=self.intent
        wire.execution_binding(i,rows);require(pending['authorizationId']!=self.authority['authorizationId'])
        self._prepared_post()
        out=fence.open_fence(self,self.marker_scope if self.settlement else self.prepared_scope);out.check()
        root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
        if self.settlement:
            require(self.authority['authorizationId']!=i['preparedBy']['authorizationId'])
            name,output=fence.expected_attempt(self,self.intent_bytes,i,pending)
            require(name not in self.preserved_markers)
            self.preserved_attempt=fence.read_marker(self,out,name,output)
            if self.preserved_attempt is not None:self.preserved_markers[name]=(self.preserved_attempt,output)
            self.execution_pending=dict(pending);fence.post(self)
            # Full record encoding stays below the existing 8KiB record limit
            # before Google, using maximum-width final digest placeholders.
            require(len(canonical(self._settlement_payload('f'*64)))+2048<=8192)
        # Ordinary read-only Reconcile still does not enumerate/adopt old markers.
        self.source.exchange('history-head',head);self.checkpoint();require(j.head()==head)
        self.observed_head=head;self._retire_journal(j)
    def _final_source_fence(self):
        if self.settlement:fence.post(self,own_pending=True)
    def source_final(self,observation):
        if self.readiness:
            from .local_store_stage import execute_final_source
            return execute_final_source(self,observation)
        require(observation is self.observation and observation.calls==8 and not self._source_final)
        self._prepared_post()
        if self.settlement:fence.post(self,own_pending=True)
        if not self.apple_reconcile:self.bundle.finish()
        self.prepared_scope.close()
        require(all(p.closed() for p in (*self.prepared_readers,*self.prior_readers))
            and (self.settlement or all(p.closed() for p in self.fence_readers)))
        if self.apple_reconcile:self.bundle.finish()
        self._source_final=True
    def runtime_environment(self):
        if self.readiness:return self.runtime.environment()
        env=self.runtime.environment()
        if self.apple_reconcile:
            self._prepared_post();self.bundle._scan();self.bundle.reader.terminal()
            env['MOBILE_RELEASE_IOS_IPA_PATH']=str(self.bundle.members[0].canonical)
            env['MOBILE_RELEASE_IOS_ARCHIVE_PATH']=str(self.bundle.archive.canonical)
        return env
    def attempt_key(self,record,root,mode,digest,authority):
        if not self.readiness:return super().attempt_key(record,root,mode,digest,authority)
        self.checkpoint();require(record is self.record and root==self.root and mode=='execute' and self._store_entered
            and digest==bytes.fromhex(self.request.context['intentSha256']) and authority==self.authority)
        from .local_release_receipt import local_readiness_attempt_key
        return local_readiness_attempt_key(intent_data=self.intent_bytes,authority_data=canonical(self.authority),
            expected_intent_sha256=self.request.context['intentSha256'],execution_receipt_sha256=self.request.context['executionReceiptSha256'])
    def attempt_directory(self,attempt,directory):
        self.checkpoint();require(attempt is self.record._pending_attempt and attempt.phase=='ACQUIRING' and self.fence_readers)
        out=self.fence_readers[0];out.check();directory.check()
        a,b=os.fstat(out.fd),os.fstat(directory.fd)
        require((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid))
        if self.settlement:fence.post(self)
    def lane_context(self,files):
        self.checkpoint();require(files is self.record._files_owner() and files.mode=='execute' and files.phase=='SEALING' and self._store_entered)
        self._prepared_post();value={'authority':self.authority,'expectedIntentSha256':self.request.context['intentSha256']}
        if self.readiness:
            self.metadata_tree.post();value.update(executionReceiptSha256=self.request.context['executionReceiptSha256'],metadataInputs=self.metadata_tree.binding_data())
        raw=canonical(value)
        require(len(raw)<=16384);return raw.decode('utf-8')
    def validate_receipt(self,raw):
        self.checkpoint();self._memory(raw,65536)
        if self.readiness:
            from .local_release_receipt import validate_local_readiness_receipt
            return validate_local_readiness_receipt(raw,intent_data=self.intent_bytes,authority_data=canonical(self.authority),
                expected_intent_sha256=self.request.context["intentSha256"],execution_receipt_sha256=self.request.context["executionReceiptSha256"])
        return validate_local_execution_receipt(raw,intent_data=self.intent_bytes,authority_data=canonical(self.authority),
            purpose='recover',expected_intent_sha256=self.request.context['intentSha256'],platform=self.platform)
    def _settlement_payload(self,digest):
        pending=self.execution_pending;require(pending is not None)
        return dict(intentSha256=pending['intentSha256'],receiptSha256=digest,
            executeAuthorizationId=pending['authorizationId'],recoveryAuthorizationId=self.authority['authorizationId'],
            assignmentRevision=pending['assignmentRevision'],preservedAttempt=self.preserved_attempt,
            priorExecutionFinality='not-established')
    def _lane_owners_closed(self):
        # Settlement alone keeps marker ancestry beyond lane/source closure.
        # It has a separate final conjunction below; no pretend close credit.
        if not self.settlement:return super()._lane_owners_closed()
        from .local_store_prepare import LocalStorePrepareRun
        return (LocalStorePrepareRun._lane_owners_closed(self) and self.prepared_iterator is None
            and self.prepared_scan_state in {'new','closed'} and self.fence_iterator is None
            and self.fence_state in {'new','closed'}
            and all(p.closed() for p in (*self.prepared_readers,*self.prior_readers)))
    def _publication(self,raw):
        if self.readiness:
            from .local_store_readiness import publication
            return publication(self,raw)
        self.checkpoint();require(self.store_completed and self._source_final and self._lane_owners_closed())
        receipt=self.validate_receipt(raw);target=Path(self.record._output)
        with _app_private_directory(target.parent,app_root=self.root,cancellation=self.guard,create=False) as out:
            require(out is not None);self.publishers.append(out)
            root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
            value=_read_file(out.fd,target.name,self.guard,65536,private=True);require(value is not None and value[1]==raw)
            binding=value[0];identity=self.record._files_owner().document_identity
            require(identity is not None and all(binding[k]==getattr(identity,k) for k in ('device','inode','uid','gid','mode')))
            # Re-open the same authentic journal. Only the closed settlement
            # variant appends; ordinary Reconcile remains read-only.
            j=self._open_journal();require(j.head()==self.observed_head)
            head=self.observed_head
            if self.settlement:
                require(self.record._pending_attempt.phase=='RETIRED');fence.post(self)
                head=j._append(expected_head=head,operation_id=self.request.context['candidateOperationId'],
                    phase='target-reconciled',payload=self._settlement_payload(hashlib.sha256(raw).hexdigest()))
                self.source.exchange('recovery-settled',{'head':head,'phase':'target-reconciled'})
                self.checkpoint();require(j.head()==head);fence.post(self)
            value=_read_file(out.fd,target.name,self.guard,65536,private=True,binding_only=True)
            require(value==(binding,b''));out.check();self._retire_journal(j)
        require(out.closed());self.checkpoint();i=self.intent
        if self.settlement:
            fence.post(self);self.marker_scope.close();require(all(p.closed() for p in self.fence_readers))
        summary=dict(operationId=i['operationId'],candidateSha256=i['candidateSha256'],intentSha256=i['integrity']['sha256'],
            receiptSha256=hashlib.sha256(raw).hexdigest(),authorizationId=self.authority['authorizationId'],
            sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],applicationId=i['application']['id'],
            version={'name':i['version']['marketing'],'build':i['version']['build']},destination=i['destination'],
            observedAt=receipt['observedAt'],result=receipt['result'],limitations=list(wire.LIMITATIONS),
            observation='current-internal-build-only' if self.apple_reconcile else 'current-internal-target-only',priorExecutionFinality='not-established')
        if self.apple_reconcile:
            summary['bundleId']=summary.pop('applicationId');summary['appStoreAppId']=i['application']['storeAppId']
        self.report={'schemaVersion':1,'scope':'local-android-recovery-settlement' if self.settlement else 'local-%s-store-reconcile'%self.platform,
            'headSequence':head['sequence'],'reconciliationReceipt':summary}
        wire.validate_result(self.report,settlement=self.settlement,platform=self.platform)
    def _close_failed_readiness(self):
        # This current original only; no pathname/history interpretation and no
        # receipt publication. Ordinary mutation/recover owners never enter it.
        from ._store_lane_files import StoreLaneAttempt
        from ._store_lane_evidence import StoreLaneCallEvidence
        from .stores import settle_store_operation
        require(type(self) is LocalStoreReconcileRun and self.readiness and self.primary is not None
            and self._close_claimed and self.source.require_operation() is self)
        record=self.record
        if record is None:return
        require(type(record) is StoreLaneCallEvidence);record._origin(self.guard)
        pending=record._pending_attempt
        if pending is None:return
        require(type(pending) is StoreLaneAttempt and pending.record is record and pending.guard is self.guard
            and pending.app_root==self.root and pending.mode=='execute')
        try:
            facts=self.guard.lifetime_ledger.verdict();verdict=record.verdict(cancellation=self.guard)
            if (pending.phase=='PENDING' and self._store_entered and self.authority is not None
                and self.authority['purpose']=='external-readiness' and self.intent_bytes is not None
                and self._request_bytes==canonical([self.request.context,self.request.native])
                and super().closed() and all(p.closed() for p in self.fence_readers)
                and not self.source.material_receiving and not self.source.material_pending
                and verdict.dependents_settled and facts.cleanup_complete and facts.contained and not facts.fatal):
                settle_store_operation(record,cancellation=self.guard,primary=self.primary)
        finally:
            # Even an ineligible unknown attempt consumes its own held handles;
            # only settle_store_operation above may retire its original marker.
            pending.close(primary=self.primary)
    def close(self):
        if self._close_claimed:return super().close()
        first=None
        try:
            error=self.primary
            if error is None:self.marker_scope.close()
            else:self.marker_scope.__exit__(type(error),error,error.__traceback__)
        except BaseException as error:self.remember(error);first=error
        try:super().close()
        except BaseException as error:
            self.remember(error)
            if first is None:first=error
        if self.readiness and self.primary is not None:
            try:self._close_failed_readiness()
            except BaseException as error:
                self.remember(error)
                if first is None:first=error
        if first is not None:raise first
    def closed(self):
        pending=None if self.record is None else self.record._pending_attempt
        return (super().closed() and all(p.closed() for p in self.fence_readers)
            and (not self.readiness or pending is None or pending.handles_closed()))
