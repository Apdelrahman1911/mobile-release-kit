"""Fresh target-only Store readback; preserves prior journal, outputs and fences."""
import hashlib
import os
from pathlib import Path
from . import _desktop_store_reconcile_protocol as wire
from ._desktop_store_reconcile_protocol import require
from .local_store_execute import LocalStoreExecuteRun
from .local_store_prepare import resource_quote,canonical
from .build_inputs import _app_private_directory,_read_file
from .local_release_receipt import validate_local_execution_receipt

class LocalStoreReconcileRun(LocalStoreExecuteRun):
    def __init__(self,request,guard,source):
        self.observed_head=None
        super().__init__(request,guard,source)
    @property
    def material_head(self):return self.observed_head
    @property
    def authority_purpose(self):return 'recover'
    def _quote(self,source=96):
        self.checkpoint()
        q=resource_quote(project_depth=len(self.root.parts),version_parent_depth=len((self.root/self.request.context['savedVersion']['source']).parent.parts),
            source=source,history_depth=len(Path(self.request.native['home']).parts))
        # Same prepared/fence original walks as Execute; no Android tool Book,
        # manifest or native current-validator subprocess is acquired.
        extra=2*len(self.root.parts)+12;q={k:v+extra for k,v in q.items()};require(q['total']<=256)
        if self.quote is not None:require(q['total']<=self.quote['total'])
        self.quote=q;return q
    def _begin(self):
        self.checkpoint();require(self.observation.calls==6 and not self.journals)
        self.enrollment,self.key=self.source.exchange('lease-ready',{})
        require(type(self.key) is bytearray and len(self.key)==32)
        j=self._open_journal();head=j.head();c=self.request.context
        require(j._rows[-1][0]['operationId']==c['candidateOperationId'] and 6<=head['sequence']<=513)
        rows=wire.execution_chain([r for r,_ in j._rows if r['operationId']==c['candidateOperationId']],c['candidateOperationId'])
        self._admit_prepared(rows[:4]);pending=rows[4]['payload'];i=self.intent
        wire.execution_binding(i,rows);require(pending['authorizationId']!=self.authority['authorizationId'])
        self._prepared_post()
        out=self.prepared_scope.enter_context(_app_private_directory(self.root/'.mobile-release/store/lane-attempts-v1',
            app_root=self.root,cancellation=self.guard,create=False))
        require(out is not None);self.fence_readers.append(out);out.check()
        root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
        # No old marker is enumerated, read/adopted or retired by this new action.
        self.source.exchange('history-head',head);self.checkpoint();require(j.head()==head)
        self.observed_head=head;self._retire_journal(j)
    def source_final(self,observation):
        require(observation is self.observation and observation.calls==8 and not self._source_final)
        self._prepared_post();self.bundle.finish();self.prepared_scope.close()
        require(all(p.closed() for p in (*self.prepared_readers,*self.fence_readers)))
        self._source_final=True
    def runtime_environment(self):return self.runtime.environment()
    def attempt_directory(self,attempt,directory):
        self.checkpoint();require(attempt is self.record._pending_attempt and attempt.phase=='ACQUIRING' and self.fence_readers)
        out=self.fence_readers[0];out.check();directory.check()
        a,b=os.fstat(out.fd),os.fstat(directory.fd)
        require((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid))
    def lane_context(self,files):
        self.checkpoint();require(files is self.record._files_owner() and files.mode=='execute' and files.phase=='SEALING' and self._store_entered)
        self._prepared_post();raw=canonical({'authority':self.authority,'expectedIntentSha256':self.request.context['intentSha256']})
        require(len(raw)<=16384);return raw.decode('utf-8')
    def validate_receipt(self,raw):
        self.checkpoint();self._memory(raw,65536)
        return validate_local_execution_receipt(raw,intent_data=self.intent_bytes,authority_data=canonical(self.authority),
            purpose='recover',expected_intent_sha256=self.request.context['intentSha256'])
    def _publication(self,raw):
        self.checkpoint();require(self.store_completed and self._source_final and self._lane_owners_closed())
        receipt=self.validate_receipt(raw);target=Path(self.record._output)
        with _app_private_directory(target.parent,app_root=self.root,cancellation=self.guard,create=False) as out:
            require(out is not None);self.publishers.append(out)
            root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
            value=_read_file(out.fd,target.name,self.guard,65536,private=True);require(value is not None and value[1]==raw)
            binding=value[0];identity=self.record._files_owner().document_identity
            require(identity is not None and all(binding[k]==getattr(identity,k) for k in ('device','inode','uid','gid','mode')))
            # Re-open the same authentic original journal, but never append or
            # emit an AnchorAdd/final checkpoint for this observation.
            j=self._open_journal();require(j.head()==self.observed_head)
            value=_read_file(out.fd,target.name,self.guard,65536,private=True,binding_only=True)
            require(value==(binding,b''));out.check();self._retire_journal(j)
        require(out.closed());self.checkpoint();i=self.intent
        summary=dict(operationId=i['operationId'],candidateSha256=i['candidateSha256'],intentSha256=i['integrity']['sha256'],
            receiptSha256=hashlib.sha256(raw).hexdigest(),authorizationId=self.authority['authorizationId'],
            sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],applicationId=i['application']['id'],
            version={'name':i['version']['marketing'],'build':i['version']['build']},destination=i['destination'],
            observedAt=receipt['observedAt'],result=receipt['result'],limitations=list(wire.LIMITATIONS),
            observation='current-internal-target-only',priorExecutionFinality='not-established')
        self.report={'schemaVersion':1,'scope':'local-android-store-reconcile','headSequence':self.observed_head['sequence'],'reconciliationReceipt':summary}
        wire.validate_result(self.report)
