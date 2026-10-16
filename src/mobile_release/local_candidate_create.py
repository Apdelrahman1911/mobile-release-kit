"""Create inputs through the SAME Android operation, lease and journal.

This private build-settled cut is before input/handler/parent finality, never a
producer-joined claim. Only an exact complete terminal may expose the bundle.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
from pathlib import Path
from uuid import UUID
from . import _desktop_android_build_protocol as wire
from . import local_candidate_create_protocol as candidate
from .build_inputs import _attempt_all
from .local_release_candidate import LocalAndroidCandidateComposition, LocalCandidateError, _need
from .local_release_journal import LocalReleaseJournal, LocalJournalError, MAX_ENTRIES

class _CreateJournal(LocalReleaseJournal):
    def __init__(self,owner):
        self.owner=owner
        super().__init__(owner.request.native['candidateHistory']['home'],end=owner.source.work_end,
            enrollment=owner.enrollment,key=bytes(owner.key))
    def _dir(self,value,**policy):
        super()._dir(value,**policy)
        _need((value.st_dev,value.st_ino)!=self.owner.input.identity[:2])
    def _load(self):
        actual=os.fstat(self.root)
        _need((actual.st_dev,actual.st_ino) not in self.owner.project_ancestry)
        super()._load()
    def _time(self):
        if not self.owner.closing:self.owner.point()
        super()._time()

class CandidateCreateRun:
    def __init__(self,engine):
        from ._desktop_android_build_engine import _Engine
        from .desktop_android_build import AndroidBuildRun
        from ._desktop_candidate_input_control import CandidateCreateInput
        _need(type(engine) is _Engine and engine.candidate is None
            and type(engine.service) is AndroidBuildRun and wire.candidate_create(engine.request.context)
            and type(engine.input.candidate_input) is CandidateCreateInput)
        self.engine,self.run,self.source,self.guard=engine,engine.service,engine.input,engine.guard
        self.request,self.input=self.run.request,self.source.candidate_input
        self.operation_id=str(UUID(hex=self.request.operation_id))
        self.request_binding=wire._encode(wire._request_binding(self.request))
        self.composition=self.publisher=None
        self.journals=[];self.key=None;self.enrollment=None
        self.pending_head=self.pending_payload=self.root_identity=None
        self.project_ancestry=();self.signer_sha256=None
        self.build_settled=self.closing=self.closed=False
        self.failure=self.result=None;self.quote=None
        engine.candidate=self.run._candidate_inputs=self # Register before child constructors.
        self.composition=LocalAndroidCandidateComposition(self.run)
    def point(self):
        _need(self.engine.candidate is self and self.run._candidate_inputs is self and not self.closed
            and not self.closing and self.input.request is self.request
            and wire._encode(wire._request_binding(self.request))==self.request_binding)
        self.guard.check();self.input.post()
        _need(self.source.require_operation() is self.run.operation)
    def reserve(self,quote):
        """Actual sequential peaks, no future-close credit on failure paths."""
        self.point()
        journal=len(Path(self.request.native['candidateHistory']['home']).parts)+5+2
        # Before any build/tool/material acquisition: held project/source/files,
        # baseline/namespace/iterators, one Git owner, inherited lease + journal.
        before=sum(quote[k] for k in ('project','source','normalFiles','namespace','baseline','normalIterators'))+20+1+journal
        # After all original Android/source owners positively close, only the
        # retained AAB+metadata scratch coexist with reopened journal/publisher.
        after=quote['handoff']+quote.get('metadataScratch',0)+journal+4+1+8+1
        base=max(quote.get('candidateBaseTotal',0),quote.get('metadataPhase',0),
            quote['total'] if 'candidateBaseTotal' not in quote else 0)
        total=max(base+1,before,after)
        _need(total<=256)
        self.quote={**quote,'candidateBaseTotal':base,'candidateJournal':journal,
            'candidateBeforeBuild':before,'candidateAfterBuild':after,'total':total}
        return dict(self.quote)
    def before_build(self,bound):
        self.point();comp=self.composition;op=self.run.operation
        _need(comp.source is not None and comp.source.calls==6 and comp.source_binding is not None
            and comp.quote==self.quote and not self.journals and self.enrollment is None
            and op.inputs is bound and all(state=='new' for state in op._roles.values()))
        project=op.invocation._original_project
        self.project_ancestry=tuple((v.st_dev,v.st_ino) for v in (os.fstat(s.number) for s in project.directory.slots))
        self.signer_sha256=bound.saved.configuration.upload_certificate_sha256.replace(':','').lower()
        _need(wire._text(self.signer_sha256,wire._SHA))
        self.enrollment,self.key=self.input.exchange('lease-ready',{})
        _need(type(self.key) is bytearray and len(self.key)==32)
        journal=self._open_journal()
        head=journal.head();last=journal._rows[-1][0] if journal._rows else None
        if last is None or last['phase'] not in {'genesis','settled-success','settled-failure'}:
            self.failure='recovery-required';raise LocalCandidateError('Local candidate history requires recovery')
        _need(head['sequence']<=MAX_ENTRIES-2 and self.operation_id not in journal._operations
            and len(journal._operations)<64)
        self.input.exchange('history-head',head)
        self.point();_need(journal.head()==head)
        self.pending_payload={'configurationSha256':hashlib.sha256(bound.saved.configuration.raw).hexdigest(),
            'versionSha256':hashlib.sha256(bound.saved.version_raw).hexdigest(),
            'sourceCommit':comp.source_binding['commit'],'sourceTree':comp.source_binding['tree']}
        self.pending_head=journal._append(expected_head=head,operation_id=self.operation_id,
            phase='inputs-pending',payload=self.pending_payload)
        self.input.exchange('inputs-pending',self.pending_head)
        self.point();_need(journal.head()==self.pending_head)
        self._retire_journal(journal) # Positive closes before any signing/build call.
    def _open_journal(self):
        self.point();_need(len(self.journals)<2 and self.enrollment is not None and self.key is not None)
        journal=_CreateJournal(self);self.journals.append(journal)
        journal.open_existing()
        root=os.fstat(journal.root)
        observed=(root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)
        if self.root_identity is None:self.root_identity=observed
        else:_need(observed==self.root_identity)
        genesis=journal._rows[0][0]['payload']['rootIdentity'] if journal._rows else None
        n=self.request.native['rootIdentity']
        _need(genesis=={'device':int(n['device']),'inode':int(n['inode']),
            'mode':n['mode']&0o7777,'uid':n['uid'],'gid':n['gid']})
        return journal
    @staticmethod
    def _retire_journal(journal):
        journal.close()
        _need(journal.closed and not journal.ancestors and not journal._close_errors)
        # No second 96MiB decoded history reserve. Retain original close state,
        # enrollment/root/head separately, never erase uncertainty evidence.
        journal._rows.clear();journal._operations.clear();journal.leaves.clear()
    def _build_cut(self):
        self.point();comp=self.composition;op=self.run.operation;v=self.guard.lifetime_ledger.verdict()
        _need(not self.build_settled and self.run._run_claimed and self.run._close_claimed
            and self.run.primary is None and op.closed() and op.signing.closed()
            and self.pending_head is not None and self.input.reply_step==3
            and all(j.closed and not j.ancestors and not j._close_errors for j in self.journals)
            and comp.source_closed and not comp.failed and len(comp._source_rows)==8
            and all(r['returned'] and r['code']==0 for r in comp._source_rows)
            and comp._source_pending is None and op.commands_settled()
            and v.complete and v.cleanup_complete and v.contained and not v.fatal
            and v.commands==14 and v.profile_calls==0
            and not self.source.closed and self.guard.handler_state!='RESTORED')
        comp._metadata_data()
        h=comp.handoff
        _need(h.captured and not h.failed and not h.closed and not h.producer_joined and not h._reading
            and h._result==wire._encode(self.run._candidate)
            and comp._output_data['signedArtifact']=={'bytes':h._size,'sha256':h._sha256})
        h.reader.terminal();self.build_settled=True
    def finish_build(self):
        self._build_cut()
        journal=self._open_journal()
        _need(journal.head()==self.pending_head and journal._rows[-1][0]['operationId']==self.operation_id
            and journal._rows[-1][0]['phase']=='inputs-pending'
            and journal._rows[-1][0]['payload']==self.pending_payload)
        from .local_candidate_publish import CandidateBundlePublisher
        publisher=CandidateBundlePublisher(self)
        digest=publisher.publish()
        ready=journal._append(expected_head=self.pending_head,operation_id=self.operation_id,
            phase='inputs-ready',payload={'candidateSha256':digest})
        self.input.exchange('inputs-ready',ready)
        self.point();_need(journal.head()==ready)
        publisher.post();self.point()
        report={'schemaVersion':1,'scope':'local-android-candidate-inputs','headSequence':ready['sequence'],
            'candidateInputs':json.loads(json.dumps(publisher.summary)),
            'build':json.loads(self.composition.handoff._result)}
        self.close()
        _need(self.originals_closed())
        self.result=report # Still provisional until input/handlers/native finality.
    def remember(self,error):
        if self.failure is None:
            self.failure='journal-unavailable' if isinstance(error,LocalJournalError) else 'candidate-inputs-unavailable'
    def close(self):
        if self.closed:
            _need(self.originals_closed());return
        self.closing=True
        actions=[]
        if self.publisher is not None and not self.publisher.closed:actions.append(self.publisher.close)
        actions.extend(j.close for j in self.journals if not j.closed)
        comp=self.composition
        if comp is not None:
            if comp.metadata is not None and not comp.metadata.closed:actions.append(comp.metadata._close)
            if comp.metadata_scratch is not None:actions.append(comp.metadata_scratch.cleanup)
            actions.append(lambda:comp.handoff._candidate_close(self))
        try:_attempt_all(self.guard,actions)
        except BaseException as error:self.remember(error);self.guard._abort(error);raise
        finally:
            if self.key is not None:self.key[:]=b'\0'*len(self.key)
            self.closed=True
        _need(self.originals_closed())
    @staticmethod
    def _scratch_closed(s):
        return (s.claimed and not s.active and s._cleanup_complete and not s.created
            and s.creation["state"] in {"NEW","NO_EFFECT","RETIRED"}
            and all(v.number is None and v.close_state=="CLOSED" for v in (*s.writer_slots,s.slot,*s.parent.slots)))
    @staticmethod
    def _metadata_closed(m):
        return m.closed and all(i.close_state=='closed' for i in m.iterators) and all(
            reader is None or all(s.state in {'UNACQUIRED','CLOSED'} for s in reader.descriptors)
            for reader in (m.reader,m.leaf))
    def original_flags(self):
        comp=self.composition
        journal=all(j.closed and not j.ancestors and not j._close_errors for j in self.journals)
        retained=comp is None or (comp.handoff.closed and (comp.handoff.reader is None or all(
            s.state in {'UNACQUIRED','CLOSED'} for s in comp.handoff.reader.descriptors))
            and (comp.metadata is None or self._metadata_closed(comp.metadata))
            and (comp.metadata_scratch is None or self._scratch_closed(comp.metadata_scratch)))
        publisher=self.publisher is None or self.publisher.originals_closed()
        return {'candidateInputsClosed':bool(self.closed and retained and publisher),
            'journalClosed':bool(self.closed and journal and (self.key is None or not any(self.key))),
            'leaseClosed':self.input.closed}
    def originals_closed(self):
        flags=self.original_flags()
        return flags['candidateInputsClosed'] and flags['journalClosed']
    def terminal(self,base):
        wire._validate_composed_terminal(base,self.request,self.composition)
        flags=self.original_flags();value={**base,'lifetime':{**base['lifetime'],**flags}}
        if not all(flags.values()):
            value.update(outcome='unknown',reason='cleanup-unknown',result=None)
            if value['disposition']['artifacts']=='retained-local-result':
                value['disposition']={**value['disposition'],'artifacts':'retained-incomplete'}
        elif base['outcome']=='complete':
            _need(self.result is not None and self.build_settled and self.result['build']==base['result'])
            value['result']=self.result
        elif self.failure is not None and base['reason']=='protocol-error':value['reason']=self.failure
        candidate.terminal(value,self.request)
        return value
