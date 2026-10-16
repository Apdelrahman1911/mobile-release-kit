"""Real private journal orchestration under one original native project lease."""
from __future__ import annotations
import os
import time
from pathlib import Path
from . import _desktop_local_history_protocol as wire
from ._desktop_local_history_control import LocalHistoryInput
from .build_inputs import InvocationCustody, invocation_custody, _attempt_all
from .cancellation import DefaultCancellation
from .local_release_journal import LocalReleaseJournal, LocalJournalError
class _HeldJournal(LocalReleaseJournal):
    def __init__(self, owner, enrollment, key):
        self.owner = owner
        super().__init__(owner.request.native["home"], end=owner.source.work_end, enrollment=enrollment, key=key)
    def _dir(self, value, **policy):
        super()._dir(value, **policy)
        root=self.owner.source.lease_identity
        # Refuse before creating anything beneath a project that contains the
        # account/journal ancestry. Native project selection alone is not this
        # continuing physical namespace exclusion.
        wire.require((value.st_dev,value.st_ino)!=root[:2])
    def _load(self):
        actual=os.fstat(self.root)
        project=self.owner.invocation._original_project
        for slot in project.directory.slots:
            value=os.fstat(slot.number)
            wire.require((value.st_dev,value.st_ino)!=(actual.st_dev,actual.st_ino))
        super()._load()
    def _time(self):
        # The actual original endpoint/STOP brackets every inherited journal IO.
        if not self.owner._close_claimed:
            self.owner.checkpoint()
        super()._time()
class LocalHistoryRun:
    def __init__(self, request, guard, source):
        wire.require(type(request) is wire.LocalHistoryRequest and type(source) is LocalHistoryInput
                     and type(guard) is DefaultCancellation and guard._local_history_source is source
                     and source.guard is guard and source.initial is request)
        self.request,self.guard,self.source=request,guard,source
        self.operation=self
        self.root=Path(request.native["projectRoot"])
        self.invocation=self.journal=self.bundle=None
        self.primary=self.report=None
        self._ran=self._close_claimed=False
        self._request_bytes=wire.canonical([request.context,request.native])
        source.bind_operation(self)
    def checkpoint(self):
        wire.require(not self._close_claimed and self.source.require_operation() is self
                     and self._request_bytes==wire.canonical([self.request.context,self.request.native]))
        self.guard.check();self.source.lease_post()
    def remember(self,error):
        if self.primary is None:self.primary=error
        self.source.failure_observed();self.guard.lifetime_ledger._remember(error)
    def bind_invocation(self,owner):
        wire.require(type(owner) is InvocationCustody and self.invocation is None and owner.root==self.root
                     and owner.mode=="build" and owner.cancellation is self.guard)
        self.invocation=owner
    def _resource_admission(self):
        # All literal path depths are already bounded. Original Project and
        # journal ancestries coexist with input/stdout/stderr, inherited lease,
        # one leaf and one directory iterator. No later tool/native child here.
        project=len(self.root.parts)
        home=len(Path(self.request.native["home"]).parts)
        wire.require(project+1+home+5+6 <=256)
        wire.require(513*8192*8 + 32768 <=96*1024*1024)  # raw+closed-shape decoded/parser reserve.
    def _candidate_inputs(self, enrollment):
        action=self.request.context["action"]
        operation_id=self.request.context["candidateOperationId"]
        rows=[row for row,_ in self.journal._rows if row["operationId"]==operation_id]
        wire.require(bool(rows))
        last=rows[-1]
        if action=="abandon-inputs":
            wire.require(self.journal._rows[-1][0] is last and last["phase"] in {"inputs-pending","inputs-ready"})
            head=self.journal._append(expected_head=self.journal.head(),operation_id=operation_id,
                phase="settled-failure",payload={"phase":last["phase"],"reason":"cancelled"})
            self.source.exchange("abandoned-head",head,"checkpoint-settled")
            self.checkpoint();return None
        wire.require(action=="review-inputs")
        if last["phase"]=="inputs-pending":return None
        if last["phase"]=="settled-failure":
            wire.require(last["payload"]["phase"] in {"inputs-pending","inputs-ready"})
            return None
        wire.require(last["phase"]=="inputs-ready" and len(rows)==2 and rows[0]["phase"]=="inputs-pending")
        from .local_candidate_bundle import CandidateBundleReview
        bundle=CandidateBundleReview(self,operation_id=operation_id,enrollment=enrollment,
            pending=rows[0]["payload"],candidate_sha256=last["payload"]["candidateSha256"])
        bundle.acquire()
        return bundle.finish()
    def run(self):
        wire.require(not self._ran);self._ran=True
        self._resource_admission();self.checkpoint()
        try:
            with invocation_custody(self.root,mode="build",cancellation=self.guard) as invocation:
                wire.require(invocation is self.invocation)
                with invocation.project(signing_lease=None):
                    self.checkpoint()
                    enrollment,key=self.source.exchange("lease-ready",{},"key-material")
                    try:
                        self.journal=_HeldJournal(self,enrollment,bytes(key))
                    finally:
                        key[:]=b"\0"*len(key)
                    if self.request.context["action"]=="enroll":
                        self.journal.open()
                        wire.require(self.journal.head()=={"sequence":0,"sha256":None})
                        self.source.exchange("empty-journal-ready",{},"key-enrolled")
                        r=self.request.native["rootIdentity"]
                        head=self.journal._append(expected_head={"sequence":0,"sha256":None},operation_id=None,
                            phase="genesis",payload={"rootIdentity":{"device":int(r["device"]),"inode":int(r["inode"]),
                                "mode":r["mode"] & 0o7777,"uid":r["uid"],"gid":r["gid"]}})
                        self.source.exchange("durable-genesis",head,"checkpoint-settled")
                    else:
                        self.journal.open_existing()
                        head=self.journal.head();wire.require(head["sequence"]>0)
                        self.source.exchange("history-head",head,"checkpoint-settled")
                    self.checkpoint()
                    wire.require(self.journal.head()==head)
                    candidate=None
                    if wire.candidate_action(self.request.context):
                        candidate=self._candidate_inputs(enrollment)
                        head=self.journal.head()
                    result={"schemaVersion":1,"scope":"local-release-history","enrolled":True,
                        "headSequence":head["sequence"],"history":self.journal.history_summary(),
                        "limitations":["no-store-authority","no-build-or-publishing","keychain-intact-rollback-boundary"]}
                    if wire.candidate_action(self.request.context):result["candidateInputs"]=candidate
                    self.journal.close();self.checkpoint()
                    self.report=result
        except BaseException as error:
            self.remember(error);raise
        finally:self.close()
    def close(self):
        if self._close_claimed:
            wire.require(self.closed());return
        self._close_claimed=True
        actions=[]
        if self.bundle is not None and not self.bundle.closed:actions.append(self.bundle.close)
        if self.journal is not None and not self.journal.closed:actions.append(self.journal.close)
        if self.invocation is not None:actions.append(self.invocation.cleanup)
        try:_attempt_all(self.guard,actions)
        except BaseException as error:
            self.remember(error);self.guard._abort(error);raise
    def closed(self):
        wire.require(self.source.operation is self)
        journal=(self.journal is None or self.journal.closed and not self.journal.ancestors and not self.journal._close_errors)
        i=self.invocation
        invocation=(i is None or i.claimed and not i.active and i._cleanup_complete and not i.reserved
                    and i.child is None and not i.frames and i.project_owner is None)
        p=None if i is None else i._original_project
        project=(p is None or p.claimed and all(slot.number is None and slot.close_state=="CLOSED"
                                               for slot in (*p.directory.slots,p.meta)))
        bundle=(self.bundle is None or self.bundle.closed and self.bundle.iterator is None and self.bundle.scan_state in {"new","closed"}
                and all(slot.state in {"UNACQUIRED","CLOSED"} for slot in self.bundle.reader.descriptors))
        return self._close_claimed and journal and invocation and project and bundle
    def terminal(self):
        v=self.guard.lifetime_ledger.verdict()
        if v.commands or v.profile_calls:self.guard._abort(wire.ProtocolError());v=self.guard.lifetime_ledger.verdict()
        if time.monotonic()>=self.source.work_end:self.source.stop("timed-out")
        elif self.guard.cancelled and self.source.stop_reason=="none":self.source.stop("cancelled")
        lifetime={"complete":v.complete,"fatal":v.fatal,"contained":v.contained,"commandDispatched":v.command_dispatched,
                  "commands":v.commands,"profileCalls":v.profile_calls,"inputClosed":self.source.closed and self.source.lease_closed,
                  "handlersRestored":self.guard.handler_state=="RESTORED","invocationClosed":self.closed(),"stopObserved":self.source.stop_reason}
        settled=v.cleanup_complete and not v.fatal and v.contained and v.command_dispatched is not None and all(
            lifetime[k] for k in ("inputClosed","handlersRestored","invocationClosed"))
        result=None
        if not settled:outcome,reason="unknown","cleanup-unknown"
        elif self.source.stop_reason!="none":outcome=reason=self.source.stop_reason
        elif self.primary is not None or self.report is None:outcome,reason="refused","journal-unavailable"
        else:outcome,reason,result="complete","none",self.report
        return {"schemaVersion":1,"context":self.request.context,"outcome":outcome,"reason":reason,"result":result,"lifetime":lifetime}
