"""One candidate-only prepare composition on existing Store/native owners."""
from __future__ import annotations
from ._desktop_store_prepare_protocol import require

# Peak owned-Python descriptors, not an ambient/native-parent limit. Closed
# successful phases are retired; failed/unknown phases never enter successors.
ORIGINAL_LIMIT=256

def resource_quote(*,project_depth,version_parent_depth,source,history_depth):
    require(all(type(n) is int and 1<=n<=128 for n in
        (project_depth,version_parent_depth,source,history_depth)) and project_depth<=24 and source<=96)
    p,v,s,h=project_depth,version_parent_depth,source,history_depth
    fixed=4 # stdin, stdout, stderr, same-OFD input lease
    project=p+1 # root ancestry + existing .mobile-release handle
    namespace=p+2 # encompassing Store namespace
    saved=2*p+v+2 # independent saved root/config/version parents + transient leaf/iterator
    bundle=p+9 # four fixed leaves + four suffix dirs + one iterator
    journal=h+7 # bounded ancestry, fixed suffix + leaf/iterator
    source_phase=fixed+namespace+project+saved+s+20
    pending_phase=fixed+namespace+project+s+bundle+journal+2
    # Fixed /private/tmp parent: HOME4, received6, selected6. Selection reader
    # holds independent project+private ancestry before its positive close.
    material_phase=fixed+namespace+project+s+bundle+16+(p+7)+2
    # Lane namespace, runner/tmp, original pending marker, joined terminal
    # output reader.20 covers existing native process owner even on failure;
    # another4 permits independent cleanup leaves/listdir before refusal.
    lane_phase=fixed+namespace+project+s+bundle+16+(p+4)+(p+6)+(p+3)+20+(p+5)+4
    # All earlier original owners MUST positively close before publication.
    # New output parent, two document originals+writer, reopened journal.
    publication_phase=fixed+(p+4)+4+journal+2
    total=max(source_phase,pending_phase,material_phase,lane_phase,publication_phase)
    require(total<=ORIGINAL_LIMIT)
    return dict(source=source_phase,pending=pending_phase,material=material_phase,
        lane=lane_phase,publication=publication_phase,total=total)

from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys
import threading
import time
from uuid import UUID
from . import _desktop_store_prepare_protocol as wire
from ._desktop_store_prepare_control import StorePrepareInput
from .desktop_store_preflight import StorePreflightRun, _Refused
from .build_inputs import (_Directory,_read_file,_attempt_all,FiniteScratch,InvocationCustody,
    invocation_custody,finite_scratch,_app_private_directory,_publish_private_file)
from .cancellation import DefaultCancellation
from .local_release_source import LocalSourceObservation,_retain_source
from .local_candidate_bundle import CandidateBundleReview
from .local_release_journal import LocalReleaseJournal,MAX_ENTRIES,canonical
from ._store_runtime import StoreRuntimeContext
from .owned_process import fatal_lifetime_error
from .stores import (_fastlane_probe_commands,StoreRequest,new_store_lane_evidence,
    _store_operation,complete_store_operation)


def prepared_intent_data(*,request,enrollment,manifest,observed,config,precondition):
    """Closed body construction only; original caller must finish Store custody."""
    from .local_release_intent import decode_local_operation_intent
    from .provenance import seal,timestamp,_intent_destination,_signing_identity
    c=request.context
    source={'commit':observed.commit,'tree':observed.tree,'ref':observed.ref}
    require(source=={'commit':manifest['sourceCommit'],'tree':manifest['sourceTree'],
        'ref':'refs/heads/'+config.section('source')['candidateBranch']}
        and manifest['operationId']==c['candidateOperationId'] and manifest['enrollment']==enrollment
        and manifest['savedConfig']==c['savedConfig'] and manifest['savedVersion']==c['savedVersion']
        and manifest['applicationId']==config.section('android')['applicationId'])
    signing=_signing_identity(config,'android',None)
    require(signing['certificateSha256']==manifest['signerSha256'])
    assignment={'kind':'google-service-account','recordId':c['recordId'],
        'expectedRevision':c['recordRevision'],'contextRevision':c['credentialContextRevision']}
    common=dict(project=enrollment,operationId=c['candidateOperationId'],candidateSha256=c['candidateSha256'])
    prepared=dict(schemaVersion=1,origin='local-desktop',purpose='prepare',**common,
        authorizationId=request.native['authorizationId'],source=source,assignment=assignment,
        confirmationSha256=hashlib.sha256(c['confirmation'].encode()).hexdigest(),intentSha256=None)
    kinds=(('android-aab','android','aab'),('store-metadata','shared','metadata'),
           ('validation-report','shared','validation-report'))
    artifacts=[dict(logicalName=a,platform=b,kind=k,fileName=row['fileName'],size=row['bytes'],
                    sha256=row['sha256'],architectures=[]) for row,(a,b,k) in zip(manifest['files'],kinds)]
    value=seal(dict(documentType='local-store-operation-intent',schemaVersion=1,origin='local-desktop',
        **common,platform='android',stage='candidate',tooling=request.native['tooling'],
        candidateSource=source,operationSource=source,preparedBy=prepared,confirmation=c['confirmation'],
        application={'id':manifest['applicationId']},version={'marketing':c['savedVersion']['name'],'build':c['savedVersion']['build']},
        destination=_intent_destination(config,'candidate','android'),
        configuration={'path':'release/mobile-release.json','sha256':c['savedConfig']['sha256'],
            'metadataSha256':manifest['files'][1]['sha256']},artifacts=artifacts,signing=[signing],
        predecessors={},storePrecondition=precondition,privateStateCommitments={},createdAt=timestamp()))
    raw=canonical(value)+b'\n';decode_local_operation_intent(raw)
    return raw,value


class _PrepareJournal(LocalReleaseJournal):
    def __init__(self,owner):
        self.owner=owner
        super().__init__(owner.request.native['home'],end=owner.source.work_end,
            enrollment=owner.enrollment,key=bytes(owner.key))
    def _time(self):
        if not self.owner._close_claimed:self.owner.checkpoint()
        super()._time()
    def _dir(self,value,**policy):
        super()._dir(value,**policy)
        require((value.st_dev,value.st_ino)!=self.owner.source.lease_identity[:2])
    def _load(self):
        value=os.fstat(self.root)
        require((value.st_dev,value.st_ino) not in self.owner.project_ancestry)
        super()._load()


class LocalStorePrepareRun:
    def __init__(self,request,guard,source):
        from .local_store_execute import LocalStoreExecuteRun
        from ._desktop_store_execute_control import StoreExecuteInput
        from ._desktop_store_execute_protocol import StoreExecuteRequest
        prepare=type(self) is LocalStorePrepareRun
        require(type(self) in (LocalStorePrepareRun,LocalStoreExecuteRun)
            and type(request) is (wire.StorePrepareRequest if prepare else StoreExecuteRequest) and type(guard) is DefaultCancellation
            and type(source) is (StorePrepareInput if prepare else StoreExecuteInput) and source.guard is guard and guard._local_store_source is source
            and source.initial is request and source.active and source.request_returned
            and threading.current_thread() is threading.main_thread())
        self.request,self.guard,self.source=request,guard,source
        self.operation=self;self.root=Path(request.native['projectRoot'])
        self._request_bytes=canonical([request.context,request.native])
        self.invocation=self.runtime=self.home=self.received=self.material_original=None
        self.config=self.version=self.record=self.store_request=None
        self.observation=self.bundle=self.readback=None
        self.directories=[];self.reads=[];self.saved_bytes={};self.scratches=[];self.journals=[];self.publishers=[]
        self.enrollment=self.key=self.pending_head=self.journal_root=None
        self.project_ancestry=();self.quote=None;self.primary=self.report=None
        self._ran=self._close_claimed=self._store_entered=self.store_completed=False
        self._pending=None;self._command_claimed=False;self._source_rows=[];self._runtime_rows=[]
        source.bind_operation(self) # Before any fallible resource admission.
    def checkpoint(self):
        require(not self._close_claimed and self.source.require_operation() is self
            and canonical([self.request.context,self.request.native])==self._request_bytes)
        self.guard.check();self.source.lease_post()
    remember=StorePreflightRun.remember
    validate_material_shape=staticmethod(StorePreflightRun.validate_material_shape)
    _saved=StorePreflightRun._saved
    _source_post=StorePreflightRun._source_post
    def _read(self,relative,maximum):
        raw=StorePreflightRun._read(self,relative,maximum);self.saved_bytes[relative]=raw;return raw
    def _quote(self,source=96):
        self.checkpoint()
        value=resource_quote(project_depth=len(self.root.parts),
            version_parent_depth=len((self.root/self.request.context['savedVersion']['source']).parent.parts),
            source=source,history_depth=len(Path(self.request.native['home']).parts))
        if self.quote is not None:require(value['total']<=self.quote['total'])
        self.quote=value;return value
    def bind_invocation(self,owner):
        require(type(owner) is InvocationCustody and self.invocation is None and owner.mode=='store'
            and owner.cancellation is self.guard and owner.root==self.root and self.quote is not None
            and owner.lane_evidence is self.record)
        self.invocation=owner
    def bind_scratch(self,scratch):
        layouts=('online-runner','store-selection','store-selection')
        require(type(scratch) is FiniteScratch and scratch.cancellation is self.guard
            and len(self.scratches)<3 and scratch.layout==layouts[len(self.scratches)]
            and self.invocation is not None and self.pending_head is not None and self.source.reply_step==3
            and scratch.journal is None and scratch._lane_binding is None)
        self.scratches.append(scratch)
    def runtime_admitted(self,runtime):
        self.checkpoint()
        require(type(runtime) is StoreRuntimeContext and runtime._invocation is self.invocation
            and self.invocation.mode=='store' and (self.runtime is None or self.runtime is runtime)
            and runtime.runtime_root==Path(self.request.native['cwd']) and runtime._home is self.home
            and self.home is not None and self.scratches[0] is self.home and self.pending_head is not None)
        return True
    def _ledger(self):
        v=self.guard.lifetime_ledger.verdict()
        require(v.complete and v.cleanup_complete and v.contained and not v.fatal and v.profile_calls==0)
        return v
    def _arm_source(self,source,args,timeout,limit):
        self.checkpoint();index=len(self._source_rows)
        require(source is self.observation and source._composition is self and source.execution_source is None
            and source.endpoint==self.source.work_end and self._pending is None and index<8
            and (index<6 and not self._runtime_rows or index>=6 and len(self._runtime_rows)==6))
        initial=(["config","--local","--no-includes","--null","--list"],
            ["rev-parse","--shared-index-path","HEAD","HEAD^{tree}"],
            ["ls-files","--stage","-z"],["ls-files","-v","-z"])
        if index<4:require(args==initial[index] and limit==(65536,1024,2<<20,2<<20)[index])
        elif index==4:require(len(args)==5 and args[:4]==['ls-tree','-r','-z','--full-tree'] and wire.sha(args[4],40) and limit==2<<20)
        else:require(args==['status','--porcelain=v1','-z','--untracked-files=all','--ignore-submodules=none'] and limit==2<<20)
        prefix=['/usr/bin/git','--no-pager','--no-replace-objects','--git-dir='+str(self.root/'.git'),
            '--work-tree='+str(self.root),'-c','core.fsmonitor=false','-c','core.hooksPath=/dev/null',
            '-c','core.untrackedCache=false','-c','core.filemode=true','-c','core.symlinks=true','-c','protocol.allow=never']
        self._arm('source',(*prefix,*args),True,timeout,limit,self._source_rows)
    def _arm(self,kind,argv,capture,timeout,limit,rows):
        v=self._ledger();require(v.commands==len(self._source_rows)+len(self._runtime_rows))
        row={'kind':kind,'argv':tuple(argv),'capture':capture,'timeout':timeout,'limit':limit,
            'before':v.commands,'returned':False,'code':None}
        rows.append(row);self._pending=row;self._command_claimed=False
    def _returned(self,code):
        row=self._pending;v=self._ledger()
        require(row is not None and self._command_claimed and v.commands==row['before']+1 and type(code) is int)
        row.update(returned=True,code=code);self._pending=None
        require(code==0)
    def _source_returned(self,source,result):
        require(source is self.observation);self._returned(result.returncode)
    def _source_error(self,source,error):
        require(source is self.observation);self._pending=None;self.remember(error)
    @contextmanager
    def command(self,runtime,argv,*,capture):
        self.checkpoint();self.runtime_admitted(runtime)
        expected=(*_fastlane_probe_commands(runtime.tooling_root),
            ('bundle','exec','ruby',str(runtime.tooling_root/'fastlane/run_lane.rb'),'android_internal_upload'))
        index=len(self._runtime_rows)
        require(self._store_entered and len(self._source_rows)==6 and self._pending is None and index<6
            and tuple(argv)==expected[index] and capture is (index<5))
        self._arm('probe' if index<5 else 'lane',argv,capture,60 if index<5 else 900,2<<20,self._runtime_rows)
        try:
            yield
            # The unchanged probe caller checks nonzero. Lane's actual return
            # and nested finality still belong to StoreLaneCallEvidence.
            row=self._pending;v=self._ledger()
            require(row is not None and self._command_claimed and v.commands==row['before']+1)
            row['returned']=True;self._pending=None
        except BaseException as error:self.remember(error);raise
        finally:self._pending=None
    def command_arguments(self,argv,*,capture,evidence):
        from ._command_process import CommandCallEvidence
        self.checkpoint();row=self._pending
        require(row is not None and not self._command_claimed and tuple(argv)==row['argv'] and capture is row['capture']
            and (type(evidence) is CommandCallEvidence and evidence is self.record._command if row['kind']=='lane' else evidence is None))
        self._command_claimed=True
    def command_limits(self,timeout,capture,output_limit):
        self.checkpoint();row=self._pending
        require(row is not None and self._command_claimed and capture is row['capture'])
        if row['kind']=='source':require(timeout<=row['timeout']<=10 and output_limit==row['limit'])
        return min(timeout,row['timeout']),min(output_limit,row['limit'])
    def lane_timing(self,files,label):
        from . import _store_lane_contract as lane
        self.checkpoint()
        require(files is self.record._files_owner() and files.mode==('prepare' if type(self) is LocalStorePrepareRun else 'execute') and files.phase=='SEALING'
            and len(self._runtime_rows)==5 and self._pending is None)
        # Same clock label already enforced by the existing native lane codec.
        # Map once from original monotonic endpoint, rounded DOWN; never renew.
        run=math.floor(self.source.work_end*1e9)
        require(time.monotonic_ns()<run and run+lane.CLEANUP_NS<=math.floor(self.source.hard_end*1e9))
        return lane.Timing(label,run,run+lane.CLEANUP_NS)
    def require_lane_evidence(self,evidence,timeout):
        self.checkpoint();row=self._pending
        require(row is not None and row['kind']=='lane' and self._command_claimed and evidence is self.record._command
            and type(timeout) is int and 1<=timeout<=900 and time.monotonic()+timeout<=self.source.work_end)
        return True
    def material_values(self):
        self.checkpoint();require(self._store_entered and self.source.reply_step==3 and self.material_original is not None)
        return {'GOOGLE_APPLICATION_CREDENTIALS':str(self.received.require(self.material_original))}
    def admit_store(self,config,release,request,record,guard,invocation):
        self.checkpoint()
        require(not self._store_entered and config is self.config and release is self.version and request is self.store_request
            and record is self.record and guard is self.guard and invocation is self.invocation
            and request.prepare and not request.execute and request.operation_intent is None
            and request.recovery_run_id is None and request.recovery_confirmation is None
            and request.stage=='candidate' and request.platform=='android' and self.source.reply_step==3
            and self.pending_head is not None and self.material_original is not None
            and len(self._source_rows)==6 and not self._runtime_rows and self.bundle is not None and not self.bundle.closed)
        self._store_entered=True;return True
    def local_environment(self,request,record):
        self.checkpoint();require(self._store_entered and request is self.store_request and record is self.record)
        return True
    def _open_journal(self):
        self.checkpoint();require(len(self.journals)<2 and self.enrollment is not None and self.key is not None)
        j=_PrepareJournal(self);self.journals.append(j);j.open_existing()
        v=os.fstat(j.root);identity=(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)
        if self.journal_root is None:self.journal_root=identity
        else:require(identity==self.journal_root)
        n=self.request.native['rootIdentity']
        require(j._rows and j._rows[0][0]['payload']['rootIdentity']==dict(device=int(n['device']),inode=int(n['inode']),
            mode=n['mode']&0o7777,uid=n['uid'],gid=n['gid']))
        return j
    @staticmethod
    def _retire_journal(j):
        j.close();require(j.closed and not j.ancestors and not j._close_errors)
        j._rows.clear();j._operations.clear();j.leaves.clear()
    def _begin(self):
        self.checkpoint();require(self.observation.calls==6 and not self.journals and self.bundle is None)
        self.enrollment,self.key=self.source.exchange('lease-ready',{})
        require(type(self.key) is bytearray and len(self.key)==32)
        j=self._open_journal();head=j.head();last=j._rows[-1][0];c=self.request.context
        require(last['operationId']==c['candidateOperationId'] and last['phase']=='inputs-ready'
            and last['payload']=={'candidateSha256':c['candidateSha256']} and head['sequence']<=MAX_ENTRIES-2)
        previous=[row for row,_ in j._rows if row['operationId']==c['candidateOperationId'] and row['phase']=='inputs-pending']
        require(len(previous)==1)
        bundle=CandidateBundleReview(self,operation_id=c['candidateOperationId'],enrollment=self.enrollment,
            pending=previous[0]['payload'],candidate_sha256=c['candidateSha256'])
        bundle.acquire();m=bundle.value;o=self.observation.observed
        require(m['sourceCommit']==o.commit and m['sourceTree']==o.tree and m['savedConfig']==c['savedConfig']
            and m['savedVersion']==c['savedVersion'] and m['applicationId']==self.config.section('android')['applicationId']
            and m['signerSha256']==self.config.section('android')['uploadCertificateSha256'].replace(':','').lower())
        self.source.exchange('history-head',head);self.checkpoint();require(j.head()==head)
        self.pending_head=j._append(expected_head=head,operation_id=c['candidateOperationId'],phase='prepare-pending',
            payload={'candidateSha256':c['candidateSha256'],'confirmationSha256':hashlib.sha256(c['confirmation'].encode()).hexdigest()})
        self.source.exchange('prepare-pending',self.pending_head);self.checkpoint();require(j.head()==self.pending_head)
        self._retire_journal(j) # Never hold a second decoded journal across the lane.
    def _retire_saved(self):
        self._source_post()
        _attempt_all(self.guard,[d.close for d in reversed(self.directories)])
        require(self._saved_closed())
    def _saved_closed(self):
        return all(d.slots and all(s.number is None and s.close_state=='CLOSED' for s in d.slots) for d in self.directories)
    def _publication(self,raw):
        self.checkpoint();require(self.store_completed and self._lane_owners_closed() and self.pending_head is not None)
        raw_intent,intent=prepared_intent_data(request=self.request,enrollment=self.enrollment,manifest=self.bundle.value,
            observed=self.observation.observed,config=self.config,precondition=json.loads(raw))
        target=Path(self.record._output);parent=target.parent
        # New checked originals, not a claim that closed lane files are still held.
        # Both readbacks and consuming closes finish before durable prepared.
        with _app_private_directory(parent,app_root=self.root,cancellation=self.guard,create=False) as out:
            require(out is not None);self.publishers.append(out);out.check()
            # The lane's project owner is closed, but its original native lease
            # is still held. Do not adopt a replacement root by pathname.
            root=os.fstat(out.parent.fd)
            require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
            require(set(os.listdir(out.fd))=={'store-precondition.json'})
            observed=_read_file(out.fd,'store-precondition.json',self.guard,4<<20)
            require(observed is not None and observed[1]==raw)
            _publish_private_file(out,'operation-intent.json',iter((raw_intent,)))
            require(set(os.listdir(out.fd))=={'store-precondition.json','operation-intent.json'})
            originals={}
            for name,expected in (('store-precondition.json',raw),('operation-intent.json',raw_intent)):
                value=_read_file(out.fd,name,self.guard,4<<20);require(value is not None and value[1]==expected)
                originals[name]=value[0]
            out.check();self.checkpoint()
            j=self._open_journal();require(j.head()==self.pending_head and j._rows[-1][0]['phase']=='prepare-pending'
                and j._rows[-1][0]['operationId']==self.request.context['candidateOperationId'])
            digest=hashlib.sha256(raw).hexdigest()
            prepared=j._append(expected_head=self.pending_head,operation_id=self.request.context['candidateOperationId'],phase='prepared',
                payload={'candidateSha256':self.request.context['candidateSha256'],'intentSha256':intent['integrity']['sha256'],
                         'storePreconditionSha256':digest})
            self.source.exchange('prepare-settled',{'head':prepared,'phase':'prepared'})
            self.checkpoint();require(j.head()==prepared)
            require(set(os.listdir(out.fd))==set(originals))
            for name,expected in (('store-precondition.json',raw),('operation-intent.json',raw_intent)):
                value=_read_file(out.fd,name,self.guard,4<<20)
                require(value is not None and value[0]==originals[name] and value[1]==expected)
            out.check();self._retire_journal(j)
        require(out.closed());self.checkpoint()
        summary={'operationId':self.request.context['candidateOperationId'],'candidateSha256':self.request.context['candidateSha256'],
            'intentSha256':intent['integrity']['sha256'],'storePreconditionSha256':digest,
            'sourceCommit':intent['operationSource']['commit'],'sourceTree':intent['operationSource']['tree'],
            'applicationId':intent['application']['id'],'version':{'name':intent['version']['marketing'],'build':intent['version']['build']},
            'destination':{'channel':'internal','releaseStatus':'completed'},'observedAt':intent['storePrecondition']['observedAt'],
            'limitations':list(wire.LIMITATIONS)}
        self.report={'schemaVersion':1,'scope':'local-android-store-prepare','headSequence':prepared['sequence'],'preparedIntent':summary}
        wire.validate_result(self.report)
    def run(self):
        self.checkpoint();require(not self._ran and sys.platform=='darwin' and os.getcwd()==self.request.native['cwd'])
        self._ran=True
        try:
            self._quote() # Conservative original peak BEFORE any source/material/file acquisition.
            self.config,self.version=self._saved()
            output=self.root/'.mobile-release/store/local'/UUID(self.request.context['candidateOperationId']).hex
            self.store_request=StoreRequest(stage='candidate',platform='android',confirmation=self.request.context['confirmation'],
                execute=False,prepare=True,output_dir=output,store_precondition=output/'store-precondition.json')
            self.record=new_store_lane_evidence(self.config,self.store_request,self.guard)
            with invocation_custody(self.root,mode='store',cancellation=self.guard,lane_evidence=self.record) as invocation:
                with invocation.project(signing_lease=None):
                    p=invocation._original_project
                    self.project_ancestry=tuple((v.st_dev,v.st_ino) for v in (os.fstat(s.number) for s in p.directory.slots))
                    observation=LocalSourceObservation(invocation,self.saved_bytes['release/mobile-release.json'],
                        self.saved_bytes[self.request.context['savedVersion']['source']],endpoint=self.source.work_end,execution_source=None)
                    self.observation=observation;observation._composition=self;self._quote(observation.descriptor_quote())
                    with _retain_source(observation):
                        self._retire_saved();self._begin()
                        with finite_scratch(layout='online-runner',cancellation=self.guard,parent=Path('/private/tmp')) as home:
                            self.home=home
                            self.runtime=StoreRuntimeContext.installed(Path(self.request.native['cwd']),invocation=invocation,private_home=home)
                            with finite_scratch(layout='store-selection',cancellation=self.guard,parent=home._path) as received:
                                self.received=received;self.material_original=self.source.receive_material(self,received)
                                self.readback=_store_operation(config=self.config,release=self.version,request=self.store_request,
                                    operation_intent=None,lane_evidence=self.record,cancellation=self.guard,invocation=invocation,_local_prepare=self)
                                observation.check();self.bundle.finish()
            require(self._lane_owners_closed() and len(self._source_rows)==8 and len(self._runtime_rows)==6)
            complete_store_operation(self.readback,lane_evidence=self.record,cancellation=self.guard)
            self.store_completed=True;self._publication(self.readback._content)
        except BaseException as error:self.remember(error);raise
        finally:self.close()
    def _lane_owners_closed(self):
        i=self.invocation;o=self.observation;b=self.bundle
        project=None if i is None else i._original_project
        return ((i is None or i._lane_closed_for(self.record,self.guard))
            and (project is None or project.claimed and all(s.number is None and s.close_state=='CLOSED' for s in (*project.directory.slots,project.meta)))
            and (o is None or o.closed and all(s.state in {'UNACQUIRED','CLOSED'} for r in o.readers for s in r.descriptors))
            and (b is None or b.closed and not b.failed and b.scan_state in {'new','closed'} and b.iterator is None
                 and all(s.state in {'UNACQUIRED','CLOSED'} for s in b.reader.descriptors))
            and all(s.claimed and not s.active and s._cleanup_complete and not s.created
                and all(v.number is None and v.close_state=='CLOSED' for v in (*s.writer_slots,s.slot,*s.parent.slots)) for s in self.scratches)
            and self._saved_closed())
    def close(self):
        if self._close_claimed:require(self.closed());return
        self._close_claimed=True
        actions=[]
        if self.bundle is not None and not self.bundle.closed:actions.append(self.bundle.close)
        if self.observation is not None and not self.observation.closed:actions.append(self.observation._close)
        actions.extend(s.cleanup for s in reversed(self.scratches))
        if self.invocation is not None:actions.append(self.invocation.cleanup)
        actions.extend(d.close for d in reversed(self.directories))
        actions.extend(j.close for j in self.journals if not j.closed)
        try:_attempt_all(self.guard,actions)
        except BaseException as error:self.remember(error);self.guard._abort(error);raise
        finally:
            if self.key is not None:self.key[:]=b'\0'*len(self.key)
    def closed(self):
        require(self.source.operation is self)
        return (self._close_claimed and self._pending is None and self._lane_owners_closed()
            and all(j.closed and not j.ancestors and not j._close_errors for j in self.journals)
            and all(p.closed() for p in self.publishers) and (self.key is None or not any(self.key)))
    def terminal(self):
        v=self.guard.lifetime_ledger.verdict()
        if v.profile_calls or v.commands>14:self.guard._abort(wire.ProtocolError());v=self.guard.lifetime_ledger.verdict()
        if time.monotonic()>=self.source.work_end:self.source.stop('timed-out')
        elif self.guard.cancelled and self.source.stop_reason=='none':self.source.stop('cancelled')
        lifetime={'complete':v.complete,'fatal':v.fatal,'contained':v.contained,'commandDispatched':v.command_dispatched,
            'commands':v.commands,'profileCalls':v.profile_calls,'inputClosed':self.source.material_closed(),
            'handlersRestored':self.guard.handler_state=='RESTORED','invocationClosed':self.closed(),'stopObserved':self.source.stop_reason}
        settled=v.cleanup_complete and v.contained and not v.fatal and v.command_dispatched is not None and all(
            lifetime[k] for k in ('inputClosed','handlersRestored','invocationClosed'))
        result=None
        if not settled:outcome,reason='unknown','cleanup-unknown'
        elif self.source.stop_reason!='none':outcome=reason=self.source.stop_reason
        elif self.primary is not None or self.report is None:outcome,reason='refused',('prepare-unavailable' if type(self) is LocalStorePrepareRun else 'execute-unavailable')
        elif not self.store_completed or v.commands!=14 or self.source.reply_step!=4:outcome,reason='failed','command-incomplete'
        else:outcome,reason,result='complete','none',self.report
        return {'schemaVersion':1,'context':self.request.context,'outcome':outcome,'reason':reason,'result':result,'lifetime':lifetime}
