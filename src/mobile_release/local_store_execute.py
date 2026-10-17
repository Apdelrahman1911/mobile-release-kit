"""One exact local Execute composition on the existing Store owners.

No restart repair, new logical upload retry or caller-provided authority. The
Saved native parent must retain its real Document/source/tools/material owners.
"""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys
import stat
import time
from uuid import UUID
from . import _desktop_store_execute_protocol as wire
from ._desktop_store_execute_protocol import require
from .local_store_prepare import LocalStorePrepareRun,resource_quote,canonical
from .local_prepared_review import FILES,_scan,_intent,_snapshot,decode_quote,MEMORY_LIMIT,RETAINED_JOURNAL
from .local_release_intent import decode_local_operation_intent,validate_local_execution_authority
from .local_release_receipt import local_execution_attempt_key,validate_local_execution_receipt
from .local_candidate_bundle import CandidateBundleReview
from .local_release_journal import MAX_ENTRIES
from .local_release_source import LocalSourceObservation,_retain_source,source_descriptor_quote
from .build_inputs import (invocation_custody,finite_scratch,_app_private_directory,_read_file,_attempt_all)
from .checked_files import _Reader,_Policy,_Node
from ._store_runtime import StoreRuntimeContext
from .stores import StoreRequest,new_store_lane_evidence,_store_operation,complete_store_operation

# Exact parent-process upload originals. No descendant is claimed by the
# native Book from resolution stdout; this reader owns each acquired slot.
UPLOAD_TOOL_SLOTS=32
XCRUN=Path('/usr/bin/xcrun')
class _UploadReader(_Reader):
    def __init__(self,owner):
        require(type(owner) is LocalStoreExecuteRun and owner.apple_execute)
        self.owner=owner;super().__init__(owner.guard)
    def _open(self,name,*,parent,directory):
        self.owner.checkpoint()
        require(self.owner.tool_reader is self and len(self.descriptors)+1<=UPLOAD_TOOL_SLOTS
            and self.owner.quote is not None and self.owner.quote['total']<=256)
        return super()._open(name,parent=parent,directory=directory)

class LocalStoreExecuteRun(LocalStorePrepareRun):
    def __init__(self,request,guard,source):
        self.prepared_readers=[];self.prepared_iterator=None;self.prepared_scan_state='new'
        self.prepared_scope=ExitStack();self.prepared_out=None;self.prepared_bindings={}
        self.intent_bytes=self.intent=self.authority=None;self._source_final=False;self._intent_memory=0
        self.tool_reader=None;self.tool_manifest=None;self.tool_environment=None
        self.upload_nodes={};self.upload_flags={};self.transport_tools=None
        self.fence_readers=[];self.fence_iterator=None;self.fence_state='new'
        self.prior_readers=[];self.preserved_markers={}
        super().__init__(request,guard,source)
    @property
    def apple_execute(self):
        return type(self) is LocalStoreExecuteRun and self.request.context['platform']=='ios'
    @property
    def runtime_count(self):
        return 8 if self.apple_execute else 6
    @property
    def platform(self):
        return 'ios' if self.apple_store else 'android'
    def _quote(self,source=96):
        self.checkpoint()
        value=resource_quote(project_depth=len(self.root.parts),version_parent_depth=len((self.root/self.request.context['savedVersion']['source']).parent.parts),
            source=source,history_depth=len(Path(self.request.native['home']).parts),platform=self.platform)
        # Two held prepared-file parent walks, protected tool manifest original,
        # and empty-fence original/iterator. Unknown close gets no phase credit.
        if self.apple_execute:
            p=len(self.root.parts)
            # Prepared(p+4) and fence(p+3) independent chains, both retained
            # through the lane. Prior Google readers close before acquisition.
            extra=2*p+7+UPLOAD_TOOL_SLOTS
            value['pending']+=extra+20 # actual resolver overlaps original journal
            value['material']+=extra;value['lane']+=extra
            value['source']=max(value['source'],value['lane']) # final Git while held
            # Initial tree precedes these chains; final tree follows POSITIVE
            # original tools/fence/prepared closes. Unknown cannot enter it.
            value['total']=max(v for k,v in value.items() if k!='total')
        else:
            extra=3*len(self.root.parts)+len(Path(self.request.native['toolchain']['root']).parts)+18
            value={k:v+extra for k,v in value.items()}
        require(value['total']<=256)
        if self.quote is not None:require(value['total']<=self.quote['total'])
        self.quote=value;return value
    def _saved_input_quote(self):
        # Only checked saved reads exist in this phase. Count all three
        # independent ancestry walks, a transient leaf, stdio/lease and cleanup.
        # Do not publish this as the later full quote or credit any future close.
        self.checkpoint();require(self.apple_execute and self.quote is None
            and not self.directories and self.invocation is None)
        p=len(self.root.parts)
        v=len((self.root/self.request.context['savedVersion']['source']).parent.parts)
        require(1<p<=24 and 4+p+(p+1)+v+1+4<=256)
    def _memory(self,raw,maximum,*,intent=False):
        quote=decode_quote(raw,maximum,checkpoint=self.checkpoint)
        own=quote-RETAINED_JOURNAL
        # Retained intent plus the two existing decoder/authority graphs can
        # overlap. Reserve their actual prequoted size, journal and16MiB fixed
        # source/candidate/control space before any decoder or pending effects.
        retained=3*(own if intent else self._intent_memory)
        archive=32<<20 if self.apple_store and self.bundle is not None and not self.bundle.closed else 0
        require(RETAINED_JOURNAL+retained+(0 if intent else own)+(16<<20)+archive<=MEMORY_LIMIT)
        if intent:self._intent_memory=own
        return quote
    def _tools(self):
        if self.apple_execute:return self._upload_tools()
        from . import android_build_tools as common,android_build_tools_macos as mac
        binding=mac.binding(self.request.native['toolchain'])
        self.tool_reader=_Reader(self.guard)
        self.tool_manifest=self.tool_reader.acquire(Path(binding.root)/common.MANIFEST_NAME,_Policy(False,1,common.MAX_MANIFEST_BYTES),None)
        node=self.tool_manifest;root=os.fstat(self.tool_reader._number(node.parent))
        require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==binding.identity)
        raw=self._tool_bytes()
        require(hashlib.sha256(raw).hexdigest()==binding.sha256)
        self._memory(raw,common.MAX_MANIFEST_BYTES)
        value=mac._json(raw,common.MAX_MANIFEST_BYTES)
        require(value['schemaVersion']==1 and value['profile']==binding.profile and value['instance']==binding.instance)
        roles=value['roles'];java=mac.parts(roles['java'])
        require(len(java)==6 and java[0]=='jdk' and java[1].endswith('.jdk') and java[2:]==('Contents','Home','bin','java')
            and roles['bundletool']=='bundletool/bundletool.jar')
        home=str(Path(binding.root).joinpath(*java[:4]));jar=str(Path(binding.root)/roles['bundletool'])
        self.tool_environment={'JAVA_HOME':home,'MOBILE_RELEASE_BUNDLETOOL_JAR':jar}
        self.tool_reader.terminal()
    @staticmethod
    def _upload_protected(st,directory=False):
        require((stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))
            and st.st_uid==0 and not st.st_mode&0o7022
            and (directory or st.st_nlink==1 and 0<st.st_size<=64<<20 and st.st_mode&0o111))
    @staticmethod
    def _root_data(st):
        return dict(device=str(st.st_dev),inode=str(st.st_ino),mode=st.st_mode,uid=st.st_uid,gid=st.st_gid)
    def _upload_post(self,*,resolved=False):
        from .ios_current_tools_macos import tool_data
        self.checkpoint();r=self.tool_reader;require(type(r) is _UploadReader)
        r.terminal();selection=self.request.native['uploadSelection']
        require(self._root_data(os.fstat(r._number(self.upload_nodes['app'].slot)))==selection['appIdentity']
            and self._root_data(os.fstat(r._number(self.upload_nodes['developer'].slot)))==selection['developerIdentity']
            and tool_data(os.fstat(r._number(self.upload_nodes['xcrun'].slot)))==selection['xcrun'])
        for node in r.nodes:
            held=os.fstat(r._number(node.slot));self._upload_protected(held,node.directory)
            named=(os.stat('/',follow_symlinks=False) if node.parent is None else r._stat(node.parent,node.name))
            require(getattr(held,'st_flags',0)==getattr(named,'st_flags',0)==self.upload_flags[id(node.slot)])
        if resolved:
            require(self.transport_tools is not None and self.tool_manifest is self.upload_nodes['altool']
                and tool_data(os.fstat(r._number(self.tool_manifest.slot)))==self.transport_tools['altoolIdentity']
                and self.transport_tools['selection']==selection)
    def _upload_tools(self):
        from .ios_current_tools_macos import bindings,tool_data
        from .owned_process import run_owned
        from ._desktop_local_history_protocol import path as path_data
        self.checkpoint();require(self.tool_reader is None and self.observation.calls==6
            and not self._runtime_rows and self.material_head is None and self.material_original is None)
        selection=wire.upload_selection(self.request.native['uploadSelection']);bindings(self.request.native['signingTools'])
        directory=Path(selection['developerDirectory']);app=directory.parent.parent
        r=_UploadReader(self);self.tool_reader=r
        require(len(XCRUN.parts)+len(directory.parts)-1<=UPLOAD_TOOL_SLOTS)
        xcrun=r.acquire(XCRUN,_Policy(False,1,64<<20),None)
        r._directories(directory.parts[1:])
        self.upload_nodes={'xcrun':xcrun}
        for key,path in (('app',app),('developer',directory)):
            matches=[n for n in r.nodes if n.directory and n.canonical==path]
            require(len(matches)==1);self.upload_nodes[key]=matches[0]
        self.upload_flags={id(n.slot):getattr(n.observed,'st_flags',0) for n in r.nodes}
        self._upload_post()
        argv=(str(XCRUN),'--no-cache','--find','altool')
        environment={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','LANG':'C','LC_ALL':'C','DEVELOPER_DIR':str(directory)}
        timeout=min(10,self.source.work_end-time.monotonic());require(timeout>0)
        self._arm('tool-resolution',argv,True,timeout,4097,self._runtime_rows)
        try:
            result=run_owned(argv,environ=environment,cwd=self.root,timeout=timeout,capture=True,text=False,
                output_limit=4097,cancellation=self.guard)
            self._returned(result.returncode)
        except BaseException as error:self._pending=None;self.remember(error);raise
        self._upload_post()
        raw=result.stdout;require(type(raw) is bytes and 0<len(raw)<=4097 and raw.endswith(b'\n') and raw.count(b'\n')==1)
        path=Path(path_data(raw[:-1].decode('utf-8')))
        require(path.name=='altool' and path.is_relative_to(app/'Contents'))
        # Quote this literal independent path walk before any descendant opens.
        require(len(r.descriptors)+len(path.parts)-1<=UPLOAD_TOOL_SLOTS)
        parent,canonical=r._directories(path.parts[1:-1])
        observed=r._stat(parent,path.name);self._upload_protected(observed)
        slot=r._open(path.name,parent=parent,directory=False)
        node=_Node(slot,parent,path.name,canonical/path.name,observed,False);r.nodes.append(node)
        self.tool_manifest=node;self.upload_nodes['altool']=node
        self.upload_flags.update({id(n.slot):getattr(n.observed,'st_flags',0) for n in r.nodes})
        self.transport_tools={'selection':selection,'altoolPath':str(node.canonical),'altoolIdentity':tool_data(observed)}
        self.tool_environment={'DEVELOPER_DIR':str(directory)}
        self._upload_post(resolved=True)
    def _tool_bytes(self):
        node=self.tool_manifest;require(node is not None and self.tool_reader is not None)
        self.tool_reader.terminal();n=self.tool_reader._number(node.slot);body=bytearray();size=node.observed.st_size
        while len(body)<size:
            self.checkpoint();part=os.pread(n,min(65536,size-len(body)),len(body));require(0<len(part)<=size-len(body));body.extend(part)
        require(not os.pread(n,1,size));self.tool_reader.terminal();return bytes(body)
    def _fence_empty(self):
        from . import local_recovery_fence as fence
        fence.open_fence(self,self.prepared_scope);fence.post(self)
    def _begin(self):
        self.checkpoint();require(self.observation.calls==6 and not self.journals)
        self.enrollment,self.key=self.source.exchange('lease-ready',{})
        require(type(self.key) is bytearray and len(self.key)==32)
        j=self._open_journal();head=j.head();c=self.request.context;last=j._rows[-1][0]
        require(last['operationId']==c['candidateOperationId'] and last['phase']=='prepared' and 5<=head['sequence']<=MAX_ENTRIES-2)
        rows=[r for r,_ in j._rows if r['operationId']==c['candidateOperationId']]
        require([r['phase'] for r in rows]==['inputs-pending','inputs-ready','prepare-pending','prepared'])
        from .local_recovery_fence import prior_markers
        self.preserved_markers=prior_markers(self,[r for r,_ in j._rows])
        self._admit_prepared(rows)
        self._prepared_post();self._tools();self._fence_empty()
        self.source.exchange('history-head',head);self.checkpoint();require(j.head()==head)
        self.pending_head=j._append(expected_head=head,operation_id=c['candidateOperationId'],phase='execute-pending',
            payload={'intentSha256':c['intentSha256'],'confirmationSha256':hashlib.sha256(c['confirmation'].encode()).hexdigest(),
                'authorizationId':self.authority['authorizationId'],'assignmentRevision':c['recordRevision']})
        self.source.exchange('execute-pending',self.pending_head);self.checkpoint();require(j.head()==self.pending_head)
        self._retire_journal(j)
    @property
    def authority_purpose(self):
        return 'execute'
    def _admit_prepared(self,rows):
        c=self.request.context
        reader=CandidateBundleReview
        if self.apple_store:
            from .local_ios_candidate_review import IOSCandidateBundleReview
            reader=IOSCandidateBundleReview
        bundle=reader(self,operation_id=c['candidateOperationId'],enrollment=self.enrollment,
            pending=rows[0]['payload'],candidate_sha256=c['candidateSha256']);bundle.acquire()
        m=bundle.value;o=self.observation.observed
        require(m['sourceCommit']==o.commit and m['sourceTree']==o.tree and m['savedConfig']==c['savedConfig'] and m['savedVersion']==c['savedVersion'])
        path=self.root/'.mobile-release/store/local'/UUID(c['candidateOperationId']).hex
        out=self.prepared_scope.enter_context(_app_private_directory(path,app_root=self.root,cancellation=self.guard,create=False))
        require(out is not None);self.prepared_readers.append(out);self.prepared_out=out
        root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
        _scan(self,out)
        for name in FILES:
            value=_read_file(out.fd,name,self.guard,FILES[name],private=True);require(value is not None)
            binding,raw=value;self.prepared_bindings[name]=binding
            if name=='operation-intent.json':
                self._memory(raw,FILES[name],intent=True)
                summary,snapshot=_intent(raw,enrollment=self.enrollment,operation_id=c['candidateOperationId'],rows=rows,manifest=m,checkpoint=self.checkpoint,platform=self.platform)
                self.intent_bytes=raw
            else:
                self._memory(raw,FILES[name])
                require(binding['sha256']==rows[-1]['payload']['storePreconditionSha256']);_snapshot(raw,snapshot,checkpoint=self.checkpoint,platform=self.platform)
        self.intent=decode_local_operation_intent(self.intent_bytes,platform=self.platform)
        require(self.intent['integrity']['sha256']==c['intentSha256'] and self.intent['confirmation']==c['confirmation'])
        self.authority=dict(self.intent['preparedBy'],purpose=self.authority_purpose,authorizationId=self.request.native['authorizationId'],intentSha256=c['intentSha256'],
            source={'commit':o.commit,'tree':o.tree,'ref':o.ref},assignment={'kind':'asc-p8' if self.apple_store else 'google-service-account','recordId':c['recordId'],
            'expectedRevision':c['recordRevision'],'contextRevision':c['credentialContextRevision']})
        validate_local_execution_authority(canonical(self.authority),intent_data=self.intent_bytes,purpose=self.authority_purpose,platform=self.platform)
    def _prepared_post(self):
        out=self.prepared_out;require(out is not None);_scan(self,out)
        for name,binding in self.prepared_bindings.items():
            actual=_read_file(out.fd,name,self.guard,FILES[name],private=True,binding_only=True)
            require(actual is not None and actual==(binding,b''))
        _scan(self,out);out.check();self.checkpoint()
    def _final_source_fence(self):
        from .local_recovery_fence import post
        post(self,own_pending=True)
    def _arm_source(self,source,args,timeout,limit):
        self.checkpoint();require(source is self.observation)
        if len(self._source_rows)==7:self._final_source_fence()
        return super()._arm_source(source,args,timeout,limit)
    def source_final(self,observation):
        require(observation is self.observation and observation.calls==8 and not self._source_final)
        self._prepared_post()
        from .local_recovery_fence import post
        post(self,own_pending=True)
        if self.apple_execute:self._upload_post(resolved=True)
        else:
            self.bundle.finish()
            require(hashlib.sha256(self._tool_bytes()).hexdigest()==self.request.native['toolchain']['inventorySha256'])
        self.tool_reader.close();self.tool_reader.assert_closed()
        self.prepared_scope.close();require(all(p.closed() for p in (*self.prepared_readers,*self.fence_readers,*self.prior_readers)))
        if self.apple_execute:self.bundle.finish()
        self._source_final=True
    def runtime_environment(self):
        self.checkpoint();require(self.tool_environment is not None and self.tool_reader is not None)
        if self.apple_execute:
            self._upload_post(resolved=True);env=self.runtime.environment();env.update(self.tool_environment)
            env['MOBILE_RELEASE_IOS_IPA_PATH']=str(self.bundle.members[0].canonical)
            env['MOBILE_RELEASE_IOS_ARCHIVE_PATH']=str(self.bundle.archive.canonical)
            return env
        self.tool_reader.terminal();env=self.runtime.environment();env.update(self.tool_environment)
        env['PATH']=self.tool_environment['JAVA_HOME']+'/bin:'+env['PATH']
        env['MOBILE_RELEASE_ANDROID_AAB_PATH']=str(self.bundle.members[0].canonical)
        return env
    def archive_artifact(self,config,request,record,invocation,path):
        self.checkpoint();require(self.apple_store and self._store_entered and config is self.config
            and request is self.store_request and record is self.record and invocation is self.invocation
            and path==self.bundle.archive.canonical and not self.bundle.closed)
        self._prepared_post();self.bundle._scan();self.bundle.reader.terminal();return True
    def admit_store(self,config,release,request,record,guard,invocation):
        self.checkpoint();require(not self._store_entered and config is self.config and release is self.version and request is self.store_request
            and record is self.record and guard is self.guard and invocation is self.invocation and request.execute and not request.prepare
            and request.recovery_run_id is None and request.recovery_confirmation is None and request.stage=='candidate' and request.platform==self.platform
            and self.source.reply_step==self.protocol.MATERIAL_STEP and self.material_head is not None and self.material_original is not None
            and len(self._source_rows)==6 and (len(self._runtime_rows)==1 and self._runtime_rows[0]['kind']=='tool-resolution'
                and self._runtime_rows[0]['returned'] and self._runtime_rows[0]['code']==0 if self.apple_execute else not self._runtime_rows) and self.bundle is not None and not self.bundle.closed)
        self._prepared_post();self._store_entered=True;return True
    def attempt_key(self,record,root,mode,digest,authority):
        self.checkpoint();require(record is self.record and root==self.root and mode=='execute' and self._store_entered
            and digest==bytes.fromhex(self.request.context['intentSha256']) and authority==self.authority)
        return local_execution_attempt_key(intent_data=self.intent_bytes,authority_data=canonical(self.authority),purpose=self.authority_purpose,expected_intent_sha256=self.request.context['intentSha256'],platform=self.platform)
    def attempt_directory(self,attempt,directory):
        self.checkpoint();require(attempt is self.record._pending_attempt and attempt.phase=='ACQUIRING' and self.fence_readers)
        out=self.fence_readers[0];out.check();directory.check()
        left,right=os.fstat(out.fd),os.fstat(directory.fd)
        require((left.st_dev,left.st_ino,left.st_mode,left.st_uid,left.st_gid)==(right.st_dev,right.st_ino,right.st_mode,right.st_uid,right.st_gid))
        from .local_recovery_fence import post
        post(self)
    def lane_context(self,files):
        self.checkpoint();require(files is self.record._files_owner() and files.mode=='execute' and files.phase=='SEALING' and self._store_entered)
        self._prepared_post()
        value={'authority':self.authority,'expectedIntentSha256':self.request.context['intentSha256']}
        if self.apple_execute:
            self._upload_post(resolved=True)
            value.update(signingTools=self.request.native['signingTools'],transportTools=self.transport_tools)
        else:value['toolchain']=self.request.native['toolchain']
        raw=canonical(value)
        require(len(raw)<=16384);return raw.decode('utf-8')
    def validate_receipt(self,raw):
        self.checkpoint();self._memory(raw,65536)
        return validate_local_execution_receipt(raw,intent_data=self.intent_bytes,authority_data=canonical(self.authority),purpose=self.authority_purpose,expected_intent_sha256=self.request.context['intentSha256'],platform=self.platform)
    def run(self):
        self.checkpoint();require(not self._ran and sys.platform=='darwin' and os.getcwd()==self.request.native['cwd']);self._ran=True
        try:
            if self.apple_execute:
                self._saved_input_quote()
                self.config,self.version=self._saved()
                # These exact names are authenticated above. Reserve every
                # later overlap before invocation/namespace/source acquisition;
                # the real source owner recomputes the same bound below.
                self._quote(source_descriptor_quote(self.root,
                    self.config.section('version')['source'],
                    self.config.section('source')['candidateBranch']))
            else:
                self._quote();self.config,self.version=self._saved()
            c=self.request.context;prepared=self.root/'.mobile-release/store/local'/UUID(c['candidateOperationId']).hex
            output=prepared.with_name(prepared.name+'-'+self.authority_purpose+'-'+UUID(self.request.native['authorizationId']).hex)
            require(not os.path.lexists(output))
            self.store_request=StoreRequest(stage='candidate',platform=self.platform,confirmation=c['confirmation'],execute=True,prepare=False,
                output_dir=output,store_receipt=output/'raw-store-receipt.json',operation_intent=prepared/'operation-intent.json')
            self.record=new_store_lane_evidence(self.config,self.store_request,self.guard)
            with invocation_custody(self.root,mode='store',cancellation=self.guard,lane_evidence=self.record) as invocation:
                with invocation.project(signing_lease=None):
                    p=invocation._original_project
                    self.project_ancestry=tuple((v.st_dev,v.st_ino) for v in (os.fstat(s.number) for s in p.directory.slots))
                    observation=LocalSourceObservation(invocation,self.saved_bytes['release/mobile-release.json'],self.saved_bytes[c['savedVersion']['source']],endpoint=self.source.work_end,execution_source=None)
                    self.observation=observation;observation._composition=self;self._quote(observation.descriptor_quote())
                    with _retain_source(observation):
                        self._retire_saved();self._begin()
                        with finite_scratch(layout='online-runner',cancellation=self.guard,parent=Path('/private/tmp')) as home:
                            self.home=home;self.runtime=StoreRuntimeContext.installed(Path(self.request.native['cwd']),invocation=invocation,private_home=home)
                            with finite_scratch(layout='store-selection',cancellation=self.guard,parent=home._path) as received:
                                self.received=received;self.material_original=self.source.receive_material(self,received)
                                if self.apple_store:self._received_material=self.source._material
                                self.readback=_store_operation(config=self.config,release=self.version,request=self.store_request,operation_intent=self.intent,
                                    lane_evidence=self.record,cancellation=self.guard,invocation=invocation,**({"_local_execute":self} if type(self) is LocalStoreExecuteRun else {"_local_reconcile":self}))
                                observation.check()
            require(self._source_final and self._lane_owners_closed() and len(self._source_rows)==8 and len(self._runtime_rows)==self.runtime_count)
            complete_store_operation(self.readback,lane_evidence=self.record,cancellation=self.guard);self.store_completed=True
            self._publication(self.readback._content)
        except BaseException as error:self.remember(error);raise
        finally:self.close()
    def _publication(self,raw):
        self.checkpoint();require(self.store_completed and self._source_final and self._lane_owners_closed())
        receipt=self.validate_receipt(raw);target=Path(self.record._output)
        with _app_private_directory(target.parent,app_root=self.root,cancellation=self.guard,create=False) as out:
            require(out is not None);self.publishers.append(out)
            root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==self.source.lease_identity)
            value=_read_file(out.fd,target.name,self.guard,65536,private=True);require(value is not None and value[1]==raw)
            binding=value[0];identity=self.record._files_owner().document_identity
            require(identity is not None and all(binding[k]==getattr(identity,k) for k in ('device','inode','uid','gid','mode')))
            j=self._open_journal();require(j.head()==self.pending_head and j._rows[-1][0]['phase']=='execute-pending')
            digest=hashlib.sha256(raw).hexdigest();head=j._append(expected_head=self.pending_head,operation_id=self.request.context['candidateOperationId'],phase='settled-success',
                payload={'intentSha256':self.request.context['intentSha256'],'receiptSha256':digest})
            self.source.exchange('execute-settled',{'head':head,'phase':'settled-success'});self.checkpoint();require(j.head()==head)
            value=_read_file(out.fd,target.name,self.guard,65536,private=True,binding_only=True);require(value is not None and value==(binding,b''));out.check();self._retire_journal(j)
        require(out.closed());self.checkpoint();i=self.intent
        summary=dict(operationId=i['operationId'],candidateSha256=i['candidateSha256'],intentSha256=i['integrity']['sha256'],receiptSha256=digest,
            authorizationId=self.authority['authorizationId'],sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],
            version={'name':i['version']['marketing'],'build':i['version']['build']},destination=i['destination'],
            observedAt=receipt['observedAt'],result=receipt['result'],limitations=list(wire.LIMITATIONS))
        summary['bundleId' if self.apple_execute else 'applicationId']=i['application']['id']
        if self.apple_execute:summary['appStoreAppId']=i['application']['storeAppId']
        self.report={'schemaVersion':1,'scope':'local-%s-store-execute'%self.platform,'headSequence':head['sequence'],'executionReceipt':summary};wire.validate_result(self.report,platform=self.platform)
    def _lane_owners_closed(self):
        return (super()._lane_owners_closed() and self.prepared_iterator is None and self.prepared_scan_state in {'new','closed'}
            and self.fence_iterator is None and self.fence_state in {'new','closed'}
            and all(p.closed() for p in (*self.prepared_readers,*self.fence_readers,*self.prior_readers))
            and (self.tool_reader is None or all(s.state in {'UNACQUIRED','CLOSED'} for s in self.tool_reader.descriptors)))
    def close(self):
        if self._close_claimed:return super().close()
        # Preserve the original exception through each retained directory's
        # existing context exit. Calling close() with a fabricated successful
        # body would turn an ordinary STOP recheck into a cleanup fault.
        def retire_prepared():
            error=self.primary
            if error is None:self.prepared_scope.close()
            else:self.prepared_scope.__exit__(type(error),error,error.__traceback__)
        actions=[retire_prepared]
        if self.tool_reader is not None:actions.append(self.tool_reader.close)
        first=None
        try:_attempt_all(self.guard,actions)
        except BaseException as error:self.remember(error);first=error
        try:super().close()
        except BaseException:
            if first is None:raise
        if first is not None:raise first
