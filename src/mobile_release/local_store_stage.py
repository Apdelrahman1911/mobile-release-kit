"""Closed later-stage cuts on the existing local Store owner, never a runner.

These functions require the original Prepare/Execute object. DATA helpers below
cannot grant a lane, an original predecessor, or repair historical finality.
"""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
from uuid import UUID
from . import _desktop_store_prepare_protocol as wire
from .build_inputs import FiniteScratch, _FD, _read_file, _app_private_directory, _publish_private_file
from .local_release_journal import canonical
from .local_store_predecessor import StorePredecessorInputs
from .local_store_metadata import StoreMetadataTree
from .local_release_intent import decode_local_operation_intent
from .provenance import seal, timestamp, _intent_destination, _signing_identity, _validate_external_locale_scope
require=wire.require


def supplementary(context):
    rows=[]
    for key,kind in (('reviewContact','apple-review-contact'),('commitment','operation-commitment'),('reviewDemo','apple-review-demo')):
        item=context['supplementalAssignments'][key]
        if item is not None:rows.append(dict(kind=kind,recordId=item['recordId'],expectedRevision=item['recordRevision'],contextRevision=context['credentialContextRevision']))
    return rows


def material_parts(parts, context):
    from .desktop_store_preflight import StorePreflightRun
    demo=context['supplementalAssignments']['reviewDemo'] is not None
    require(type(parts) is tuple and len(parts)==(11 if demo else 9) and all(type(p) is bytes for p in parts))
    StorePreflightRun.validate_apple_shape(parts[:3])
    try:
        for value in (*parts[3:7],*parts[9:]):
            require(1<=len(value)<=4096 and value.decode('utf-8').strip() and b'\0' not in value)
        require(len(parts[7])==44 and len(base64.b64decode(parts[7],validate=True))==32
            and base64.b64encode(base64.b64decode(parts[7],validate=True))==parts[7]
            and re.fullmatch(rb'[A-Za-z0-9_.-]{1,64}',parts[8]) is not None)
    except (ValueError,UnicodeError):raise wire.ProtocolError() from None


def _prepare(owner):
    from .local_store_prepare import LocalStorePrepareRun
    require(type(owner) is LocalStorePrepareRun and owner.later_stage and owner.request.context['operation']=='local-store-prepare')
    owner.checkpoint()


def metadata_quote(owner,directories,scratch):
    _prepare(owner);m=owner.metadata;o=owner.observation
    require(owner.quote is not None and o.calls==6 and o.active and not owner._runtime_rows
        and owner.pending_head is None and not scratch.active and not scratch.parent.slots
        and m is not None and m.rows is not None and scratch is owner.metadata_scratch)
    p=len(owner.root.parts);n=2 if owner.stage=='production-submit' or getattr(owner,'readiness',False) else 1
    private={''}
    for path in m.rows:
        if path.name=='.gitkeep':continue
        for parent in PurePosixPath(path.relative_to(m.root).as_posix()).parents:
            if parent!=PurePosixPath('.'):private.add(parent.as_posix())
    require(len(private)<=96)
    # Existing source/project/bundle/namespace counters are already in quote.
    # Journal remains the same original across lane; publication never overlaps
    # a second original or decoded journal. Scratch parents are independent;
    # tree uses those original slots, not another ancestry walk.
    predecessors=(2*n+(1 if owner.request.context['platform']=='ios' and owner.stage=='production-submit' else 0))*(p+4)+2
    scratch_slots=len(scratch.parent.path.parts)+1
    journal=len(owner.journals[0].ancestors)+2
    extra=predecessors+directories+scratch_slots+len(private)+4
    q=dict(owner.quote)
    q['pending']+=extra
    q['material']+=extra+journal;q['lane']+=extra+journal
    q['tree']+=scratch_slots # only after positive metadata/pred/journal closes
    q['publication']+=scratch_slots+2
    q['total']=max(q[k] for k in ('source','pending','material','lane','tree','publication'))
    require(q['total']<=256)
    owner.quote=q;owner.stage_extra_quote=dict(predecessors=predecessors,metadataDirectories=directories,
        privateDirectories=len(private),scratch=scratch_slots,journal=journal)
    return q['total']


def _candidate(owner,journal):
    c=owner.request.context
    rows=[r for r,_ in journal._rows if r['operationId']==c['candidateOperationId']]
    require(len(rows)==6 and [r['phase'] for r in rows]==['inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending','settled-success'])
    from .local_candidate_bundle import CandidateBundleReview
    reader=CandidateBundleReview
    if c['platform']=='ios':
        from .local_ios_candidate_review import IOSCandidateBundleReview
        reader=IOSCandidateBundleReview
    bundle=reader(owner,operation_id=c['candidateOperationId'],enrollment=owner.enrollment,
        pending=rows[0]['payload'],candidate_sha256=c['candidateSha256']);bundle.acquire()
    m=bundle.value;o=owner.observation.observed;platform=c['platform'];section=owner.config.section(platform)
    require(m['savedVersion']==c['savedVersion'])
    if owner.stage=='external-testing':
        require(m['sourceCommit']==o.commit and m['sourceTree']==o.tree and m['savedConfig']==c['savedConfig'])
    if platform=='ios':
        from .local_ios_candidate_bundle import signing_data
        require(m['bundleId']==section['bundleId']);_signing_identity(owner.config,platform,signing_data(m['signing']))
        require((c['supplementalAssignments']['reviewDemo'] is not None)==section.get('review',{}).get('demoAccountRequired',False))
    else:require(m['applicationId']==section['applicationId'] and m['signerSha256']==section['uploadCertificateSha256'].replace(':','').lower())


def begin(owner):
    _prepare(owner);o=owner.observation;c=owner.request.context
    require(o.calls==6 and not owner.journals and owner.bundle is None and owner.metadata is not None)
    owner.enrollment,owner.key=owner.source.exchange('lease-ready',{})
    require(type(owner.key) is bytearray and len(owner.key)==32)
    j=owner._open_journal();head=j.head()
    # Initial candidate tree is checked before the additional predecessor and
    # metadata originals exist. All subsequent acquisitions are prequoted.
    _candidate(owner,j)
    scratch=FiniteScratch('store-metadata',owner.guard,parent=owner.root/'.mobile-release')
    require(owner.metadata_scratch is scratch)
    owner.metadata._reserve_store(owner,scratch)
    scratch.acquire()
    owner.metadata_tree=StoreMetadataTree(scratch,platform=c['platform'])
    owner.metadata_snapshot=scratch.metadata_archive(owner.metadata.root,platform=c['platform'],_source=owner.metadata,_tree=owner.metadata_tree)
    payload=dict(stage=owner.stage,candidateOperationId=c['candidateOperationId'],candidateSha256=c['candidateSha256'],
        predecessorOperationId=c['predecessorOperationId'],predecessorReceiptSha256=c['predecessorReceiptSha256'],
        sourceCommit=o.observed.commit,sourceTree=o.observed.tree,configurationSha256=c['savedConfig']['sha256'],
        versionSha256=c['savedVersion']['sha256'],metadataSha256=owner.metadata_snapshot.sha256,
        confirmationSha256=hashlib.sha256(c['confirmation'].encode()).hexdigest())
    if j._rows[-1][0]['phase']=='external-ready':
        require(owner.stage=='production-submit' and c['platform']=='ios')
        payload['externalReadinessReceiptSha256']=j._rows[-1][0]['payload']['readinessReceiptSha256']
    pred=StorePredecessorInputs(owner.invocation._original_project.directory,j,owner.guard,
        operation_id=owner.stage_id,payload=payload,platform=c['platform'])
    owner.stage_predecessors=pred;pred.acquire();owner.stage_facts=pred.facts()
    candidate=owner.stage_facts['candidate'];m=owner.bundle.value
    require(candidate['candidateSha256']==c['candidateSha256'] and candidate['operationId']==c['candidateOperationId']
        and candidate['candidateSource']['commit']==m['sourceCommit'] and candidate['candidateSource']['tree']==m['sourceTree']
        and candidate['version']=={'marketing':c['savedVersion']['name'],'build':c['savedVersion']['build']})
    if c['platform']=='ios':
        require(candidate['application']['storeAppId']==str(owner.config.section('ios')['appStoreAppId']))
    owner.source.exchange('history-head',head);owner.checkpoint();require(j.head()==head)
    owner.pending_head=j._append(expected_head=head,operation_id=owner.stage_id,phase='promotion-pending',payload=payload)
    owner.source.exchange('prepare-pending',owner.pending_head);owner.checkpoint();require(j.head()==owner.pending_head)
    # SAME journal original stays alive for the predecessor prefix POST. It
    # closes after source8, before publication's existing fresh original.


def metadata_intent_post(owner,intent):
    """Config-specific target notes from the original private tree, not live paths."""
    _validate_external_locale_scope(intent,owner.config)
    if intent['platform']!='android' or intent['stage']!='production-submit':return
    from .metadata import validate_android_release_note,ANDROID_NOTE_MAX_BYTES
    tree=owner.metadata_tree;tree._point();expected=[]
    for locale in sorted(owner.config.section('metadata')['androidLocales']):
        prefix='android/'+locale+'/changelogs/'
        exact=prefix+str(intent['version']['build'])+'.txt'
        name=exact if exact in tree.files else prefix+'default.txt'
        require(name in tree.files);entry=tree.files[name]
        value=_read_file(entry['parent'].number,entry['name'],owner.guard,ANDROID_NOTE_MAX_BYTES)
        require(value is not None and value[0]==entry['binding'])
        expected.append(dict(language=locale,text=validate_android_release_note(value[1].decode('utf-8'))))
    tree._point();require(intent['storePrecondition']['snapshot']['targetRelease']['releaseNotes']==expected)


def intent_data(owner,precondition):
    _prepare(owner);c=owner.request.context;platform=c['platform'];f=owner.stage_facts;candidate=f['candidate']
    o=owner.observation.observed;source=dict(commit=o.commit,tree=o.tree,ref=o.ref)
    snap=owner.metadata_snapshot;owner.metadata_scratch.require(snap)
    authority=dict(schemaVersion=1,origin='local-desktop',purpose='prepare',project=owner.enrollment,
        operationId=owner.stage_id,candidateSha256=c['candidateSha256'],authorizationId=owner.request.native['authorizationId'],
        source=source,assignment=dict(kind='asc-p8' if platform=='ios' else 'google-service-account',recordId=c['recordId'],
            expectedRevision=c['recordRevision'],contextRevision=c['credentialContextRevision']),
        confirmationSha256=hashlib.sha256(c['confirmation'].encode()).hexdigest(),intentSha256=None)
    if platform=='ios':authority['supplementalAssignments']=supplementary(c)
    predecessors=dict(candidateManifestSha256=c['candidateSha256'],candidateReceiptSha256=candidate['receiptSha256'])
    if owner.stage=='production-submit':
        predecessors['externalReceiptSha256']=f['predecessor']['receiptSha256']
        if 'readinessReceiptSha256' in f['predecessor']:predecessors['externalReadinessReceiptSha256']=f['predecessor']['readinessReceiptSha256']
    artifacts=json.loads(canonical(candidate['artifacts']))
    require(artifacts[1]['logicalName']=='store-metadata');artifacts[1].update(size=snap.size,sha256=snap.sha256)
    value=seal(dict(documentType='local-store-operation-intent',schemaVersion=1,origin='local-desktop',
        project=owner.enrollment,operationId=owner.stage_id,candidateOperationId=c['candidateOperationId'],candidateSha256=c['candidateSha256'],
        platform=platform,stage=owner.stage,tooling=owner.request.native['tooling'],candidateSource=candidate['candidateSource'],
        operationSource=source,preparedBy=authority,confirmation=c['confirmation'],application=candidate['application'],
        version=candidate['version'],destination=_intent_destination(owner.config,owner.stage,platform),
        configuration=dict(path='release/mobile-release.json',sha256=c['savedConfig']['sha256'],metadataSha256=snap.sha256),
        artifacts=artifacts,signing=candidate['signing'],predecessors=predecessors,storePrecondition=precondition,
        privateStateCommitments=precondition['snapshot'].get('privateStateCommitments',{}),createdAt=timestamp()))
    raw=canonical(value)+b'\n';decode_local_operation_intent(raw,platform=platform,stage=owner.stage)
    metadata_intent_post(owner,value)
    return raw,value


def final_source(owner,observation):
    _prepare(owner)
    require(observation is owner.observation and observation.calls==8 and owner.metadata.final_post
        and not owner.stage_source_closed and owner.readback is not None and not owner._pending)
    owner.stage_predecessors.post();owner.metadata_tree.post()
    # Current raw precondition was produced by the sealed lane using this
    # exact tree; prepare the DATA while all source/metadata originals live.
    owner.stage_intent_bytes,owner.stage_intent=intent_data(owner,json.loads(owner.readback._content))
    owner.metadata_tree.cleanup();require(owner.metadata_tree.closed and owner.metadata_tree.retired)
    owner.metadata._close();require(owner.metadata.closed and not owner.metadata.failed)
    owner.stage_predecessors.close();require(owner.stage_predecessors.closed and not owner.stage_predecessors.failed)
    owner._retire_journal(owner.journals[0])
    owner.bundle.finish() # iOS full tree AFTER positively closed extra originals.
    owner.stage_source_closed=True


def publication(owner,raw):
    _prepare(owner)
    require(owner.store_completed and owner.stage_source_closed and owner._lane_owners_closed())
    i=owner.stage_intent;raw_intent=owner.stage_intent_bytes;scratch=owner.metadata_scratch;snapshot=owner.metadata_snapshot
    require(i is not None and raw_intent==canonical(i)+b'\n');scratch.require(snapshot)
    target=Path(owner.record._output);metadata='store-metadata.zip'
    with _app_private_directory(target.parent,app_root=owner.root,cancellation=owner.guard,create=False) as out:
        require(out is not None);owner.publishers.append(out)
        root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==owner.source.lease_identity)
        require(set(os.listdir(out.fd))=={'store-precondition.json'})
        original=_read_file(out.fd,target.name,owner.guard,4<<20,private=True);require(original is not None and original[1]==raw)
        _publish_private_file(out,'operation-intent.json',iter((raw_intent,)))
        def blocks():
            scratch.require(snapshot);slot=_FD(owner.guard);owner.stage_copy_slots.append(slot)
            try:
                fd=slot.open(scratch._spec('metadata').name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=scratch.slot.number)
                from .build_inputs import _file
                require(all(_file(os.fstat(fd))[k]==v for k,v in scratch.records['metadata']['binding'].items() if k!='sha256'));left=snapshot.size
                while left:
                    owner.checkpoint();part=os.read(fd,min(left,65536));require(0<len(part)<=left);left-=len(part);yield part
                require(not os.read(fd,1) and all(_file(os.fstat(fd))[k]==v for k,v in scratch.records['metadata']['binding'].items() if k!='sha256'));scratch.require(snapshot)
            finally:slot.close()
        _publish_private_file(out,metadata,blocks())
        expected={target.name:hashlib.sha256(raw).hexdigest(),'operation-intent.json':hashlib.sha256(raw_intent).hexdigest(),metadata:snapshot.sha256}
        require(set(os.listdir(out.fd))==set(expected));bindings={}
        for name,digest in expected.items():
            value=_read_file(out.fd,name,owner.guard,snapshot.size if name==metadata else 4<<20,private=True,binding_only=True)
            require(value is not None and value[0]['sha256']==digest);bindings[name]=value[0]
        j=owner._open_journal();require(j.head()==owner.pending_head and j._rows[-1][0]['phase']=='promotion-pending')
        digest=hashlib.sha256(raw).hexdigest()
        head=j._append(expected_head=owner.pending_head,operation_id=owner.stage_id,phase='prepared',payload=dict(
            candidateSha256=owner.request.context['candidateSha256'],intentSha256=i['integrity']['sha256'],storePreconditionSha256=digest))
        owner.source.exchange('prepare-settled',dict(head=head,phase='prepared'));owner.checkpoint();require(j.head()==head)
        require(set(os.listdir(out.fd))==set(bindings))
        for name,binding in bindings.items():
            require(_read_file(out.fd,name,owner.guard,snapshot.size if name==metadata else 4<<20,private=True,binding_only=True)==(binding,b''))
        out.check();scratch.require(snapshot);owner._retire_journal(j)
    require(out.closed());scratch.cleanup();require(scratch._cleanup_complete)
    c=owner.request.context;platform=c['platform'];summary=dict(operationId=owner.stage_id,candidateSha256=c['candidateSha256'],
        intentSha256=i['integrity']['sha256'],storePreconditionSha256=digest,sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],
        version=dict(name=i['version']['marketing'],build=i['version']['build']),destination=i['destination'],observedAt=i['storePrecondition']['observedAt'],
        limitations=list(wire.STAGE_LIMITATIONS),stage=owner.stage,candidateOperationId=c['candidateOperationId'],
        predecessorOperationId=c['predecessorOperationId'],predecessorReceiptSha256=c['predecessorReceiptSha256'])
    summary['bundleId' if platform=='ios' else 'applicationId']=i['application']['id']
    if platform=='ios':summary['appStoreAppId']=i['application']['storeAppId']
    owner.report=dict(schemaVersion=1,scope='local-%s-store-stage-prepare'%platform,headSequence=head['sequence'],preparedIntent=summary)
    wire.validate_result(owner.report,platform=platform,selected=owner.stage)


def _execute(owner):
    from .local_store_execute import LocalStoreExecuteRun
    from .local_store_reconcile import LocalStoreReconcileRun
    require((type(owner) is LocalStoreExecuteRun or type(owner) is LocalStoreReconcileRun and owner.readiness) and owner.later_stage)
    owner.checkpoint()


def execute_quote(owner,source):
    _execute(owner)
    from .local_store_prepare import resource_quote
    p=len(owner.root.parts);n=2 if owner.stage=='production-submit' or getattr(owner,'readiness',False) else 1
    q=resource_quote(project_depth=p,version_parent_depth=len((owner.root/owner.request.context['savedVersion']['source']).parent.parts),
        source=source,history_depth=len(Path(owner.request.native['home']).parts),platform=owner.platform)
    # Original predecessor(2/4), current prepared, empty-fence and private
    # scratch walks; no build tools or uploader original in a later-stage lane.
    extra=(2*n+(1 if owner.request.context['platform']=='ios' and owner.stage=='production-submit' else 0))*(p+4)+2+(p+4)+(p+3)+(p+2)+2
    journal=len(Path(owner.request.native['home']).parts)+6
    for key in ('pending','material','lane'):q[key]+=extra+journal
    q['source']=max(q['source'],q['lane']);q['total']=max(v for k,v in q.items() if k!='total')
    require(q['total']<=256)
    if owner.quote is not None:require(q['total']<=owner.quote['total'])
    owner.quote=q;return q


def execute_tree_quote(owner,tree,count):
    _execute(owner)
    require(tree is owner.metadata_tree and not tree.started and owner.pending_head is None
        and owner.observation.calls==6 and owner.stage_extra_quote is None and not owner._runtime_rows)
    q=dict(owner.quote)
    for key in ('source','pending','material','lane'):q[key]+=count
    q['total']=max(v for k,v in q.items() if k!='total');require(q['total']<=256)
    owner.quote=q;owner.stage_extra_quote=dict(privateDirectories=count)


def execute_post(owner):
    _execute(owner);out=owner.prepared_out;pred=owner.stage_predecessors
    require(out is not None and pred is not None)
    pred._names(out,owner.prepared_bindings)
    for name,(binding,limit) in owner.prepared_bindings.items():
        require(_read_file(out.fd,name,owner.guard,limit,private=True,binding_only=True)==(binding,b''))
    pred._names(out,owner.prepared_bindings);pred.post()


def execute_begin(owner):
    _execute(owner);c=owner.request.context;o=owner.observation
    require(o.calls==6 and not owner.journals and owner.metadata_tree is None and not owner._runtime_rows)
    owner.enrollment,owner.key=owner.source.exchange('lease-ready',{})
    require(type(owner.key) is bytearray and len(owner.key)==32)
    j=owner._open_journal();head=j.head();rows=[r for r,_ in j._rows if r['operationId']==owner.stage_id]
    readiness=getattr(owner,'readiness',False)
    if readiness:
        from .local_release_journal import external_readiness_chain
        external_readiness_chain(rows,owner.stage_id)
        require([r for r,_ in j._rows[-4:]]==rows and 11<=head['sequence']<=508
            and rows[-1]['payload']['receiptSha256']==c['executionReceiptSha256']
            and rows[2]['payload']['authorizationId']!=owner.request.native['authorizationId'])
    else:require(len(rows)==2 and [r['phase'] for r in rows]==['promotion-pending','prepared']
        and [r for r,_ in j._rows[-2:]]==rows and head['sequence']<=511)
    start,prepared=rows[0]['payload'],rows[1]['payload']
    match=('candidateOperationId','candidateSha256') if readiness else ('stage','candidateOperationId','candidateSha256','predecessorOperationId','predecessorReceiptSha256')
    require(all(start[k]==c[k] for k in match)
        and start['sourceCommit']==o.observed.commit and start['sourceTree']==o.observed.tree
        and start['configurationSha256']==c['savedConfig']['sha256'] and start['versionSha256']==c['savedVersion']['sha256']
        and start['confirmationSha256']==hashlib.sha256(c['confirmation'].encode()).hexdigest())
    _candidate(owner,j)
    from .local_recovery_fence import prior_markers
    owner.preserved_markers=prior_markers(owner,[r for r,_ in j._rows])
    pred=StorePredecessorInputs(owner.invocation._original_project.directory,j,owner.guard,
        operation_id=owner.stage_id,payload=start,platform=owner.platform)
    owner.stage_predecessors=pred
    if readiness:pred.acquire(_readiness=owner)
    else:pred.acquire(prepared=True)
    owner.stage_facts=pred.facts()
    out=owner.prepared_scope.enter_context(_app_private_directory(owner.root/'.mobile-release/store/local'/UUID(owner.stage_id).hex,
        app_root=owner.root,cancellation=owner.guard,create=False))
    require(out is not None);owner.prepared_out=out;owner.prepared_readers.append(out)
    root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==owner.source.lease_identity)
    from .local_release_intent import MAX_LOCAL_INTENT_BYTES,validate_local_execution_authority
    from .local_store_metadata import MAX_ARCHIVE_SIZE,MAX_ROWS_BYTES,MAX_FILE_COUNT,MAX_FILE_SIZE
    limit=MAX_ARCHIVE_SIZE+4*MAX_ROWS_BYTES+512*MAX_FILE_COUNT+65536
    names={'operation-intent.json':MAX_LOCAL_INTENT_BYTES,'store-precondition.json':4<<20,'store-metadata.zip':limit}
    pred._names(out,names)
    for name,maximum in names.items():
        value=_read_file(out.fd,name,owner.guard,maximum,private=True,binding_only=name=='store-metadata.zip');require(value is not None)
        binding,raw=value;owner.prepared_bindings[name]=(binding,maximum)
        if name=='operation-intent.json':
            owner._memory(raw,maximum,intent=True);owner.intent_bytes=raw
            owner.intent=decode_local_operation_intent(raw,platform=owner.platform,stage=owner.stage)
        elif name=='store-precondition.json':
            owner._memory(raw,maximum);require(binding['sha256']==prepared['storePreconditionSha256'])
            from .provenance import validate_store_precondition,_reject_duplicate_pairs,canonical_json_bytes
            snapshot=json.loads(raw,object_pairs_hook=_reject_duplicate_pairs,parse_constant=lambda _:require(False))
            validate_store_precondition(snapshot,platform=owner.platform,stage=owner.stage)
            require(canonical_json_bytes(snapshot)==canonical_json_bytes(owner.intent['storePrecondition']))
            del snapshot
        else:require(binding['sha256']==start['metadataSha256']==owner.intent['configuration']['metadataSha256']
            and binding['sha256']==owner.intent['artifacts'][1]['sha256'] and binding['size']==owner.intent['artifacts'][1]['size'])
    i=owner.intent;facts=owner.stage_facts['candidate'];predecessors=dict(candidateManifestSha256=c['candidateSha256'],candidateReceiptSha256=facts['receiptSha256'])
    if owner.stage=='production-submit':
        predecessors['externalReceiptSha256']=owner.stage_facts['predecessor']['receiptSha256']
        if 'readinessReceiptSha256' in owner.stage_facts['predecessor']:predecessors['externalReadinessReceiptSha256']=owner.stage_facts['predecessor']['readinessReceiptSha256']
    require(i['project']==owner.enrollment and i['operationId']==owner.stage_id and i['candidateOperationId']==c['candidateOperationId']
        and i['candidateSha256']==c['candidateSha256']==prepared['candidateSha256'] and i['integrity']['sha256']==c['intentSha256']==prepared['intentSha256']
        and i['confirmation']==c['confirmation'] and i['predecessors']==predecessors
        and i['operationSource']==dict(commit=o.observed.commit,tree=o.observed.tree,ref=o.observed.ref)
        and i['configuration']['sha256']==start['configurationSha256']
        and all(i[k]==facts[k] for k in ('application','version','signing','candidateSource'))
        and [a for a in i['artifacts'] if a['kind']!='metadata']==[a for a in facts['artifacts'] if a['kind']!='metadata']
        and i['destination']==_intent_destination(owner.config,owner.stage,owner.platform))
    if owner.platform=='ios':require(i['application']['storeAppId']==str(owner.config.section('ios')['appStoreAppId']))
    owner.authority=dict(i['preparedBy'],purpose='execute',authorizationId=owner.request.native['authorizationId'],intentSha256=c['intentSha256'],
        source=dict(commit=o.observed.commit,tree=o.observed.tree,ref=o.observed.ref),assignment=dict(kind='asc-p8' if owner.platform=='ios' else 'google-service-account',
            recordId=c['recordId'],expectedRevision=c['recordRevision'],contextRevision=c['credentialContextRevision']))
    if owner.platform=='ios':owner.authority['supplementalAssignments']=supplementary(c)
    if readiness:
        from .local_release_intent import validate_local_readiness_authority
        owner.authority.update(purpose='external-readiness',executionReceiptSha256=c['executionReceiptSha256'])
        validate_local_readiness_authority(canonical(owner.authority),intent_data=owner.intent_bytes,
            expected_intent_sha256=c['intentSha256'],execution_receipt_sha256=c['executionReceiptSha256'])
    else:validate_local_execution_authority(canonical(owner.authority),intent_data=owner.intent_bytes,purpose='execute',platform=owner.platform,stage=owner.stage)
    # Authenticated ZIP input is copied once into the existing scratch layout;
    # its private extraction is the only later metadata route. Account for raw
    # chunks+join, BytesIO and a file decoder simultaneously, not JSON96MiB.
    size=owner.prepared_bindings['store-metadata.zip'][0]['size']
    require(2*size+2*MAX_FILE_SIZE+4*MAX_ROWS_BYTES+(96<<20)<=(640<<20))
    scratch=FiniteScratch('store-metadata',owner.guard,parent=owner.root/'.mobile-release');require(owner.metadata_scratch is scratch)
    scratch.acquire()
    def blocks():
        slot=_FD(owner.guard);owner.stage_copy_slots.append(slot)
        try:
            fd=slot.open('store-metadata.zip',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=out.fd)
            from .build_inputs import _file
            binding=owner.prepared_bindings['store-metadata.zip'][0]
            require(all(_file(os.fstat(fd))[k]==v for k,v in binding.items() if k!='sha256'));left=size
            while left:
                owner.checkpoint();part=os.read(fd,min(left,65536));require(0<len(part)<=left);left-=len(part);yield part
            require(not os.read(fd,1));execute_post(owner)
        finally:slot.close()
    owner.metadata_snapshot=scratch._publish('metadata',blocks(),expected=start['metadataSha256'])
    owner.metadata_tree=StoreMetadataTree(scratch,platform=owner.platform);owner.metadata_tree.from_snapshot(owner.metadata_snapshot)
    metadata_intent_post(owner,i)
    execute_post(owner)
    if readiness:
        from .local_recovery_fence import open_fence
        out=open_fence(owner,owner.prepared_scope);out.check()
        root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==owner.source.lease_identity)
    else:owner._fence_empty()
    owner.source.exchange('history-head',head);owner.checkpoint();require(j.head()==head)
    if readiness:
        owner.observed_head=head;return
    owner.pending_head=j._append(expected_head=head,operation_id=owner.stage_id,phase='execute-pending',payload=dict(
        intentSha256=c['intentSha256'],confirmationSha256=start['confirmationSha256'],authorizationId=owner.authority['authorizationId'],assignmentRevision=c['recordRevision']))
    owner.source.exchange('execute-pending',owner.pending_head);owner.checkpoint();require(j.head()==owner.pending_head)


def execute_final_source(owner,observation):
    _execute(owner);require(observation is owner.observation and observation.calls==8 and not owner._source_final)
    execute_post(owner);owner.metadata_tree.post()
    from .local_recovery_fence import post
    if not getattr(owner,'readiness',False):post(owner,own_pending=True)
    owner.metadata_tree.cleanup();require(owner.metadata_tree.closed and owner.metadata_tree.retired)
    owner.stage_predecessors.close();require(owner.stage_predecessors.closed and not owner.stage_predecessors.failed)
    owner.prepared_scope.close();require(all(p.closed() for p in (*owner.prepared_readers,*owner.fence_readers,*owner.prior_readers)))
    owner._retire_journal(owner.journals[0])
    owner.metadata_scratch.cleanup();require(owner.metadata_scratch._cleanup_complete)
    owner.bundle.finish() # no extra originals coexist with final iOS tree
    owner._source_final=True
