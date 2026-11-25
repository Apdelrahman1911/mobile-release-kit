"""Closed readonly Beta publication/summary cuts on the original Reconcile owner."""
import hashlib
import os
from pathlib import Path
from . import _desktop_store_reconcile_protocol as wire
from .build_inputs import _app_private_directory,_read_file
from .local_release_journal import external_readiness_chain
require=wire.require


def summary(intent,receipt,digest,*,offline=False):
    result=dict(operationId=intent['operationId'],candidateOperationId=intent['candidateOperationId'],
        candidateSha256=intent['candidateSha256'],intentSha256=intent['integrity']['sha256'],
        executionReceiptSha256=receipt['executionReceiptSha256'],receiptSha256=digest,
        authorizationId=receipt['observedBy']['authorizationId'],sourceCommit=intent['operationSource']['commit'],
        sourceTree=intent['operationSource']['tree'],bundleId=intent['application']['id'],appStoreAppId=intent['application']['storeAppId'],
        version=dict(name=intent['version']['marketing'],build=intent['version']['build']),destination=intent['destination'],
        observedAt=receipt['observedAt'],result='ready',state='available-to-testers',limitations=list(wire.LIMITATIONS),
        observation='current-external-readiness-files-only' if offline else 'current-external-target-only',priorExecutionFinality='not-established')
    wire.readiness_summary(result,offline=offline);return result


def publication(owner,raw):
    from .local_store_reconcile import LocalStoreReconcileRun
    require(type(owner) is LocalStoreReconcileRun and owner.readiness)
    owner.checkpoint();require(owner.store_completed and owner._source_final and owner._lane_owners_closed()
        and owner.record._pending_attempt.phase=='RETIRED')
    receipt=owner.validate_receipt(raw);target=Path(owner.record._output);digest=hashlib.sha256(raw).hexdigest()
    with _app_private_directory(target.parent,app_root=owner.root,cancellation=owner.guard,create=False) as out:
        require(out is not None);owner.publishers.append(out)
        root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==owner.source.lease_identity)
        value=_read_file(out.fd,target.name,owner.guard,65536,private=True);require(value is not None and value[1]==raw)
        binding=value[0];identity=owner.record._files_owner().document_identity
        require(identity is not None and all(binding[k]==getattr(identity,k) for k in ('device','inode','uid','gid','mode')))
        j=owner._open_journal();require(j.head()==owner.observed_head)
        rows=external_readiness_chain([r for r,_ in j._rows if r['operationId']==owner.stage_id],owner.stage_id)
        require(j._rows[-1][0]==rows[-1] and 11<=owner.observed_head['sequence']<=508)
        head=j._append(expected_head=owner.observed_head,operation_id=owner.stage_id,phase='external-ready',payload=dict(
            intentSha256=owner.intent['integrity']['sha256'],executionReceiptSha256=receipt['executionReceiptSha256'],
            readinessReceiptSha256=digest,refreshAuthorizationId=owner.authority['authorizationId']))
        owner.source.exchange('external-ready',dict(head=head,phase='external-ready'))
        owner.checkpoint();require(j.head()==head)
        require(_read_file(out.fd,target.name,owner.guard,65536,private=True,binding_only=True)==(binding,b''))
        out.check();owner._retire_journal(j)
    require(out.closed());owner.checkpoint()
    owner.report=dict(schemaVersion=1,scope='local-ios-external-readiness',headSequence=head['sequence'],
        readinessReceipt=summary(owner.intent,receipt,digest))
    wire.validate_readiness_result(owner.report)


def review_readiness(owner,enrollment):
    from .local_release_history import LocalHistoryRun
    from .local_ios_candidate_review import IOSCandidateBundleReview
    from .local_store_predecessor import StorePredecessorInputs
    require(type(owner) is LocalHistoryRun and owner.request.context['action']=='review-external-readiness'
        and owner.request.context['platform']=='ios')
    owner.checkpoint();operation=owner.request.context['stageOperationId']
    rows=external_readiness_chain([r for r,_ in owner.journal._rows if r['operationId']==operation],operation,ready=True)
    require(owner.journal.head()['sequence']>=12)
    start=rows[0]['payload'];candidate_id=start['candidateOperationId']
    candidates=[r for r,_ in owner.journal._rows if r['operationId']==candidate_id]
    require([r['phase'] for r in candidates]==['inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending','settled-success'])
    bundle=IOSCandidateBundleReview(owner,operation_id=candidate_id,enrollment=enrollment,
        pending=candidates[0]['payload'],candidate_sha256=start['candidateSha256'])
    bundle.acquire();bundle.finish();require(bundle.closed and not bundle.failed and bundle.tree_closed())
    pred=StorePredecessorInputs(owner.invocation._original_project.directory,owner.journal,owner.guard,
        operation_id=operation,payload=start,platform='ios');owner.stage_inputs=pred
    try:
        pred.acquire(_readiness=owner);facts=pred.facts();c=facts['candidate'];e=facts['external'];m=bundle.value
        require(c['candidateSha256']==start['candidateSha256'] and c['operationId']==candidate_id
            and c['version']==dict(marketing=m['savedVersion']['name'],build=m['savedVersion']['build'])
            and c['candidateSource']['commit']==m['sourceCommit'] and c['candidateSource']['tree']==m['sourceTree'])
        projection=dict(e,integrity={'sha256':e['intentSha256']})
        result=summary(projection,facts['readiness'],rows[-1]['payload']['readinessReceiptSha256'],offline=True)
        pred.post();owner.checkpoint()
    finally:pred.close()
    require(pred.closed and not pred.failed);owner.checkpoint();return result
