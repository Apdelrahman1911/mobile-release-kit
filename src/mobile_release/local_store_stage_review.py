"""Current original later-stage files, never new Store or old-tail authority."""
import hashlib
import json
from uuid import UUID
from ._desktop_local_history_protocol import require,stage_action
from .local_release_journal import canonical
from .local_store_predecessor import StorePredecessorInputs
from .local_release_intent import decode_local_operation_intent,MAX_LOCAL_INTENT_BYTES
from .local_release_receipt import validate_local_execution_receipt,MAX_LOCAL_RECEIPT_BYTES
from .local_prepared_review import decode_quote,RETAINED_JOURNAL,MEMORY_LIMIT
from .provenance import validate_store_precondition,canonical_json_bytes,_reject_duplicate_pairs


def review_stage(owner,enrollment):
    from .local_release_history import LocalHistoryRun
    require(type(owner) is LocalHistoryRun and stage_action(owner.request.context));owner.checkpoint()
    if owner.request.context['action']=='review-external-readiness':
        from .local_store_readiness import review_readiness
        return review_readiness(owner,enrollment)
    c=owner.request.context;platform=c['platform'];operation=c['stageOperationId'];execution=c['action']=='review-stage-execution'
    rows=[r for r,_ in owner.journal._rows if r['operationId']==operation]
    phases=['promotion-pending','prepared']+(['execute-pending','settled-success'] if execution else [])
    require([r['phase'] for r in rows]==phases);start,prepared=rows[0]['payload'],rows[1]['payload'];stage=start['stage']
    candidate_id=start['candidateOperationId'];candidate_rows=[r for r,_ in owner.journal._rows if r['operationId']==candidate_id]
    require([r['phase'] for r in candidate_rows]==['inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending','settled-success'])
    from .local_candidate_bundle import CandidateBundleReview
    reader=CandidateBundleReview
    if platform=='ios':
        from .local_ios_candidate_review import IOSCandidateBundleReview
        reader=IOSCandidateBundleReview
    bundle=reader(owner,operation_id=candidate_id,enrollment=enrollment,pending=candidate_rows[0]['payload'],candidate_sha256=start['candidateSha256'])
    bundle.acquire();bundle.finish();require(bundle.closed and not bundle.failed and (platform!='ios' or bundle.tree_closed()))
    pred=StorePredecessorInputs(owner.invocation._original_project.directory,owner.journal,owner.guard,operation_id=operation,payload=start,platform=platform)
    owner.stage_inputs=pred
    try:
        pred.acquire(_history=owner);facts=pred.facts();candidate=facts['candidate'];m=bundle.value
        require(candidate['candidateSha256']==start['candidateSha256'] and candidate['operationId']==candidate_id
            and candidate['version']==dict(marketing=m['savedVersion']['name'],build=m['savedVersion']['build'])
            and candidate['candidateSource']['commit']==m['sourceCommit'] and candidate['candidateSource']['tree']==m['sourceTree'])
        names={'operation-intent.json':MAX_LOCAL_INTENT_BYTES,'store-precondition.json':4<<20,'store-metadata.zip':512<<20}
        out,bindings=pred._open(UUID(operation).hex,names)
        _,raw=pred._read(out,bindings,'operation-intent.json',MAX_LOCAL_INTENT_BYTES)
        own=decode_quote(raw,MAX_LOCAL_INTENT_BYTES,checkpoint=owner.checkpoint)-RETAINED_JOURNAL
        require(RETAINED_JOURNAL+3*own+(16<<20)<=MEMORY_LIMIT)
        intent=decode_local_operation_intent(raw,platform=platform,stage=stage);i=intent
        expected=dict(candidateManifestSha256=start['candidateSha256'],candidateReceiptSha256=candidate['receiptSha256'])
        if stage=='production-submit':
            expected['externalReceiptSha256']=facts['predecessor']['receiptSha256']
            if 'readinessReceiptSha256' in facts['predecessor']:expected['externalReadinessReceiptSha256']=facts['predecessor']['readinessReceiptSha256']
        require(i['project']==enrollment and i['operationId']==operation and i['candidateOperationId']==candidate_id
            and i['candidateSha256']==start['candidateSha256']==prepared['candidateSha256'] and i['integrity']['sha256']==prepared['intentSha256']
            and i['operationSource']['commit']==start['sourceCommit'] and i['operationSource']['tree']==start['sourceTree']
            and i['configuration']['sha256']==start['configurationSha256'] and i['configuration']['metadataSha256']==start['metadataSha256']
            and i['preparedBy']['confirmationSha256']==start['confirmationSha256'] and i['predecessors']==expected
            and all(i[k]==candidate[k] for k in ('candidateSource','application','version','signing'))
            and [a for a in i['artifacts'] if a['kind']!='metadata']==[a for a in candidate['artifacts'] if a['kind']!='metadata'])
        digest=i['integrity']['sha256'];authority=i['preparedBy'];metadata=i['artifacts'][1]
        expected_snapshot=hashlib.sha256(canonical_json_bytes(i['storePrecondition'])).hexdigest()
        common=dict(operationId=operation,candidateSha256=start['candidateSha256'],intentSha256=digest,
            sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],
            version=dict(name=i['version']['marketing'],build=i['version']['build']),destination=i['destination'],
            stage=stage,candidateOperationId=candidate_id,predecessorOperationId=start['predecessorOperationId'],predecessorReceiptSha256=start['predecessorReceiptSha256'])
        common['bundleId' if platform=='ios' else 'applicationId']=i['application']['id']
        if platform=='ios':common['appStoreAppId']=i['application']['storeAppId']
        observed_at=i['storePrecondition']['observedAt'];del intent,i
        snapshot_binding,snapshot_raw=pred._read(out,bindings,'store-precondition.json',4<<20)
        require(snapshot_binding['sha256']==prepared['storePreconditionSha256']
            and decode_quote(snapshot_raw,4<<20,checkpoint=owner.checkpoint)+len(raw)+(1<<20)<=MEMORY_LIMIT)
        snapshot=json.loads(snapshot_raw,object_pairs_hook=_reject_duplicate_pairs,parse_constant=lambda _:require(False))
        validate_store_precondition(snapshot,stage=stage,platform=platform)
        require(hashlib.sha256(canonical_json_bytes(snapshot)).hexdigest()==expected_snapshot);del snapshot,snapshot_raw
        value,_=pred._read(out,bindings,'store-metadata.zip',512<<20,collect=False)
        require(value['sha256']==metadata['sha256']==start['metadataSha256'] and value['size']==metadata['size'])
        if execution:
            pending,settled=rows[2]['payload'],rows[3]['payload']
            require(pending['intentSha256']==settled['intentSha256']==digest and pending['confirmationSha256']==authority['confirmationSha256']
                and pending['assignmentRevision']==authority['assignment']['expectedRevision'])
            executed=dict(authority,purpose='execute',authorizationId=pending['authorizationId'],intentSha256=digest)
            receipt_out,receipt_bindings=pred._open(UUID(operation).hex+'-execute-'+UUID(pending['authorizationId']).hex,{'raw-store-receipt.json':MAX_LOCAL_RECEIPT_BYTES})
            binding,receipt_raw=pred._read(receipt_out,receipt_bindings,'raw-store-receipt.json',MAX_LOCAL_RECEIPT_BYTES)
            rq=decode_quote(receipt_raw,MAX_LOCAL_RECEIPT_BYTES,checkpoint=owner.checkpoint)-RETAINED_JOURNAL
            require(binding['sha256']==settled['receiptSha256'] and RETAINED_JOURNAL+3*own+rq+(16<<20)<=MEMORY_LIMIT)
            receipt=validate_local_execution_receipt(receipt_raw,intent_data=raw,authority_data=canonical(executed),purpose='execute',
                expected_intent_sha256=digest,platform=platform,stage=stage)
            from . import _desktop_store_execute_protocol as wire
            common.update(receiptSha256=binding['sha256'],authorizationId=executed['authorizationId'],observedAt=receipt['observedAt'],result=receipt['result'],
                state=receipt['state'],limitations=list(wire.STAGE_LIMITATIONS))
            wire.receipt_summary(common,wire.STAGE_LIMITATIONS,platform=platform,selected=stage)
            common.update(observation='current-execution-files-only',priorExecutionFinality='not-established')
        else:
            from . import _desktop_store_prepare_protocol as wire
            common.update(storePreconditionSha256=prepared['storePreconditionSha256'],observedAt=observed_at,limitations=list(wire.STAGE_LIMITATIONS))
            wire.validate_result(dict(schemaVersion=1,scope='local-%s-store-stage-prepare'%platform,headSequence=rows[-1]['sequence'],preparedIntent=common),platform=platform,selected=stage)
            common.update(observation='current-prepared-files-only',priorPrepareFinality='not-established')
        pred.post();owner.checkpoint()
    finally:pred.close()
    require(pred.closed and not pred.failed);owner.checkpoint();return common
