"""Closed target-only Reconcile DATA. Never upload/retry or old-tail authority."""
from dataclasses import dataclass
import hashlib
from . import _desktop_store_prepare_protocol as prepare
from . import _desktop_store_execute_protocol as execute
from ._desktop_local_history_protocol import decode,token,integer
from .local_release_journal import canonical
require,sha,ProtocolError=prepare.require,prepare.sha,prepare.ProtocolError
PROTOCOL='mrk-local-store-reconcile/1'
CONSENT='local-android-store-reconcile-v1'
IOS_CONSENT='local-ios-store-reconcile-v1'
WORK_SECONDS,FINALITY_SECONDS=1200,1210
REQUEST_LIMIT,RESPONSE_LIMIT=16*1024,64*1024
KEY_PREFIX,KEY_SUFFIX=prepare.KEY_PREFIX,prepare.KEY_SUFFIX
PHASES=('lease-ready','history-head')
MATERIAL_STEP=2
LIMITATIONS=['non-publishing','not-retry-permission','old-evidence-preserved','saved-inputs-not-atomic']
SETTLEMENT='record-current-target'
def settling(value):
    return type(value) is dict and value.get('operation')=='local-store-recovery-settle'
def readiness(value):
    return type(value) is dict and value.get('action')=='external-readiness'
def context(value):
    require(type(value) is dict and sha(value.get('intentSha256')))
    if readiness(value):
        from ._desktop_store_preflight_protocol import context as access_context
        from .local_release_journal import _uuid
        extra={'action','candidateOperationId','candidateSha256','stageOperationId','executionReceiptSha256','intentSha256','confirmation','supplementalAssignments'}
        require(extra<=value.keys() and value.get('operation')=='local-store-reconcile' and value.get('platform')=='ios'
            and _uuid(value.get('stageOperationId')) and _uuid(value.get('candidateOperationId'))
            and value['stageOperationId']!=value['candidateOperationId'] and sha(value.get('candidateSha256')) and sha(value.get('executionReceiptSha256')))
        prepare.supplemental(value['supplementalAssignments'])
        old={k:v for k,v in value.items() if k not in extra};old['operation']='local-store-preflight'
        access_context(old,apple_access=True)
        require(value['confirmation']=='external-testing:ios:%s:%s'%(value['savedVersion']['name'],value['savedVersion']['build']))
        return value
    if settling(value):require(value.get('settlement')==SETTLEMENT and value.get('platform')=='android')
    else:require(value.get('operation')=='local-store-reconcile' and 'settlement' not in value)
    old={k:v for k,v in value.items() if k not in {'intentSha256','settlement'}};old['operation']='local-store-prepare'
    prepare.context(old,apple_prepare=True);return value
@dataclass(frozen=True)
class StoreReconcileRequest:
    operation_id:str
    owner_generation:str
    context:dict
    native:dict
    digest:str
def parse_request(raw):
    try:
        value=decode(raw,REQUEST_LIMIT)
        require(type(value) is dict and set(value)=={'protocol','operationId','ownerGeneration','context','native'}
            and value['protocol']==PROTOCOL and token(value['operationId']) and token(value['ownerGeneration']))
        return StoreReconcileRequest(value['operationId'],value['ownerGeneration'],context(value['context']),
            prepare.native(value['native']),hashlib.sha256(raw).hexdigest())
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError):raise ProtocolError() from None
def phases(request):
    require(type(request) is StoreReconcileRequest);context(request.context)
    return PHASES+('external-ready',) if readiness(request.context) else PHASES+('recovery-settled',) if settling(request.context) else PHASES
response,reply=prepare.response,prepare.reply
def validate_result(value,*,settlement=False,platform='android'):
    require(type(settlement) is bool and platform in {'android','ios'} and not (settlement and platform=='ios'))
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','reconciliationReceipt'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']==('local-android-recovery-settlement' if settlement else 'local-%s-store-reconcile'%platform) and integer(value['headSequence'],513,7 if settlement else 6))
    r=value['reconciliationReceipt']
    require(type(r) is dict and r.get('observation')==('current-internal-build-only' if platform=='ios' else 'current-internal-target-only')
        and r.get('priorExecutionFinality')=='not-established' and r.get('result')=='reconciled')
    execute.receipt_summary({k:v for k,v in r.items() if k not in {'observation','priorExecutionFinality'}},LIMITATIONS,platform=platform)
    require(len(canonical(value))<=16*1024);return value

def execution_chain(rows,operation_id):
    # Authenticate structure before considering any current Store readback.
    require(type(rows) is list and len(rows) in (5,6)
        and all(r['operationId']==operation_id for r in rows)
        and [r['phase'] for r in rows[:5]]==['inputs-pending','inputs-ready','prepare-pending','prepared','execute-pending'])
    if len(rows)==6:
        last=rows[-1];require(last['phase'] in {'settled-success','settled-failure','reconciliation-required'})
        if last['phase']!='settled-success':require(last['payload']['phase']=='execute-pending')
    return rows

def execution_binding(intent,rows):
    pending=rows[4]['payload']
    require(pending['intentSha256']==intent['integrity']['sha256']
        and pending['confirmationSha256']==intent['preparedBy']['confirmationSha256']
        and pending['assignmentRevision']==intent['preparedBy']['assignment']['expectedRevision'])


def readiness_summary(r,*,offline=False):
    from .local_release_journal import _uuid
    require(type(r) is dict and set(r)=={'operationId','candidateOperationId','candidateSha256','intentSha256','executionReceiptSha256',
        'receiptSha256','authorizationId','sourceCommit','sourceTree','bundleId','appStoreAppId','version','destination','observedAt',
        'result','state','limitations','observation','priorExecutionFinality'}
        and _uuid(r['candidateOperationId']) and r['candidateOperationId']!=r['operationId']
        and sha(r['executionReceiptSha256']) and r['state']=='available-to-testers' and r['result']=='ready'
        and r['observation']==('current-external-readiness-files-only' if offline else 'current-external-target-only')
        and r['priorExecutionFinality']=='not-established')
    # Reuse only the unchanged scalar summary grammar, not an execution grant.
    core={k:v for k,v in r.items() if k not in {'candidateOperationId','executionReceiptSha256','state','observation','priorExecutionFinality'}}
    core['result']='reconciled';core['destination']={'channel':'testflight-internal'}
    execute.receipt_summary(core,LIMITATIONS,platform='ios')
    require(r['destination']=={'channel':'testflight-external'})
    return r

def validate_readiness_result(value):
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','readinessReceipt'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='local-ios-external-readiness' and integer(value['headSequence'],509,12))
    readiness_summary(value['readinessReceipt']);require(len(canonical(value))<=16384);return value
