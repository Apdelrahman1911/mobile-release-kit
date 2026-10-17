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
WORK_SECONDS,FINALITY_SECONDS=1200,1210
REQUEST_LIMIT,RESPONSE_LIMIT=16*1024,64*1024
KEY_PREFIX,KEY_SUFFIX=prepare.KEY_PREFIX,prepare.KEY_SUFFIX
PHASES=('lease-ready','history-head')
MATERIAL_STEP=2
LIMITATIONS=['non-publishing','not-retry-permission','old-evidence-preserved','saved-inputs-not-atomic']
SETTLEMENT='record-current-target'
def settling(value):
    return type(value) is dict and value.get('operation')=='local-store-recovery-settle'
def context(value):
    require(type(value) is dict and sha(value.get('intentSha256')))
    if settling(value):require(value.get('settlement')==SETTLEMENT)
    else:require(value.get('operation')=='local-store-reconcile' and 'settlement' not in value)
    old={k:v for k,v in value.items() if k not in {'intentSha256','settlement'}};old['operation']='local-store-prepare'
    prepare.context(old);return value
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
    return PHASES+('recovery-settled',) if settling(request.context) else PHASES
response,reply=prepare.response,prepare.reply
def validate_result(value,*,settlement=False):
    require(type(settlement) is bool)
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','reconciliationReceipt'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']==('local-android-recovery-settlement' if settlement else 'local-android-store-reconcile') and integer(value['headSequence'],513,7 if settlement else 6))
    r=value['reconciliationReceipt']
    require(type(r) is dict and r.get('observation')=='current-internal-target-only'
        and r.get('priorExecutionFinality')=='not-established' and r.get('result')=='reconciled')
    execute.receipt_summary({k:v for k,v in r.items() if k not in {'observation','priorExecutionFinality'}},LIMITATIONS)
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
