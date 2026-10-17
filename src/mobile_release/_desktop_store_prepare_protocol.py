"""Closed local Play preparation DATA; no credential, lease or Store grant."""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from . import _desktop_local_history_protocol as history
from . import _desktop_store_preflight_protocol as access
from .local_release_journal import canonical, _uuid, _enrollment

PROTOCOL = 'mrk-local-store-prepare/1'
CONSENT = 'local-android-store-prepare-v1'
WORK_SECONDS, FINALITY_SECONDS = 1200, 1210
REQUEST_LIMIT, RESPONSE_LIMIT = 16*1024, 64*1024
MATERIAL_STEP = 3
PHASES = ('lease-ready','history-head','prepare-pending','prepare-settled')
KEY_PREFIX, KEY_SUFFIX = history.KEY_PREFIX, history.KEY_SUFFIX
LIMITATIONS = ['non-publishing','prepare-not-execute','temporary-edit-may-expire',
                'current-bundle-not-historical-finality','saved-inputs-not-atomic']
class ProtocolError(ValueError):
    def __init__(self,*_):super().__init__('Local Play preparation protocol refused')
def require(value):
    if not value:raise ProtocolError()
def sha(value,count=64):return type(value) is str and re.fullmatch('[0-9a-f]{%d}'%count,value) is not None

def context(value):
    require(type(value) is dict)
    extra={'candidateOperationId','candidateSha256','confirmation'}
    require(extra <= value.keys() and value.get('operation')=='local-store-prepare')
    old={k:v for k,v in value.items() if k not in extra};old['operation']='local-store-preflight'
    try:access.context(old)
    except (ValueError,TypeError,KeyError):raise ProtocolError() from None
    require(_uuid(value['candidateOperationId']) and sha(value['candidateSha256'])
        and value['confirmation']=='candidate:android:%s:%s'%(value['savedVersion']['name'],value['savedVersion']['build']))
    return value

@dataclass(frozen=True)
class StorePrepareRequest:
    operation_id:str
    owner_generation:str
    context:dict
    native:dict
    digest:str

def native(n):
    require(type(n) is dict and set(n)=={'profile','projectRoot','rootIdentity','credentialConfig','cwd',
        'home','leaseFd','nonce','clock','authorizationId','tooling'})
    require(n['profile'] in access.PROFILES and history.integer(n['leaseFd'],255,3)
        and sha(n['nonce'],32) and n['nonce']!='0'*32 and _uuid(n['authorizationId']))
    for key in ('projectRoot','cwd','home'):history.path(n[key])
    history.root(n['rootIdentity']);access.content(n['credentialConfig'])
    require(type(n['clock']) is dict and set(n['clock'])=={'workEndNs','hardEndNs'})
    for v in n['clock'].values():require(type(v) is str and re.fullmatch('[1-9][0-9]{0,19}',v) is not None)
    work,hard=(int(n['clock'][k]) for k in ('workEndNs','hardEndNs'))
    require(work<hard<1<<64 and hard-work<=10_000_000_000)
    t=n['tooling'];require(type(t) is dict and set(t)=={'version','commit'} and sha(t['commit'],40)
        and type(t['version']) is str and re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?',t['version']))
    return n

def parse_request(raw):
    try:
        value=history.decode(raw,REQUEST_LIMIT)
        require(type(value) is dict and set(value)=={'protocol','operationId','ownerGeneration','context','native'}
            and value['protocol']==PROTOCOL and history.token(value['operationId']) and history.token(value['ownerGeneration']))
        n=native(value['native'])
        return StorePrepareRequest(value['operationId'],value['ownerGeneration'],context(value['context']),n,hashlib.sha256(raw).hexdigest())
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError):raise ProtocolError() from None

def _request_wire(request):
    if type(request) is StorePrepareRequest:
        from . import _desktop_store_prepare_protocol as prepare
        return prepare
    from . import _desktop_store_execute_protocol as execute
    if type(request) is execute.StoreExecuteRequest:return execute
    from . import _desktop_store_reconcile_protocol as reconcile
    require(type(request) is reconcile.StoreReconcileRequest);return reconcile

def response(request,kind,payload,sequence):
    selected=_request_wire(request);PROTOCOL,PHASES=selected.PROTOCOL,selected.PHASES
    require(_request_wire(request) is selected and type(sequence) is int and 0<=sequence<len(PHASES)+2
        and kind in {'accepted',*PHASES,'terminal'}
        and (kind=='terminal' and sequence>=1 or kind=='accepted' and sequence==0
             or kind in PHASES and sequence==PHASES.index(kind)+1))
    raw=canonical(dict(protocol=PROTOCOL,operationId=request.operation_id,ownerGeneration=request.owner_generation,
        sequence=sequence,kind=kind,nonce=request.native['nonce'],requestSha256=request.digest,payload=payload))+b'\n'
    require(len(raw)<=(16*1024 if kind in {'accepted','terminal'} else 2048));return raw

def reply(raw,request,kind,step):
    PROTOCOL=_request_wire(request).PROTOCOL
    try:
        value=history.decode(raw,2048)
        require(type(value) is dict and set(value)=={'protocol','operationId','ownerGeneration','nonce','requestSha256','kind','step','payload'}
            and value['protocol']==PROTOCOL and value['operationId']==request.operation_id
            and value['ownerGeneration']==request.owner_generation and value['nonce']==request.native['nonce']
            and value['requestSha256']==request.digest and value['kind']==kind
            and type(value['step']) is int and value['step']==step and 1<=step<=len(_request_wire(request).PHASES)
            and kind==('key-material' if step==1 else 'checkpoint-settled'))
        if step==1:return _enrollment(value['payload'])
        require(value['payload']=={});return None
    except (ValueError,TypeError,KeyError):raise ProtocolError() from None

def validate_result(value):
    from ._desktop_android_build_protocol import ANDROID_ID_RE,_VERSION_TEXT
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','preparedIntent'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='local-android-store-prepare' and history.integer(value['headSequence'],513,1))
    p=value['preparedIntent']
    require(type(p) is dict and set(p)=={'operationId','candidateSha256','intentSha256','storePreconditionSha256',
        'sourceCommit','sourceTree','applicationId','version','destination','observedAt','limitations'}
        and _uuid(p['operationId']) and all(sha(p[k]) for k in ('candidateSha256','intentSha256','storePreconditionSha256'))
        and all(sha(p[k],40) for k in ('sourceCommit','sourceTree'))
        and type(p['applicationId']) is str and len(p['applicationId'])<=255 and ANDROID_ID_RE.fullmatch(p['applicationId'])
        and type(p['version']) is dict and set(p['version'])=={'name','build'}
        and type(p['version']['name']) is str and _VERSION_TEXT.fullmatch(p['version']['name'])
        and history.integer(p['version']['build'],2100000000,1)
        and p['destination']=={'channel':'internal','releaseStatus':'completed'}
        and type(p['observedAt']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',p['observedAt'])
        and p['limitations']==LIMITATIONS and len(canonical(value))<=16*1024)
    return value
