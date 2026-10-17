"""Closed local Play preparation DATA; no credential, lease or Store grant."""
from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass
from . import _desktop_local_history_protocol as history
from . import _desktop_store_preflight_protocol as access
from .local_release_journal import canonical, _uuid, _enrollment
from uuid import UUID

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

IOS_LIMITATIONS = ['non-publishing','prepare-not-execute','current-asc-snapshot-may-change',
                    'current-bundle-not-historical-finality','saved-inputs-not-atomic']

STAGES=('external-testing','production-submit')
STAGE_LIMITATIONS=['non-publishing','prepare-not-execute','current-store-snapshot-may-change',
    'original-binary-reused','prior-native-finality-not-established','saved-inputs-not-atomic']
def stage(value):
    result=value.get('stage','candidate')
    require('stage' not in value or result in STAGES)
    return result

def stage_operation_id(request):
    require(stage(request.context)!='candidate')
    try:
        parsed=UUID(hex=request.operation_id)
        require(parsed.version==4 and parsed.hex==request.operation_id)
        return str(parsed)
    except (ValueError,AttributeError):raise ProtocolError() from None

def supplemental(value):
    require(type(value) is dict and set(value)=={'reviewContact','commitment','reviewDemo'})
    seen=set()
    for name in ('reviewContact','commitment','reviewDemo'):
        row=value[name]
        if name=='reviewDemo' and row is None:continue
        require(type(row) is dict and set(row)=={'recordId','recordRevision'}
            and history.token(row['recordId']) and history.integer(row['recordRevision'],0xffffffff,1)
            and row['recordId'] not in seen)
        seen.add(row['recordId'])
    return value

def destination(value,*,platform,selected):
    require(selected in ('candidate',*STAGES) and platform in ('android','ios') and type(value) is dict)
    if platform=='android':
        require(set(value)=={'channel','releaseStatus'} and type(value['channel']) is str
            and 1<=len(value['channel'])<=255 and not any(ord(c)<32 for c in value['channel'])
            and value['releaseStatus']==('draft' if selected=='production-submit' else 'completed'))
        require(value['channel']=='internal' if selected=='candidate' else value['channel']=='production'
            if selected=='production-submit' else value['channel'] not in ('internal','production'))
    else:
        require(value==({'channel':'testflight-internal'} if selected=='candidate' else
            {'channel':'testflight-external'} if selected=='external-testing' else {'channel':'app-store-review','automaticRelease':False}))
    return True

def context(value, *, apple_prepare=False):
    require(type(value) is dict)
    selected=stage(value)
    extra={'candidateOperationId','candidateSha256','confirmation'}
    if selected!='candidate':
        extra|={'stage','predecessorOperationId','predecessorReceiptSha256'}
        require(_uuid(value.get('predecessorOperationId')) and sha(value.get('predecessorReceiptSha256')))
        if value.get('platform')=='ios':
            extra.add('supplementalAssignments');supplemental(value.get('supplementalAssignments'))
    require(extra <= value.keys() and value.get('operation')=='local-store-prepare')
    old={k:v for k,v in value.items() if k not in extra};old['operation']='local-store-preflight'
    try:access.context(old, apple_access=apple_prepare)
    except (ValueError,TypeError,KeyError):raise ProtocolError() from None
    require(_uuid(value['candidateOperationId']) and sha(value['candidateSha256'])
        and value['confirmation']=='%s:%s:%s:%s'%(selected,value['platform'],value['savedVersion']['name'],value['savedVersion']['build']))
    if selected=='external-testing':require(value['predecessorOperationId']==value['candidateOperationId'])
    elif selected=='production-submit':require(value['predecessorOperationId']!=value['candidateOperationId'])
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
        request=StorePrepareRequest(value['operationId'],value['ownerGeneration'],context(value['context'],apple_prepare=True),n,hashlib.sha256(raw).hexdigest())
        if stage(request.context)!='candidate':require(stage_operation_id(request) not in (request.context['candidateOperationId'],request.context['predecessorOperationId']))
        return request
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError):raise ProtocolError() from None

def _request_wire(request):
    if type(request) is StorePrepareRequest:
        from . import _desktop_store_prepare_protocol as prepare
        return prepare
    from . import _desktop_store_execute_protocol as execute
    if type(request) is execute.StoreExecuteRequest:return execute
    from . import _desktop_store_reconcile_protocol as reconcile
    require(type(request) is reconcile.StoreReconcileRequest);return reconcile

def request_phases(request):
    selected=_request_wire(request)
    from . import _desktop_store_reconcile_protocol as reconcile
    return reconcile.phases(request) if selected is reconcile else selected.PHASES

def response(request,kind,payload,sequence):
    selected=_request_wire(request);PROTOCOL,PHASES=selected.PROTOCOL,request_phases(request)
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
            and type(value['step']) is int and value['step']==step and 1<=step<=len(request_phases(request))
            and kind==('key-material' if step==1 else 'checkpoint-settled'))
        if step==1:return _enrollment(value['payload'])
        require(value['payload']=={});return None
    except (ValueError,TypeError,KeyError):raise ProtocolError() from None

def validate_result(value, *, platform='android', selected='candidate'):
    require(platform in {'android','ios'})
    require(selected in ('candidate',*STAGES));later=selected!='candidate'
    apple=platform=='ios'
    identity='bundleId' if apple else 'applicationId'
    from .config import IOS_ID_RE, APP_STORE_ID_RE
    from ._desktop_android_build_protocol import ANDROID_ID_RE,_VERSION_TEXT
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','preparedIntent'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']==('local-%s-store-stage-prepare' if later else 'local-%s-store-prepare')%platform
        and history.integer(value['headSequence'],511 if later else 513,9 if selected=='external-testing' else 13 if later else 5 if apple else 1))
    p=value['preparedIntent']
    extra={'stage','candidateOperationId','predecessorOperationId','predecessorReceiptSha256'} if later else set()
    if later:
        require(type(p) is dict and extra<=p.keys() and p['stage']==selected
            and _uuid(p['candidateOperationId']) and _uuid(p['predecessorOperationId'])
            and sha(p['predecessorReceiptSha256']) and p.get('operationId') not in (p['candidateOperationId'],p['predecessorOperationId'])
            and (p['predecessorOperationId']==p['candidateOperationId'])==(selected=='external-testing'))
    require(type(p) is dict and set(p)=={'operationId','candidateSha256','intentSha256','storePreconditionSha256',
        'sourceCommit','sourceTree',identity,'version','destination','observedAt','limitations'} | ({'appStoreAppId'} if apple else set()) | extra
        and _uuid(p['operationId']) and all(sha(p[k]) for k in ('candidateSha256','intentSha256','storePreconditionSha256'))
        and all(sha(p[k],40) for k in ('sourceCommit','sourceTree'))
        and type(p[identity]) is str and len(p[identity])<=255 and (IOS_ID_RE if apple else ANDROID_ID_RE).fullmatch(p[identity])
        and (not apple or type(p['appStoreAppId']) is str and APP_STORE_ID_RE.fullmatch(p['appStoreAppId']))
        and type(p['version']) is dict and set(p['version'])=={'name','build'}
        and type(p['version']['name']) is str and _VERSION_TEXT.fullmatch(p['version']['name'])
        and history.integer(p['version']['build'],2100000000,1)
        and destination(p['destination'],platform=platform,selected=selected)
        and type(p['observedAt']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',p['observedAt'])
        and p['limitations']==(STAGE_LIMITATIONS if later else IOS_LIMITATIONS if apple else LIMITATIONS) and len(canonical(value))<=16*1024)
    return value
