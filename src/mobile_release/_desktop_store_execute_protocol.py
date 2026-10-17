"""Closed local candidate Execute wire DATA; no native/Store permission."""
from dataclasses import dataclass
import hashlib
import re
from . import _desktop_store_prepare_protocol as prepare
from . import _desktop_android_build_protocol as android
from ._desktop_local_history_protocol import decode,token,integer
from .local_release_journal import canonical,_uuid
require,sha=prepare.require,prepare.sha
ProtocolError=prepare.ProtocolError
PROTOCOL='mrk-local-store-execute/1'
CONSENT='local-android-store-execute-v1'
WORK_SECONDS,FINALITY_SECONDS=1200,1210
REQUEST_LIMIT,RESPONSE_LIMIT=16*1024,64*1024
KEY_PREFIX,KEY_SUFFIX=prepare.KEY_PREFIX,prepare.KEY_SUFFIX
PHASES=('lease-ready','history-head','execute-pending','execute-settled')
LIMITATIONS=['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic']
def context(value):
    require(type(value) is dict and value.get('operation')=='local-store-execute'
        and {'intentSha256','toolchainSelection'}<=value.keys() and sha(value['intentSha256']))
    ordinary={k:v for k,v in value.items() if k not in {'intentSha256','toolchainSelection'}}
    ordinary['operation']='local-store-prepare';prepare.context(ordinary)
    android.mac_toolchain_selection(value['toolchainSelection']);return value
@dataclass(frozen=True)
class StoreExecuteRequest:
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
        c=context(value['context']);n=value['native']
        require(type(n) is dict and 'toolchain' in n)
        prepare.native({k:v for k,v in n.items() if k!='toolchain'})
        tools=android._native({k:n[k] for k in ('profile','projectRoot','rootIdentity','cwd','toolchain')})['toolchain']
        require(tools['schemaVersion']==2 and tools['selection']==c['toolchainSelection'])
        return StoreExecuteRequest(value['operationId'],value['ownerGeneration'],c,n,hashlib.sha256(raw).hexdigest())
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError):raise ProtocolError() from None
response,reply=prepare.response,prepare.reply
def validate_result(value):
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','executionReceipt'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='local-android-store-execute' and integer(value['headSequence'],513,7))
    r=value['executionReceipt']
    require(type(r) is dict and set(r)=={'operationId','candidateSha256','intentSha256','receiptSha256','authorizationId',
        'sourceCommit','sourceTree','applicationId','version','destination','observedAt','result','limitations'}
        and _uuid(r['operationId']) and _uuid(r['authorizationId'])
        and all(sha(r[k]) for k in ('candidateSha256','intentSha256','receiptSha256'))
        and all(sha(r[k],40) for k in ('sourceCommit','sourceTree'))
        and type(r['applicationId']) is str and len(r['applicationId'])<=255 and android.ANDROID_ID_RE.fullmatch(r['applicationId'])
        and type(r['version']) is dict and set(r['version'])=={'name','build'}
        and type(r['version']['name']) is str and android._VERSION_TEXT.fullmatch(r['version']['name'])
        and integer(r['version']['build'],2100000000,1) and r['destination']=={'channel':'internal','releaseStatus':'completed'}
        and type(r['observedAt']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',r['observedAt'])
        and r['result'] in {'accepted','reconciled'} and r['limitations']==LIMITATIONS and len(canonical(value))<=16*1024)
    return value
