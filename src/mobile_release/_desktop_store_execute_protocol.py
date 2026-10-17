"""Closed local candidate Execute wire DATA; no native/Store permission."""
from dataclasses import dataclass
import hashlib
import re
from pathlib import Path
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
MATERIAL_STEP=3
PHASES=('lease-ready','history-head','execute-pending','execute-settled')
APPLICATIONS=Path('/Applications')
LIMITATIONS=['internal-testing-only','not-public-release','prior-prepare-finality-not-established','saved-inputs-not-atomic']
def upload_selection(value):
    from ._desktop_ios_archive_protocol import _identity,_tool_identity
    from ._desktop_local_history_protocol import path
    require(type(value) is dict and set(value)=={'schemaVersion','developerDirectory','appIdentity','developerIdentity','xcrun'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1)
    directory=path(value['developerDirectory']);parts=Path(directory).parts
    require(len(parts)==len(APPLICATIONS.parts)+3 and parts[:len(APPLICATIONS.parts)]==APPLICATIONS.parts
        and parts[-3].endswith('.app') and parts[-2:]==('Contents','Developer'))
    for key in ('appIdentity','developerIdentity'):
        _identity(value[key]);require(value[key]['uid']==0 and not value[key]['mode']&0o7022)
    _tool_identity(value['xcrun']);require(value['xcrun']['uid']==0 and not value['xcrun']['mode']&0o7022)
    return value

def context(value):
    require(type(value) is dict and value.get('operation')=='local-store-execute'
        and 'intentSha256' in value and sha(value['intentSha256']))
    apple=value.get('platform')=='ios'
    require('toolchainSelection' not in value if apple else 'toolchainSelection' in value)
    ordinary={k:v for k,v in value.items() if k not in {'intentSha256','toolchainSelection'}}
    ordinary['operation']='local-store-prepare';prepare.context(ordinary,apple_prepare=apple)
    if not apple:android.mac_toolchain_selection(value['toolchainSelection'])
    return value
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
        require(type(n) is dict)
        if c['platform']=='ios':
            require({'signingTools','uploadSelection'}<=n.keys())
            prepare.native({k:v for k,v in n.items() if k not in {'signingTools','uploadSelection'}})
            from .ios_current_tools_macos import bindings
            bindings(n['signingTools']);upload_selection(n['uploadSelection'])
        else:
            require('toolchain' in n)
            prepare.native({k:v for k,v in n.items() if k!='toolchain'})
            tools=android._native({k:n[k] for k in ('profile','projectRoot','rootIdentity','cwd','toolchain')})['toolchain']
            require(tools['schemaVersion']==2 and tools['selection']==c['toolchainSelection'])
        return StoreExecuteRequest(value['operationId'],value['ownerGeneration'],c,n,hashlib.sha256(raw).hexdigest())
    except (ValueError,TypeError,KeyError,OverflowError,RecursionError):raise ProtocolError() from None
response,reply=prepare.response,prepare.reply
def validate_result(value, *, platform='android'):
    require(platform in {'android','ios'})
    require(type(value) is dict and set(value)=={'schemaVersion','scope','headSequence','executionReceipt'}
        and type(value['schemaVersion']) is int and value['schemaVersion']==1
        and value['scope']=='local-%s-store-execute'%platform and integer(value['headSequence'],513,7))
    receipt_summary(value['executionReceipt'],LIMITATIONS,platform=platform)
    return value

def receipt_summary(r,limitations,*,platform='android'):
    require(platform in {'android','ios'});apple=platform=='ios';identity='bundleId' if apple else 'applicationId'
    from .config import IOS_ID_RE,APP_STORE_ID_RE
    require(type(r) is dict and set(r)=={'operationId','candidateSha256','intentSha256','receiptSha256','authorizationId',
        'sourceCommit','sourceTree',identity,'version','destination','observedAt','result','limitations'} | ({'appStoreAppId'} if apple else set())
        and _uuid(r['operationId']) and _uuid(r['authorizationId'])
        and all(sha(r[k]) for k in ('candidateSha256','intentSha256','receiptSha256'))
        and all(sha(r[k],40) for k in ('sourceCommit','sourceTree'))
        and type(r[identity]) is str and len(r[identity])<=255 and (IOS_ID_RE if apple else android.ANDROID_ID_RE).fullmatch(r[identity])
        and (not apple or type(r['appStoreAppId']) is str and APP_STORE_ID_RE.fullmatch(r['appStoreAppId']))
        and type(r['version']) is dict and set(r['version'])=={'name','build'}
        and type(r['version']['name']) is str and android._VERSION_TEXT.fullmatch(r['version']['name'])
        and integer(r['version']['build'],2100000000,1) and r['destination']==({'channel':'testflight-internal'} if apple else {'channel':'internal','releaseStatus':'completed'})
        and type(r['observedAt']) is str and re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',r['observedAt'])
        and r['result'] in {'accepted','reconciled'} and r['limitations']==limitations and len(canonical(r))<=16*1024)
    return r
