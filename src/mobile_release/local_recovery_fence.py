"""Exact preserved attempt names under the existing Store Run's original readers.

No process-finality assertion, filesystem adoption or removal. A journal row's
name is checked against its authenticated original local intent/pending authority.
"""
import json
import os
from uuid import UUID
from ._desktop_store_prepare_protocol import require
from .build_inputs import _app_private_directory,_read_file
from .local_release_journal import canonical,marker_data,recovery_chain,_pairs,_constant
from .local_release_intent import decode_local_operation_intent
from .local_release_receipt import local_execution_attempt_key
from .local_prepared_review import FILES


def expected_attempt(owner,raw,intent,pending):
    require(intent['project']==owner.enrollment and intent['integrity']['sha256']==pending['intentSha256']
        and intent['preparedBy']['assignment']['expectedRevision']==pending['assignmentRevision']
        and intent['preparedBy']['confirmationSha256']==pending['confirmationSha256'])
    authority=dict(intent['preparedBy'],purpose='execute',authorizationId=pending['authorizationId'],intentSha256=pending['intentSha256'])
    key=local_execution_attempt_key(intent_data=raw,authority_data=canonical(authority),purpose='execute',expected_intent_sha256=pending['intentSha256'])
    output=owner.root/'.mobile-release/store/local'/(
        UUID(intent['operationId']).hex+'-execute-'+UUID(pending['authorizationId']).hex)/'raw-store-receipt.json'
    return key+'.pending',str(output)


def prior_markers(owner,rows):
    """Sequential bounded originals; no old decoded intent survives its scope."""
    result={}
    for row in rows:
        if row['phase']!='target-reconciled':continue
        owner.checkpoint();require(len(result)<64)
        descriptor=row['payload']['preservedAttempt'];marker_data(descriptor)
        if descriptor is None:continue
        operation=row['operationId']
        chain=recovery_chain([r for r in rows if r['operationId']==operation and r['sequence']<row['sequence']],operation)
        path=owner.root/'.mobile-release/store/local'/UUID(operation).hex
        with _app_private_directory(path,app_root=owner.root,cancellation=owner.guard,create=False) as out:
            require(out is not None);owner.prior_readers.append(out)
            root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==owner.source.lease_identity)
            value=_read_file(out.fd,'operation-intent.json',owner.guard,FILES['operation-intent.json'],private=True);require(value is not None)
            binding,raw=value;before=owner._intent_memory
            owner._memory(raw,FILES['operation-intent.json'],intent=True)
            intent=decode_local_operation_intent(raw)
            require(intent['operationId']==operation and intent['integrity']['sha256']==row['payload']['intentSha256']
                and intent['candidateSha256']==chain[3]['payload']['candidateSha256'])
            name,output=expected_attempt(owner,raw,intent,chain[4]['payload'])
            require(name==descriptor['name'] and name not in result)
            result[name]=(descriptor,output)
            require(_read_file(out.fd,'operation-intent.json',owner.guard,FILES['operation-intent.json'],private=True,binding_only=True)==(binding,b''))
            out.check()
            del intent,raw,value
            owner._intent_memory=before
        require(out.closed())
    return result


def read_marker(owner,out,name,output):
    value=_read_file(out.fd,name,owner.guard,8192,private=True)
    if value is None:return None
    binding,raw=value
    owner._memory(raw,8192)
    body=json.loads(raw,object_pairs_hook=_pairs,parse_constant=_constant)
    require(type(body) is dict and set(body)=={'version','key','nonce','lane','mode','output'}
        and type(body['version']) is int and body['version']==1 and body['key']==name.removesuffix('.pending')
        and body['lane']=='android_internal_upload' and body['mode']=='execute' and body['output']==output
        and type(body['nonce']) is str and len(body['nonce'])==32 and all(c in '0123456789abcdef' for c in body['nonce'])
        and canonical(body)+b'\n'==raw)
    descriptor={'name':name,'binding':binding};marker_data(descriptor);return descriptor


def names(owner,out,expected):
    owner.checkpoint();out.check()
    require(owner.fence_iterator is None and owner.fence_state in {'new','closed'} and len(expected)<=65)
    owner.fence_state='acquiring'
    try:
        owner.fence_iterator=os.scandir(out.fd);owner.fence_state='open';seen=set()
        for entry in owner.fence_iterator:
            owner.checkpoint();require(len(seen)<len(expected) and entry.name in expected and entry.name not in seen);seen.add(entry.name)
        require(seen==set(expected))
    finally:
        original,owner.fence_iterator=owner.fence_iterator,None
        if original is not None:
            owner.fence_state='closing'
            try:original.close()
            except BaseException as error:
                owner.fence_state='unknown';owner.guard._abort(error);raise
            owner.fence_state='closed'
        elif owner.fence_state=='acquiring':
            owner.fence_state='unknown';owner.guard._abort(ValueError('Preserved marker iterator did not settle'))
    out.check();owner.checkpoint()


def open_fence(owner,scope):
    out=scope.enter_context(_app_private_directory(owner.root/'.mobile-release/store/lane-attempts-v1',
        app_root=owner.root,cancellation=owner.guard,create=False))
    require(out is not None);owner.fence_readers.append(out)
    root=os.fstat(out.parent.fd);require((root.st_dev,root.st_ino,root.st_mode,root.st_uid,root.st_gid)==owner.source.lease_identity)
    return out


def post(owner,*,own_pending=False):
    require(len(owner.fence_readers)==1)
    out=owner.fence_readers[0];expected=dict(owner.preserved_markers)
    if own_pending:
        attempt=owner.record._pending_attempt
        require(attempt.phase=='PENDING' and attempt.name not in expected)
        # Current own marker authority remains its original StoreLaneAttempt,
        # never a recovered descriptor. Check exact identity/content before use.
        value=_read_file(out.fd,attempt.name,owner.guard,8192,private=True)
        require(value is not None and value[1]==attempt.content and attempt.identity is not None
            and all(value[0][k]==getattr(attempt.identity,k) for k in ('device','inode','uid','gid','mode')))
        expected[attempt.name]=None
    names(owner,out,expected)
    for name,(descriptor,output) in owner.preserved_markers.items():
        require(read_marker(owner,out,name,output)==descriptor)
    names(owner,out,expected)
