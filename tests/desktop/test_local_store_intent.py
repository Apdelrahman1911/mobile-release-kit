"""Pure local/CI contract DATA; no native grant, authenticated journal or Store."""
import copy
import hashlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from mobile_release import local_release_intent as L
from mobile_release.provenance import canonical_json_bytes, seal, validate_operation_intent, validate_evidence_document
from mobile_release.stores import StoreRequest, guard_ci_mutation
from mobile_release.errors import ValidationError, MutationGuardError
from unit.evidence_helpers import git_identity
from unit.helpers import android_config, write_project
from mobile_release.config import load_config
import tempfile

FIXTURES=Path(__file__).resolve().parents[1]/'fixtures'
def encoded(value):return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
def fixture():return json.loads((FIXTURES/'local-intent-candidate-valid.json').read_bytes())
def reseal(value):return seal({k:v for k,v in value.items() if k!='integrity'})
def authority(intent,purpose='execute'):
    v=copy.deepcopy(intent['preparedBy']);v.update(purpose=purpose,intentSha256=intent['integrity']['sha256'],authorizationId='55555555-5555-4555-8555-555555555555');return v

class LocalStoreIntentTests(unittest.TestCase):
    def test_prepared_intent_and_distinct_execute_recover_data_binding(self):
        d=fixture();raw=encoded(d)
        self.assertEqual(L.decode_local_operation_intent(raw),d)
        self.assertEqual(hashlib.sha256(canonical_json_bytes({k:v for k,v in d.items() if k!='integrity'})).hexdigest(),d['integrity']['sha256'])
        self.assertEqual(L.decode_local_authority(encoded(d['preparedBy']),purpose='prepare'),d['preparedBy'])
        for purpose in ('execute','recover'):
            a=authority(d,purpose)
            self.assertEqual(L.validate_local_execution_authority(encoded(a),intent_data=raw,purpose=purpose),a)
        # DATA has no effectful authority minting or environment-dependent path.
        with patch.dict(os.environ,{'GITHUB_ACTIONS':'true','MOBILE_RELEASE_EXECUTION_AUTHORITY_JSON':'foreign'},clear=True):
            self.assertEqual(L.decode_local_operation_intent(raw),d)
    def test_cross_origin_hybrid_relabel_and_unsupported_stage_refused(self):
        local=fixture();ci=json.loads((FIXTURES/'intent-candidate-valid.json').read_bytes())
        validate_operation_intent(ci)
        with self.assertRaises(ValidationError):validate_operation_intent(local)
        with self.assertRaises(ValidationError):validate_evidence_document(local)
        with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(ci))
        for key,value in [('documentType','store-operation-intent'),('origin','github-actions'),('repository',ci['repository']),
            ('authorizedBy',ci['authorizedBy']),('stage','external-testing'),('platform','ios')]:
            d=copy.deepcopy(local);d[key]=value
            with self.subTest(key=key),self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(reseal(d)))
        hybrid=copy.deepcopy(local);hybrid['documentType']='store-operation-intent'
        with self.assertRaises(ValidationError):validate_operation_intent(reseal(hybrid))
    def test_envelope_assignment_and_authority_bindings_refuse_substitution(self):
        d=fixture()
        changes=[('project',dict(d['project'],keyId='66666666-6666-4666-8666-666666666666')),
            ('operationId','66666666-6666-4666-8666-666666666666'),('candidateSha256','f'*64),
            ('source',dict(d['operationSource'],tree='f'*40)),('confirmationSha256','f'*64),
            ('assignment',dict(d['preparedBy']['assignment'],expectedRevision=2)),('intentSha256','f'*64),
            ('authorizationId',d['preparedBy']['authorizationId']),('purpose','recover')]
        for key,value in changes:
            a=authority(d);a[key]=value
            with self.subTest(key=key),self.assertRaises(L.LocalIntentError):L.validate_local_execution_authority(encoded(a),intent_data=encoded(d),purpose='execute')
        for key,value in changes[:5]:
            v=copy.deepcopy(d);v['preparedBy'][key]=value
            with self.subTest(prepared=key),self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(reseal(v)))
    def test_actual_shared_body_rejects_artifact_and_store_target_changes(self):
        mutations=[lambda d:d['destination'].update(channel='production'),
            lambda d:d['artifacts'][1].update(sha256='f'*64),lambda d:d['artifacts'][0].update(fileName='foreign.aab'),
            lambda d:d['artifacts'][0].update(size=1024**3+1),lambda d:d['artifacts'].reverse(),
            lambda d:d['storePrecondition']['snapshot'].update(targetPresent=True),
            lambda d:d['storePrecondition'].update(appIdentity='com.foreign.app'),
            lambda d:d['candidateSource'].update(commit='f'*40),lambda d:d['signing'][0].update(kind='foreign')]
        for change in mutations:
            v=fixture();change(v)
            with self.subTest(change=change),self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(reseal(v)))
    def test_bounded_duplicate_strict_type_and_private_input_refusal(self):
        raw=encoded(fixture())
        self.assertEqual(L.decode_local_operation_intent(raw+b' '*(L.MAX_LOCAL_INTENT_BYTES-len(raw))),fixture())
        duplicate=b'{\"origin\":\"local-desktop\",'+raw[1:]
        for bad in (b'',b'\xff',b'[]',duplicate,raw+b' ',b' '* (L.MAX_LOCAL_INTENT_BYTES+1),b'{"a":1,"a":2}'):
            if bad==raw+b' ': # Whitespace is legal JSON, not an integrity change.
                self.assertEqual(L.decode_local_operation_intent(bad),fixture());continue
            with self.subTest(raw=bad[:8]),self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(bad)
        for update in (lambda d:d.update(schemaVersion=True),lambda d:d['preparedBy']['assignment'].update(expectedRevision=True),
            lambda d:d['project'].update(keyRevision=2),lambda d:d['preparedBy'].update(extra='SECRET_SENTINEL'),
            lambda d:d['operationSource'].update(ref='refs/heads/bad\nref')):
            d=fixture();update(d)
            with self.subTest(update=update),self.assertRaises(L.LocalIntentError) as ctx:L.decode_local_operation_intent(encoded(reseal(d)))
            self.assertEqual(str(ctx.exception),'Invalid local Store intent or authority DATA')
        authority_raw=encoded(fixture()['preparedBy'])
        self.assertEqual(L.decode_local_authority(authority_raw+b' '*(L.MAX_LOCAL_AUTHORITY_BYTES-len(authority_raw)),purpose='prepare'),fixture()['preparedBy'])
        for bad in (b'{\"origin\":\"local-desktop\",'+authority_raw[1:],b'{}',b' '* (L.MAX_LOCAL_AUTHORITY_BYTES+1),b'{"schemaVersion":1,"schemaVersion":1}',b'{"x":NaN}',b'{"x":1.5}'):
            with self.assertRaises(L.LocalIntentError):L.decode_local_authority(bad,purpose='prepare')
    def test_local_contract_does_not_bypass_actual_ci_mutation_guard(self):
        with tempfile.TemporaryDirectory() as root:
            config=load_config(write_project(Path(root),android_config(),platform='android'))
            request=StoreRequest(stage='candidate',platform='android',confirmation='candidate:android:1.2.3:42',execute=True,output_dir=Path(root)/'output')
            with patch.dict(os.environ,{'MOBILE_RELEASE_LOCAL_STORE_ENABLED':'true'},clear=True):
                with self.assertRaises(MutationGuardError):guard_ci_mutation(config=config,release=config.release_version(),git=git_identity(),request=request)

if __name__=='__main__':unittest.main()
