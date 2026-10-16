"""Local execution DATA only: no lane, journal/native owner or Store request."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from mobile_release import local_release_receipt as R
from mobile_release.provenance import (canonical_json_bytes, seal,
    _validate_store_receipt_document, validate_operation_intent)
from mobile_release.config import ReleaseVersion
from mobile_release.errors import ValidationError
from mobile_release._store_lane_files import execution_attempt_key
from unit.evidence_helpers import raw_receipt

FIXTURES=Path(__file__).resolve().parents[1]/'fixtures'
def encoded(v):return json.dumps(v,ensure_ascii=False,separators=(',',':')).encode()
def fixture(name):return json.loads((FIXTURES/name).read_bytes())

class LocalStoreReceiptTests(unittest.TestCase):
    def setUp(self):
        self.intent=fixture('local-intent-candidate-valid.json')
        self.receipt=fixture('local-execution-receipt-valid.json')
        self.authority=copy.deepcopy(self.receipt['executedBy'])
        self.args=dict(intent_data=encoded(self.intent),authority_data=encoded(self.authority),
            purpose='execute',expected_intent_sha256=self.intent['integrity']['sha256'])
    def read(self,value,**args):return R.validate_local_execution_receipt(encoded(value),**(self.args|args))
    def test_exact_current_receipt_and_recovery_shape_preserve_finality_boundary(self):
        self.assertEqual(self.read(self.receipt),self.receipt)
        reconciled=copy.deepcopy(self.receipt);reconciled['result']='reconciled'
        # Execute can reconcile its own ambiguous commit without erasing mutation evidence.
        self.assertEqual(self.read(reconciled),reconciled)
        authority=dict(self.authority,purpose='recover')
        reconciled['executedBy']=authority
        args=dict(authority_data=encoded(authority),purpose='recover')
        with self.assertRaises(R.LocalReceiptError):self.read(reconciled,**args)
        reconciled['storeState']['mode']='recovery';del reconciled['storeState']['mutationEditId']
        self.assertEqual(self.read(reconciled,**args),reconciled)
        reconciled['result']='accepted'
        with self.assertRaises(R.LocalReceiptError):self.read(reconciled,**args)
    def test_ci_and_local_envelopes_cannot_be_relabelled_or_adopted(self):
        ci=fixture('intent-candidate-valid.json');raw=raw_receipt(ci)
        validate_operation_intent(ci)
        params=dict(platform_config={'applicationId':'com.example.reader'},release=ReleaseVersion('1.2.3',42),
            stage='candidate',platform='android',operation_intent=ci)
        self.assertEqual(_validate_store_receipt_document(raw,**params),raw)
        with self.assertRaises(ValidationError):_validate_store_receipt_document(self.receipt,**params)
        for value in [raw,dict(self.receipt,authorizedBy=ci['authorizedBy']),dict(self.receipt,origin='github-actions'),
            dict(self.receipt,documentType='store-receipt'),dict(self.receipt,schemaVersion=3)]:
            with self.subTest(value=value.get('documentType')),self.assertRaises(R.LocalReceiptError):self.read(value)
        with self.assertRaises(R.LocalReceiptError):self.read(self.receipt,intent_data=encoded(ci))
        with self.assertRaises(R.LocalReceiptError):self.read(self.receipt,authority_data=encoded(ci['authorizedBy']))
    def test_identity_authority_and_strict_nested_types_cannot_be_substituted(self):
        for field in self.receipt:
            bad=copy.deepcopy(self.receipt);del bad[field]
            with self.subTest(missing=field),self.assertRaises(R.LocalReceiptError):self.read(bad)
        for field,value in [('operationId','66666666-6666-4666-8666-666666666666'),('candidateSha256','f'*64),
            ('operationIntentSha256','f'*64),('appIdentity','com.other.app'),('marketingVersion','1.2.4'),
            ('buildNumber',42.0),('versionCode',True),('schemaVersion',True),('observedAt','yesterday'),
            ('extra','SECRET_SENTINEL')]:
            with self.subTest(field=field),self.assertRaises(R.LocalReceiptError) as e:self.read(dict(self.receipt,**{field:value}))
            self.assertEqual(str(e.exception),'Invalid local Store receipt or attempt DATA')
        for mutate in [lambda r:r['project'].update(keyRevision=True),
            lambda r:r['preparedBy']['project'].update(keyRevision=True),
            lambda r:r['executedBy']['assignment'].update(expectedRevision=True),
            lambda r:r['executedBy'].update(authorizationId='66666666-6666-4666-8666-666666666666'),
            lambda r:r['preparedBy'].update(authorizationId='66666666-6666-4666-8666-666666666666')]:
            bad=copy.deepcopy(self.receipt);mutate(bad)
            with self.assertRaises(R.LocalReceiptError):self.read(bad)
        with self.assertRaises(R.LocalReceiptError):self.read(self.receipt,expected_intent_sha256='f'*64)
    def test_real_shared_android_body_requires_complete_original_target(self):
        changes=[lambda r:r.update(destinationTrack='production'),lambda r:r.update(releaseStatus='draft'),
            lambda r:r.update(state='draft'),lambda r:r.update(result='already_present'),lambda r:r.update(storeEditId='foreign'),
            lambda r:r['storeState'].update(mutationEditId='readback-edit'),
            lambda r:r['storeState'].update(mode='observation'),lambda r:r['storeState'].update(extra='bad'),
            lambda r:r['storeState'].update(destinationExpectedSha256='f'*64,destinationCommittedSha256='f'*64),
            lambda r:r['storeState'].update(unrelatedBeforeSha256='f'*64,unrelatedCommittedSha256='f'*64),
            lambda r:r['storeState'].update(targetReleaseSha256='f'*64)]
        for mutate in changes:
            bad=copy.deepcopy(self.receipt);mutate(bad)
            with self.subTest(mutation=mutate),self.assertRaises(R.LocalReceiptError):self.read(bad)
        intent=copy.deepcopy(self.intent);intent['artifacts'][0]['fileName']='foreign.aab'
        intent=seal({k:v for k,v in intent.items() if k!='integrity'})
        authority=dict(self.authority,intentSha256=intent['integrity']['sha256'])
        with self.assertRaises(R.LocalReceiptError):self.read(self.receipt,intent_data=encoded(intent),authority_data=encoded(authority),expected_intent_sha256=intent['integrity']['sha256'])
    def test_bounded_parser_rejects_duplicate_private_and_non_json_data(self):
        raw=encoded(self.receipt)
        self.assertEqual(R.validate_local_execution_receipt(raw+b' '*(R.MAX_LOCAL_RECEIPT_BYTES-len(raw)),**self.args),self.receipt)
        for bad in [b'',b'\xff',b'[]',b'{"origin":"local-desktop",'+raw[1:],raw+b' '*(R.MAX_LOCAL_RECEIPT_BYTES+1-len(raw)),
            b'{"x":NaN}',encoded(dict(self.receipt,privateKey='SECRET_SENTINEL'))]:
            with self.assertRaises(R.LocalReceiptError) as e:R.validate_local_execution_receipt(bad,**self.args)
            self.assertEqual(str(e.exception),'Invalid local Store receipt or attempt DATA')
    def test_fixed_local_attempt_key_is_canonical_domain_separated_and_unrouted(self):
        expected='4ac8941d05da26dbe491363baeb9cf501558b5c49efd93b2dded2683c687128f'
        self.assertEqual(R.local_execution_attempt_key(**self.args),expected)
        pretty=json.dumps(self.authority,indent=2).encode()
        self.assertEqual(R.local_execution_attempt_key(**(self.args|{'authority_data':pretty})),expected)
        for authority in [dict(self.authority,purpose='recover'),dict(self.authority,authorizationId='66666666-6666-4666-8666-666666666666')]:
            value=R.local_execution_attempt_key(**(self.args|dict(authority_data=encoded(authority),purpose=authority['purpose'])))
            self.assertNotEqual(value,expected)
        raw=canonical_json_bytes(self.authority);lane=b'android_internal_upload'
        ci_domain=hashlib.sha256(b'mrk-store-attempt-v1\0'+bytes.fromhex(self.args['expected_intent_sha256'])+len(raw).to_bytes(4,'big')+raw+bytes([len(lane)])+lane).hexdigest()
        self.assertNotEqual(expected,ci_domain)
        # Actual ordinary CI refusal-key API still cannot admit local authority.
        with self.assertRaises(ValueError):execution_attempt_key(bytes.fromhex(self.args['expected_intent_sha256']),self.authority,lane.decode())
        ci=fixture('intent-candidate-valid.json')
        self.assertEqual(len(execution_attempt_key(bytes.fromhex(ci['integrity']['sha256']),ci['authorizedBy'],lane.decode())),64)
        for change in [dict(expected_intent_sha256='f'*64),dict(purpose='prepare'),dict(authority_data=encoded(ci['authorizedBy']))]:
            with self.assertRaises(R.LocalReceiptError):R.local_execution_attempt_key(**(self.args|change))

if __name__=='__main__':unittest.main()
