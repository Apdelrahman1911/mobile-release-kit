"""Explicit iOS codec DATA only: no lane, Store, native grant or archive custody."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from mobile_release import local_release_intent as L, local_release_receipt as R
from mobile_release.errors import ValidationError
from mobile_release.provenance import canonical_json_bytes, seal, validate_operation_intent, _validate_operation_intent_body

FIXTURES = Path(__file__).resolve().parents[1] / 'fixtures'
def encoded(value): return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
def reseal(value): return seal({k:v for k,v in value.items() if k != 'integrity'})
def fixture(name): return json.loads((FIXTURES / name).read_bytes())

class LocalIOSStoreDataTests(unittest.TestCase):
    def setUp(self):
        self.intent = fixture('local-intent-ios-candidate-valid.json')
        self.receipt = fixture('local-ios-execution-receipt-valid.json')
        self.authority = copy.deepcopy(self.receipt['executedBy'])
        self.args = dict(intent_data=encoded(self.intent), authority_data=encoded(self.authority),
            expected_intent_sha256=self.intent['integrity']['sha256'], purpose='execute', platform='ios')
    def read(self, value): return L.decode_local_operation_intent(encoded(reseal(value)), platform='ios')
    def receipt_read(self, value, **args):
        return R.validate_local_execution_receipt(encoded(value), **(self.args | args))
    def rejected_intents(self, changes):
        for change in changes:
            value=copy.deepcopy(self.intent);change(value)
            with self.subTest(change=change), self.assertRaises(L.LocalIntentError):self.read(value)
    def test_explicit_local_selector_preserves_android_and_ci_defaults(self):
        self.assertEqual(self.read(self.intent), self.intent)
        self.assertEqual(L.validate_local_execution_authority(self.args['authority_data'],
            intent_data=self.args['intent_data'], purpose='execute', platform='ios'), self.authority)
        self.assertEqual(L.decode_local_authority(encoded(self.intent['preparedBy']),
            purpose='prepare', platform='ios'), self.intent['preparedBy'])
        with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(self.args['intent_data'])
        with self.assertRaises(R.LocalReceiptError):
            R.validate_local_execution_receipt(encoded(self.receipt), **{k:v for k,v in self.args.items() if k != 'platform'})
        with self.assertRaises(ValidationError):validate_operation_intent(self.intent)
        # CI's actual shared body retains its file-only default grammar.
        with self.assertRaises(ValidationError):_validate_operation_intent_body(self.intent, stage='candidate', platform='ios')
        android=fixture('local-intent-candidate-valid.json')
        self.assertEqual(L.decode_local_operation_intent(encoded(android)), android)
        with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(android), platform='ios')
        for name in ('intent-candidate-valid.json','intent-external-valid.json','intent-production-valid.json'):
            ci=fixture(name);validate_operation_intent(ci)
            with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(encoded(ci), platform='ios')
    def test_archive_inventory_is_not_file_or_zip_and_limits_are_closed(self):
        original=self.intent['artifacts'][-1]
        self.assertEqual(set(original),{'logicalName','platform','kind','directory','entries','bytes','sha256'})
        value=copy.deepcopy(self.intent);value['artifacts'][-1].update(entries=100000,bytes=8<<30);value['artifacts'][0]['size']=4<<30
        self.assertEqual(self.read(value),reseal(value))
        self.rejected_intents([lambda d:d['artifacts'][-1].update(entries=True),
            lambda d:d['artifacts'][-1].update(entries=100001),lambda d:d['artifacts'][-1].update(bytes=(8<<30)+1),
            lambda d:d['artifacts'][-1].update(directory='export/archive.xcarchive'),
            lambda d:d['artifacts'][-1].update(fileName='archive.zip'),lambda d:d['artifacts'][-1].update(size=12),
            lambda d:d['artifacts'][-1].update(sha256='z'*64),lambda d:d['artifacts'][-1].update(architectures=[]),
            lambda d:d['artifacts'][0].update(fileName='export/Reader.ipa'),lambda d:d['artifacts'][0].update(fileName='a'*252+'.ipa'),
            lambda d:d['artifacts'][0].update(size=(4<<30)+1),lambda d:d['artifacts'].reverse(),
            lambda d:d['artifacts'].append(copy.deepcopy(original)),lambda d:d['artifacts'].pop()])
        value=copy.deepcopy(self.intent);value['artifacts'][-1]=dict(logicalName='ios-archive',platform='ios',kind='xcarchive',
            fileName='archive.zip',size=123,sha256=original['sha256'],architectures=[])
        with self.assertRaises(L.LocalIntentError):self.read(value)
    def test_shared_apple_signing_and_store_body_remain_required(self):
        self.rejected_intents([lambda d:d['signing'][0].update(profileUuid='not-a-profile'),
            lambda d:d['signing'][0].update(profileExpiresAt='2027-02-30T00:00:00Z'),
            lambda d:d['signing'][0].update(teamId=1234567890),lambda d:d['signing'][0].update(certificateSha256='bad'),
            lambda d:d['signing'][0].pop('profileUuid'),lambda d:d['artifacts'][1].update(sha256='f'*64),
            lambda d:d['destination'].update(channel='testflight-external'),lambda d:d['application'].update(storeAppId='00123'),
            lambda d:d['storePrecondition']['snapshot'].update(build={}),
            lambda d:d['storePrecondition'].update(appIdentity='com.foreign.app'),
            lambda d:d['preparedBy']['assignment'].update(kind='google-service-account'),
            lambda d:d['preparedBy']['assignment'].update(expectedRevision=True)])
    def test_ios_recover_hybrids_and_self_authorized_receipts_are_refused(self):
        for field,value in [('origin','github-actions'),('documentType','store-operation-intent'),
            ('stage','external-testing'),('authorizedBy',self.authority)]:
            with self.subTest(field=field),self.assertRaises(L.LocalIntentError):self.read(dict(self.intent,**{field:value}))
        changed=copy.deepcopy(self.authority);changed['purpose']='recover'
        with self.assertRaises(L.LocalIntentError):
            L.validate_local_execution_authority(encoded(changed),intent_data=self.args['intent_data'],purpose='recover',platform='ios')
        with self.assertRaises(R.LocalReceiptError):self.receipt_read(dict(self.receipt,executedBy=changed),authority_data=encoded(changed),purpose='recover')
        changed=copy.deepcopy(self.authority);changed['authorizationId']='66666666-6666-4666-8666-666666666666'
        with self.assertRaises(R.LocalReceiptError):self.receipt_read(dict(self.receipt,executedBy=changed))
        altered=copy.deepcopy(self.intent);altered['artifacts'][-1]['sha256']='f'*64
        with self.assertRaises(R.LocalReceiptError):self.receipt_read(self.receipt,intent_data=encoded(reseal(altered)))
    def test_complete_local_receipt_uses_shared_apple_body_without_ci_authority(self):
        self.assertEqual(self.receipt_read(self.receipt),self.receipt)
        reconciled=dict(self.receipt,result='reconciled',state='available-to-testers')
        self.assertEqual(self.receipt_read(reconciled),reconciled)
        for key in self.receipt:
            value=copy.deepcopy(self.receipt);del value[key]
            with self.subTest(missing=key),self.assertRaises(R.LocalReceiptError):self.receipt_read(value)
        for key,value in [('appStoreAppId','999'),('buildResourceId',''),('processingState','PROCESSING'),
            ('autoNotifyEnabled',True),('autoNotifyEnabled',0),('state','submitted-for-review'),('buildNumber',42.0),
            ('result','operator_authorized_retry'),('observedAt','yesterday'),('versionCode',42),('schemaVersion',True),
            ('operation','android_internal_upload'),('extra','PRIVATE_SENTINEL')]:
            with self.subTest(key=key),self.assertRaises(R.LocalReceiptError) as refused:self.receipt_read(dict(self.receipt,**{key:value}))
            self.assertEqual(str(refused.exception),'Invalid local Store receipt or attempt DATA')
    def test_canonical_attempt_key_matches_ruby_and_cannot_relabel_ci_domain(self):
        expected='1e926ffd3eeff5f02b6460c52266d0ff44db38e01ee73318a651cf9d0314a3c9'
        self.assertEqual(R.local_execution_attempt_key(**self.args),expected)
        self.assertEqual(R.local_execution_attempt_key(**(self.args|dict(authority_data=json.dumps(self.authority,indent=2).encode()))),expected)
        raw=canonical_json_bytes(self.authority);lane=b'ios_testflight_internal'
        ci=hashlib.sha256(b'mrk-store-attempt-v1\0'+bytes.fromhex(self.args['expected_intent_sha256'])+len(raw).to_bytes(4,'big')+raw+bytes([len(lane)])+lane).hexdigest()
        self.assertNotEqual(expected,ci)
        with self.assertRaises(R.LocalReceiptError):R.local_execution_attempt_key(**(self.args|dict(expected_intent_sha256='f'*64)))
    def test_bounded_duplicate_and_wrong_json_remain_fixed_refusals(self):
        raw=encoded(self.intent)
        for bad in (b'',b'[]',b'\xff',b'{"origin":"local-desktop",'+raw[1:],raw+b' '*L.MAX_LOCAL_INTENT_BYTES):
            with self.assertRaises(L.LocalIntentError):L.decode_local_operation_intent(bad,platform='ios')
        raw=encoded(self.receipt)
        for bad in (b'{}',b'{"origin":"local-desktop",'+raw[1:],raw+b' '*R.MAX_LOCAL_RECEIPT_BYTES):
            with self.assertRaises(R.LocalReceiptError):R.validate_local_execution_receipt(bad,**self.args)
