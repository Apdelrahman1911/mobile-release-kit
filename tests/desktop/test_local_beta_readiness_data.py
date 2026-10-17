"""Closed cross-purpose Python DATA parity; no owner/native/Store operations."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from mobile_release.local_release_journal import canonical,_payload,external_readiness_chain,LocalJournalError
from mobile_release.local_release_intent import LocalIntentError
from mobile_release.local_release_receipt import LocalReceiptError
from mobile_release.errors import ValidationError
from mobile_release.local_release_intent import decode_local_operation_intent,validate_local_readiness_authority,validate_local_execution_authority
from mobile_release.local_release_receipt import validate_local_readiness_receipt,local_readiness_attempt_key
from mobile_release.provenance import seal,verify_sealed,validate_operation_intent

class LocalBetaReadinessDataTests(unittest.TestCase):
    def setUp(self):
        self.fixtures=Path(__file__).resolve().parents[1]/'fixtures'
        self.raw=(self.fixtures/'local-ios-external-testing-intent.json').read_bytes()
        self.intent=decode_local_operation_intent(self.raw,platform='ios',stage='external-testing');i=self.intent
        self.authority=dict(i['preparedBy'],purpose='external-readiness',authorizationId='99999999-9999-4999-8999-999999999999',
            intentSha256=i['integrity']['sha256'],executionReceiptSha256='e'*64)
        self.args=dict(intent_data=self.raw,authority_data=canonical(self.authority),expected_intent_sha256=i['integrity']['sha256'],execution_receipt_sha256='e'*64)
        self.receipt=dict(documentType='local-store-external-readiness-receipt',schemaVersion=1,origin='local-desktop',operation='ios_testflight_external',platform='ios',
            stage='external-testing',project=i['project'],operationId=i['operationId'],candidateOperationId=i['candidateOperationId'],candidateSha256=i['candidateSha256'],
            operationIntentSha256=i['integrity']['sha256'],executionReceiptSha256='e'*64,preparedBy=i['preparedBy'],observedBy=self.authority,
            appIdentity=i['application']['id'],appStoreAppId=i['application']['storeAppId'],marketingVersion=i['version']['marketing'],buildNumber=i['version']['build'],
            observedAt='2026-10-17T00:00:00Z',result='ready',state='available-to-testers',buildResourceId=i['storePrecondition']['snapshot']['build']['id'],
            processingState='VALID',externalGroup=i['storePrecondition']['snapshot']['external']['groupName'],autoNotifyEnabled=False,betaReviewState='BETA_APPROVED',
            priorExecutionFinality='not-established')
    def test_exact27_and_shared_attempt_domain_bind_fresh_observer_not_executor(self):
        self.assertEqual(len(self.receipt),27);self.assertEqual(validate_local_readiness_receipt(canonical(self.receipt),**self.args),self.receipt)
        key=local_readiness_attempt_key(**self.args);raw=canonical(self.authority);lane=b'ios_testflight_external'
        self.assertEqual(key,hashlib.sha256(b'mrk-local-store-attempt-v1\0'+bytes.fromhex(self.intent['integrity']['sha256'])+len(raw).to_bytes(4,'big')+raw+bytes((len(lane),))+lane).hexdigest())
        for state in ('NOT_SUBMITTED','WAITING_FOR_REVIEW','WAITING_FOR_BETA_REVIEW','SUBMITTED','IN_REVIEW','IN_BETA_REVIEW','BETA_APPROVED','APPROVED'):
            r=dict(self.receipt,betaReviewState=state);validate_local_readiness_receipt(canonical(r),**self.args)
    def test_changed_original_bindings_foreign_purpose_and_hostile_shape_refuse(self):
        for change in ({'origin':'github'},{'executionReceiptSha256':'f'*64},{'result':'accepted'},{'state':'submitted-for-review'},
            {'processingState':'PROCESSING'},{'autoNotifyEnabled':True},{'buildNumber':True},{'buildResourceId':'foreign'},
            {'externalGroup':'foreign'},{'betaReviewState':'REJECTED'},{'executedBy':self.authority},{'priorExecutionFinality':'established'}):
            with self.subTest(change=change),self.assertRaises(LocalReceiptError):validate_local_readiness_receipt(canonical(dict(self.receipt,**change)),**self.args)
        for purpose in ('execute','recover'):
            with self.assertRaises(LocalIntentError):validate_local_execution_authority(canonical(self.authority),intent_data=self.raw,purpose=purpose,platform='ios',stage='external-testing')
        a=copy.deepcopy(self.authority);a['supplementalAssignments'][0]['expectedRevision']+=1
        with self.assertRaises(LocalIntentError):validate_local_readiness_authority(canonical(a),intent_data=self.raw,expected_intent_sha256=self.intent['integrity']['sha256'],execution_receipt_sha256='e'*64)
    def test_readiness_reference_only_local_ios_production_and_not_ci_default(self):
        for platform,stage in (('ios','production-submit'),('ios','external-testing'),('android','production-submit')):
            value=json.loads((self.fixtures/f'local-{platform}-{stage}-intent.json').read_bytes());value=verify_sealed(value)
            value['predecessors']['externalReadinessReceiptSha256']='f'*64;raw=canonical(seal(value))
            if platform=='ios' and stage=='production-submit':decode_local_operation_intent(raw,platform=platform,stage=stage)
            else:
                with self.assertRaises(LocalIntentError):decode_local_operation_intent(raw,platform=platform,stage=stage)
        value=verify_sealed(json.loads((self.fixtures/'intent-production-valid.json').read_bytes()))
        value['predecessors']['externalReadinessReceiptSha256']='f'*64
        with self.assertRaises(ValidationError):validate_operation_intent(seal(value))
    def test_exact_journal_suffix_cannot_be_a_generic_settlement_or_predecessor_waiver(self):
        good=dict(intentSha256='a'*64,executionReceiptSha256='b'*64,readinessReceiptSha256='c'*64,refreshAuthorizationId=self.authority['authorizationId'])
        _payload('external-ready',good)
        for change in ({'oldFinality':'settled'},{'refreshAuthorizationId':'0'*32},{'readinessReceiptSha256':True}):
            with self.assertRaises(LocalJournalError):_payload('external-ready',dict(good,**change))
        with self.assertRaises(LocalJournalError):external_readiness_chain([],self.intent['operationId'])

    def test_readiness_descriptor_reserve_is_ios_only(self):
        from mobile_release.local_store_predecessor import StorePredecessorInputs
        owner=object.__new__(StorePredecessorInputs);owner.root=Path('/case/project')
        for platform,stage,count in (('android','external-testing',2),('android','production-submit',4),
                ('ios','external-testing',2),('ios','production-submit',5)):
            owner.platform=platform;owner.payload={'stage':stage}
            self.assertEqual(owner.descriptor_quote(),count*(len(owner.root.parts)+4)+2)
        owner.payload={'stage':'external-testing'};owner.readiness_owner=object()
        self.assertEqual(owner.descriptor_quote(),5*(len(owner.root.parts)+4)+2)
