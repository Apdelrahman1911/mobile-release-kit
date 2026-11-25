"""Real shared intent constructor, DATA only; no Store/credential/native owner."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from mobile_release.config import ReleaseConfig
from mobile_release.local_store_prepare import prepared_intent_data
from mobile_release.local_release_intent import decode_local_operation_intent
from mobile_release.errors import ValidationError
from mobile_release._desktop_store_prepare_protocol import ProtocolError
from unit.helpers import ios_config

class IOSPreparedIntentDataTests(unittest.TestCase):
    def setUp(self):
        fixture=Path(__file__).resolve().parents[1]/'fixtures/local-intent-ios-candidate-valid.json'
        self.intent=json.loads(fixture.read_bytes());v=self.intent;a=v['preparedBy']['assignment']
        c=dict(platform='ios',savedConfig=dict(bytes=10,sha256=v['configuration']['sha256']),
            savedVersion=dict(source='release/version.properties',bytes=20,sha256='f'*64,name=v['version']['marketing'],build=v['version']['build']),
            candidateOperationId=v['operationId'],candidateSha256=v['candidateSha256'],recordId=a['recordId'],
            recordRevision=a['expectedRevision'],credentialContextRevision=a['contextRevision'],confirmation=v['confirmation'])
        self.request=SimpleNamespace(context=c,native=dict(authorizationId=v['preparedBy']['authorizationId'],tooling=v['tooling']))
        self.manifest=dict(operationId=v['operationId'],enrollment=v['project'],sourceCommit=v['candidateSource']['commit'],
            sourceTree=v['candidateSource']['tree'],savedConfig=copy.deepcopy(c['savedConfig']),savedVersion=copy.deepcopy(c['savedVersion']),
            bundleId=v['application']['id'],signing=copy.deepcopy(v['signing'][0]),
            archive={k:v['artifacts'][-1][k] for k in ('directory','entries','bytes','sha256')},
            files=[dict(fileName=('export/' if i==0 else '')+r['fileName'],bytes=r['size'],sha256=r['sha256']) for i,r in enumerate(v['artifacts'][:3])])
        data=ios_config();data['ios']['distributionCertificateSha256']=':'.join(['AA']*32)
        self.config=ReleaseConfig(Path('/unused/release/mobile-release.json'),Path('/unused'),data)
        self.observed=SimpleNamespace(**v['candidateSource'])
    def build(self,manifest=None,**extra):
        return prepared_intent_data(**(dict(request=self.request,enrollment=self.intent['project'],
            manifest=self.manifest if manifest is None else manifest,observed=self.observed,config=self.config,
            precondition=self.intent['storePrecondition'])|extra))
    def test_shared_constructor_preserves_embedded_profile_and_directory_inventory(self):
        before=copy.deepcopy(self.manifest);raw,value=self.build()
        self.assertEqual(decode_local_operation_intent(raw,platform='ios'),value)
        self.assertEqual(value['signing'],self.intent['signing'])
        expected=copy.deepcopy(self.intent['artifacts']);expected[0]['architectures']=[]
        # Retained manifest carries no architecture field: do not invent one.
        self.assertEqual(value['artifacts'],expected)
        self.assertEqual(value['application'],self.intent['application']);self.assertEqual(value['destination'],{'channel':'testflight-internal'})
        self.assertEqual(value['preparedBy'],self.intent['preparedBy']);self.assertEqual(self.manifest,before)
        with self.assertRaises(ValidationError):decode_local_operation_intent(raw)
    def test_source_identity_saved_inputs_and_signer_cannot_be_substituted(self):
        changes=[lambda v:v.update(bundleId='com.foreign.app'),lambda v:v.update(sourceCommit='9'*40),
            lambda v:v['savedConfig'].update(sha256='9'*64),lambda v:v['savedVersion'].update(build=43),
            lambda v:v['signing'].update(teamId='FOREIGN123'),lambda v:v['signing'].update(certificateSha256='9'*64),
            lambda v:v['signing'].pop('profileUuid'),lambda v:v['signing'].update(profileExpiresAt='2027-02-30T00:00:00Z'),
            lambda v:v.update(operationId='99999999-9999-4999-8999-999999999999')]
        for change in changes:
            value=copy.deepcopy(self.manifest);change(value)
            with self.subTest(change=change),self.assertRaises((ValidationError,ProtocolError)):self.build(value)
    def test_artifact_adapter_never_truncates_unvalidated_paths_or_accepts_zip_archive(self):
        changes=[lambda v:v['files'][0].update(fileName='foreign/App.ipa'),
            lambda v:v['files'][0].update(fileName='export/nested/App.ipa'),lambda v:v['files'].reverse(),
            lambda v:v['files'].append(copy.deepcopy(v['files'][0])),lambda v:v['archive'].update(directory='archive.zip'),
            lambda v:v['archive'].update(fileName='archive.zip'),lambda v:v['archive'].update(entries=True)]
        for change in changes:
            value=copy.deepcopy(self.manifest);change(value)
            with self.subTest(change=change),self.assertRaises((ValidationError,ProtocolError)):self.build(value)
        precondition=copy.deepcopy(self.intent['storePrecondition']);precondition['snapshot']['appStoreAppId']='999'
        with self.assertRaises(ValidationError):self.build(precondition=precondition)
