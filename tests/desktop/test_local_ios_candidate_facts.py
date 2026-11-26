"""Real IPA parser/policy/deposit; native auth and snapshot transport are inert."""
from contextlib import nullcontext, contextmanager
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import plistlib
from types import SimpleNamespace
import unittest
import zipfile
from mobile_release import ios, ios_artifacts as A
from mobile_release.errors import ValidationError
from mobile_release._desktop_ios_archive_protocol import ProtocolError
from mobile_release.reporting import Status
from mobile_release.local_ios_candidate_bundle import signing_data
import test_local_ios_candidate_create as chain

class IOSCandidateFactsTests(unittest.TestCase):
    setUp=chain.IOSCandidateCreateTests.setUp
    patch=chain.IOSCandidateCreateTests.patch
    subject=chain.IOSCandidateCreateTests.subject

    def fixture(self):
        body=io.BytesIO()
        with zipfile.ZipFile(body,'w') as z:
            for name,value in {'Info.plist':plistlib.dumps(dict(CFBundleIdentifier='org.example.inert',
                 CFBundleShortVersionString='1.2.3',CFBundleVersion='7',CFBundleExecutable='Inert')),
                 'Inert':b'inert-not-executable','_CodeSignature/CodeResources':b'inert-signature',
                 'embedded.mobileprovision':b'inert-CMS-native-boundary'}.items():
                z.writestr('Payload/Inert.app/'+name,value)
        f=self.subject(ipa_body=body.getvalue());op=f.op
        bundle=f.bound.saved.configuration.bundle_id;team=f.run.request.context['signing']['teamId']
        # Match actual source, not a second caller-selected bundle identity.
        self.assertEqual(bundle,'org.example.inert')
        entitlements={'application-identifier':team+'.'+bundle,'com.apple.developer.team-identifier':team,
            'get-task-allow':False,'beta-reports-active':True}
        profile=dict(UUID='12345678-1234-1234-1234-123456789AbC',TeamIdentifier=[team],Entitlements=entitlements,
            CreationDate=datetime(2020,1,1,tzinfo=timezone.utc),ExpirationDate=datetime(2030,1,1,tzinfo=timezone.utc))
        observed=dict(platform='ios',kind='apple-distribution',certificateSha256=f.run.request.context['signing']['distributionCertificateSha256'],teamId=team,
            profileUuid=profile['UUID'],profileExpiresAt='2030-01-01T00:00:00Z')
        temporary=f.op.root/'validation';temporary.mkdir(mode=0o700)
        snapshot_owner=object()
        deadline=SimpleNamespace(check=f.guard.check,snapshot_owner=lambda:snapshot_owner)
        snapshot=A.IOSArtifactSnapshot({'ios-archive':f.archive,'ios-ipa':f.ipa},{},
            {'ios-archive':op._artifact.inventory,'ios-ipa':op._ipa.inventory},temporary,deadline,
            cancellation=f.guard,_owner=snapshot_owner)
        op.inspection_deadline=deadline;op.snapshot_binding.owner=snapshot_owner
        op.snapshot_binding.consumer_active=True
        op._ipa.inventory=None;op._artifact.inventory=None
        @contextmanager
        def archive_context(archive,**_):
            try:yield archive,f.guard
            finally:archive.close()
        # The actual outer handler owner and native scratch are supplied by the
        # signed producer in production; this parser test owns only the ZIP.
        self.patch(ios,'first_primary_context',new=archive_context)
        self.patch(ios,'_native_scratch',return_value=nullcontext((temporary,f.guard)))
        self.patch(ios,'_profile_details',return_value=profile)
        self.patch(ios,'_profile_certificate_fingerprints',return_value={observed['certificateSha256']})
        self.patch(ios,'_codesign_entitlements',return_value=entitlements)
        self.patch(ios,'_codesign_fingerprint',return_value=observed['certificateSha256'])
        nested=self.patch(ios,'_nested_codesign_identities',return_value=[])
        return f,snapshot,profile,observed,nested

    def validate(self,f,snapshot):
        return ios.validate_ipa(f.ipa,expected_bundle_id=f.bound.saved.configuration.bundle_id,
            expected_team_id=f.run.request.context['signing']['teamId'],expected_fingerprint=f.run.request.context['signing']['distributionCertificateSha256'],
            release=f.bound.saved.release,require_tools=True,deadline=snapshot.deadline,cancellation=f.guard)

    def test_real_validation_deposits_once_then_original_snapshot_joins(self):
        f,snapshot,profile,facts,_=self.fixture();op=f.op
        op._candidate_begin_ipa_validation(snapshot)
        findings=self.validate(f,snapshot)
        self.assertTrue(all(v.status is Status.PASS for v in findings),findings)
        record=f.owner.composition.signing_record
        self.assertIs(record[0],op._ipa);self.assertEqual(json.loads(record[3]),facts)
        op.inspection_observed(snapshot);self.assertEqual(op._ipa.inventory,record[2])
        with self.assertRaises(ProtocolError):op._candidate_validated_ipa(f.ipa,f.guard,snapshot.deadline,facts)
        self.assertIs(f.owner.composition.signing_record,record)
        f.owner.close();f.adapter.close()

    def test_bad_profile_nested_identity_and_foreign_borrow_deposit_nothing(self):
        for i,kind in enumerate(('profile','nested','unarmed','foreign')):
            if i:self.doCleanups();self.setUp()
            with self.subTest(kind=kind):
                f,snapshot,profile,facts,nested=self.fixture();op=f.op
                if kind!='unarmed':op._candidate_begin_ipa_validation(snapshot)
                if kind=='profile':profile.pop('UUID')
                if kind=='nested':nested.return_value=[(Path('inert-nested'),'XXXXXXXXXX','a'*64)]
                if kind=='foreign':
                    with self.assertRaises(ProtocolError):op._candidate_validated_ipa(f.ipa,object(),snapshot.deadline,facts)
                elif kind=='unarmed':
                    with self.assertRaises(ProtocolError):self.validate(f,snapshot)
                else:
                    findings=self.validate(f,snapshot)
                    self.assertTrue(any(v.status is Status.FAIL for v in findings))
                self.assertIsNone(f.owner.composition.signing_record)
                with self.assertRaises(ProtocolError):op.inspection_observed(snapshot)
                f.owner.close();f.adapter.close()
        for key in ('profileUuid','profileExpiresAt','certificateSha256','kind'):
            bad={**facts,key:'invalid'}
            with self.assertRaises(ValidationError):signing_data(bad)

if __name__=='__main__':unittest.main()
