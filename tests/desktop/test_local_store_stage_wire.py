"""Explicit later-stage DATA/private frame; no native Document or Store grant."""
import copy
from pathlib import Path
import tempfile
import unittest
from uuid import UUID
from mobile_release import _desktop_store_prepare_protocol as P, _desktop_store_execute_protocol as E
from mobile_release._desktop_store_preflight_control import parse_header
from mobile_release.local_release_journal import canonical
from unit.test_desktop_store_preflight import request
from unit.helpers import android_config, write_project
from test_local_store_stages import CANDIDATE, EXTERNAL, PRODUCTION, documents

class LocalStoreStageWireTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=Path.home());self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)/'project';write_project(root,android_config())
        self.base=request(root,Path(self.tmp.name)/'runtime')
        self.base['native'].update(home=str(Path(self.tmp.name)),leaseFd=3,nonce='e'*32,
            clock=dict(workEndNs='1200000000000',hardEndNs='1210000000000'),
            authorizationId='66666666-6666-4666-8666-666666666666',tooling=dict(version='0.3.0',commit='a'*40))
    def value(self,platform,stage,execute=False):
        v=copy.deepcopy(self.base);v['protocol']=E.PROTOCOL if execute else P.PROTOCOL
        v['operationId']=UUID(EXTERNAL if stage=='external-testing' else PRODUCTION).hex
        c=v['context'];c.update(operation='local-store-execute' if execute else 'local-store-prepare',platform=platform,
            candidateOperationId=CANDIDATE,candidateSha256='b'*64,stage=stage,
            predecessorOperationId=CANDIDATE if stage=='external-testing' else EXTERNAL,predecessorReceiptSha256='c'*64,
            confirmation=f'{stage}:{platform}:1.2.3:42')
        if platform=='ios':c['supplementalAssignments']=dict(reviewContact=dict(recordId='d'*32,recordRevision=1),
            commitment=dict(recordId='e'*32,recordRevision=2),reviewDemo=None)
        if execute:c.update(stageOperationId=EXTERNAL if stage=='external-testing' else PRODUCTION,intentSha256='d'*64)
        return v
    def test_explicit_stage_prepare_outer_uuid_and_execute_no_tools_both_platforms(self):
        for platform in ('android','ios'):
            for stage in P.STAGES:
                v=self.value(platform,stage);r=P.parse_request(canonical(v)+b"\n")
                self.assertEqual(P.stage_operation_id(r),EXTERNAL if stage=='external-testing' else PRODUCTION)
                self.assertNotIn('stageOperationId',r.context)
                x=self.value(platform,stage,True);self.assertEqual(E.parse_request(canonical(x)+b"\n").context,x['context'])
                for key in ('toolchain','signingTools','uploadSelection'):
                    bad=copy.deepcopy(x);bad['native'][key]={}
                    with self.assertRaises(P.ProtocolError):E.parse_request(canonical(bad)+b"\n")
                bad=copy.deepcopy(x);bad['context']['toolchainSelection']={}
                with self.assertRaises(P.ProtocolError):E.parse_request(canonical(bad)+b"\n")
    def test_prepare_cannot_import_stage_uuid_or_non_uuid_owner_or_foreign_lineage(self):
        value=self.value('android','external-testing')
        for mutate in (lambda v:v['context'].update(stageOperationId=EXTERNAL),lambda v:v.update(operationId='a'*32),
            lambda v:v.update(operationId=UUID(CANDIDATE).hex),lambda v:v['context'].update(stage='candidate'),
            lambda v:v['context'].update(predecessorOperationId=PRODUCTION),lambda v:v['context'].update(confirmation='candidate:android:1.2.3:42')):
            bad=copy.deepcopy(value);mutate(bad)
            with self.assertRaises(P.ProtocolError):P.parse_request(canonical(bad)+b"\n")
        for mutate in (lambda v:v['context'].pop('stageOperationId'),lambda v:v['context'].update(stageOperationId=CANDIDATE)):
            bad=self.value('ios','external-testing',True);mutate(bad)
            with self.assertRaises(P.ProtocolError):E.parse_request(canonical(bad)+b"\n")
    def test_private_supplemental_exact_order_bounds_and_no_ordinary_expansion(self):
        roles=[('asc-p8',16384),('asc-key-id',10),('asc-issuer-id',36),
            ('contact-first-name',4096),('contact-last-name',4096),('contact-email',4096),('contact-phone',4096),
            ('commitment-key-base64',44),('commitment-version',64),('demo-username',4096),('demo-password',4096)]
        def raw(rows):return canonical(dict(schemaVersion=1,files=[dict(role=k,bytes=n) for k,n in rows]))+b'\n'
        self.assertEqual(sum(parse_header(raw(roles),platform='ios',stage='external-testing',review_demo=True)),41114)
        self.assertEqual(len(parse_header(raw(roles[:9]),platform='ios',stage='production-submit')),9)
        self.assertEqual(len(parse_header(raw(roles[:3]),platform='ios')),3)
        for rows,kwargs in ((roles,{}),(roles[:9],dict(review_demo=True)),(roles[:3],dict(stage='production-submit')),
            (roles[::-1],dict(stage='external-testing',review_demo=True)),(roles[:7]+[('commitment-key-base64',43)]+roles[8:],dict(stage='external-testing',review_demo=True)),
            (roles[:3]+[('contact-first-name',4097)]+roles[4:],dict(stage='external-testing',review_demo=True))):
            with self.assertRaises(ValueError):parse_header(raw(rows),platform='ios',**kwargs)
        with self.assertRaises(ValueError):parse_header(raw(roles),platform='android',stage='external-testing',review_demo=True)
    def test_supplemental_assignment_is_explicit_ios_only_and_unique(self):
        v=self.value('ios','external-testing')
        for mutate in (lambda c:c.pop('supplementalAssignments'),lambda c:c['supplementalAssignments']['commitment'].update(recordId='d'*32),
            lambda c:c['supplementalAssignments']['reviewContact'].update(recordRevision=True),lambda c:c['supplementalAssignments'].update(extra=None)):
            bad=copy.deepcopy(v);mutate(bad['context'])
            with self.assertRaises(P.ProtocolError):P.parse_request(canonical(bad)+b"\n")
        bad=self.value('android','external-testing');bad['context']['supplementalAssignments']=v['context']['supplementalAssignments']
        with self.assertRaises(P.ProtocolError):P.parse_request(canonical(bad)+b"\n")
    def test_exact_stage_summaries_cannot_enter_candidate_or_claim_reconciled(self):
        for platform in ('android','ios'):
            for selected in P.STAGES:
                i,a,r=documents(platform,selected);identity='bundleId' if platform=='ios' else 'applicationId'
                common=dict(operationId=i['operationId'],candidateSha256=i['candidateSha256'],intentSha256=i['integrity']['sha256'],
                    sourceCommit=i['operationSource']['commit'],sourceTree=i['operationSource']['tree'],
                    version=dict(name='1.2.3',build=42),destination=i['destination'],observedAt=r['observedAt'],stage=selected,
                    candidateOperationId=i['candidateOperationId'],predecessorOperationId=i['candidateOperationId'] if selected=='external-testing' else EXTERNAL,
                    predecessorReceiptSha256='a'*64)
                common[identity]=i['application']['id']
                if platform=='ios':common['appStoreAppId']=i['application']['storeAppId']
                p=dict(schemaVersion=1,scope=f'local-{platform}-store-stage-prepare',headSequence=9 if selected=='external-testing' else 13,
                    preparedIntent=dict(common,storePreconditionSha256='b'*64,limitations=P.STAGE_LIMITATIONS))
                e=dict(schemaVersion=1,scope=f'local-{platform}-store-stage-execute',headSequence=11 if selected=='external-testing' else 15,
                    executionReceipt=dict(common,receiptSha256='c'*64,authorizationId=a['authorizationId'],result='accepted',state=r['state'],limitations=E.STAGE_LIMITATIONS))
                P.validate_result(p,platform=platform,selected=selected);E.validate_result(e,platform=platform,selected=selected)
                for parser,value in ((P.validate_result,p),(E.validate_result,e)):
                    with self.assertRaises(P.ProtocolError):parser(value,platform=platform)
                    bad=copy.deepcopy(value);bad['headSequence']-=1
                    with self.assertRaises(P.ProtocolError):parser(bad,platform=platform,selected=selected)
                for change in (dict(result='reconciled'),dict(state='processed'),dict(candidateOperationId=i['operationId'])):
                    bad=copy.deepcopy(e);bad['executionReceipt'].update(change)
                    with self.assertRaises(P.ProtocolError):E.validate_result(bad,platform=platform,selected=selected)
