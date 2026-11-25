"""Real closed candidate codec; DATA only, no native/signing or Store calls."""
import copy
import hashlib
import unittest
from uuid import UUID
import test_ios_archive as old
import test_ios_signed as signed
from mobile_release import _desktop_ios_archive_protocol as wire
from mobile_release import local_ios_candidate_protocol as C
from mobile_release.local_ios_candidate_bundle import CandidateBundleError, summary_data

OP='33333333333343338333333333333333'
def request_data():
    r=signed.signed_request()
    return dict(protocol=wire.CANDIDATE_PROTOCOL,operationId=OP,ownerGeneration=r.owner_generation,
        context={**r.context,'operation':'ios-candidate-inputs','action':'create'},native={**r.native,
            'candidateHistory':dict(home='/Users/inert',leaseFd=7,nonce='c'*32,clock=dict(
                workEndNs='5400000000000',cleanupEndNs='5520000000000',hardEndNs='5530000000000'))})
def request():return wire.parse_request(old.encode(request_data())+b'\n')
def complete(r):
    value=old.complete_terminal(r)
    directory=f'.mobile-release/desktop-ios-archive/{r.operation_id}'
    value['activity']['commands']={role:dict(outcome='not-configured' if role=='prepare' else 'exited',
        exitCode=None if role=='prepare' else 0) for role in wire.SIGNED_ROLES}
    value['activity']['findings']=[dict(check=k,status='PASS') for k in ('signing-material','profile-material',
        'artifact-correspondence','ipa-structure','ipa-profile','ipa-entitlements','ipa-signer')]
    value['disposition']['relativeDirectory']=directory
    build=value['result']; build.update(scope=wire.SIGNED_SCOPE,archive=directory+'/archive.xcarchive',
        ipa=directory+'/export/Inert.ipa',ipaBytes=123,pairing=dict(nativePaths=1,nativeIdentities=1,presentSymbolSlices=0),
        limitations=list(wire.SIGNED_LIMITATIONS))
    value['lifetime'].update(commands=8+len(wire.SIGNED_ROLES)-1,profileCalls=3,sourceCommands=8,
        **dict.fromkeys((*wire.SIGNED_CLOSE_FIELDS,*C.CLOSES),True))
    value['result']=dict(schemaVersion=1,scope=C.SCOPE,headSequence=3,build=build,candidateInputs=dict(
        operationId=str(UUID(hex=OP)),candidateSha256='a'*64,sourceCommit='b'*40,sourceTree='c'*40,
        bundleId='org.example.inert',version=dict(name='1.2.3',build=7),
        archive=dict(directory='archive.xcarchive',entries=10,bytes=1000,sha256='d'*64),
        files=[dict(fileName=name,bytes=123 if i==0 else 17,sha256='e'*64) for i,name in enumerate(
            ('export/Inert.ipa','store-metadata.zip','validation-report.json'))],
        observation='current-bundle-only',priorCreateFinality='not-established'))
    return value

class IOSCandidateProtocolTests(unittest.TestCase):
    def test_exact_request_three_original_endpoints_and_ordinary_signed_unchanged(self):
        raw=old.encode(request_data())+b'\n';r=wire.parse_request(raw)
        self.assertEqual(r.digest,hashlib.sha256(raw).hexdigest());self.assertEqual(signed.signed_request().digest,'')
        for change in (lambda d:d.update(protocol=wire.SIGNED_PROTOCOL),lambda d:d.update(operationId='a'*32),
            lambda d:d['context'].pop('action'),lambda d:d['context'].update(action='review-inputs'),
            lambda d:d['native'].pop('candidateHistory'),lambda d:d['native']['candidateHistory'].update(leaseFd=True),
            lambda d:d['native']['candidateHistory']['clock'].update(cleanupEndNs='5530000000000'),
            lambda d:d['native']['candidateHistory']['clock'].update(workEndNs='1'*1000)):
            d=request_data();change(d)
            with self.subTest(change=change),self.assertRaises(ValueError):wire.parse_request(old.encode(d)+b'\n')
        ordinary=complete(r);ordinary['context']=signed.signed_request().context
        with self.assertRaises(wire.ProtocolError):wire.validate_terminal(ordinary,signed.signed_request())
    def test_four_phases_seventeen_frames_bind_current_archive_and_ipa(self):
        r=request();f=wire.IOSArchiveFrames(r);rows=[]
        def emit(kind,value):rows.append(f.response(kind,value))
        emit('accepted',dict(schemaVersion=1,context=r.context));emit('progress',dict(schemaVersion=1,stage=wire.SIGNED_STAGES[0]))
        emit('lease-ready',{});emit('history-head',dict(sequence=1,sha256='1'*64))
        emit('inputs-pending',dict(sequence=2,sha256='2'*64))
        for stage in wire.SIGNED_STAGES[1:]:emit('progress',dict(schemaVersion=1,stage=stage))
        emit('inputs-ready',dict(sequence=3,sha256='3'*64));emit('terminal',complete(r))
        self.assertEqual(len(rows),17);self.assertLess(sum(map(len,rows)),65536)
        for change in (lambda d:d['lifetime'].update(sourceCommands=7),lambda d:d['lifetime'].update(commands=8),
            lambda d:d['result']['candidateInputs']['archive'].update(bytes=999),
            lambda d:d['result']['candidateInputs']['files'][0].update(bytes=999),
            lambda d:d['result']['candidateInputs'].update(operationId='44444444-4444-4444-8444-444444444444'),
            lambda d:d['result']['candidateInputs'].update(bundleId='org.other.inert'),
            lambda d:d['lifetime'].update(leaseClosed=False)):
            d=complete(r);change(d)
            with self.subTest(change=change),self.assertRaises(ValueError):C.terminal(d,r)
    def test_reply_and_phase_cannot_skip_pending_before_material_or_replay(self):
        r=request();value=dict(protocol=wire.CANDIDATE_PROTOCOL,operationId=OP,ownerGeneration=r.owner_generation,
            nonce=r.native['candidateHistory']['nonce'],requestSha256=r.digest,kind='checkpoint-settled',step=3,payload={})
        self.assertIsNone(C.reply(old.encode(value)+b'\n',r,'checkpoint-settled',3))
        for k,v in (('nonce','d'*32),('requestSha256','e'*64),('step',2),('step',True),('payload',{'extra':1})):
            with self.subTest(key=k),self.assertRaises(ValueError):C.reply(old.encode({**value,k:v})+b'\n',r,'checkpoint-settled',3)
        f=wire.IOSArchiveFrames(r);f.response('accepted',dict(schemaVersion=1,context=r.context))
        f.response('progress',dict(schemaVersion=1,stage=wire.SIGNED_STAGES[0]))
        with self.assertRaises(ValueError):f.response('progress',dict(schemaVersion=1,stage=wire.SIGNED_STAGES[1]))
        with self.assertRaises(ValueError):f.response('lease-ready',{})
    def test_failure_counts_actual_source_not_assumed_eight_and_unknown_close(self):
        r=request();v=complete(r);v.update(outcome='failed',reason='candidate-inputs-unavailable',result=None)
        v['activity'].update(stage='inputs-bound',findings=[],commands={role:dict(outcome='not-dispatched',exitCode=None) for role in wire.SIGNED_ROLES})
        v['disposition']=dict(snapshot='not-created',work='not-created',output='not-created',relativeDirectory=None)
        v['lifetime'].update(commands=1,sourceCommands=1,profileCalls=0)
        C.terminal(v,r)
        v['lifetime'].update(sourceCommands=2)
        with self.assertRaises(ValueError):C.terminal(v,r)
        v['lifetime'].update(sourceCommands=1,journalClosed=False)
        with self.assertRaises(ValueError):C.terminal(v,r)
        v.update(outcome='unknown',reason='cleanup-unknown');C.terminal(v,r)
        v['lifetime']['stopObserved']='cancelled';C.terminal(v,r)
    def test_summary_uses_real_saved_ios_identity_policy(self):
        summary=complete(request())['result']['candidateInputs'];summary_data(summary)
        for bundle in ('123.example','org','org..example','org.example.','org.1example','a.'+'b'*254):
            with self.subTest(bundle=bundle),self.assertRaises(CandidateBundleError):summary_data({**summary,'bundleId':bundle})

if __name__=='__main__':unittest.main()
