"""Closed wire DATA only; no native calls, journal or original-FD evidence."""
import copy
import hashlib
import unittest
import test_android_build_protocol as old
from mobile_release import _desktop_android_build_protocol as wire
from mobile_release import local_candidate_create_protocol as C

OP='33333333333343338333333333333333'
def request_data():
    data=old.signed_request_data();data['protocol']=wire.CANDIDATE_PROTOCOL;data['operationId']=OP
    data['context'].update(operation='android-candidate-inputs',action='create')
    data['native']['candidateHistory']=dict(home='/Users/inert',leaseFd=7,nonce='c'*32,
        clock=dict(workEndNs='3000000000000',hardEndNs='3010000000000'))
    return data

def complete(request):
    report=old.report([(key,old.Status.PASS) for key in ('android.aab.structure','android.aab.manifest','android.aab.signature','android.aab.signer')])
    value=old.complete(request,report);build=value['result']
    value['lifetime'].update(commands=14,buildInputsClosed=True,materialRetired=True,**dict.fromkeys(C.CLOSES,True))
    value['result']=dict(schemaVersion=1,scope='local-android-candidate-inputs',headSequence=3,build=build,
        candidateInputs=dict(operationId='33333333-3333-4333-8333-333333333333',candidateSha256='a'*64,
            sourceCommit='b'*40,sourceTree='c'*40,applicationId=build['selection']['applicationId'],
            version={k:build['usedVersion'][k] for k in ('name','build')},
            files=[dict(fileName=name,bytes=build['artifacts'][0]['size'] if index==0 else 17,
                        sha256=build['artifacts'][0]['sha256'] if index==0 else 'd'*64)
                   for index,(name,_) in enumerate(C.FILES)],observation='current-bundle-only',priorCreateFinality='not-established'))
    return value

class CandidateCreateProtocolTests(unittest.TestCase):
    def test_exact_new_request_and_ordinary_signed_six_unchanged(self):
        raw=old.encoded(request_data());r=wire.parse_request(raw)
        self.assertEqual(r.digest,hashlib.sha256(raw).hexdigest());self.assertEqual(wire.maximum_frames(r.context),14)
        for change in (lambda d:d.update(protocol=wire.PROTOCOL),lambda d:d.update(operationId='a'*32),
                       lambda d:d['context'].update(action='review-inputs'),lambda d:d['native'].pop('candidateHistory'),
                       lambda d:d['native']['candidateHistory']['clock'].update(workEndNs='1'*4096),
                       lambda d:d['native']['candidateHistory'].update(leaseFd=True)):
            d=request_data();change(d)
            with self.subTest(change=change),self.assertRaises(ValueError):wire.parse_request(old.encoded(d))
        old_r=wire.parse_request(old.encoded(old.signed_request_data()))
        self.assertEqual((old_r.digest,wire.maximum_frames(old_r.context)),('',10))
        with self.assertRaises(wire.ProtocolError):wire.validate_terminal(complete(r),r)
    def test_full_four_phase_fourteen_frame_sequence_and_exact_result(self):
        r=wire.parse_request(old.encoded(request_data()));frames=wire.AndroidBuildFrames(r);rows=[]
        def emit(k,p):rows.append(frames.response(k,p))
        emit('accepted',dict(schemaVersion=1,context=r.context));emit('progress',dict(schemaVersion=1,stage='inputs-bound'))
        emit('lease-ready',{})
        for index,kind in enumerate(('history-head','inputs-pending'),1):emit(kind,dict(sequence=index,sha256=str(index)*64))
        for stage in wire.SIGNED_STAGES[1:]:emit('progress',dict(schemaVersion=1,stage=stage))
        emit('inputs-ready',dict(sequence=3,sha256='3'*64));emit('terminal',complete(r))
        self.assertEqual(len(rows),14);self.assertLess(sum(map(len,rows)),65536)
        for mutation in (lambda v:v['result']['build']['usedVersion'].update(build=99),
                         lambda v:v['result']['candidateInputs']['files'].reverse(),
                         lambda v:v['lifetime'].update(commands=6),
                         lambda v:v['lifetime'].update(leaseClosed=False),
                         lambda v:v['disposition'].update(artifacts='retained-incomplete')):
            v=complete(r);mutation(v)
            with self.subTest(mutation=mutation),self.assertRaises(wire.ProtocolError):C.terminal(v,r)
    def test_no_replayed_reply_or_early_build_and_ready_phase(self):
        r=wire.parse_request(old.encoded(request_data()))
        value=dict(protocol=wire.CANDIDATE_PROTOCOL,operationId=r.operation_id,ownerGeneration=r.owner_generation,
            nonce=r.native['candidateHistory']['nonce'],requestSha256=r.digest,kind='checkpoint-settled',step=3,payload={})
        self.assertIsNone(C.reply(old.encoded(value),r,'checkpoint-settled',3))
        for key,bad in (('nonce','e'*32),('requestSha256','f'*64),('step',True),('step',2),('payload',{'ignored':True})):
            with self.subTest(key=key),self.assertRaises(ValueError):C.reply(old.encoded({**value,key:bad}),r,'checkpoint-settled',3)
        f=wire.AndroidBuildFrames(r);f.response('accepted',dict(schemaVersion=1,context=r.context))
        f.response('progress',dict(schemaVersion=1,stage='inputs-bound'))
        with self.assertRaises(wire.ProtocolError):f.response('progress',dict(schemaVersion=1,stage='building'))
        f=wire.AndroidBuildFrames(r);f.response('accepted',dict(schemaVersion=1,context=r.context))
        f.response('progress',dict(schemaVersion=1,stage='inputs-bound'))
        f.response('lease-ready',{});f.response('history-head',dict(sequence=511,sha256='a'*64))
        with self.assertRaises(wire.ProtocolError):f.response('inputs-pending',dict(sequence=511,sha256='a'*64))
    def test_negative_terminals_retain_stop_and_build_failure_consistency(self):
        r=wire.parse_request(old.encoded(request_data()))
        def failure(reason, *, stop='none', command=None, stage='building', work='removed'):
            v=complete(r);v.update(outcome='failed',reason=reason,result=None)
            v['activity']=wire.project_activity(None,stage=stage,selection=old.selection(),
                command=command or dict(outcome='not-dispatched',exitCode=None))
            v['disposition']=dict(work=work,artifacts='retained-incomplete')
            v['lifetime'].update(commands=8,stopObserved=stop)
            return v
        exited=dict(outcome='exited',exitCode=0)
        for reason in ('cancelled','context-changed','document-lost','shutdown','timed-out'):
            valid=failure(reason,stop='timed-out' if reason=='timed-out' else 'cancelled')
            C.terminal(valid,r)
            for stop in ('none','cancelled' if reason=='timed-out' else 'timed-out'):
                bad=copy.deepcopy(valid);bad['lifetime']['stopObserved']=stop
                with self.subTest(reason=reason,stop=stop),self.assertRaises(wire.ProtocolError):C.terminal(bad,r)
        positives=[failure('command-failed',command=dict(outcome='exited',exitCode=7)),
            failure('command-incomplete'),failure('work-retained',work='retained-work')]
        positives.extend(failure(reason,command=exited,stage='capturing') for reason in
            ('artifact-missing','artifact-ambiguous','artifact-unsafe','artifact-changed'))
        for value in positives:
            with self.subTest(valid=value['reason']):C.terminal(value,r)
        invalid=[failure('command-failed',command=exited),failure('command-failed'),
            failure('command-incomplete',command=exited),failure('work-retained')]
        for reason in ('artifact-missing','artifact-ambiguous','artifact-unsafe','artifact-changed'):
            invalid.extend((failure(reason,command=exited,stage='building'),
                            failure(reason,command=dict(outcome='exited',exitCode=2))))
        for value in invalid:
            with self.subTest(invalid=value['reason'],activity=value['activity']),self.assertRaises(wire.ProtocolError):C.terminal(value,r)
        cancelled=failure('cancelled',stop='cancelled',work='retained-work');cancelled['outcome']='cancelled'
        with self.assertRaises(wire.ProtocolError):C.terminal(cancelled,r)

    def test_source_only_failure_keeps_real_ledger_without_ordinary_six_subtraction(self):
        r=wire.parse_request(old.encoded(request_data()));v=complete(r)
        v.update(outcome='refused',reason='protocol-error',result=None)
        v['activity']=wire.project_activity(None,stage='inputs-bound',selection=old.selection(),command=dict(outcome='not-dispatched',exitCode=None))
        v['disposition']=dict(work='not-created',artifacts='not-created');v['lifetime']['commands']=1
        C.terminal(v,r)
        v['lifetime']['commands']=18;C.terminal(v,r)
        v['lifetime']['commands']=19
        with self.assertRaises(wire.ProtocolError):C.terminal(v,r)
        v['lifetime'].update(commands=1,journalClosed=False)
        with self.assertRaises(wire.ProtocolError):C.terminal(v,r)
        v.update(outcome='unknown',reason='cleanup-unknown');C.terminal(v,r)
        v.update(reason='journal-unavailable')
        with self.assertRaises(wire.ProtocolError):C.terminal(v,r)

if __name__=='__main__':unittest.main()
