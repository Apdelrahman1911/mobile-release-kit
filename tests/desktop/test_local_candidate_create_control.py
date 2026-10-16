"""Real input/lease/phase IO; build and native parent replies are inert."""
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from mobile_release._desktop_android_build_engine import _Engine
from mobile_release._desktop_android_build_control import AndroidBuildInput
from mobile_release.desktop_android_build import AndroidBuildRun
from mobile_release.local_candidate_create import CandidateCreateRun
from mobile_release._desktop_candidate_input_control import CandidateCreateInput
from mobile_release.cancellation import CleanupScope
from mobile_release import _desktop_local_history_protocol as history
import test_local_candidate_create_protocol as data
from test_local_release_history import ENROLLMENT,KEY

class CandidateInputControlTests(unittest.TestCase):
    def subject(self,*,bad=False):
        self.assertNotEqual(os.getuid(),0)
        with tempfile.TemporaryDirectory(dir=Path.home()) as tmp:
            root=Path(tmp)/'project';root.mkdir(mode=0o700)
            parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY);fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
            loan=os.dup(parent);os.set_inheritable(loan,True)
            v=root.stat();r=data.request_data();now=time.monotonic_ns()
            r['native'].update(projectRoot=str(root),rootIdentity=dict(device=str(v.st_dev),inode=str(v.st_ino),mode=v.st_mode,uid=v.st_uid,gid=v.st_gid))
            r['native']['candidateHistory'].update(home=tmp,leaseFd=loan,clock=dict(workEndNs=str(now+100_000_000_000),hardEndNs=str(now+110_000_000_000)))
            old=[os.dup(n) for n in (0,1,2)];ir,iw=os.pipe();out,ow=os.pipe();err,ew=os.pipe()
            os.dup2(ir,0);os.dup2(ow,1);os.dup2(ew,2)
            for fd in (ir,ow,ew):os.close(fd)
            os.write(iw,data.old.encoded(r));events=[];keys=[];original=_Engine.write
            queued=b'ORIGINAL_SIGNING_MATERIAL_NOT_A_PHASE\n'
            def write(engine,raw,**kw):
                original(engine,raw,**kw);row=json.loads(raw)
                kind=row['kind']
                if kind not in data.C.PHASES:return
                events.append(kind)
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(fd)
                n=engine.input.candidate_input.reply_step
                reply=dict(protocol=data.wire.CANDIDATE_PROTOCOL,operationId=engine.request.operation_id,
                    ownerGeneration=engine.request.owner_generation,nonce='e'*32 if bad else r['native']['candidateHistory']['nonce'],
                    requestSha256=engine.request.digest,kind='key-material' if n==1 else 'checkpoint-settled',step=n,
                    payload=ENROLLMENT if n==1 else {})
                body=data.old.encoded(reply)
                if n==1:body+=history.KEY_PREFIX+KEY+history.KEY_SUFFIX
                if n==3:body+=queued
                os.write(iw,body)
            def run(service):
                engine=service.source._engine
                engine._progress(service.source,'inputs-bound')
                owner=engine.candidate
                enrollment,key=owner.input.exchange('lease-ready',{})
                self.assertEqual(enrollment,ENROLLMENT);self.assertEqual(key,KEY);keys.append(key)
                key[:]=b'\0'*len(key)
                for n,kind in enumerate(('history-head','inputs-pending'),1):owner.input.exchange(kind,dict(sequence=n,sha256='a'*64))
                self.assertEqual(service.source.buffer,bytearray())
                self.assertEqual(os.read(service.source.fd,len(queued)),queued)
                self.assertTrue(service.source.material_pending)
            engine=_Engine(time.monotonic());error=None
            scope=CleanupScope(engine.guard,engine.cleanup,owns_cancellation=True,first_primary=True)
            try:
                with patch.object(time,'CLOCK_UPTIME_RAW',time.CLOCK_MONOTONIC,create=True),patch.object(_Engine,'write',write),patch.object(AndroidBuildRun,'run',run),patch.object(CandidateCreateRun,'finish_build',return_value=None),patch.object(subprocess,'Popen',side_effect=AssertionError('no native')):
                    try:
                        with scope:engine.run()
                    except BaseException as e:error=e
                    finally:scope.__exit__(None,None,None)
                    engine.close_output()
            finally:
                for n,fd in enumerate(old):os.dup2(fd,n);os.close(fd)
                os.close(iw)
            output=b''
            while True:
                chunk=os.read(out,65536)
                if not chunk:break
                output+=chunk
            os.close(out);self.assertEqual(os.read(err,65536),b'');os.close(err)
            self.assertTrue(engine.input.closed and engine.input.candidate_input.closed)
            self.assertTrue(engine.candidate.originals_closed())
            self.assertEqual(engine.guard.handler_state,'RESTORED')
            with self.assertRaises(OSError):os.fstat(loan)
            os.close(parent)
            if bad:self.assertIsNotNone(error);self.assertEqual(events,['lease-ready'])
            else:self.assertIsNone(error,repr(error));self.assertEqual(events,list(data.C.PHASES[:3]));self.assertEqual(keys,[bytearray(32)])
            return engine,output
    def test_original_lease_and_phase_reader_leave_original_signing_segment_untouched(self):self.subject()
    def test_wrong_nonce_positive_input_lease_closes_without_journal_or_build(self):self.subject(bad=True)

if __name__=='__main__':unittest.main()
