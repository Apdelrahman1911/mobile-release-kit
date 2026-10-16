"""Original core/IO/journal lifetimes. Only the native parent reply is inert."""
from contextlib import ExitStack
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from mobile_release import _desktop_local_history_protocol as wire
from mobile_release._desktop_local_history_engine import _Engine
from mobile_release._desktop_local_history_control import LocalHistoryInput
from mobile_release._desktop_saved_command_engine import run_engine
from mobile_release.local_release_journal import LocalReleaseJournal

ENROLLMENT=dict(projectLocator='a'*64,projectBinding='b'*64,
    projectId='11111111-1111-4111-8111-111111111111',keyId='22222222-2222-4222-8222-222222222222',keyRevision=1)
KEY=b'K'*32

def encode(value):return json.dumps(value,separators=(',',':')).encode()+b'\n'

class LocalHistoryTests(unittest.TestCase):
    def setUp(self):
        self.assertNotEqual(os.geteuid(),0)
        self.tmp=tempfile.TemporaryDirectory(dir=Path.home())
        self.base=Path(self.tmp.name)
        self.root=self.base/'project';self.root.mkdir(mode=0o700)
        self.home=self.base/'account';self.home.mkdir(mode=0o700)
    def tearDown(self):self.tmp.cleanup()
    def request(self,fd,action):
        r=self.root.stat(); now=time.monotonic_ns()
        return dict(protocol=wire.PROTOCOL,operationId='o'*32,ownerGeneration='g'*32,
            context=dict(projectId='registered-project',executionMode='local',action=action),
            native=dict(profile='macos-arm64',projectRoot=str(self.root),home=str(self.home),cwd=str(self.base),
                rootIdentity=dict(device=str(r.st_dev),inode=str(r.st_ino),mode=r.st_mode,uid=r.st_uid,gid=r.st_gid),
                leaseFd=fd,nonce='1'*32,clock=dict(workEndNs=str(now+60_000_000_000),hardEndNs=str(now+62_000_000_000))))
    def run_original(self,action='enroll',fault=None):
        parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        fcntl.flock(parent,fcntl.LOCK_EX|fcntl.LOCK_NB)
        loan=os.dup(parent);os.set_inheritable(loan,True)
        old=[os.dup(n) for n in (0,1,2)]
        input_r,input_w=os.pipe();output_r,output_w=os.pipe();error_r,error_w=os.pipe()
        os.dup2(input_r,0);os.dup2(output_w,1);os.dup2(error_w,2)
        for fd in (input_r,output_w,error_w):os.close(fd)
        request=self.request(loan,action)
        os.write(input_w,encode(request))
        events=[]; original=_Engine.local_event; input_live=[True]
        def parent_reply(engine,kind,payload):
            original(engine,kind,payload);events.append((kind,copy.deepcopy(payload)))
            independent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(independent,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(independent)
            expected={'lease-ready':'key-material','empty-journal-ready':'key-enrolled','durable-genesis':'checkpoint-settled','history-head':'checkpoint-settled'}[kind]
            value=dict(protocol=wire.PROTOCOL,operationId=engine.request.operation_id,ownerGeneration=engine.request.owner_generation,
                nonce=engine.request.native['nonce'],requestSha256=engine.request.digest,kind=expected,
                step=engine.input.reply_step,payload=ENROLLMENT if expected=='key-material' else {})
            if fault=='nonce' and kind=='lease-ready':value['nonce']='2'*32
            if fault=='head-stop' and kind=='durable-genesis':os.close(input_w);input_live[0]=False;return
            body=encode(value)
            if expected=='key-material':body+=wire.KEY_PREFIX+KEY+wire.KEY_SUFFIX
            if fault=='key-suffix' and expected=='key-material':body=body[:-2]+b'!\n'
            os.write(input_w,body)
        taken=[];original_take=LocalHistoryInput._take
        def take(original,count):
            value=original_take(original,count)
            if count==32:taken.append(value)
            return value
        engine=_Engine(time.monotonic())
        try:
            with patch.object(time,'CLOCK_UPTIME_RAW',time.CLOCK_MONOTONIC,create=True),patch.object(_Engine,'local_event',parent_reply),patch.object(subprocess,'Popen',side_effect=AssertionError('no tools')),patch.object(LocalHistoryInput,'_take',take):
                code=run_engine(engine)
        finally:
            for n,fd in enumerate(old):os.dup2(fd,n);os.close(fd)
            if input_live[0]:os.close(input_w)
        output=b''
        while True:
            data=os.read(output_r,32768)
            if not data:break
            output+=data
        error=os.read(error_r,32768)
        os.close(output_r);os.close(error_r)
        os.close(parent)
        # Actual inherited close, not a projected closed boolean.
        with self.assertRaises(OSError):os.fstat(loan)
        self.assertEqual(error,b'')
        self.assertEqual(code,0,(engine.primary,output))
        rows=[json.loads(row) for row in output.splitlines()]
        self.assertEqual([r['sequence'] for r in rows],list(range(len(rows))))
        self.assertEqual(rows[0]['kind'],'accepted')
        self.assertEqual(rows[-1]['kind'],'terminal')
        self.assertTrue(engine.service.closed())
        self.assertTrue(engine.input.closed and engine.input.lease_closed)
        self.assertEqual(engine.input.buffer,bytearray())
        if fault=='key-suffix':self.assertEqual(taken,[bytearray(32)])
        return rows[-1]['payload'],events,engine
    def test_real_enroll_verify_and_finite_history(self):
        enrolled,events,_=self.run_original()
        self.assertEqual(enrolled['outcome'],'complete')
        self.assertEqual([e[0] for e in events],['lease-ready','empty-journal-ready','durable-genesis'])
        self.assertEqual(enrolled['result']['history'],[])
        j=LocalReleaseJournal(str(self.home),end=time.monotonic()+10,enrollment=ENROLLMENT,key=KEY)
        j.open_existing()
        j._append(expected_head=j.head(),operation_id='33333333-3333-4333-8333-333333333333',phase='inputs-pending',
            payload=dict(sourceCommit='c'*40,sourceTree='d'*40,configurationSha256='e'*64,versionSha256='f'*64))
        j.close()
        verified,events,_=self.run_original('verify')
        self.assertEqual(verified['outcome'],'complete')
        self.assertEqual(verified['result']['headSequence'],2)
        self.assertEqual(verified['result']['history'],[dict(operationId='33333333-3333-4333-8333-333333333333',phase='inputs-pending',recoveryRequired=True)])
        self.assertEqual([e[0] for e in events],['lease-ready','history-head'])
    def test_existing_only_does_not_create_even_first_parent(self):
        terminal,events,_=self.run_original('verify')
        self.assertEqual(terminal['outcome'],'refused')
        self.assertEqual(list(self.home.iterdir()),[])
        self.assertEqual([e[0] for e in events],['lease-ready'])
    def test_mismatched_parent_nonce_refuses_before_disk(self):
        terminal,_,_=self.run_original(fault='nonce')
        self.assertNotEqual(terminal['outcome'],'complete')
        self.assertEqual(list(self.home.iterdir()),[])
    def test_stop_after_durable_genesis_preserves_unanchored_record(self):
        terminal,events,_=self.run_original(fault='head-stop')
        self.assertEqual(terminal['outcome'],'cancelled')
        self.assertIsNone(terminal['result'])
        leaf=self.home/'.local/share/mobile-release-kit/local-releases'/ENROLLMENT['projectLocator']/'0001.json'
        self.assertTrue(leaf.is_file())
        self.assertEqual(leaf.stat().st_mode&0o777,0o400)
        self.assertEqual(events[-1][0],'durable-genesis')
    def test_closed_reply_shape_rejects_boolean_step_and_duplicate_keys(self):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:r=wire.parse_request(encode(self.request(fd,'enroll')))
        finally:os.close(fd)
        value=dict(protocol=wire.PROTOCOL,operationId=r.operation_id,ownerGeneration=r.owner_generation,nonce=r.native['nonce'],requestSha256=r.digest,kind='key-material',step=1,payload=ENROLLMENT)
        self.assertEqual(wire.reply(encode(value),r,'key-material',1),ENROLLMENT)
        value['step']=True
        with self.assertRaises(ValueError):wire.reply(encode(value),r,'key-material',1)
        with self.assertRaises(ValueError):wire.parse_request(encode(self.request(4,'enroll')).replace(b'"protocol":',b'"protocol":"duplicate","protocol":',1))

    def test_bad_key_suffix_erases_unreturned_private_handoff(self):
        terminal,events,_=self.run_original(fault='key-suffix')
        self.assertNotEqual(terminal['outcome'],'complete')
        self.assertEqual([e[0] for e in events],['lease-ready'])
        self.assertEqual(list(self.home.iterdir()),[])
        self.assertEqual(str(wire.ProtocolError('PRIVATE-SENTINEL')),'Local release history protocol refused')

    def test_terminal_respects_earlier_inherited_hard_endpoint(self):
        engine=_Engine(100.0)
        engine.frames=1
        engine.input.hard_end=105.0
        self.assertEqual(engine.input.hard_endpoint(),105.0)
        # Actual engine terminal writer must reject before any descriptor/write
        # even though its local started+62 deadline is still far in the future.
        with patch.object(time,'monotonic',return_value=105.0),patch.object(os,'write',side_effect=AssertionError('late write')):
            with self.assertRaises(wire.ProtocolError):engine.write(b'{}\n',terminal=True)
        engine.input.first_failure=101.0
        self.assertEqual(engine.input.hard_endpoint(),103.0)
