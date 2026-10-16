"""Create-only same-OFD/private-phase adapter on original Android input.

Not a new command source. Ordinary Android operation/material/role admission is
unchanged; the adapter only borrows the fixed native lease and four replies.
"""
from __future__ import annotations
import math
import os
import select
import time
from . import _desktop_android_build_protocol as wire
from . import _desktop_local_history_protocol as history
from . import local_candidate_create_protocol as candidate

class CandidateCreateInput:
    def __init__(self,source,request):
        from ._desktop_android_build_control import AndroidBuildInput
        wire.require(type(source) is AndroidBuildInput and wire.candidate_create(request.context)
                     and source.candidate_input is None)
        self.source,self.request=source,request
        self.lease=self.identity=None;self.close_claimed=self.closed=False
        self.reply_step=0;self.read_remaining=0;self.reading=False
        self.hard_end=source.work_end+10
        source.candidate_input=self
    def acquire(self):
        self.source._owner();n=self.request.native["candidateHistory"]
        before=time.monotonic();clock=getattr(time,"CLOCK_UPTIME_RAW",None)
        wire.require(type(clock) is int);now=time.clock_gettime_ns(clock)
        work,hard=(int(n["clock"][k]) for k in ("workEndNs","hardEndNs"))
        wire.require(0<now<work<=hard)
        self.source.work_end=min(self.source.work_end,math.nextafter(before+(work-now)/1e9,-math.inf))
        self.hard_end=min(self.hard_end,math.nextafter(before+(hard-now)/1e9,-math.inf))
        self.lease=n["leaseFd"]
        v=os.fstat(self.lease);expected=self.request.native["rootIdentity"]
        identity=(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)
        wire.require(identity==(int(expected["device"]),int(expected["inode"]),expected["mode"],expected["uid"],expected["gid"])
            and v.st_uid==os.getuid()==os.geteuid() and os.getgid()==os.getegid()
            and not getattr(v,"st_flags",0) and os.get_inheritable(self.lease))
        self.identity=identity;os.set_inheritable(self.lease,False);self.post()
    def post(self):
        self.source._owner()
        wire.require(self.source.candidate_input is self and not self.close_claimed and self.lease is not None and self.identity is not None)
        v=os.fstat(self.lease)
        wire.require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)==self.identity
                     and not getattr(v,"st_flags",0) and not os.get_inheritable(self.lease))
    def borrow_project(self,project):
        op=self.source.require_operation()
        wire.require(wire.candidate_create(op.request.context) and op.request is self.request
            and op.invocation is not None and op.invocation._original_project is project
            and op.invocation.project_owner is project and project.guard is self.source.guard)
        self.post();v=os.fstat(project.fd)
        wire.require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)==self.identity)
    def _take(self,count):
        out=bytearray()
        try:
            while len(out)<count:
                self.read_remaining=count-len(out)
                self.source.guard.check();self.post()
                if self.source.buffer:
                    n=min(len(self.source.buffer),count-len(out));out.extend(self.source.buffer[:n])
                    self.source.buffer[:n]=b"\0"*n;del self.source.buffer[:n]
                else:select.select([self.source.fd],[],[],min(.05,max(0,self.source.work_end-time.monotonic())))
            return out
        except BaseException:
            out[:]=b"\0"*len(out);raise
        finally:self.read_remaining=0
    def exchange(self,kind,payload):
        from .local_candidate_create import CandidateCreateRun
        owner=getattr(self.source._engine,"candidate",None)
        wire.require(type(owner) is CandidateCreateRun and owner.input is self and self.reply_step<4
            and kind==candidate.PHASES[self.reply_step] and not self.reading
            and not self.source.material_receiving and not self.source.buffer)
        owner.point();self.reply_step+=1
        self.reading=True;self.read_remaining=1;self.source.material_pending=self.source.material_receiving=True
        self.source._engine.write(self.source._engine._response(kind,payload))
        line=bytearray();key=None
        try:
            while not line.endswith(b"\n"):
                wire.require(len(line)<2048);line.extend(self._take(1))
            expected="key-material" if self.reply_step==1 else "checkpoint-settled"
            value=candidate.reply(bytes(line),self.request,expected,self.reply_step)
            if self.reply_step==1:
                wire.require(self._take(len(history.KEY_PREFIX))==history.KEY_PREFIX)
                key=self._take(32)
                wire.require(self._take(len(history.KEY_SUFFIX))==history.KEY_SUFFIX and any(key))
            wire.require(not self.source.buffer)
            self.source.material_receiving=False
            # Only the pending checkpoint unlocks the original signing reader.
            # Exact-size phase reads leave any queued material in the pipe.
            self.source.material_pending=self.reply_step==3
            self.reading=False;owner.point();return value,key
        except BaseException:
            if key is not None:key[:]=b"\0"*len(key)
            raise
        finally:
            line[:]=b"\0"*len(line)
            self.read_remaining=0;self.reading=False;self.source.material_receiving=False
    def close(self):
        self.source._owner()
        if self.close_claimed:wire.require(self.closed);return
        self.close_claimed=True
        fd,self.lease=self.lease,None
        if fd is not None:
            wire.require(self.identity is not None)
            v=os.fstat(fd);wire.require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)==self.identity)
            os.close(fd)
        self.closed=True
