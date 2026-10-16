"""Private phases on the original saved stdin; never a general RPC reader."""
from __future__ import annotations
import math
import os
import select
import stat
import time
from ._desktop_saved_command_control import SavedCommandDomain, _SavedCommandInput
from . import _desktop_local_history_protocol as wire
class LocalHistoryInput(_SavedCommandInput):
    def __init__(self, started):
        super().__init__(started, domain=SavedCommandDomain.LocalReleaseHistory)
        self.operation = self.engine = self.initial = None
        self.material_pending = self.material_receiving = False
        self.reply_kind = None
        self.reply_step = 0
        self.hard_end = started + wire.FINALITY_SECONDS
        self.raw_clock = self.raw_work_end = self.raw_hard_end = None
        self.lease = None
        self.lease_identity = None
        self.lease_close_claimed = self.lease_closed = False
    def _bind_engine(self, engine):
        from ._desktop_local_history_engine import _Engine
        self._require(type(engine) is _Engine and engine.input is self and self.engine is None)
        self.engine = engine
    def request(self):
        request = super().request()
        self.initial = request
        n = request.native
        clock = getattr(time, "CLOCK_UPTIME_RAW", None)
        self._require(type(clock) is int)
        before = time.monotonic(); raw = time.clock_gettime_ns(clock)
        work = int(n["clock"]["workEndNs"])
        hard = int(n["clock"]["hardEndNs"])
        self._require(0 < raw < work <= hard)
        self.raw_clock,self.raw_work_end,self.raw_hard_end=clock,work,hard
        self.work_end = min(self.work_end, math.nextafter(before + (work - raw)/1e9, -math.inf))
        self.hard_end = min(self.hard_end, math.nextafter(before + (hard - raw)/1e9, -math.inf))
        fd = n["leaseFd"]
        value = os.fstat(fd)
        expected = n["rootIdentity"]
        identity = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
        self._require(identity == (int(expected["device"]), int(expected["inode"]), expected["mode"], expected["uid"], expected["gid"])
                      and value.st_uid == os.getuid() == os.geteuid() and os.getgid() == os.getegid()
                      and not getattr(value, "st_flags", 0) and os.get_inheritable(fd))
        self.lease, self.lease_identity = fd, identity  # Before the first mutation/late failure.
        os.set_inheritable(fd, False)
        self.guard.check()
        return request
    def bind_operation(self, operation):
        from .local_release_history import LocalHistoryRun
        self._require(type(operation) is LocalHistoryRun and self.operation is None
                      and self.initial is operation.request and operation.source is self and operation.guard is self.guard)
        self.operation = operation
    def require_operation(self):
        from .local_release_history import LocalHistoryRun
        self._require(type(self.operation) is LocalHistoryRun and self.operation.source is self and self.operation.guard is self.guard)
        return self.operation
    def lease_post(self):
        self._owner()
        self._require(self.lease is not None and not self.lease_close_claimed and self.lease_identity is not None)
        v = os.fstat(self.lease)
        self._require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid) == self.lease_identity
                      and not getattr(v,"st_flags",0) and not os.get_inheritable(self.lease))
    def borrow_project(self, project):
        op = self.require_operation()
        self._require(op.invocation is not None and op.invocation._original_project is project
                      and op.invocation.project_owner is project and project.guard is self.guard)
        self.lease_post()
        v = os.fstat(project.fd)
        self._require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid) == self.lease_identity)
    def _take(self, count):
        result = bytearray()
        try:
            while len(result) < count:
                self.guard.check()
                if self.buffer:
                    n = min(count-len(result),len(self.buffer))
                    result.extend(self.buffer[:n]);self.buffer[:n]=b"\0"*n;del self.buffer[:n]
                else:
                    select.select([self.fd], [], [], min(.05,max(0.,self.work_end-time.monotonic())))
            return result
        except BaseException:
            result[:]=b"\0"*len(result)
            self.buffer[:]=b"\0"*len(self.buffer);self.buffer.clear()
            raise
    def exchange(self, event, payload, expected):
        self._owner();op = self.require_operation();op.checkpoint()
        self._require(self.reply_kind is None and not self.material_pending and not self.buffer)
        route = (("lease-ready","key-material"),("empty-journal-ready","key-enrolled"),("durable-genesis","checkpoint-settled")) if self.initial.context["action"] == "enroll" else (("lease-ready","key-material"),("history-head","checkpoint-settled"))
        admitted = self.reply_step < len(route) and route[self.reply_step] == (event,expected)
        self._require(admitted)
        self.reply_kind=expected;self.reply_step+=1;self.material_pending=self.material_receiving=True
        self.engine.local_event(event,payload)
        line = bytearray()
        while not line.endswith(b"\n"):
            self._require(len(line)<2048);line.extend(self._take(1))
        data = wire.reply(bytes(line),self.initial,expected,self.reply_step)
        key = None
        try:
            if expected == "key-material":
                self._require(self._take(len(wire.KEY_PREFIX)) == wire.KEY_PREFIX)
                key = self._take(32)
                self._require(self._take(len(wire.KEY_SUFFIX)) == wire.KEY_SUFFIX)
            self._require(not self.buffer)
            self.material_pending=self.material_receiving=False;self.reply_kind=None
            op.checkpoint()
            return data,key
        except BaseException:
            # The caller owns erasure only AFTER return. A malformed suffix,
            # unexpected tail or late original check must erase this partial
            # private handoff here instead of depending on exception GC.
            if key is not None:key[:]=b"\0"*len(key)
            self.buffer[:]=b"\0"*len(self.buffer)
            self.buffer.clear()
            raise
    def command_limits(self,*args): self._require(False)  # No tools under this input.
    def hard_endpoint(self):
        self._owner()
        return min(self.hard_end,self.first_failure+2) if self.first_failure is not None else self.hard_end
    def close(self):
        self.buffer[:]=b"\0"*len(self.buffer);self.buffer.clear()
        first = None
        if not self.lease_close_claimed:
            self.lease_close_claimed=True
            fd,self.lease=self.lease,None
            if fd is not None:
                try:
                    v=os.fstat(fd)
                    self._require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)==self.lease_identity)
                    os.close(fd);self.lease_closed=True
                except BaseException as error:
                    first=error;self.guard._abort(error)
            else: self.lease_closed=self.lease_identity is None
        try: super().close()
        except BaseException as error:
            if first is None:first=error
        if first is not None:raise first
