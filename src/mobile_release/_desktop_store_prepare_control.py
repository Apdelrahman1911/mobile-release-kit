"""Fixed preparation phases on the existing saved input and native project OFD."""
from __future__ import annotations
import math
import os
import select
import time
from ._desktop_saved_command_control import SavedCommandDomain,_SavedCommandInput,_protocol
from ._desktop_local_history_control import LocalHistoryInput
from ._desktop_store_preflight_control import StorePreflightInput
from . import _desktop_store_prepare_protocol as wire
class StorePrepareInput(_SavedCommandInput):
    def __init__(self,started):
        from ._desktop_store_execute_control import StoreExecuteInput
        self._require_type=type(self) in (StorePrepareInput,StoreExecuteInput)
        if not self._require_type:raise wire.ProtocolError()
        super().__init__(started,domain=SavedCommandDomain.LocalStorePrepare if type(self) is StorePrepareInput else SavedCommandDomain.LocalStoreExecute)
        self.initial=self.operation=self.engine=None
        self.material_pending=self.material_receiving=self._material_read=False
        self._material=None;self.reply_step=0;self.read_remaining=0;self.reading=False
        self.lease=self.lease_identity=None;self.lease_close_claimed=self.lease_closed=False
        self.raw_clock=self.raw_work_end=self.raw_hard_end=None
        self.hard_end=started+wire.FINALITY_SECONDS
    def _bind_engine(self,engine):
        from ._desktop_store_prepare_engine import _Engine
        from ._desktop_store_execute_engine import _Engine as ExecuteEngine
        expected=_Engine if self.domain is SavedCommandDomain.LocalStorePrepare else ExecuteEngine
        self._require(type(engine) is expected and engine.input is self and self.engine is None);self.engine=engine
    def request(self):
        request=super().request();self.initial=request;n=request.native
        clock=getattr(time,'CLOCK_UPTIME_RAW',None);self._require(type(clock) is int)
        before=time.monotonic();raw=time.clock_gettime_ns(clock)
        work,hard=(int(n['clock'][k]) for k in ('workEndNs','hardEndNs'))
        self._require(0<raw<work<hard)
        self.raw_clock,self.raw_work_end,self.raw_hard_end=clock,work,hard
        self.work_end=min(self.work_end,math.nextafter(before+(work-raw)/1e9,-math.inf))
        self.hard_end=min(self.hard_end,math.nextafter(before+(hard-raw)/1e9,-math.inf))
        self.lease=n['leaseFd'] # Claim even a failed first fstat; never report it closed.
        value=os.fstat(self.lease);e=n['rootIdentity']
        identity=(value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)
        self._require(identity==(int(e['device']),int(e['inode']),e['mode'],e['uid'],e['gid'])
            and value.st_uid==os.getuid()==os.geteuid() and os.getgid()==os.getegid()
            and not getattr(value,'st_flags',0) and os.get_inheritable(self.lease))
        self.lease_identity=identity;os.set_inheritable(self.lease,False);self.guard.check();return request
    def bind_operation(self,operation):
        from .local_store_prepare import LocalStorePrepareRun
        from .local_store_execute import LocalStoreExecuteRun
        expected=LocalStorePrepareRun if self.domain is SavedCommandDomain.LocalStorePrepare else LocalStoreExecuteRun
        self._require(type(operation) is expected and self.operation is None
            and operation.source is self and operation.guard is self.guard and operation.request is self.initial)
        self.operation=operation
    def require_operation(self):
        from .local_store_prepare import LocalStorePrepareRun
        from .local_store_execute import LocalStoreExecuteRun
        expected=LocalStorePrepareRun if self.domain is SavedCommandDomain.LocalStorePrepare else LocalStoreExecuteRun
        self._owner();self._require(type(self.operation) is expected and self.operation.source is self
            and self.operation.guard is self.guard);return self.operation
    # Identical original OFD checks: no new root open, flock or numeric retry.
    lease_post=LocalHistoryInput.lease_post
    borrow_project=LocalHistoryInput.borrow_project
    def _take(self,count):
        value=bytearray()
        try:
            while len(value)<count:
                self.read_remaining=count-len(value);self.guard.check();self.lease_post()
                if self.buffer:
                    n=min(len(self.buffer),count-len(value));value.extend(self.buffer[:n])
                    self.buffer[:n]=b'\0'*n;del self.buffer[:n]
                else:select.select([self.fd],[],[],min(.05,max(0,self.work_end-time.monotonic())))
            return value
        except BaseException:
            value[:]=b'\0'*len(value);raise
        finally:self.read_remaining=0
    def exchange(self,event,payload):
        wire=_protocol(self.domain)
        op=self.require_operation();op.checkpoint()
        self._require(self.reply_step<4 and event==wire.PHASES[self.reply_step] and not self.reading
            and not self.material_pending and not self.buffer)
        self.reply_step+=1;self.reading=True;self.read_remaining=1
        self.material_pending=self.material_receiving=True;line=bytearray();key=None
        try:
            self.engine.local_event(event,payload)
            while not line.endswith(b'\n'):
                self._require(len(line)<2048);line.extend(self._take(1))
            result=wire.reply(bytes(line),self.initial,'key-material' if self.reply_step==1 else 'checkpoint-settled',self.reply_step)
            if self.reply_step==1:
                self._require(self._take(len(wire.KEY_PREFIX))==wire.KEY_PREFIX)
                key=self._take(32);self._require(any(key) and self._take(len(wire.KEY_SUFFIX))==wire.KEY_SUFFIX)
            self._require(not self.buffer)
            self.material_pending=self.reply_step==3;self.material_receiving=False
            self.reading=False;op.checkpoint();return result,key
        except BaseException:
            if key is not None:key[:]=b'\0'*len(key)
            raise
        finally:line[:]=b'\0'*len(line);self.reading=False;self.read_remaining=0;self.material_receiving=False
    def receive_material(self,operation,scratch):
        self._require(self.reply_step==3 and self.material_pending and not self.reading)
        return StorePreflightInput.receive_material(self,operation,scratch)
    def hard_endpoint(self):
        self._owner();return min(self.hard_end,self.first_failure+10) if self.first_failure is not None else self.hard_end
    def close(self):
        self.buffer[:]=b'\0'*len(self.buffer);self.buffer.clear();self._material=None
        first=None
        if not self.lease_close_claimed:
            self.lease_close_claimed=True;fd,self.lease=self.lease,None
            if fd is not None:
                try:
                    v=os.fstat(fd);self._require((v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid)==self.lease_identity)
                    os.close(fd);self.lease_closed=True
                except BaseException as error:first=error;self.guard._abort(error)
            else:self.lease_closed=self.lease_identity is None
        try:super().close()
        except BaseException as error:
            if first is None:first=error
        if first is not None:raise first
    def material_closed(self):
        return self.closed and self.lease_closed and not self.material_receiving and not self.buffer and self._material is None
