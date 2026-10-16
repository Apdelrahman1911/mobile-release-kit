"""Exclusive three-sibling publication beside the SAME retained signed AAB.

The former Android file owner must already have positively retired. This owner
never renames/deletes/reopens the AAB, never extends a user-selected directory,
and keeps newly created original files through the durable journal checkpoint.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
from .build_inputs import _FD, _attempt_all, _file
from .local_release_journal import canonical
from .local_candidate_bundle import FILES, MANIFEST, MANIFEST_BYTES, CHUNK, manifest_data, need

class CandidateBundlePublisher:
    def __init__(self,owner):
        from .local_candidate_create import CandidateCreateRun
        need(type(owner) is CandidateCreateRun and owner.publisher is None and owner.build_settled)
        self.owner=owner;self.guard=owner.guard;self.handoff=owner.composition.handoff
        self.parent=self.handoff.node.parent
        self.names={"app-release.aab"};self.files=[];self.source=None
        self.iterator=None;self.scan_state="new";self.closed=False;self.failed=False
        self.summary=self.digest=None
        owner.publisher=self
    def point(self):
        need(not self.closed and not self.failed and self.owner.publisher is self)
        self.owner.point();self.handoff.reader.terminal()
        for name,slot,expected in self.files:
            if expected is not None:
                actual=os.fstat(slot.number);named=os.stat(name,dir_fd=self.parent_number(),follow_symlinks=False)
                need(not getattr(actual,"st_flags",0) and not getattr(named,"st_flags",0)
                    and _file(actual)==expected==_file(named))
    def parent_number(self):return self.handoff.reader._number(self.parent)
    def scan(self):
        self.point();need(self.scan_state in {"new","closed"});self.scan_state="acquiring"
        try:
            self.iterator=os.scandir(self.parent_number());self.scan_state="open";names=[]
            for entry in self.iterator:
                self.point();need(len(names)<4);names.append(entry.name)
            need(len(names)==len(self.names) and set(names)==self.names)
        finally:
            if self.iterator is not None:
                original,self.iterator=self.iterator,None;self.scan_state="closing"
                try:original.close()
                except BaseException as error:self.scan_state="unknown";self.guard._abort(error);raise
                self.scan_state="closed"
            elif self.scan_state=="acquiring":
                self.scan_state="unknown";self.failed=True
    def _hash(self,number,size):
        digest=hashlib.sha256();position=0
        while position<size:
            self.point();block=os.pread(number,min(CHUNK,size-position),position)
            need(type(block) is bytes and len(block)==min(CHUNK,size-position))
            position+=len(block);digest.update(block)
        need(not os.pread(number,1,position));self.point();return digest.hexdigest()
    def _write(self,name,blocks,*,size,expected):
        self.scan();need(name not in self.names and name in {MANIFEST,*(n for n,_ in FILES[1:])}
            and len(self.files)<3 and 0<size<=dict((*FILES,(MANIFEST,MANIFEST_BYTES)))[name])
        slot=_FD(self.guard);record=[name,slot,None];self.files.append(record)
        number=slot.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.parent_number())
        actual=os.fstat(number);need(not getattr(actual,"st_flags",0))
        initial=_file(actual);parent=os.fstat(self.parent_number())
        need(initial["uid"]==os.getuid()==os.geteuid()==parent.st_uid and initial["gid"]==parent.st_gid
            and initial["mode"]==0o600 and initial["links"]==1 and initial["device"]==parent.st_dev and initial["size"]==0)
        self.names.add(name);position=0;digest=hashlib.sha256()
        for block in blocks:
            self.point();need(type(block) is bytes and 0<len(block)<=CHUNK and position+len(block)<=size)
            sent=0
            while sent<len(block):
                self.point();written=os.write(number,block[sent:]);need(type(written) is int and 0<written<=len(block)-sent);sent+=written
            position+=len(block);digest.update(block)
        need(position==size and digest.hexdigest()==expected)
        os.fsync(number);final=_file(os.fstat(number))
        need(all(final[k]==initial[k] for k in ("device","inode","uid","gid","mode","links")) and final["size"]==size
             and final==_file(os.stat(name,dir_fd=self.parent_number(),follow_symlinks=False)))
        record[2]=final
        need(self._hash(number,size)==expected);os.fsync(self.parent_number());self.scan()
        return {"fileName":name,"bytes":size,"sha256":expected}
    def _metadata_blocks(self):
        comp=self.owner.composition;scratch=comp.metadata_scratch;snapshot=comp.metadata_snapshot
        scratch.require(snapshot)
        name=scratch._spec(snapshot._role).name
        self.source=_FD(self.guard)
        number=self.source.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW,dir_fd=scratch.slot.number)
        actual=os.fstat(number);parent=os.fstat(scratch.slot.number)
        expected=_file(actual);need(expected["size"]==snapshot.size and expected["mode"]==0o600
            and expected["links"]==1 and expected["uid"]==os.getuid()==os.geteuid()
            and expected["device"]==parent.st_dev and expected["gid"]==parent.st_gid and not getattr(actual,"st_flags",0))
        position=0;digest=hashlib.sha256()
        while position<snapshot.size:
            self.point();scratch._check()
            need(_file(os.fstat(number))==expected==_file(os.stat(name,dir_fd=scratch.slot.number,follow_symlinks=False)))
            block=os.pread(number,min(CHUNK,snapshot.size-position),position)
            need(type(block) is bytes and len(block)==min(CHUNK,snapshot.size-position))
            position+=len(block);digest.update(block);yield block
        need(not os.pread(number,1,position) and digest.hexdigest()==snapshot.sha256)
        scratch.require(snapshot);self.source.close()
    @staticmethod
    def _bytes(raw):
        for offset in range(0,len(raw),CHUNK):yield raw[offset:offset+CHUNK]
    def publish(self):
        self.scan();parent=os.fstat(self.parent_number())
        need(stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode)==0o700
            and parent.st_uid==os.getuid()==os.geteuid() and not getattr(parent,"st_flags",0))
        comp=self.owner.composition;h=self.handoff;snapshot=comp.metadata_snapshot
        need(0<snapshot.size<=FILES[1][1])
        free=os.fstatvfs(self.parent_number());need(free.f_bavail*free.f_frsize>=snapshot.size+65536+MANIFEST_BYTES)
        # Second of the original handoff's three full read allowances; the
        # third belongs to POST after the exact native checkpoint reply.
        for _ in h._candidate_blocks(self.owner):pass
        rows=[{"fileName":"app-release.aab","bytes":h._size,"sha256":h._sha256}]
        blocks=self._metadata_blocks()
        try:rows.append(self._write("store-metadata.zip",blocks,size=snapshot.size,expected=snapshot.sha256))
        finally:blocks.close()
        report=h._result;need(0<len(report)<=65536)
        rows.append(self._write("validation-report.json",self._bytes(report),size=len(report),expected=hashlib.sha256(report).hexdigest()))
        build=json.loads(report);saved=build["usedVersion"]
        manifest={"schemaVersion":1,"scope":"local-android-candidate-inputs","operationId":self.owner.operation_id,
            "enrollment":self.owner.enrollment,"sourceCommit":comp.source_binding["commit"],"sourceTree":comp.source_binding["tree"],
            "savedConfig":build["usedConfig"],"savedVersion":saved,"applicationId":build["selection"]["applicationId"],
            "signerSha256":self.owner.signer_sha256,"files":rows}
        raw=canonical(manifest)+b"\n"
        manifest_data(raw,operation_id=self.owner.operation_id,enrollment=self.owner.enrollment,pending=self.owner.pending_payload)
        self.digest=hashlib.sha256(raw).hexdigest()
        self._write(MANIFEST,self._bytes(raw),size=len(raw),expected=self.digest)
        self.summary={"operationId":self.owner.operation_id,"candidateSha256":self.digest,
            "sourceCommit":manifest["sourceCommit"],"sourceTree":manifest["sourceTree"],"applicationId":manifest["applicationId"],
            "version":{k:saved[k] for k in ("name","build")},"files":rows,"observation":"current-bundle-only",
            "priorCreateFinality":"not-established"}
        self.scan();return self.digest
    def post(self):
        self.point();need(self.summary is not None and len(self.files)==3)
        for _ in self.handoff._candidate_blocks(self.owner):pass
        expected={row["fileName"]:row for row in self.summary["files"][1:]}
        expected[MANIFEST]={"bytes":self.files[-1][2]["size"],"sha256":self.digest}
        for name,slot,identity in self.files:
            need(self._hash(slot.number,expected[name]["bytes"])==expected[name]["sha256"])
        self.scan()
    def close(self):
        if self.closed:
            need(self.originals_closed());return
        self.closed=True
        actions=[record[1].close for record in self.files]
        if self.source is not None:actions.append(self.source.close)
        try:_attempt_all(self.guard,actions)
        except BaseException:self.failed=True;raise
        need(self.originals_closed())
    def originals_closed(self):
        return self.closed and self.iterator is None and self.scan_state in {"new","closed"} and all(
            slot.close_state=="CLOSED" for slot in [*(r[1] for r in self.files),*([self.source] if self.source else [])])
