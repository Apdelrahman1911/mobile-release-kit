"""Fixed retained local candidate bundle; no Store or historical finality claim.

Only the actual local-history owner may review an authenticated journal row.
Names derive from its UUID, never an arbitrary renderer output path. All original
reads and consuming closes finish before a public summary may escape.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
from pathlib import Path
from uuid import UUID

from .checked_files import _Reader, _Policy, _Node
from .local_release_journal import canonical, _uuid, _enrollment
from ._desktop_android_build_protocol import content, saved_version, ANDROID_ID_RE
from .errors import ValidationError
from .owned_process import ProcessCleanupError

MANIFEST = "candidate-inputs.json"
FILES = (("app-release.aab", 1 << 30), ("store-metadata.zip", 512 << 20),
         ("validation-report.json", 65536))
MANIFEST_BYTES, CHUNK = 16384, 65536

class CandidateBundleError(ValidationError):
    def __init__(self, *_ignored): super().__init__("Local candidate inputs unavailable")

def need(value):
    if not value: raise CandidateBundleError()

def _sha(value, count=64):
    return type(value) is str and len(value)==count and all(c in "0123456789abcdef" for c in value)

def _pairs(rows):
    value={}
    for k,v in rows:
        need(k not in value); value[k]=v
    return value

def manifest_data(raw, *, operation_id, enrollment, pending):
    """Closed DATA only; caller still owes authenticated journal and originals."""
    need(type(raw) is bytes and 0<len(raw)<=MANIFEST_BYTES and _uuid(operation_id))
    try: value=json.loads(raw,object_pairs_hook=_pairs,parse_constant=lambda _:need(False))
    except (ValueError,TypeError,UnicodeError,RecursionError): raise CandidateBundleError() from None
    need(type(value) is dict and set(value)=={"schemaVersion","scope","operationId","enrollment","sourceCommit",
        "sourceTree","savedConfig","savedVersion","applicationId","signerSha256","files"}
        and type(value["schemaVersion"]) is int and value["schemaVersion"]==1
        and value["scope"]=="local-android-candidate-inputs" and value["operationId"]==operation_id
        and value["enrollment"]==_enrollment(enrollment) and canonical(value)+b"\n"==raw
        and _sha(value["sourceCommit"],40) and _sha(value["sourceTree"],40)
        and type(value["applicationId"]) is str and len(value["applicationId"])<=255
        and ANDROID_ID_RE.fullmatch(value["applicationId"]) is not None and _sha(value["signerSha256"]))
    config=content(value["savedConfig"]); version=saved_version(value["savedVersion"])
    need(type(pending) is dict and set(pending)=={"configurationSha256","versionSha256","sourceCommit","sourceTree"}
        and config["sha256"]==pending["configurationSha256"] and version["sha256"]==pending["versionSha256"]
        and value["sourceCommit"]==pending["sourceCommit"] and value["sourceTree"]==pending["sourceTree"])
    need(type(value["files"]) is list and len(value["files"])==3)
    for row,(name,maximum) in zip(value["files"],FILES):
        need(type(row) is dict and set(row)=={"fileName","bytes","sha256"} and row["fileName"]==name
             and type(row["bytes"]) is int and 0<row["bytes"]<=maximum and _sha(row["sha256"]))
    return value

class CandidateBundleReview:
    def __init__(self, owner, *, operation_id, enrollment, pending, candidate_sha256):
        from .local_release_history import LocalHistoryRun
        from .local_store_prepare import LocalStorePrepareRun
        from .local_store_execute import LocalStoreExecuteRun
        from .local_store_reconcile import LocalStoreReconcileRun
        admitted=(type(owner) is LocalHistoryRun and owner.request.context["action"] in {"review-inputs","review-prepared","review-execution","review-reconcile","review-recovery"}
                  or type(owner) is LocalStorePrepareRun and owner.request.context["operation"]=="local-store-prepare"
                  or type(owner) is LocalStoreExecuteRun and owner.request.context["operation"]=="local-store-execute"
                  or type(owner) is LocalStoreReconcileRun and owner.request.context["operation"] in {"local-store-reconcile","local-store-recovery-settle"})
        need(admitted and owner.bundle is None and not owner._close_claimed
             and owner.request.context["candidateOperationId"]==operation_id
             and _uuid(operation_id) and _sha(candidate_sha256))
        self.owner,self.operation_id,self.enrollment,self.pending=owner,operation_id,enrollment,pending
        self.expected=candidate_sha256
        self.reader=_Reader(owner.guard)
        self.manifest=self.parent=self.value=None
        self.members=[]; self.reads={}; self.closed=False; self.failed=False
        self.iterator=None; self.scan_state="new"
        owner.bundle=self  # Register before any acquisition or first checkpoint.

    def point(self):
        need(not self.closed and not self.failed and self.owner.bundle is self)
        self.owner.checkpoint()
        if self.reader.root is not None:self.reader.terminal()

    def _scan(self):
        self.point(); need(self.parent is not None and self.scan_state in {"new","closed"})
        self.scan_state="acquiring"
        try:
            self.iterator=os.scandir(self.reader._number(self.parent)); self.scan_state="open"
            names=[]
            for entry in self.iterator:
                self.point(); need(len(names)<4); names.append(entry.name)
            need(set(names)=={MANIFEST,*(name for name,_ in FILES)} and len(names)==4)
        finally:
            if self.iterator is not None:
                original,self.iterator=self.iterator,None
                self.scan_state="closing"
                try: original.close()
                except BaseException as error:
                    self.scan_state="unknown"; self.failed=True; self.owner.guard._abort(error); raise
                self.scan_state="closed"
            elif self.scan_state=="acquiring":
                self.scan_state="unknown"; self.failed=True
                self.owner.guard._abort(ProcessCleanupError("Local candidate directory original did not settle"))
        self.point()

    def _shape(self,node,maximum):
        value=node.observed; parent=os.fstat(self.reader._number(node.parent))
        need(stat.S_ISREG(value.st_mode) and stat.S_IMODE(value.st_mode)==0o600
             and value.st_uid==os.getuid()==os.geteuid()==parent.st_uid
             and value.st_gid==parent.st_gid and value.st_dev==parent.st_dev and value.st_nlink==1
             and not getattr(value,"st_flags",0) and 0<value.st_size<=maximum)

    def _hash(self,node,expected,*,capture=False):
        self.point(); key=node.name
        need(self.reads.get(key,0)<2); self.reads[key]=self.reads.get(key,0)+1
        value=node.observed; digest=hashlib.sha256(); out=bytearray(); count=0
        number=self.reader._number(node.slot)
        while count<value.st_size:
            self.point(); data=os.pread(number,min(CHUNK,value.st_size-count),count)
            need(type(data) is bytes and 0<len(data)<=value.st_size-count)
            count+=len(data); digest.update(data)
            if capture: need(count<=MANIFEST_BYTES); out.extend(data)
        need(not os.pread(number,1,count) and digest.hexdigest()==expected)
        self.point(); return bytes(out) if capture else None

    def acquire(self):
        self.point()
        # Project+home/journal originals remain live. Quote this reader's whole
        # ancestry, fixed four leaves and one iterator before first open.
        root=self.owner.root
        base=len(root.parts)+1+len(Path(self.owner.request.native["home"]).parts)+5+6
        need(base+len(root.parts)+4+4+2<=256)
        path=root/".mobile-release"/"desktop-android-build"/UUID(self.operation_id).hex/"artifacts"/MANIFEST
        self.manifest=self.reader.acquire(path,_Policy(False,1,MANIFEST_BYTES),None)
        self.parent=self.manifest.parent
        # Exact private owned suffix, not merely a readable public path.
        ancestors=[n for n in self.reader.nodes if n.directory]
        need(len(ancestors)>=4)
        for node in ancestors[-4:]:
            v=node.observed
            need(v.st_uid==os.getuid()==os.geteuid() and v.st_gid==os.getgid()==os.getegid()
                 and stat.S_IMODE(v.st_mode)==0o700 and not getattr(v,"st_flags",0))
        self._shape(self.manifest,MANIFEST_BYTES); self._scan()
        raw=self._hash(self.manifest,self.expected,capture=True)
        self.value=manifest_data(raw,operation_id=self.operation_id,enrollment=self.enrollment,pending=self.pending)
        for row,(name,maximum) in zip(self.value["files"],FILES):
            self.point(); before=self.reader._stat(self.parent,name)
            self._shape(_Node(self.parent,self.parent,name,path.parent/name,before,False),maximum)
            slot=self.reader._open(name,parent=self.parent,directory=False)
            node=_Node(slot,self.parent,name,path.parent/name,before,False)
            self.reader.nodes.append(node); self.members.append(node)
            self.point(); need(node.observed.st_size==row["bytes"])
            self._hash(node,row["sha256"])
        self._scan(); return self

    def finish(self):
        self.point(); need(self.value is not None and len(self.members)==3)
        self._hash(self.manifest,self.expected)
        for node,row in zip(self.members,self.value["files"]): self._hash(node,row["sha256"])
        self._scan(); value=self.value
        summary={"operationId":self.operation_id,"candidateSha256":self.expected,
            "sourceCommit":value["sourceCommit"],"sourceTree":value["sourceTree"],
            "applicationId":value["applicationId"],"version":{k:value["savedVersion"][k] for k in ("name","build")},
            "files":[dict(row) for row in value["files"]],"observation":"current-bundle-only",
            "priorCreateFinality":"not-established"}
        self.close(); return summary

    def close(self):
        if self.closed:
            need(not self.failed); self.reader.assert_closed(); return
        self.closed=True
        try:
            need(self.iterator is None and self.scan_state in {"new","closed"})
            # Success already passed finish's full POST while the service was
            # active. Failure cleanup must not resurrect its closed checkpoint.
            if not self.owner._close_claimed and self.reader.root is not None:self.reader.terminal()
        except BaseException:
            self.failed=True; raise
        finally:
            try: self.reader.close(); self.reader.assert_closed()
            except BaseException: self.failed=True; raise
