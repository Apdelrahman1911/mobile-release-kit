"""Closed Create DATA and phase sequence; no lease/key/Store authority."""
from __future__ import annotations
from uuid import UUID
from . import _desktop_android_build_protocol as android
from . import _desktop_local_history_protocol as history
from .local_candidate_bundle import FILES

PHASES=("lease-ready","history-head","inputs-pending","inputs-ready")
REASONS=frozenset({"journal-unavailable","recovery-required","candidate-inputs-unavailable"})
CLOSES=("candidateInputsClosed","journalClosed","leaseClosed")

def native_history(value):
    android._keys(value,{"home","leaseFd","nonce","clock"})
    android._path(value["home"])
    android.require(android.integer(value["leaseFd"],255,3) and android._text(value["nonce"],android._TOKEN)
        and value["nonce"]!="0"*32)
    clock=android._keys(value["clock"],{"workEndNs","hardEndNs"})
    for n in clock.values():android.require(type(n) is str and 1<=len(n)<=20 and n.isascii() and n.isdigit() and not n.startswith("0") and 0<int(n)<1<<64)
    android.require(0<=int(clock["hardEndNs"])-int(clock["workEndNs"])<=10_000_000_000)
    return {**value,"clock":dict(clock)}

def head(value):
    android._keys(value,{"sequence","sha256"})
    android.require(android.integer(value["sequence"],513,1) and android._text(value["sha256"],android._SHA))
    return dict(value)

def reply(raw,request,kind,step):
    value=history.decode(raw,2048)
    android._keys(value,{"protocol","operationId","ownerGeneration","nonce","requestSha256","kind","step","payload"})
    android.require(value["protocol"]==android.CANDIDATE_PROTOCOL and value["operationId"]==request.operation_id
        and value["ownerGeneration"]==request.owner_generation and value["nonce"]==request.native["candidateHistory"]["nonce"]
        and value["requestSha256"]==request.digest and value["kind"]==kind
        and android.integer(value["step"],4,1) and value["step"]==step)
    if step==1:
        android.require(kind=="key-material");return history._enrollment(value["payload"])
    android.require(kind=="checkpoint-settled" and value["payload"]=={});return None

def summary(value,request):
    android._keys(value,{"operationId","candidateSha256","sourceCommit","sourceTree","applicationId","version","files","observation","priorCreateFinality"})
    android.require(value["operationId"]==str(UUID(hex=request.operation_id))
        and android._text(value["candidateSha256"],android._SHA)
        and all(type(value[k]) is str and len(value[k])==40 and all(c in "0123456789abcdef" for c in value[k]) for k in ("sourceCommit","sourceTree"))
        and type(value["applicationId"]) is str and len(value["applicationId"])<=255 and android.ANDROID_ID_RE.fullmatch(value["applicationId"]) is not None
        and value["observation"]=="current-bundle-only" and value["priorCreateFinality"]=="not-established")
    v=android._keys(value["version"],{"name","build"})
    android.require(android._text(v["name"],android._VERSION_TEXT) and android.integer(v["build"],2_100_000_000,1)
        and type(value["files"]) is list and len(value["files"])==3)
    for row,(name,limit) in zip(value["files"],FILES):
        android._keys(row,{"fileName","bytes","sha256"})
        android.require(row["fileName"]==name and android.integer(row["bytes"],limit,1) and android._text(row["sha256"],android._SHA))

def terminal(value,request):
    android._keys(value,{"schemaVersion","context","outcome","reason","activity","disposition","result","lifetime"})
    android.require(type(value["schemaVersion"]) is int and value["schemaVersion"]==1
        and android.context(value["context"])==request.context and value["outcome"] in android.OUTCOMES
        and value["reason"] in android.REASONS|REASONS)
    life=value["lifetime"]; android.require(type(life) is dict and all(type(life.get(k)) is bool for k in CLOSES))
    ordinary={k:v for k,v in life.items() if k not in CLOSES}
    android._lifetime(ordinary,signed=True,command_limit=18)
    activity=android._activity(value["activity"]);disposition=android._disposition(value["disposition"])
    android._inspection_mode(activity["findings"],request.context["artifactValidation"])
    settled=(life["complete"] and not life["fatal"] and life["contained"]
        and life["commandDispatched"] is not None and "unknown" not in disposition.values()
        and all(life[k] for k in (*android._CLOSE_FIELDS,*android.SIGNED_CLOSE_FIELDS,*CLOSES)))
    android.require(life["commandDispatched"] is not False or life["commands"]==0)

    if value["outcome"]=="complete":
        android.require(value["reason"]=="none" and life["commands"]==14 and life["profileCalls"]==0
            and settled and life["commandDispatched"] is True
            and activity["stage"]=="disposing-work" and activity["command"]=={"outcome":"exited","exitCode":0}
            and disposition=={"work":"removed","artifacts":"retained-local-result"}
            and life["stopObserved"]=="none" and all(life[k] for k in (*android._CLOSE_FIELDS,*android.SIGNED_CLOSE_FIELDS,*CLOSES)))
        result=android._keys(value["result"],{"schemaVersion","scope","headSequence","candidateInputs","build"})
        android.require(type(result["schemaVersion"]) is int and result["schemaVersion"]==1
            and result["scope"]=="local-android-candidate-inputs" and android.integer(result["headSequence"],513,3))
        summary(result["candidateInputs"],request);android.validate_result(result["build"])
        android.require(result["build"]["signing"]=="local-upload-key"
            and result["build"]["usedConfig"]==request.context["savedConfig"]
            and result["build"]["usedVersion"]==request.context["savedVersion"]
            and result["build"]["artifactValidation"]==request.context["artifactValidation"]
            and result["build"]["toolchainProfile"]==request.native["toolchain"]["profile"]
            and result["build"]["toolchainSelection"]==request.native["toolchain"]["selection"]
            and all(result["build"][k]==activity[k] for k in ("selection","command","findings","summary")))
        selected=result["candidateInputs"];built=result["build"]
        android.require(selected["applicationId"]==built["selection"]["applicationId"]
            and selected["version"]=={k:built["usedVersion"][k] for k in ("name","build")}
            and selected["files"][0]["bytes"]==built["artifacts"][0]["size"]
            and selected["files"][0]["sha256"]==built["artifacts"][0]["sha256"])
    else:
        android.require(value["result"] is None and value["reason"]!="none"
            and disposition["artifacts"]!="retained-local-result")
        if value["outcome"]=="unknown":android.require(value["reason"]=="cleanup-unknown" and not settled)
        else:android.require(settled and value["reason"]!="cleanup-unknown")
        if value["outcome"] in {"cancelled","timed-out"}:
            android.require(value["outcome"]==value["reason"]==life["stopObserved"])
        if value["outcome"]=="refused":android.require(activity["command"]["outcome"]=="not-dispatched")
        # Preserve ordinary negative facts without treating source calls as build calls.
        if value["reason"] == "command-failed":
            android.require(value["outcome"] == "failed" and activity["command"]["outcome"] == "exited"
                    and activity["command"]["exitCode"] != 0)
        if value["reason"] == "command-incomplete":
            android.require(value["outcome"] == "failed" and activity["command"]["outcome"] != "exited")
        if value["reason"] in {"artifact-missing", "artifact-ambiguous", "artifact-unsafe", "artifact-changed"}:
            # Build artifact failures still describe capture/inspection after
            # the original zero return; candidate preparation has its own reason.
            android.require(value["outcome"] == "failed" and activity["selection"] is not None
                    and activity["command"] == {"outcome": "exited", "exitCode": 0}
                    and activity["stage"] in {"capturing", "signing", "restoring-inputs", "inspecting", "disposing-work"})
        if value["reason"] in {"cancelled", "context-changed", "document-lost", "shutdown"}:
            android.require(life["stopObserved"] == "cancelled")
        if value["reason"] == "timed-out":
            android.require(life["stopObserved"] == "timed-out")
        if value["reason"] == "work-retained":
            android.require(value["outcome"] == "failed" and disposition["work"] == "retained-work")
    if disposition["work"] == "retained-work":
        android.require(value["outcome"] in {"failed", "unknown"})


class CandidateFrames:
    def __init__(self,request):
        android.require(android.candidate_create(request.context) and android._text(request.digest,android._SHA))
        self.request=request;self.binding=android._encode(android._request_binding(request))
        self.count=self.total=self.phase=0;self.stage=-1;self.finished=self.failed=False;self.previous_head=None
    def response(self,kind,payload):
        try:
            android.require(not self.failed and not self.finished and self.count<14
                and android._encode(android._request_binding(self.request))==self.binding)
            if self.count==0:
                android.require(kind=="accepted" and payload=={"schemaVersion":1,"context":self.request.context})
            elif kind=="progress":
                android._keys(payload,{"schemaVersion","stage"})
                android.require(type(payload["schemaVersion"]) is int and payload["schemaVersion"]==1 and payload["stage"] in android.SIGNED_STAGES)
                stage=android.SIGNED_STAGES.index(payload["stage"]);android.require(stage>self.stage)
                if stage>0:android.require(self.phase>=3)
                self.stage=stage
            elif kind in PHASES:
                android.require(self.phase<4 and kind==PHASES[self.phase] and self.stage>=0)
                if self.phase==0:android.require(payload=={})
                else:
                    current=head(payload)
                    if self.phase==1:android.require(current["sequence"]<=511)
                    else:android.require(self.previous_head is not None and current["sequence"]==self.previous_head["sequence"]+1)
                    self.previous_head=current
                if kind=="inputs-ready":android.require(self.stage==7)
                self.phase+=1
            elif kind=="terminal":
                terminal(payload,self.request)
                if payload["outcome"]=="complete":
                    android.require(self.phase==4 and payload["result"]["headSequence"]==self.previous_head["sequence"] and self.stage==7)
                self.finished=True
            else:android.require(False)
            raw=android._encode({"protocol":android.CANDIDATE_PROTOCOL,"operationId":self.request.operation_id,
                "ownerGeneration":self.request.owner_generation,"nonce":self.request.native["candidateHistory"]["nonce"],
                "requestSha256":self.request.digest,"sequence":self.count,"kind":kind,"payload":payload})
            android.require(len(raw)<=(32768 if kind=="terminal" else 4096) and self.total+len(raw)<=65536)
            self.count+=1;self.total+=len(raw);return raw
        except BaseException:
            self.failed=True;raise
