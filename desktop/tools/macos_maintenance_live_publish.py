#!/usr/bin/env python3
"""Closed fixture diagnostic projection only; never imports native owner entry."""
import importlib.util,json,os,re,stat,sys
from pathlib import Path
CHECKOUT=Path("/Users/runner/work/mobile-release-kit/mobile-release-kit")
def read(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or before.st_nlink!=1 or not 0<before.st_size<=limit:raise ValueError("bounded-input")
        body=os.read(fd,limit+1)
        if len(body)!=before.st_size or os.read(fd,1):raise ValueError("complete-input")
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError("changed-input")
        return body
    finally:os.close(fd)
def main():
    root=Path(os.environ["MRK_MACOS_WORK"]);source=os.environ["GITHUB_SHA"];outcome=os.environ["MRK_NATIVE_STEP_OUTCOME"]
    if Path.cwd()!=CHECKOUT or root.parent!=Path("/Users/runner/work/_temp") or re.fullmatch(r"mrk-macos-maintenance-fixture\.[A-Za-z0-9]{8}",root.name) is None or re.fullmatch(r"[0-9a-f]{40}",source) is None or outcome not in ("success","failure","cancelled","skipped"):raise ValueError("fixed-route")
    module_path=CHECKOUT/"desktop/tools/macos_e2_native_fixture.py"
    read(module_path,1048576)
    spec=importlib.util.spec_from_file_location("_live_fixture_data",module_path);fixture=importlib.util.module_from_spec(spec);sys.modules[spec.name]=fixture;spec.loader.exec_module(fixture)
    result=None
    try:result=fixture.decode(read(root/"e2-native-result.json",65536),65536)
    except (OSError,ValueError):pass
    entered=type(result) is dict and result.get("source")==source and result.get("nativeEntered") is True
    cases=[];checks=False
    if type(result) is dict and result.get("source")==source and type(result.get("native")) is dict:
        native=result["native"];code={"passed":0,"failed":1,"unavailable":77}.get(native.get("outcome"))
        try:
            native=fixture.native_result(fixture.canonical(native),code,source,result["sourceReleaseId"])
            cases=[{"case":row["case"],"outcome":row["outcome"],"preServiceStop":row["preServiceStop"],"mainObservations":row["mainObservations"]} for row in native["cases"]]
            checks=outcome=="success" and result.get("passed") is True and native["outcome"]=="passed" and result.get("nativeOwnerReturned") is True
        except (ValueError,KeyError,TypeError):pass
    diagnostics=[]
    try:
        value=fixture.decode(read(root/"e2-native-maintenance-diagnostics.json",8192),8192)
        if set(value)!={"schemaVersion","type","sourceCommit","nativeFinalityQualified","shippingQualified","records"} or value["sourceCommit"]!=source or value["nativeFinalityQualified"] is not False or value["shippingQualified"] is not False or type(value["records"]) is not list or len(value["records"])>3:raise ValueError("diagnostic-envelope")
        seen=set()
        for row in value["records"]:
            case=row.get("case") if type(row) is dict else None
            if case in seen:raise ValueError("diagnostic-duplicate")
            diagnostics.append(fixture.maintenance_diagnostic(fixture.canonical(row),case));seen.add(case)
    except (OSError,ValueError,TypeError):pass
    body=fixture.canonical({"schemaVersion":1,"type":"mrk-hosted-native-maintenance-diagnostic-v1","sourceCommit":source,"nativeStepOutcome":outcome,"nativeEntered":entered,"fixtureChecksPassed":checks,"shippingQualified":False,"ownerFailureExplained":False,"cases":cases,"diagnostics":diagnostics})
    if len(body)>16384:raise ValueError("summary-bound")
    fd=os.open(root/"e2-native-live-summary.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        if os.write(fd,body)!=len(body):raise ValueError("summary-write")
    finally:os.close(fd)
if __name__=="__main__":main()
