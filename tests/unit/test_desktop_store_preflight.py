"""Real inert input/file owners; mocked command execution, no native or network."""
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import desktop_store_preflight as service, stores
from mobile_release import _desktop_store_preflight_protocol as wire
from mobile_release._desktop_store_preflight_control import StorePreflightInput, PREFIX, SUFFIX, parse_header
from mobile_release._command_process import CommandCallEvidence
from mobile_release.build_inputs import finite_scratch
from mobile_release.cancellation import CleanupScope, DefaultCancellation
from mobile_release.owned_process import ProcessCleanupError, ProcessError, run_owned
from mobile_release.reporting import Finding, Status
from mobile_release.tooling import REQUIRED_TOOLING_FILES
from .helpers import android_config, write_project


def encode(value):
    return json.dumps(value, separators=(",", ":")).encode() + b"\n"


def account():
    return {"type":"service_account", "project_id":"example-project", "private_key_id":"a"*40,
            "private_key":"-----BEGIN PRIVATE KEY-----\nMBUCAQAwDQYJKoZIhvcNAQEBBQAEAQE=\n-----END PRIVATE KEY-----\n",
            "client_email":"release@example-project.iam.gserviceaccount.com", "client_id":"123456789",
            "token_uri":"https://oauth2.googleapis.com/token"}


def request(root, runtime):
    raw = (root / "release/mobile-release.json").read_bytes()
    version = (root / "release/version.properties").read_bytes()
    facts = root.stat()
    canonical = json.dumps(json.loads(raw), sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return {"protocol":wire.PROTOCOL,"operationId":"a"*32,"ownerGeneration":"b"*32,
        "context":{"projectId":"test-project","draftRevision":1,"baselineGeneration":1,
            "savedConfig":{"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()},
            "savedVersion":{"source":"release/version.properties","bytes":len(version),
                            "sha256":hashlib.sha256(version).hexdigest(),"name":"1.2.3","build":42},
            "credentialContextRevision":1,"recordId":"c"*32,"recordRevision":2,
            "executionMode":"local","platform":"android","operation":"local-store-preflight"},
        "native":{"profile":"macos-arm64","projectRoot":str(root),"cwd":str(runtime),
            "credentialConfig":{"bytes":len(canonical),"sha256":hashlib.sha256(canonical).hexdigest()},
            "rootIdentity":{"device":str(facts.st_dev),"inode":str(facts.st_ino),
                            "mode":facts.st_mode,"uid":facts.st_uid,"gid":facts.st_gid}}}


class DesktopStorePreflightTests(unittest.TestCase):
    @contextmanager
    def files(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root, runtime = base / "project", base / "runtime with spaces"
            config = android_config()
            config["projectChecks"]["preflight"] = [["must-never-run-project-command"]]
            write_project(root, config)
            for name in ("ruby", "bundle"):
                path = runtime / "store/bin" / name
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"inert\n"); path.chmod(0o755)
            for name in REQUIRED_TOOLING_FILES:
                path = runtime / "store/tooling" / name
                path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b"inert tooling\n")
            yield base, root, runtime

    @contextmanager
    def original(self, *, material=None, credential_config=None):
        with self.files() as (base, root, runtime):
            value = request(root, runtime)
            if credential_config is not None: value["native"]["credentialConfig"] = credential_config
            body = encode(account()) if material is None else material
            frame = PREFIX + encode({"schemaVersion":1,"files":[{"role":"google-service-account","bytes":len(body)}]}) + body + SUFFIX
            old_stdin = os.dup(0); reader, writer = os.pipe()
            os.dup2(reader, 0); os.close(reader)
            os.write(writer, encode(value) + frame)  # Small bounded fixture below pipe capacity.
            guard = DefaultCancellation(ProcessCleanupError, "test Store owner")
            source = StorePreflightInput(time.monotonic()); operation = None
            old_cwd = Path.cwd(); os.chdir(runtime)
            def cleanup():
                if operation is not None:
                    operation.close()
                source.close()
            scope = CleanupScope(guard, cleanup, owns_cancellation=True, first_primary=True)
            def scratch(**kwargs):
                if kwargs.get("parent") == Path("/private/tmp"):
                    kwargs["parent"] = base  # Only the macOS system temp location is substituted.
                return finite_scratch(**kwargs)
            try:
                with patch.object(service, "sys", SimpleNamespace(platform="darwin")), patch.object(
                        service, "finite_scratch", side_effect=scratch), patch.object(
                        subprocess, "Popen", side_effect=AssertionError("no real processes")), patch.dict(
                        os.environ, {"TMPDIR":str(base)}, clear=True):
                    try:
                        with scope:
                            guard.install(); source.acquire(); guard._install_store_preflight_source(source); guard.activate()
                            parsed = source.request()
                            operation = service.StorePreflightRun(parsed, guard, source)
                            yield base, root, runtime, source, operation
                    finally:
                        scope.__exit__(*sys.exc_info())
            finally:
                os.chdir(old_cwd)
                os.close(writer); os.dup2(old_stdin, 0); os.close(old_stdin)

    def test_closed_local_request_and_private_frame_reject_other_modes_and_roles(self):
        with self.files() as (_, root, runtime):
            value = request(root, runtime)
            parsed = wire.parse_request(encode(value))
            self.assertEqual(parsed.context, value["context"])
            for field, bad in (("executionMode","github"),("platform","ios"),("recordRevision",True),
                               ("credentialContextRevision",0),("recordId","foreign")):
                invalid = copy.deepcopy(value); invalid["context"][field] = bad
                with self.assertRaises(ValueError): wire.parse_request(encode(invalid))
            for invalid in ({**value,"environment":{}}, {**value,"credentials":account()}):
                with self.assertRaises(ValueError): wire.parse_request(encode(invalid))
            with self.assertRaises(ValueError): wire.parse_request(encode(value).replace(b'"protocol":',b'"protocol":"duplicate","protocol":',1))
        self.assertEqual(parse_header(encode({"schemaVersion":1,"files":[{"role":"google-service-account","bytes":16384}]})),16384)
        for role, size in (("google-adc",8),("google-service-account",0),("google-service-account",16385),("google-service-account",True)):
            with self.assertRaises(ValueError): parse_header(encode({"schemaVersion":1,"files":[{"role":role,"bytes":size}]}))

    def test_material_is_strict_google_service_account_not_execution_or_authentication(self):
        service.StorePreflightRun.validate_material_shape(encode(account()))
        for name, value in (("type","authorized_user"),("type","external_account"),("token_uri","https://other.invalid"),
                ("credential_source",{"executable":{"command":"unused"}}),("auth_uri",None),
                ("client_x509_cert_url","https://other.invalid"),("private_key","bad")):
            bad = {**account(),name:value}
            with self.assertRaises(service._Refused) as result:
                service.StorePreflightRun.validate_material_shape(encode(bad))
            self.assertNotIn("other.invalid",str(result.exception))
        with self.assertRaises(service._Refused):
            service.StorePreflightRun.validate_material_shape(encode(account()).replace(b'"type":',b'"type":"service_account","type":',1))

    def test_saved_source_change_and_invalid_material_prevent_any_tool_command(self):
        for mode in ("config", "version", "material"):
            with self.subTest(mode=mode), self.original(material=b'{"type":"external_account"}' if mode=="material" else None) as (_,root,_,source,operation):
                if mode in ("config","version"):
                    path = root / ("release/mobile-release.json" if mode=="config" else "release/version.properties")
                    path.write_bytes(path.read_bytes()+b"\n")
                with patch("mobile_release._command_process.run_command") as run:
                    with self.assertRaises((service._Refused,ProcessError)):
                        operation.run()
                    run.assert_not_called()
                self.assertTrue(operation.closed())
                self.assertEqual(operation._next_command,0)
            self.assertTrue(source.material_closed())

    def test_actual_engine_emits_closed_refusal_and_never_promotes_cleanup_unknown(self):
        from mobile_release._desktop_store_preflight_engine import _Engine
        from mobile_release._desktop_saved_command_engine import run_engine, _RETAINED
        for lost_cleanup in (False, True):
            with self.subTest(lost_cleanup=lost_cleanup), self.files() as (_,root,runtime):
                value=request(root,runtime)
                value["native"]["credentialConfig"]={"bytes":2,"sha256":hashlib.sha256(b"{}").hexdigest()}
                saved=[os.dup(fd) for fd in (0,1,2)]
                readers=[]; writers=[]; previous=Path.cwd(); engine=None
                original_close=service.StorePreflightRun.close
                raised=False
                def close_then_lose_return(operation):
                    nonlocal raised
                    original_close(operation)
                    if not raised:
                        raised=True
                        raise ProcessCleanupError("inert lost cleanup return")
                try:
                    for fd in (0,1,2):
                        reader,writer=os.pipe(); readers.append(reader); writers.append(writer)
                        os.dup2(reader if fd==0 else writer,fd)
                    os.write(writers[0],encode(value))
                    os.chdir(runtime)
                    engine=_Engine(time.monotonic())
                    with patch.object(service,"sys",SimpleNamespace(platform="darwin")), patch(
                            "mobile_release._command_process.run_command",side_effect=AssertionError("no process permitted")), patch.object(
                            service.StorePreflightRun,"close",close_then_lose_return if lost_cleanup else original_close):
                        result=run_engine(engine)
                finally:
                    os.chdir(previous)
                    for fd,original in enumerate(saved): os.dup2(original,fd); os.close(original)
                    for writer in writers: os.close(writer)
                try:
                    output=os.read(readers[1],wire.RESPONSE_LIMIT+1)
                    self.assertEqual(os.read(readers[2],1024),b"")
                finally:
                    for reader in readers: os.close(reader)
                try:
                    self.assertEqual(result,0)
                    frames=[json.loads(line) for line in output.splitlines()]
                    self.assertEqual([row["kind"] for row in frames],["accepted","terminal"])
                    terminal=frames[1]["payload"]
                    wire.validate_terminal(terminal,engine.request)
                    self.assertEqual(terminal["outcome"],"unknown" if lost_cleanup else "refused")
                    self.assertEqual(terminal["reason"],"cleanup-unknown" if lost_cleanup else "saved-source-changed")
                    self.assertIsNone(terminal["result"])
                    self.assertTrue(engine.input.material_closed())
                    self.assertTrue(engine.service.closed())
                    self.assertTrue(engine.output.closed and engine.error_output.closed)
                    self.assertEqual(engine.guard.handler_state,"RESTORED")
                    self.assertEqual(engine in _RETAINED,lost_cleanup)
                    self.assertNotIn("inert lost",output.decode())
                finally:
                    # Actual descriptors are closed; retire only this synthetic fatal fixture.
                    if engine in _RETAINED: _RETAINED.remove(engine)

    def test_native_credential_config_is_not_renderer_or_raw_file_authority(self):
        with self.original(credential_config={"bytes":2,"sha256":hashlib.sha256(b"{}").hexdigest()}) as (_,_,_,source,operation):
            with patch("mobile_release._command_process.run_command") as run:
                with self.assertRaises(service._Refused) as failure: operation.run()
                self.assertEqual(failure.exception.reason,"saved-source-changed")
                run.assert_not_called()
            self.assertEqual(operation._next_command,0)
            self.assertEqual(len(operation.scratches),0)
            self.assertTrue(operation.closed())
        with self.files() as (_,root,runtime):
            value=request(root,runtime)
            self.assertNotEqual(value["native"]["credentialConfig"],value["context"]["savedConfig"])
            value["context"]["credentialConfig"]=value["native"].pop("credentialConfig")
            with self.assertRaises(ValueError): wire.parse_request(encode(value))

    def test_real_input_scratch_and_all_six_roles_share_guard_with_no_ambient_or_project_command(self):
        calls=[]; private_paths=[]
        with self.original() as (_,root,runtime,source,operation):
            output=("3.3.12","4.0.16","","MRK_RUNTIME_3.3.12_FIDDLE_1.1.2","MRK_RUNTIME_3.3.12_FIDDLE_1.1.2")
            def inert_command(argv, **kwargs):
                i=len(calls); calls.append(tuple(argv))
                self.assertIs(kwargs["cancellation"],operation.guard)
                self.assertEqual(kwargs["capture"], i<5)
                self.assertLessEqual(kwargs["timeout"],60 if i<5 else 900)
                env=kwargs["environ"]
                self.assertEqual(env["PATH"].split(":")[0],str(runtime / "store/bin"))
                for name in ("GITHUB_ACTIONS","RUBYOPT","RUBYLIB"):
                    self.assertNotIn(name,env)
                if i<5: return subprocess.CompletedProcess(argv,0,stdout=output[i],stderr="")
                self.assertEqual(argv[-1],"android_online_preflight")
                private_paths.append(Path(env["GOOGLE_APPLICATION_CREDENTIALS"]))
                self.assertEqual(json.loads(private_paths[-1].read_bytes()),account())
                evidence=kwargs["_evidence"]
                self.assertIs(type(evidence),CommandCallEvidence)
                self.assertTrue(evidence._desktop_readback_capped)
                self.assertEqual(evidence._expected[5],kwargs["timeout"])
                # No fabricated successful writer/readback or Store receipt.
                return subprocess.CompletedProcess(argv,1)
            with patch("mobile_release._command_process.run_command",side_effect=inert_command), patch.dict(
                    os.environ,{"GITHUB_ACTIONS":"true","RUBYOPT":"-rforeign","GOOGLE_APPLICATION_CREDENTIALS":"/foreign"}):
                operation.run()
            self.assertEqual(len(calls),6)
            self.assertEqual(operation.report["findings"], [{"check":"credential-format","status":"PASS"},{"check":"store-access","status":"FAIL"}])
            self.assertTrue(operation.closed())
            self.assertTrue(all(not path.exists() for path in private_paths))
            self.assertNotIn("release@example",json.dumps(operation.report))
        self.assertTrue(source.material_closed())

    def test_late_query_narrows_actual_seal_once_without_resetting_deadline(self):
        with self.original() as (_,_,_,source,operation):
            outputs=iter(("3.3.12","4.0.16","","MRK_RUNTIME_3.3.12_FIDDLE_1.1.2","MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"))
            original_end=source.work_end; captured=[]
            real_run=run_owned
            def call(argv,**kwargs):
                if not kwargs["capture"]:
                    evidence = kwargs["_evidence"]
                    for other, duration in ((source, 901), (source, 0),
                            (SimpleNamespace(guard=source.guard), 123),
                            (SimpleNamespace(guard=DefaultCancellation(ProcessCleanupError, "other")), 123)):
                        with self.assertRaises((ValueError, ProcessError)): evidence._cap_store_preflight(other, timeout=duration)
                    self.assertFalse(evidence._desktop_readback_capped)
                    self.assertEqual(evidence._expected[5], 900)
                    # Not yet admitted by actual run_owned: same-source alone is insufficient.
                    with self.assertRaises((ValueError, ProcessError)): evidence._cap_store_preflight(source, timeout=123)
                    # Exercise actual remaining clamp, not a new source endpoint.
                    with patch("time.monotonic",return_value=original_end-123.25):
                        return real_run(argv,**kwargs)
                return real_run(argv,**kwargs)
            def target(argv,**kwargs):
                if kwargs["capture"]: return subprocess.CompletedProcess(argv,0,stdout=next(outputs),stderr="")
                evidence=kwargs["_evidence"];captured.append(evidence)
                self.assertEqual(kwargs["timeout"],123)
                self.assertEqual(source.work_end,original_end)
                self.assertEqual(evidence._expected[0],tuple(argv))
                with self.assertRaises((ValueError, ProcessError)): evidence._cap_store_preflight(source,timeout=123)
                return subprocess.CompletedProcess(argv,1)
            with patch("mobile_release.stores.run_owned",side_effect=call), patch("mobile_release._command_process.run_command",side_effect=target):
                operation.run()
            self.assertEqual(len(captured),1)
            self.assertEqual(captured[0]._expected[5],123)

    def test_ordinary_readback_timing_remains_exact_and_source_post_cannot_pass_changed_input(self):
        from .test_store_runtime_context import StoreRuntimeContextTests
        with StoreRuntimeContextTests().fixture() as (_, _, runtime, invocation):
            evidence = CommandCallEvidence(invocation.cancellation)
            evidence._reserve_readback(object(), "android", Path("/inert/android.json"), invocation.cancellation)
            evidence.seal_readback(runner=runtime / "store/tooling/fastlane/run_lane.rb", cwd=runtime,
                                   environ={"MOBILE_RELEASE_PREFLIGHT_READBACK_PATH":"/inert/android.json"})
            with self.assertRaises(ProcessError):
                evidence._attempt(invocation.cancellation, timeout=123, ordinary=True)
            self.assertTrue(evidence._used)
            self.assertEqual(evidence._expected[5], 900)
        with self.original() as (_, root, _, _, operation):
            outputs = iter(("3.3.12", "4.0.16", "", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2", "MRK_RUNTIME_3.3.12_FIDDLE_1.1.2"))
            def target(argv, **kwargs):
                if kwargs["capture"]:
                    return subprocess.CompletedProcess(argv, 0, stdout=next(outputs), stderr="")
                path = root / "release/version.properties"
                path.write_bytes(path.read_bytes() + b"#changed during query\n")
                return subprocess.CompletedProcess(argv, 1)
            with patch("mobile_release._command_process.run_command", side_effect=target):
                with self.assertRaises(service._Refused) as result:
                    operation.run()
                self.assertEqual(result.exception.reason, "saved-source-changed")
            self.assertTrue(operation.closed())
            self.assertIsNone(operation.report)

    def test_stop_after_private_body_prevents_probes_and_closes_actual_originals(self):
        operation = source = None
        with self.assertRaises((ProcessError, KeyboardInterrupt)):
            with self.original() as (_, _, _, source, operation):
                # Actual pending material bytes are already in the same held pipe.
                # A following byte is STOP, never credential data or a retry.
                source.buffer.extend(b"!")
                with patch("mobile_release._command_process.run_command") as run:
                    try:
                        operation.run()
                    finally:
                        run.assert_not_called()
        self.assertIsNotNone(operation)
        self.assertEqual(source.stop_reason, "cancelled")
        self.assertTrue(operation.closed())
        self.assertTrue(source.material_closed())

    def test_finite_output_and_finality_do_not_publish_provider_details(self):
        result=wire.project_result([Finding("store.online.android",Status.FAIL,"PRIVATE_PROVIDER_ERROR",details={"token":"PRIVATE_TOKEN"})])
        self.assertNotIn("PRIVATE",json.dumps(result))
        with self.files() as (_,root,runtime):
            parsed=wire.parse_request(encode(request(root,runtime)))
        value={"schemaVersion":1,"context":parsed.context,"outcome":"complete","reason":"none","result":result,
            "lifetime":{"complete":True,"fatal":False,"contained":True,"commandDispatched":False,"commands":0,
                        "profileCalls":0,"inputClosed":True,"handlersRestored":True,"invocationClosed":True,"stopObserved":"none"}}
        wire.validate_terminal(value,parsed)
        for key in ("inputClosed","handlersRestored","invocationClosed","contained","complete"):
            bad=copy.deepcopy(value);bad["lifetime"][key]=False
            with self.assertRaises(ValueError):wire.validate_terminal(bad,parsed)
            bad.update(outcome="unknown",reason="cleanup-unknown",result=None)
            wire.validate_terminal(bad,parsed)
        with self.assertRaises(ValueError): wire.project_result([Finding("PRIVATE_PROVIDER_CODE",Status.FAIL,"secret")])


if __name__ == "__main__": unittest.main()
