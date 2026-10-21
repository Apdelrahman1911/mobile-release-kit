"""Fixed create-Push setup/driver comparisons, never a Mac observation.

Only public temporary directories use real FD/roster reads; every process,
provider and native report/return below is explicitly inert. No Git is run.
"""
import configparser
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from mobile_release import _git_push_create_observation as create
from mobile_release import _git_push_observation_data as data
import test_macos_git_push_observation as previous

setup = previous.setup


def report(case):
    held, apply = case == create.CASES[4], case != create.CASES[1]
    return dict(mechanism="same-original-git-push-create-v1",case=case,syntheticProviderBytes=True,
        connectionOriginalJoined=True,readOriginalJoined=True,prepareOriginalJoined=True,
        applyRequested=apply,applyOriginalJoined=apply,connectionRetired=True,remoteReturned=case==create.CASES[0],
        helperRefusedBeforeAllCopyEof=held,producerPendingBeforeStop=held,sameTicketStop=held,
        toolSha256="a"*64,normalQuitOriginal=2,allOriginalsSettled=True,worktreePreserved=True,
        shippingNominationEnabled=False,tlsQualified=False,liveAccountQualified=False,productionQualified=False)


class PushCreateQualificationTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen", "socket.socket", "socket.create_connection"):
            self.enterContext(patch(name, side_effect=AssertionError("Native execution forbidden")))
        self.aqua = previous._module("_push_create_aqua", "macos_aqua_qualification.py")
        self.current = previous._module("_push_create_current", "macos_identity_current_runtime.py")
        self.binding = self.aqua.Binding("a"*40, "123", "1")

    def test_closed_family_has_no_upstream_and_does_not_expand_old_three_scope(self):
        self.assertEqual(setup.CREATE.CASES, create.CASES)
        self.assertEqual(setup.CREATE.SCOPE, create.SCOPE)
        self.assertEqual(self.aqua.selected_cases(create.SCOPE), create.CASES)
        self.assertEqual(self.aqua.selected_cases(setup.SCOPE), setup.CASES)
        self.assertEqual(len(setup.CASES), 3)
        for case in create.CASES:
            config = configparser.RawConfigParser()
            config.read_string(setup._configuration(case).decode("ascii"))
            self.assertEqual(config.sections(), ["core", "user"])
            self.assertEqual(config["user"]["email"], "push-fixture@example.invalid")
            raw = setup._transcript(case, "a"*40, "b"*40, "c"*40)
            self.assertEqual(data.decode(raw, case).raw(), raw)
        for mixed in ((), create.CASES[:1], (*setup.CASES, create.CASES[0]), list(create.CASES)):
            with self.subTest(mixed=mixed), self.assertRaises(ValueError): setup.case_family(mixed)
        # Cross-family call is rejected before original setup/command entry.
        f = SimpleNamespace(cases=setup.CASES,push_cases={},inflight=False,close_errors=0,
                            _namespace=lambda: self.fail("must refuse before setup"))
        with self.assertRaises(ValueError):
            setup.before_invocation(f, create.CASES[0], lambda *a,**k:self.fail("no command"), "runner")

    def test_create_selector_requires_same_explicit_combined_image_not_old_singleton(self):
        m = self.current
        env = {"MRK_MACOS_NATIVE_SCOPE":m.GIT_SCOPE,"MRK_MACOS_PACKAGE_ROLE":m.ROLE,"GITHUB_REF":m.REF}
        self.assertEqual(m.arguments(["--target",m.TARGET,"--scope",create.SCOPE]), create.SCOPE)
        self.assertEqual(m.observation_scope(env, create.SCOPE), create.SCOPE)
        self.assertEqual(self.aqua.argument_scope(["--scope",create.SCOPE]), create.SCOPE)
        for native in (m.PUSH_SCOPE,m.FETCH_SCOPE,create.SCOPE,"disabled","all"):
            with self.subTest(native=native), self.assertRaises(m.Refused):
                m.observation_scope({**env,"MRK_MACOS_NATIVE_SCOPE":native}, create.SCOPE)
        home = "/Users/fixed-public-runner"
        old = setup.fixture_path(self.binding,home)
        new = setup.fixture_path(self.binding,home,cases=create.CASES)
        self.assertNotEqual(old,new)
        self.assertTrue(str(old).endswith("git-push-native"))
        self.assertTrue(str(new).endswith(create.SCOPE))
        self.assertIn("mrk-macos-aqua-push-create-",str(setup.application_path(self.binding,home,create.CASES[0])))

    def test_real_absence_rosters_use_same_fixture_fds_and_refuse_new_tracking_or_parent(self):
        a = self.aqua
        with tempfile.TemporaryDirectory(prefix="mrk-create-absence-") as temporary:
            root = Path(temporary)
            for name in ("refs","refs/heads","refs/tags","logs","logs/refs","logs/refs/heads"):
                (root/name).mkdir(mode=0o700)
            f = a.Fixtures(self.binding, os.getuid(), os.getgid(), create.SCOPE)
            try:
                with f._temporary(f._open(str(root),directory=True)) as git:
                    before = setup.CREATE.absence(f,git,setup._sig,setup._names,setup._need)
                    self.assertEqual(before,setup.CREATE.absence(f,git,setup._sig,setup._names,setup._need))
                    (root/"refs/remotes").mkdir(mode=0o700)
                    with self.assertRaises(ValueError):
                        setup.CREATE.absence(f,git,setup._sig,setup._names,setup._need)
                    (root/"refs/remotes").rmdir()
                    (root/"logs/refs").rename(root/"logs/old-refs")
                    (root/"logs/refs").mkdir(mode=0o700)
                    (root/"logs/refs/heads").mkdir(mode=0o700)
                    self.assertNotEqual(before,setup.CREATE.absence(f,git,setup._sig,setup._names,setup._need))
                self.assertEqual(f.fds,set())
                self.assertEqual(f.close_errors,0)
            finally:
                f.close()

    def test_prepare_only_report_cannot_claim_apply_or_turn_race_unknown_into_success(self):
        for case in create.CASES:
            value=report(case)
            self.assertIs(setup.report(value,case,setup._need),value)
            for key,bad in (("applyRequested",not value["applyRequested"]),
                            ("applyOriginalJoined",not value["applyOriginalJoined"]),
                            ("remoteReturned",not value["remoteReturned"]),
                            ("allOriginalsSettled",False),("shippingNominationEnabled",True),
                            ("tlsQualified",True),("extra",False)):
                with self.subTest(case=case,key=key),self.assertRaises(ValueError):
                    setup.report({**value,key:bad},case,setup._need)
            bad=value.copy();bad.pop("applyRequested")
            with self.assertRaises(ValueError): setup.report(bad,case,setup._need)
            template=self.aqua.expected_result(self.binding,case)
            self.assertIsNone(template["gitPush"])
            encode=lambda v:self.aqua.MARKER+json.dumps(v,sort_keys=True,separators=(",",":")).encode()+b"\n"
            with self.assertRaises(self.aqua.Refused):
                self.aqua.parse_result(encode(template),b"",self.binding,case)
            result={**template,"gitPush":value}
            self.assertEqual(self.aqua.parse_result(encode(result),b"",self.binding,case),result)

    def test_readback_preserves_unconfigured_originals_not_a_new_tracking_snapshot(self):
        case=create.CASES[0]
        before={"config":(1,"original"),"index":(2,"original"),"absent-tracking":("refs",3),"objects":{}}
        f=SimpleNamespace(push_cases={case:{"calls":0,"end":140.0,"before":copy.deepcopy(before),"version":"public git fixture"}},
            push_end=200.0,inflight=False,last_returned=True,close_errors=0,path=Path("/inert"),
            push_entered={case},push_completed=set(),_namespace=lambda:None,push_tool=(None,None,None,"a"*64))
        with patch.object(setup,"parents_current"),patch.object(setup,"tool_current"),\
                patch.object(setup.time,"monotonic",return_value=100.0),\
                patch.object(setup,"_capture",return_value={**before,"absent-tracking":("refs",4)}) as capture:
            with self.assertRaises(ValueError):setup.readback(f,case,report(case),setup._need)
            self.assertEqual(f.push_completed,set())
            capture.return_value=before
            f.last_returned=False
            with self.assertRaises(ValueError):setup.readback(f,case,report(case),setup._need)
            f.last_returned=True
            value=setup.readback(f,case,report(case),setup._need)
            self.assertTrue(value["upstreamAbsent"] and value["localTrackingAbsent"] and value["untrackedPreserved"])
            self.assertFalse(value["nativeAuthority"])

    def test_original_five_case_driver_retains_order_and_no_next_case_after_missing_return(self):
        a,events=self.aqua,[]
        f=SimpleNamespace(cases=create.CASES,path=Path("/inert-owned-create"),inflight=False,last_returned=True,
            recovery_runtime_paths=lambda:events.append("runtime"),
            before_call=lambda c:events.append(("before",c)))
        failure=RuntimeError("inert original did not return")
        def owner(argv,**kwargs):
            self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
            self.assertEqual(kwargs["timeout"],73)
            events.append(("call",argv[1]))
            raise failure
        with patch.object(a.PUSH,"before_invocation",side_effect=lambda f,c,r,u:events.append(("setup",c))),\
                patch.object(a.PUSH,"remaining",return_value=73),patch.object(a.PUSH,"readback") as readback,\
                patch.object(a,"parse_result") as parse,patch.object(a,"app_environment",return_value={}):
            with self.assertRaises(RuntimeError) as caught:
                a.run_cases(self.binding,f,owner,501,"runner",lambda v:self.fail("no emit"),create.SCOPE)
            self.assertIs(caught.exception,failure)
            self.assertEqual(events,["runtime",("setup",create.CASES[0]),("before",create.CASES[0]),("call",create.CASES[0])])
            self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
            readback.assert_not_called();parse.assert_not_called()

    def test_same_run_cases_consumes_exact_five_original_returns_including_prepare_only(self):
        a,m,events=self.aqua,self.current,[]
        f=SimpleNamespace(cases=create.CASES,path=Path("/inert-owned-create"),inflight=False,last_returned=True,
            recovery_runtime_paths=lambda:events.append("runtime"),before_call=lambda c:events.append(("before",c)),
            prepare=lambda:events.append("prepare"),close=lambda:events.append("close"))
        def owner(argv,**kwargs):
            self.assertEqual(kwargs["timeout"],73)
            self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
            case=argv[1]; events.append(("call",case))
            value={**a.expected_result(self.binding,case),"gitPush":report(case)}
            return subprocess.CompletedProcess(argv,0,a.MARKER+json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n",b"")
        def readback(f,case,value,need):
            self.assertFalse(f.inflight);self.assertTrue(f.last_returned)
            self.assertIs(a.PUSH.report(value,case,need),value)
            events.append(("readback",case))
            return {"inertOnly":True}
        emitted=[]
        with patch.object(a.PUSH,"before_invocation",side_effect=lambda f,c,r,u:events.append(("setup",c))),\
                patch.object(a.PUSH,"remaining",return_value=73),patch.object(a.PUSH,"readback",side_effect=readback),\
                patch.object(a,"app_environment",return_value={}),patch.object(a,"Fixtures",return_value=f),\
                patch.object(a,"load_owner",return_value=SimpleNamespace(run_owned=owner)),\
                patch.object(a,"emit_record",side_effect=lambda value,stream:emitted.append(value)),\
                patch.object(m,"_admit_runtime"),patch.object(m,"_current"):
            env={"MRK_MACOS_NATIVE_SCOPE":m.GIT_SCOPE,"MRK_MACOS_PACKAGE_ROLE":m.ROLE,"GITHUB_REF":m.REF}
            self.assertEqual(m._run(a,self.binding,501,20,"runner",Path("/inert"),env,scope=create.SCOPE),0)
        self.assertEqual([x[1] for x in events if isinstance(x,tuple) and x[0]=="call"],list(create.CASES))
        self.assertEqual([v["case"] for v in emitted[:-1]],list(create.CASES))
        self.assertFalse(emitted[1]["observer"]["gitPush"]["applyOriginalJoined"])
        self.assertEqual(emitted[-1]["type"],"macos-git-push-create-current-complete")
        self.assertEqual(emitted[-1]["cases"],list(create.CASES))
        self.assertFalse(emitted[-1]["shippingBinaryQualified"])
        self.assertEqual(events[-1],"close")
        self.assertEqual([x[0] for x in events if isinstance(x,tuple)], ["setup","before","call","readback"]*5)


if __name__=="__main__":
    unittest.main()
