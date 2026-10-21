"""Inert route/original-call tests; no CLT, native app, provider or credentials.

The complete fixture comparator is exercised as comparison DATA. It never
constructs a SourceBook, Candidate ACK, native status or production grant.
"""
import copy
import configparser
import json
import os
import tempfile
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_macos_git_push_observation as previous
setup = previous._module("mrk_upstream_fixture_tests", "macos_git_upstream_qualification.py")


def report():
    return dict(mechanism="same-original-git-upstream-v1",case=setup.CASE,
        readOriginalsJoined=2,prepareOriginalsJoined=2,applyOriginalJoined=True,
        unchangedReviewClosed=True,normalQuitOriginal=2,allOriginalsSettled=True,
        configOnly=True,newParentDirectories=4,trackingAbsent=True,worktreePreserved=True,
        networkRequested=False,bootstrapOverride=False,productionQualified=False)


def comparison(config=setup.CONFIG):
    def identity(inode, mode, size=0):
        return (1, inode, mode, 501, 20, 1, size, 100, 100)
    def directory(inode, names):
        return ("directory",identity(inode,stat.S_IFDIR|0o700),tuple(sorted(names)))
    def file(inode, body):
        import hashlib
        return ("file",identity(inode,stat.S_IFREG|0o600,len(body)),hashlib.sha256(body).hexdigest(),body)
    tree={".":directory(1,("HEAD","COMMIT_EDITMSG","config","index","refs","logs","objects")),
        "refs":directory(2,("heads","tags")),"logs/refs":directory(3,("heads",)),
        "refs/heads":directory(4,("main",)),"logs/refs/heads":directory(5,("main",)),
        "HEAD":file(6,b"ref: refs/heads/main\n"),"COMMIT_EDITMSG":file(60,b"last-setup-commit"),"index":file(7,b"retained-index"),
        "objects/ab/"+"c"*38:file(8,b"retained-compressed-object"),"config":file(9,config)}
    before={"files":{"untracked.txt":(identity(20,stat.S_IFREG|0o600),"unchanged")},
            "directories":{".":identity(21,stat.S_IFDIR|0o700)},"git":tree}
    after=copy.deepcopy(before)
    for path in (".","refs","logs/refs"):
        kind, original, names=tree[path]
        after["git"][path]=(kind,(*original[:7],200,200),
            tuple(sorted((*names,"remotes"))) if path!="." else names)
    after["git"]["config"]=file(30,config+setup.APPENDED)
    for i,path in enumerate(setup.CREATED):
        after["git"][path]=directory(40+i,() if path.endswith("/origin") else ("origin",))
    return before,after


class UpstreamObservationTests(unittest.TestCase):
    def setUp(self):
        for name in ("subprocess.Popen","socket.socket","socket.create_connection"):
            self.enterContext(patch(name,side_effect=AssertionError("Native effects forbidden")))
        self.aqua=previous._module("_upstream_aqua", "macos_aqua_qualification.py")
        self.current=previous._module("_upstream_current", "macos_identity_current_runtime.py")
        self.binding=self.aqua.Binding("a"*40,"123","1")

    def test_one_local_case_requires_same_combined_image_not_remote_control_or_generic_scope(self):
        a,m=self.aqua,self.current
        self.assertEqual(a.selected_cases(setup.SCOPE),setup.CASES)
        self.assertEqual(a.argument_scope(["--scope",setup.SCOPE]),setup.SCOPE)
        self.assertEqual(a.case_timeout(setup.CASE),120)
        self.assertEqual(m.arguments(["--target",m.TARGET,"--scope",setup.SCOPE]),setup.SCOPE)
        env={"MRK_MACOS_NATIVE_SCOPE":m.GIT_SCOPE}
        self.assertEqual(m.observation_scope(env,setup.SCOPE),setup.SCOPE)
        for scope in (m.FETCH_SCOPE,m.PUSH_SCOPE,m.TOOLS_SCOPE,setup.SCOPE,"disabled","all"):
            with self.subTest(scope=scope),self.assertRaises(m.Refused):
                m.observation_scope({"MRK_MACOS_NATIVE_SCOPE":scope},setup.SCOPE)
        self.assertEqual(a.selected_cases(m.PUSH_SCOPE),a.PUSH.CASES)
        self.assertEqual(a.selected_cases(m.PUSH_CREATE_SCOPE),a.PUSH.CREATE.CASES)
        self.assertEqual(a.selected_cases(m.FETCH_SCOPE),a.FETCH.CASES)
        home="/Users/fixed-public-runner"
        root=setup.fixture_path(self.binding,home)
        self.assertTrue(str(root).startswith(home+"/Library/Application Support/"))
        self.assertTrue(str(root).endswith("-"+setup.SCOPE))
        self.assertNotEqual(root,a.PUSH.fixture_path(self.binding,home))
        self.assertEqual(setup.application_path(self.binding,home).parts[-2:],(setup.CASE,setup.shared.APPLICATION))

    def test_real_bounded_comparison_reads_setup_commit_message_and_rejects_unlisted_metadata(self):
        # Tiny inert byte fixture only, no Git command or native source owner.
        with tempfile.TemporaryDirectory(prefix="mrk-upstream-comparison-") as temporary:
            root=Path(temporary)
            for name in ("refs","refs/heads","refs/tags","logs","logs/refs","logs/refs/heads","objects","objects/info","objects/pack"):
                (root/name).mkdir(mode=0o700)
            for name,body in {"HEAD":b"ref: refs/heads/main\n","config":setup.CONFIG,"index":b"inert-index",
                "COMMIT_EDITMSG":b"last public fixture message\n","refs/heads/main":b"a"*40+b"\n",
                "logs/HEAD":b"inert-log","logs/refs/heads/main":b"inert-log"}.items():
                (root/name).write_bytes(body);(root/name).chmod(0o600)
            f=self.aqua.Fixtures(self.binding,os.getuid(),os.getgid(),setup.SCOPE)
            try:
                with f._temporary(f._open(str(root),directory=True)) as held:
                    original=setup._git_tree(f,held)
                    self.assertEqual(original["config"][3],setup.CONFIG)
                    self.assertEqual(original,setup._git_tree(f,held))
                    self.assertIn("COMMIT_EDITMSG",original)
                    (root/"COMMIT_EDITMSG").write_bytes(b"different message")
                    self.assertNotEqual(original["COMMIT_EDITMSG"],setup._git_tree(f,held)["COMMIT_EDITMSG"])
                    (root/"foreign").write_bytes(b"unapproved")
                    with self.assertRaises(ValueError):setup._git_tree(f,held)
                self.assertEqual(f.fds,set());self.assertEqual(f.close_errors,0)
            finally:f.close()

    def test_only_four_explicit_keys_append_and_no_identity_or_tracking_file_is_created(self):
        parser=configparser.RawConfigParser()
        parser.read_string(setup.CONFIG.decode())
        self.assertEqual(parser.sections(),["core","user"])
        before=dict(parser["user"])
        parser.read_string((setup.CONFIG+setup.APPENDED).decode())
        self.assertEqual(dict(parser["user"]),before)
        self.assertEqual(dict(parser['remote "origin"']),{"url":"https://github.com/mrk-upstream-fixture/local.git",
            "fetch":"+refs/heads/*:refs/remotes/origin/*"})
        self.assertEqual(dict(parser['branch "main"']),{"remote":"origin","merge":"refs/heads/main"})
        self.assertEqual(len(setup.CREATED),4)
        self.assertTrue(all(not p.endswith("/main") for p in setup.CREATED))
        a,b=comparison();self.assertTrue(setup.compare(a,b))
        self.assertEqual(a,comparison()[0])  # Comparator does not normalize originals in place.

    def test_actual_init_core_probes_are_bounded_fixture_data_not_additional_config_authority(self):
        actual = setup.CONFIG.replace(b"repositoryformatversion = 0", b"\trepositoryformatversion = 0")
        actual = actual.replace(b"[user]\n", b"\tignorecase = true\n\tprecomposeunicode = false\n[user]\n")
        self.assertIs(setup.fixture_config(actual), actual)
        for bad in (actual+b"[remote \"origin\"]\nurl = https://github.com/other/repo.git\n",
                    actual.replace(b"filemode = true", b"filemode = false"),
                    actual.replace(b"[user]\n", b"\tignorecase = true\n[user]\n"),
                    actual.replace(b"[user]\n", b"\tworktree = /other\n[user]\n"),
                    actual.replace(b"MRK Upstream Fixture", b"other user"),
                    actual+b"[user]\n", actual+b"\n", actual.replace(b"\n",b"\r\n"),
                    b" "*4097, actual.decode()):
            with self.subTest(kind=type(bad).__name__), self.assertRaises(ValueError):
                setup.fixture_config(bad)

    def test_init_result_bytes_are_original_prefix_not_normalized_or_replaced_after_apply(self):
        actual = setup.CONFIG.replace(b"[user]\n", b"\tignorecase = true\n\tprecomposeunicode = true\n[user]\n")
        before, after = comparison(actual)
        self.assertTrue(setup.compare(before, after))
        for prefix in (setup.CONFIG, actual.replace(b"ignorecase = true", b"ignorecase = false")):
            bad=copy.deepcopy(after); old=bad["git"]["config"]
            bad["git"]["config"]=(*old[:3],prefix+setup.APPENDED)
            with self.assertRaises(ValueError):setup.compare(before,bad)
        self.assertEqual(before["git"]["config"][3],actual)

    def test_complete_comparison_refuses_changed_objects_index_head_foreign_entries_and_new_tracking(self):
        before,after=comparison()
        for path in ("HEAD","COMMIT_EDITMSG","index","objects/ab/"+"c"*38,"refs/heads"):
            with self.subTest(path=path):
                bad=copy.deepcopy(after);old=bad["git"][path]
                changed=(*old[1][:8],old[1][8]+1)
                bad["git"][path]=(old[0],changed,*old[2:])
                with self.assertRaises(ValueError):setup.compare(before,bad)
        for path in ("refs/remotes/origin/main","logs/refs/remotes/origin/main","foreign"):
            bad=copy.deepcopy(after);bad["git"][path]=after["git"]["HEAD"]
            with self.subTest(path=path),self.assertRaises(ValueError):setup.compare(before,bad)
        bad=copy.deepcopy(after);bad["files"]["untracked.txt"]=("changed",)
        with self.assertRaises(ValueError):setup.compare(before,bad)
        bad=copy.deepcopy(after);bad["directories"]["."]=("new-root",)
        with self.assertRaises(ValueError):setup.compare(before,bad)

    def test_only_exact_retained_parent_successors_and_config_prefix_mode_group_are_accepted(self):
        before,after=comparison()
        for path,field in (("refs",1),("logs/refs",1),(".",1),("refs/remotes/origin",3),("refs/remotes",4)):
            bad=copy.deepcopy(after);kind,identity,names=bad["git"][path];new=list(identity);new[field]+=1
            bad["git"][path]=(kind,tuple(new),names)
            with self.subTest(path=path,field=field),self.assertRaises(ValueError):setup.compare(before,bad)
        for field,value in ((1,9),(2,stat.S_IFREG|0o644),(4,99),(5,2)):
            bad=copy.deepcopy(after);kind,identity,h,body=bad["git"]["config"];new=list(identity);new[field]=value
            bad["git"]["config"]=(kind,tuple(new),h,body)
            with self.subTest(field=field),self.assertRaises(ValueError):setup.compare(before,bad)
        for body in (setup.APPENDED,setup.CONFIG+setup.APPENDED+b"[user]\nname = changed\n",setup.CONFIG):
            bad=copy.deepcopy(after);old=bad["git"]["config"];bad["git"]["config"]=(*old[:3],body)
            with self.assertRaises(ValueError):setup.compare(before,bad)
        bad=copy.deepcopy(after);k,i,n=bad["git"]["refs"];bad["git"]["refs"]=(k,i,(*n,"foreign"))
        with self.assertRaises(ValueError):setup.compare(before,bad)

    def test_report_never_fills_missing_joins_or_allows_remote_runtime_qualification_claim(self):
        failure=b"MRK_MACOS_AQUA_FAILURE_REASON=git-upstream-original-contract\n"
        self.assertEqual(self.aqua.failure_reason(failure,b""),"git-upstream-original-contract")
        self.assertIsNone(self.aqua.failure_reason(failure+failure,b""))
        value=report();self.assertIs(setup.report(value,setup.CASE,self.aqua.need),value)
        for key,bad in (("readOriginalsJoined",True),("prepareOriginalsJoined",1),("applyOriginalJoined",False),
                        ("unchangedReviewClosed",False),("allOriginalsSettled",False),("newParentDirectories",0),
                        ("bootstrapOverride",True),("networkRequested",True),("productionQualified",True),("extra",None)):
            with self.subTest(key=key),self.assertRaises(self.aqua.Refused):
                setup.report({**value,key:bad},setup.CASE,self.aqua.need)
        template=self.aqua.expected_result(self.binding,setup.CASE)
        self.assertIsNone(template["gitUpstream"])
        encode=lambda v:self.aqua.MARKER+json.dumps(v,sort_keys=True,separators=(",",":")).encode()+b"\n"
        with self.assertRaises(self.aqua.Refused):self.aqua.parse_result(encode(template),b"",self.binding,setup.CASE)
        actual={**template,"gitUpstream":value}
        self.assertEqual(self.aqua.parse_result(encode(actual),b"",self.binding,setup.CASE),actual)

    def test_setup_original_return_uses_remaining_case_clock_and_foreign_return_stays_inflight(self):
        f=SimpleNamespace(upstream_case={"end":104.0,"calls":0},upstream_end=200.0,close_errors=0,
            inflight=False,last_returned=True,path=Path("/inert"))
        def owner(argv,**kw):
            self.assertEqual(kw["timeout"],4);self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
            self.assertEqual(argv[:5],[setup.GIT,"-c","gc.auto=0","-c","maintenance.auto=false"])
            return subprocess.CompletedProcess(argv,0,b"bounded",b"")
        with patch.object(setup.time,"monotonic",return_value=100.0),patch.object(setup,"tool_current"):
            self.assertEqual(setup._call(f,owner,{},["--version"]),b"bounded")
            self.assertTrue(f.last_returned);self.assertFalse(f.inflight);self.assertEqual(f.upstream_case["calls"],1)
            with self.assertRaises(ValueError):setup._call(f,lambda *a,**k:subprocess.CompletedProcess(["foreign"],0,b"",b""),{},["--version"])
            self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
            with self.assertRaises(ValueError):setup._call(f,lambda *a,**k:self.fail("no retry"),{},["--version"])
        f.inflight=False
        with patch.object(setup.time,"monotonic",return_value=104.0),patch.object(setup,"tool_current") as tool:
            with self.assertRaises(ValueError):setup._call(f,lambda *a,**k:self.fail("no late call"),{},["--version"])
            tool.assert_not_called()

    def test_setup_exception_keeps_same_original_unknown_and_no_source_reinspection(self):
        f=SimpleNamespace(upstream_case={"end":140.0,"calls":0},upstream_end=200.0,close_errors=0,
            inflight=False,last_returned=True,path=Path("/inert"))
        failure=RuntimeError("inert original missing")
        with patch.object(setup.time,"monotonic",return_value=100.0),patch.object(setup,"tool_current") as tool:
            with self.assertRaises(RuntimeError) as caught:setup._call(f,lambda *a,**k:(_ for _ in ()).throw(failure),{},["--version"])
            self.assertIs(caught.exception,failure);self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
            self.assertEqual(tool.call_count,1)

    def _drive(self,cut=None):
        a,m,events=self.aqua,self.current,[]
        f=SimpleNamespace(cases=setup.CASES,path=Path("/inert-owned-upstream"),inflight=False,last_returned=True,
            recovery_runtime_paths=lambda:events.append("runtime"),before_call=lambda c:events.append("before"),
            prepare=lambda:events.append("prepare"))
        def close():
            events.append("close")
            if cut=="close":raise RuntimeError("inert close unknown")
        f.close=close
        def owner(argv,**kwargs):
            self.assertEqual(argv,[a.EXECUTABLE,setup.CASE]);self.assertEqual(kwargs["timeout"],73)
            self.assertTrue(f.inflight);self.assertFalse(f.last_returned);events.append("call")
            if cut=="return":raise RuntimeError("inert original lost")
            value={**a.expected_result(self.binding,setup.CASE),"gitUpstream":report()}
            return subprocess.CompletedProcess(argv,0,a.MARKER+json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n",b"")
        def readback(f,case,value,need):
            self.assertFalse(f.inflight);self.assertTrue(f.last_returned)
            a.UPSTREAM.report(value,case,need);events.append("readback")
            if cut=="readback":raise RuntimeError("inert source drift")
            return {"inertOnly":True}
        currents=0
        def current(*args):
            nonlocal currents
            currents+=1;events.append("post")
            if cut=="post" and currents==2:raise RuntimeError("inert runtime post failed")
        emitted=[]
        with patch.object(a.UPSTREAM,"before_invocation",side_effect=lambda *args:events.append("setup")),\
                patch.object(a.UPSTREAM,"remaining",return_value=73),patch.object(a.UPSTREAM,"readback",side_effect=readback),\
                patch.object(a,"app_environment",return_value={}),patch.object(a,"Fixtures",return_value=f),\
                patch.object(a,"load_owner",return_value=SimpleNamespace(run_owned=owner)),\
                patch.object(a,"emit_record",side_effect=lambda value,stream:emitted.append(value)),\
                patch.object(m,"_admit_runtime"),patch.object(m,"_current",side_effect=current):
            env={"MRK_MACOS_NATIVE_SCOPE":m.GIT_SCOPE,"MRK_MACOS_PACKAGE_ROLE":m.ROLE,"GITHUB_REF":m.REF}
            result=m._run(a,self.binding,501,20,"runner",Path("/inert"),env,scope=setup.SCOPE)
        return result,events,emitted,f

    def test_actual_current_driver_consumes_one_original_then_readback_post_close_before_completion(self):
        result,events,emitted,f=self._drive()
        self.assertEqual(result,0);self.assertFalse(f.inflight)
        self.assertEqual(events,["prepare","post","runtime","setup","before","call","readback","post","post","close"])
        self.assertEqual(emitted[-1]["type"],"macos-git-upstream-current-complete")
        self.assertEqual(emitted[-1]["cases"],[setup.CASE]);self.assertFalse(emitted[-1]["shippingBinaryQualified"])
        self.assertEqual(sum(v.get("type")=="macos-aqua-case" for v in emitted),1)

    def test_original_return_readback_runtime_post_or_close_failure_never_emits_completion_or_retries(self):
        for cut in ("return","readback","post","close"):
            with self.subTest(cut=cut):
                result,events,emitted,f=self._drive(cut)
                self.assertEqual(result,1);self.assertEqual(events.count("call"),1)
                self.assertFalse(any(v.get("type")=="macos-git-upstream-current-complete" for v in emitted))
                if cut=="return":
                    self.assertTrue(f.inflight);self.assertFalse(f.last_returned)
                    self.assertNotIn("readback",events);self.assertNotIn("close",events)
                elif cut=="readback":self.assertEqual(events.count("post"),1)

    def test_readback_requires_actual_return_and_complete_tree_before_marking_case_done(self):
        before,after=comparison()
        f=SimpleNamespace(upstream_case={"before":before,"calls":7,"end":140.0,"version":"public git build"},
            upstream_end=200.0,upstream_entered=True,upstream_completed=False,inflight=False,last_returned=True,
            close_errors=0,_namespace=lambda:None,upstream_tool=(None,None,None,"a"*64))
        with patch.object(setup,"parents_current"),patch.object(setup,"tool_current"),\
                patch.object(setup.time,"monotonic",return_value=100.0),patch.object(setup,"_capture",return_value=after) as capture:
            f.last_returned=False
            with self.assertRaises(self.aqua.Refused):setup.readback(f,setup.CASE,report(),self.aqua.need)
            capture.assert_not_called();self.assertFalse(f.upstream_completed)
            f.last_returned=True
            bad=copy.deepcopy(after);bad["git"]["HEAD"]=before["git"]["index"];capture.return_value=bad
            with self.assertRaises(ValueError):setup.readback(f,setup.CASE,report(),self.aqua.need)
            self.assertFalse(f.upstream_completed)
            capture.return_value=after
            value=setup.readback(f,setup.CASE,report(),self.aqua.need)
            self.assertTrue(f.upstream_completed);self.assertTrue(value["trackingAbsent"])
            self.assertFalse(value["nativeAuthority"]);self.assertFalse(value["networkRequested"])
            with self.assertRaises(self.aqua.Refused):setup.readback(f,setup.CASE,report(),self.aqua.need)


if __name__=="__main__":unittest.main()
