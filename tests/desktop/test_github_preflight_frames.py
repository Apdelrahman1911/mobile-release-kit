"""Inert journal-record/two-frame contracts, not filesystem or native evidence."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mobile_release import _desktop_github_preflight_engine as engine
from mobile_release import _github_preflight_journal as journal
from mobile_release import github_preflight as policy
from test_github_preflight import PRIVATE, RUN, execute, prepared, target


def initial(kind: str = "dispatch") -> dict:
    action = policy.Action(kind, target(), None if kind == "prepare" else prepared(),
                           str(RUN) if kind == "track" else None)
    return {"protocol": policy.PROTOCOL, "id": "github-preflight-1", "action": action.value(),
            "pendingScope": None, "home": None if kind == "prepare" else "/home/mrk"}


def frame(value: object) -> bytes:
    return journal.canonical(value) + b"\n"


class GitHubPreflightFrameTests(unittest.TestCase):
    def test_intent_and_run_are_exact_canonical_noncredential_records(self):
        raw = journal.intent_bytes(prepared())
        self.assertEqual(journal.parse_intent(raw), prepared())
        self.assertNotIn(PRIVATE.encode(), raw)
        digest = hashlib.sha256(raw).hexdigest()
        run = journal.run_bytes(digest, str(RUN))
        self.assertEqual(journal.parse_run(run, digest), str(RUN))
        for invalid in (raw[:-1], raw + b"\n", b" " + raw, raw.replace(b'"schemaVersion":1', b'"schemaVersion":true')):
            with self.assertRaises(ValueError):
                journal.parse_intent(invalid)
        for key, value in (("intentSha256", "e" * 64), ("attempt", 2), ("schemaVersion", True),
                           ("runId", RUN), ("token", PRIVATE), ("outcome", "success")):
            changed = json.loads(run); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                journal.parse_run(frame(changed), digest)

    def test_intent_rejects_broadened_authority_and_modified_caller(self):
        value = json.loads(journal.intent_bytes(prepared()))
        for key, altered in (("token", PRIVATE), ("dispatchAllowed", True), ("runId", str(RUN))):
            with self.assertRaises(ValueError):
                journal.parse_intent(frame({**value, key: altered}))
        changed = copy.deepcopy(value)
        changed["prepared"]["callerSha256"] = "0" * 64
        with self.assertRaises(ValueError):
            journal.parse_intent(frame(changed))

    def test_initial_contains_no_credential_and_binds_exact_ready_digest(self):
        for kind, status in (("prepare", "not-applicable"), ("dispatch", "durable-intent"),
                             ("track", "matched-intent"), ("reconcile", "matched-intent")):
            raw = frame(initial(kind)); request = engine.parse_initial(raw)
            ready = json.loads(engine.ready_frame(request))
            self.assertLessEqual(len(engine.ready_frame(request)), engine.MAX_READY_BYTES)
            self.assertEqual(ready, {"protocol": policy.PROTOCOL, "id": request.id,
                                    "ready": {"requestSha256": hashlib.sha256(raw).hexdigest(), "journal": status}})
            changed = initial(kind); changed["token"] = PRIVATE
            with self.assertRaises(ValueError):
                engine.parse_initial(frame(changed))

        from mobile_release import _desktop_github_setup_engine as setup_engine
        from mobile_release import _desktop_github_engine as private
        from mobile_release import github_setup_remote as setup
        from mobile_release._github_connection_transport import ReadResult, _control, _CloseFailure
        target_data = {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1", "repositoryId": "2",
                       "selection": {"kind": "actions_enabled", "enabled": True}}
        action_data = {"kind": "prepare", "target": target_data, "prepared": None}
        initial_data = frame({"protocol": setup.PROTOCOL, "id": "setup", "action": action_data})
        request = setup.parse_initial(initial_data)
        go_data = frame({"protocol": setup.PROTOCOL, "id": "setup", "go": {"requestSha256": request.digest, "token": PRIVATE}})
        def run_case(fault=None):
            events, outgoing, closed = [], bytearray(), []
            incoming = [initial_data, go_data, b""]
            clock = [100.0]
            def read(fd, size):
                self.assertEqual(fd, 10)
                events.append("read")
                if len(incoming) == 2:
                    self.assertIn(b'"ready"', outgoing)
                    if fault == "bad-go":
                        return incoming.pop(0).replace(request.digest.encode(), b"0" * 64)
                    if fault == "late-go":
                        clock[0] = 110.0
                block = incoming.pop(0)
                self.assertLessEqual(len(block), size)
                return block
            def write(fd, data):
                self.assertEqual(fd, 11)
                events.append("write")
                if fault == "write":
                    raise OSError("inert original output failure")
                take = min(len(data), 37)  # Real bounded writer partial-progress path.
                outgoing.extend(data[:take])
                return take
            def close(fd):
                closed.append(fd)
                if fault in {"close", "close-interrupt", "transport-and-close"} and fd == 12:
                    if fault == "close-interrupt":
                        raise KeyboardInterrupt()
                    raise OSError("inert original close failure")
            ports = SimpleNamespace(dup=lambda fd: 10 + fd, open=lambda *_args: 12,
                                    set_inheritable=lambda *_args: None, dup2=lambda *_args, **_kwargs: None,
                                    read=read, write=write, close=close, devnull="/inert/null", O_RDONLY=0,
                                    path=setup_engine.os.path)
            class Reader:
                def __init__(self):
                    self.cursor = setup.Schedule(setup.Action.parse(action_data))
                def read(self, step, reference=None):
                    self.cursor.claim(step, reference)
                    events.append(step)
                    if fault in {"transport-close", "transport-and-close"}:
                        raise _CloseFailure("inert original transport close")
                    body = ({"id": 1, "login": "owner"} if step == "account" else
                            {"id": 2, "full_name": "owner/repo", "default_branch": "main", "visibility": "private", "archived": False}
                            if step.startswith("repository-") else
                            {"enabled": False, "allowed_actions": "selected", "sha_pinning_required": True})
                    return ReadResult({"status": 200, "body": body, "failure": "none"}, _control())
            def factory(action, token, **kwargs):
                self.assertEqual((action.value(), token, kwargs), (action_data, PRIVATE, {"started": 100.0, "runtime_dir": "/inert/runtime"}))
                self.assertEqual(incoming, [])  # GO and its actual EOF already consumed.
                events.append("factory")
                return Reader()
            timer = SimpleNamespace(monotonic=lambda: clock[0])
            with patch.object(setup_engine, "os", ports), patch.object(private, "os", ports), \
                 patch.object(setup_engine, "time", timer), patch.object(private, "time", timer), \
                 patch.object(setup, "_make_live_reader", side_effect=factory):
                status = setup_engine.main(started=100.0, runtime_dir="/inert/runtime")
            return status, bytes(outgoing), events, closed
        for fault in (None, "bad-go", "late-go", "write", "close", "close-interrupt", "transport-close", "transport-and-close"):
            status, outgoing, events, closed = run_case(fault)
            self.assertEqual(closed, [12, 11, 10])
            self.assertNotIn(PRIVATE.encode(), outgoing)
            self.assertEqual(status, 0 if fault is None else 74 if fault in {"close", "close-interrupt"} else 70)
            if fault in {"bad-go", "late-go", "write"}:
                self.assertNotIn("factory", events)
            if fault is None or fault in {"close", "close-interrupt"}:
                result = json.loads(outgoing.splitlines()[1])["result"]
                self.assertEqual(result["reason"], "none")
                self.assertFalse(result["writeClaimed"])
                self.assertEqual(events[events.index("factory") + 1:], ["account", "repository-before", "resource-before", "repository-after"] + ["write"] * events[events.index("factory") + 1:].count("write"))

    def test_initial_and_go_frames_reject_extra_pipelined_duplicate_or_unbound_input(self):
        request = engine.parse_initial(frame(initial()))
        good = {"protocol": policy.PROTOCOL, "id": request.id,
                "go": {"requestSha256": request.digest, "token": PRIVATE}}
        self.assertEqual(engine.parse_go(frame(good), request), PRIVATE)
        for raw in (frame(good) + frame(good), frame(good) + b" ", frame(good).replace(b'"go":', b'"go":null,"go":'),
                    frame({**good, "url": "https://other.invalid/"}), frame({**good, "id": "different"}),
                    frame({**good, "go": {"requestSha256": "0" * 64, "token": PRIVATE}})):
            with self.assertRaises(ValueError):
                engine.parse_go(raw, request)
        for raw in (frame(initial()) + frame(good), frame(initial())[:-1], b" " + frame(initial()),
                    b'{"x":' * 40 + b"null" + b"}" * 40 + b"\n"):
            with self.assertRaises(ValueError):
                engine.parse_initial(raw)

        from mobile_release import _desktop_github_setup_engine as setup_engine
        from mobile_release import github_setup_remote as setup
        value = {"protocol": setup.PROTOCOL, "id": "setup", "action": {"kind": "prepare", "prepared": None,
                 "target": {"projectBinding": "a" * 64, "repository": "owner/repo", "accountId": "1", "repositoryId": "2",
                            "selection": {"kind": "actions_enabled", "enabled": True}}}}
        raw = frame(value)
        for supplied in (raw + raw, b" " * (setup.MAX_INITIAL_BYTES + 1), raw[:-1]):
            parts = [supplied[:4096], supplied[4096:], b""] if len(supplied) > 4096 else [supplied, b""]
            ports = SimpleNamespace(read=lambda _fd, _maximum: parts.pop(0))
            with patch.object(setup_engine, "os", ports), patch.object(setup_engine, "time", SimpleNamespace(monotonic=lambda: 100.0)):
                with self.assertRaises(ValueError):
                    setup_engine._read_initial(10, 110.0)

    def test_pending_is_fresh_native_scope_only_and_go_contains_no_token(self):
        value = initial(); value["action"] = None
        value["pendingScope"] = {key: target().value()[key] for key in
                                 ("projectBinding", "repository", "accountId", "repositoryId")}
        request = engine.parse_initial(frame(value))
        go = {"protocol": policy.PROTOCOL, "id": request.id,
              "go": {"requestSha256": request.digest, "token": None}}
        self.assertIsNone(engine.parse_go(frame(go), request))
        go["go"]["token"] = PRIVATE
        with self.assertRaises(ValueError):
            engine.parse_go(frame(go), request)
        for change in ({"home": None}, {"action": initial()["action"]},
                       {"pendingScope": {**value["pendingScope"], "token": PRIVATE}}):
            with self.assertRaises(ValueError):
                engine.parse_initial(frame({**value, **change}))
        result = engine.encode_result(request, None, [{"prepared": prepared().value(), "runId": str(RUN)}])
        self.assertNotIn(PRIVATE.encode(), result)
        self.assertIsNone(json.loads(result)["result"])

    def test_final_result_preserves_accepted_uncertain_and_observed_distinctions(self):
        for kind in ("prepare", "dispatch", "track", "reconcile"):
            request = engine.parse_initial(frame(initial(kind)))
            result, _ = execute(kind)
            final = json.loads(engine.encode_result(request, result))
            self.assertEqual(final["result"], result)
            self.assertIsNone(final["pending"])
            if kind == "dispatch":
                self.assertEqual(final["result"]["effect"], "accepted")
                self.assertIsNone(final["result"]["run"])
                result["effect"] = "not-sent"
                with self.assertRaises(ValueError):
                    engine.encode_result(request, result)
            result["token"] = PRIVATE
            with self.assertRaises(ValueError):
                engine.encode_result(request, result)



class GitHubPreflightBootstrapTests(unittest.TestCase):
    """Fixed bootstrap SOURCE plus recording DATA; no runtime or network call."""

    @staticmethod
    def _bootstrap():
        path = Path(__file__).resolve().parents[2] / "desktop" / "github_preflight_bootstrap.py"
        spec = importlib.util.spec_from_file_location("_mrk_preflight_bootstrap_contract", path)
        if spec is None or spec.loader is None:
            raise AssertionError("fixed bootstrap SOURCE is unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    @staticmethod
    def _system(**changes):
        values = dict(argv=["fixed-bootstrap", "/inert/core.zip"],
                      flags=SimpleNamespace(isolated=True, no_site=True),
                      dont_write_bytecode=True, version_info=(3, 11),
                      platform="darwin", path=[])
        values.update(changes)
        return SimpleNamespace(**values)

    @staticmethod
    def _run(module, system, *, source="/inert/runtime/github_preflight_bootstrap.py"):
        # Replacing this module's references never edits the process sys.path or
        # clock. The already imported fixed engine entry is a recording double.
        with patch.object(module, "sys", system), patch.object(module, "__file__", source), \
             patch.object(module, "time", SimpleNamespace(monotonic=lambda: 11.0)), \
             patch.object(engine, "main", return_value=17) as entry:
            code = module.main()
        return code, entry

    def test_exact_linux_and_darwin_admit_only_the_fixed_engine_family(self):
        module = self._bootstrap()
        for platform in ("linux", "darwin"):
            system = self._system(platform=platform)
            with self.subTest(platform=platform):
                code, entry = self._run(module, system)
                self.assertEqual(code, 17)
                entry.assert_called_once_with(started=11.0, runtime_dir="/inert/runtime")
                self.assertEqual(system.path, ["/inert/core.zip"])

        from mobile_release import _desktop_github_setup_engine as setup_engine
        path = Path(__file__).resolve().parents[2] / "desktop" / "github_setup_bootstrap.py"
        spec = importlib.util.spec_from_file_location("_mrk_setup_bootstrap_contract", path)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        setup_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(setup_module)  # Real import only; __main__ is never invoked.
        for platform, expected in (("darwin", 17), ("linux", 78), ("Darwin", 78), ("win32", 78)):
            system = self._system(platform=platform)
            with patch.object(setup_module, "sys", system), patch.object(setup_module, "__file__", "/inert/runtime/github_setup_bootstrap.py"), \
                 patch.object(setup_module, "time", SimpleNamespace(monotonic=lambda: 11.0)), \
                 patch.object(setup_engine, "main", return_value=17) as entry:
                self.assertEqual(setup_module.main(), expected)
            if expected == 17:
                entry.assert_called_once_with(started=11.0, runtime_dir="/inert/runtime")
                self.assertEqual(system.path, ["/inert/core.zip"])
            else:
                entry.assert_not_called()
                self.assertEqual(system.path, [])
        for changes in ({"argv": []}, {"argv": ["fixed"]}, {"argv": ["fixed", "relative.zip"]},
                        {"argv": ["fixed", "/inert/core.zip", "extra"]},
                        {"flags": SimpleNamespace(isolated=False, no_site=True)},
                        {"flags": SimpleNamespace(isolated=True, no_site=False)},
                        {"dont_write_bytecode": False}, {"version_info": (3, 10)}):
            system = self._system(**changes)
            with patch.object(setup_module, "sys", system), patch.object(setup_module, "__file__", "/inert/runtime/github_setup_bootstrap.py"), \
                 patch.object(setup_module, "time", SimpleNamespace(monotonic=lambda: 11.0)), \
                 patch.object(setup_engine, "main", side_effect=AssertionError("invalid Setup bootstrap entered engine")):
                self.assertEqual(setup_module.main(), 78)
            self.assertEqual(system.path, [])

    def test_other_platforms_flags_and_unbound_paths_refuse_before_engine_entry(self):
        module = self._bootstrap()
        cases = [dict(platform=value) for value in ("linux2", "Darwin", "win32", "freebsd", "")]
        cases += [dict(argv=value) for value in ([], ["fixed-bootstrap"],
                  ["fixed-bootstrap", "/inert/core.zip", "extra"], ["fixed-bootstrap", "relative.zip"])]
        cases += [dict(flags=SimpleNamespace(isolated=False, no_site=True)),
                  dict(flags=SimpleNamespace(isolated=True, no_site=False)),
                  dict(dont_write_bytecode=False), dict(version_info=(3, 10))]
        for changes in cases:
            system = self._system(**changes)
            with self.subTest(changes=changes):
                code, entry = self._run(module, system)
                self.assertEqual(code, 78)
                entry.assert_not_called()
                self.assertEqual(system.path, [])
        for source in ("github_preflight_bootstrap.py", ""):
            system = self._system()
            with self.subTest(source=source):
                code, entry = self._run(module, system, source=source)
                self.assertEqual(code, 78)
                entry.assert_not_called()
                self.assertEqual(system.path, [])


if __name__ == "__main__":
    unittest.main()
