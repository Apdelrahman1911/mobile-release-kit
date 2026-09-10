"""Pure native-admission regressions: every reached native/resource effect is fake.

These tests are not macOS evidence. Loading the helper only defines its inert
functions; no probe entry, listener, subprocess, account or permission operation
is executed. Each test replaces the helper's namespace, not shared stdlib APIs.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]


def helper():
    spec = importlib.util.spec_from_file_location(
        "_mrk_pure_native_authority", ROOT / ".github/scripts/ci_native_authority.py")
    if spec is None or spec.loader is None:
        raise AssertionError("fixed native helper is missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def clock(module, now=10.0):
    return patch.object(module, "time", SimpleNamespace(monotonic=lambda: now))


def mach_row(codes):
    return {"schema": 1, "codes": list(codes), "released": [code == 0 for code in codes]}


def aia_fixtures(module):
    # Deliberately not actual X.509. Native effects are wholly replaced below.
    return [{"case": name, "route": f"/mrk-aia/{index:032x}/{name}.der",
             **{role: f"\x30synthetic-{name}-{role}".encode() for role in ("root", "issuer", "leaf")}}
            for index, name in enumerate(module._CASES)]


def aia_evidence(module, fixtures):
    rows, requests = [], []
    for fixture in fixtures:
        name = fixture["case"]
        online = name in ("online", "mutant")
        rows.append({"case": name, "baseline_network": True, "network": online,
                     "keychains": name != "product-offline", "accepted": online, "error": not online,
                     "result": 4 if online else 5, "chain": [module.hashlib.sha256(fixture[role]).hexdigest()
                         for role in (("leaf", "issuer", "root") if online else ("leaf",))]})
        if online:
            requests.append((fixture["route"], module.hashlib.sha256(fixture["issuer"]).hexdigest()))
    return {"schema": 1, "cases": rows}, requests


class NativeAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.module = helper()

    def test_fixed_cli_forms_use_only_the_selected_helper_role(self):
        m = self.module

        class PurePath(PurePosixPath):
            def resolve(self, *, strict):
                return self

        prefix = PurePath("/private/tmp/mrk-pure/bootstrap")
        identity = SimpleNamespace(**{name: lambda: 60123 for name in ("getuid", "geteuid", "getgid", "getegid")})
        mach = Mock(return_value=mach_row([0, 1102, 0]))
        nested = Mock(return_value=mach_row([1100] * 3))
        prepare, evaluate, printed = Mock(), Mock(return_value={"schema": 1, "cases": []}), Mock()
        with clock(m), patch.multiple(m, Path=PurePath, __file__=str(prefix / "ci_native_authority.py"),
                                     os=identity, sys=SimpleNamespace(platform="darwin"), mach_probe=mach,
                                     mach_nonexpand=nested, prepare_aia=prepare, evaluate_aia=evaluate), \
                patch.object(m, "print", printed, create=True):
            for args in (["--mach", "100.0"], ["--mach-nonexpand", str(prefix / "native-authority-source.sb"), "100.0"],
                         ["--aia-prepare", "60123", "100.0"], ["--aia-evaluate", "60123", "100.0"]):
                self.assertEqual(m._main(args), 0)
            for args in (["--mach-nonexpand", "100.0"], ["--mach", "extra", "100.0"],
                         ["--aia-evaluate", "060123", "100.0"], ["--arbitrary-role", "100.0"]):
                with self.subTest(args=args), self.assertRaises(m.NativeControlError):
                    m._main(args)
        mach.assert_called_once_with(100.0)
        nested.assert_called_once_with(prefix / "native-authority-source.sb", 100.0)
        prepare.assert_called_once_with(60123, 100.0)
        evaluate.assert_called_once_with(60123, 100.0)
        self.assertEqual(printed.call_count, 4)

    def test_failure_attribution_is_bounded_closed_and_never_copies_private_values(self):
        m = self.module
        try:
            m._require(False, "private-message-canary")
        except m.NativeControlError as error:
            native = error
        foreign = type("PrivateForeignErrorCanary", (Exception,), {})("private-argument-canary")
        group = BaseExceptionGroup("private-group-canary", [native, foreign])
        note = m._failure_note(group, ["--aia-evaluate", "private-URL-canary", "private-deadline-canary"])
        self.assertEqual(note["role"], "aia-evaluate")
        self.assertEqual(note["error_count"], 2)
        self.assertFalse(note["truncated"])
        self.assertEqual([row["exception"] for row in note["exceptions"]], ["NativeControlError", "Exception"])
        self.assertTrue(note["exceptions"][0]["lines"])
        self.assertEqual(note["exceptions"][1]["lines"], [])
        raw = m._FAILURE_PREFIX + json.dumps(note).encode() + b"\n"
        self.assertEqual(m.parse_failure(raw, "aia-evaluate"), note)
        for private in ("private-", "PrivateForeignErrorCanary", str(ROOT)):
            self.assertNotIn(private, raw.decode())
        for bounded in (BaseExceptionGroup("private", [foreign] * 80), group):
            if bounded is group:
                for _ in range(80):
                    bounded = BaseExceptionGroup("private", [bounded])
            note = m._failure_note(bounded, ["--mach", "100.0"])
            self.assertTrue(note["truncated"])
            self.assertEqual(note["error_count"], len(note["exceptions"]))
            self.assertLessEqual(note["error_count"], 16)
            raw = m._FAILURE_PREFIX + json.dumps(note).encode() + b"\n"
            self.assertLessEqual(len(raw), 4096)
            self.assertEqual(m.parse_failure(raw, "mach"), note)

    def test_failed_child_diagnostic_parser_rejects_extra_data_types_and_wrong_roles(self):
        m = self.module
        good = {"schema": 1, "role": "aia-prepare", "error_count": 1, "truncated": False,
                "exceptions": [{"exception": "OSError", "lines": [10, 20]}]}
        encode = lambda value: m._FAILURE_PREFIX + json.dumps(value).encode() + b"\n"
        data = encode(good)
        self.assertEqual(m.parse_failure(data, "aia-prepare"), good)
        bad_data = [b"", data[:-1], data + b"private-output\n", b"prefix " + data,
                    data.replace(b'"schema": 1', b'"schema": 1, "schema": 1'), b"x" * 4097,
                    m._FAILURE_PREFIX + b"[" * 1800 + b"]" * 1800 + b"\n"]
        for key, value in (("schema", True), ("role", "aia-evaluate"), ("error_count", True),
                           ("error_count", 0), ("truncated", 0), ("private-extra", "canary"),
                           ("exceptions", [{"exception": "PrivateError", "lines": []}]),
                           ("exceptions", [{"exception": "OSError", "lines": [True]}]),
                           ("exceptions", [{"exception": "OSError", "lines": [20, 10]}]),
                           ("exceptions", [{"exception": "OSError", "lines": [10, 10]}]),
                           ("exceptions", [{"exception": "OSError", "lines": [10000]}]),
                           ("exceptions", [{"exception": "OSError", "lines": [], "message": "canary"}])):
            bad_data.append(encode({**good, key: value}))
        for raw in bad_data:
            with self.subTest(data=raw):
                self.assertIsNone(m.parse_failure(raw, "aia-prepare"))
        self.assertIsNone(m.parse_failure(data, "mach"))
        self.assertIsNone(m.parse_failure(data, "unknown"))

    def test_fixed_mach_inventory_and_closed_parser(self):
        m = self.module
        self.assertEqual(m.MACH_SERVICES, ("com.apple.trustd", "com.apple.trustd.agent",
                                           "com.apple.cfprefsd.daemon"))
        good = m.MACH_PREFIX + json.dumps(mach_row([0, 1102, 0])).encode() + b"\n"
        self.assertEqual(m.parse_mach(good), mach_row([0, 1102, 0]))
        for bad in (good + b"\n", good[:-1], good.replace(b'"schema": 1', b'"schema": 1,"schema": 1'),
                    good.replace(b'"schema": 1', b'"schema": true'), b"unknown\n",
                    m.MACH_PREFIX + json.dumps(mach_row([0, 5, 0])).encode() + b"\n",
                    m.MACH_PREFIX + json.dumps({**mach_row([0, 0, 0]), "released": [False] * 3}).encode() + b"\n"):
            with self.subTest(data=bad), self.assertRaises(m.NativeControlError):
                m.parse_mach(bad)

    def test_mach_negative_requires_real_matching_outside_positive(self):
        m = self.module
        positive, ordinary, authority = mach_row([0, 1102, 0]), mach_row([1100] * 3), mach_row([0, 1102, 1100])
        m.require_mach_controls(positive, ordinary, authority, ordinary)
        for baseline, plain, allowed, nested in (
                (mach_row([1102] * 3), ordinary, authority, ordinary),
                (mach_row([1102, 1102, 0]), ordinary, authority, ordinary),
                (positive, mach_row([0, 1100, 1100]), authority, ordinary),
                (positive, ordinary, mach_row([1100, 1102, 1100]), ordinary),
                (positive, ordinary, mach_row([0, 1102, 0]), ordinary),
                (positive, ordinary, authority, mach_row([1100, 0, 1100])),
                (positive, ordinary, mach_row([0, 0, 1100]), ordinary)):
            with self.subTest(rows=(baseline, plain, allowed, nested)), self.assertRaises(m.NativeControlError):
                m.require_mach_controls(baseline, plain, allowed, nested)

    def test_each_successful_mach_right_is_released_before_next_lookup(self):
        m, events = self.module, []
        replies = iter(((0, 41), (1102, 0), (0, 42)))

        def lookup(name):
            events.append(("lookup", name))
            return next(replies)

        api = SimpleNamespace(lookup=lookup, release=lambda port: events.append(("release", port)) or 0)
        with clock(m), patch.object(m, "sys", SimpleNamespace(platform="darwin")), patch.object(m, "_mach_api", return_value=api):
            self.assertEqual(m.mach_probe(100.0), mach_row([0, 1102, 0]))
        self.assertEqual(events, [("lookup", m.MACH_SERVICES[0]), ("release", 41),
                                  ("lookup", m.MACH_SERVICES[1]), ("lookup", m.MACH_SERVICES[2]), ("release", 42)])

    def test_failed_mach_deallocation_and_unknown_result_never_pass(self):
        m = self.module
        for reply, release in (((0, 51), 5), ((5, 0), 0), ((1102, 99), 0), ((0, 0), 0)):
            api = SimpleNamespace(lookup=Mock(return_value=reply), release=Mock(return_value=release))
            with self.subTest(reply=reply, release=release), clock(m), patch.object(m, "sys", SimpleNamespace(platform="darwin")), \
                    patch.object(m, "_mach_api", return_value=api), self.assertRaises(BaseExceptionGroup):
                m.mach_probe(100.0)
            self.assertEqual(api.lookup.call_count, 1)
            self.assertEqual(api.release.call_count, int(reply[0] == 0 and bool(reply[1])))

    def test_cutoff_and_wrong_platform_reject_before_native_acquisition(self):
        m = self.module
        native = Mock(side_effect=AssertionError("no actual native acquisition"))
        with clock(m), patch.object(m, "sys", SimpleNamespace(platform="linux")), patch.object(m, "_mach_api", native):
            for deadline in (True, float("nan"), 9.0, 5000.0, 100.0):
                with self.subTest(deadline=deadline), self.assertRaises(m.NativeControlError):
                    m.mach_probe(deadline)
        native.assert_not_called()

    def test_original_child_failure_keeps_kill_wait_and_close_errors(self):
        m = self.module
        child = SimpleNamespace(returncode=None, stdout=SimpleNamespace(close=Mock(side_effect=OSError("close"))),
                                wait=Mock(side_effect=TimeoutError("wait")), kill=Mock(side_effect=OSError("kill")))
        process = SimpleNamespace(DEVNULL=-3, PIPE=-1, Popen=Mock(return_value=child))
        with clock(m), patch.object(m, "subprocess", process), self.assertRaises(BaseExceptionGroup) as raised:
            m._command(["/fixed/fixture"], 100.0)
        self.assertEqual(len(raised.exception.exceptions), 4)
        self.assertEqual(child.wait.call_count, 2)
        child.kill.assert_called_once_with()
        child.stdout.close.assert_called_once_with()
        self.assertTrue(process.Popen.call_args.kwargs["close_fds"])

    def test_per_child_deadline_is_not_renewed_by_spawn_or_late_wait(self):
        m = self.module
        for stage in ("spawn", "wait"):
            now = [10.0]
            child = SimpleNamespace(returncode=None, stdout=None, kill=Mock())

            def wait(*, timeout):
                if stage == "wait":
                    now[0] = 41.0  # Beyond original10+30, still before aggregate100.
                child.returncode = 0
                return 0

            child.wait = Mock(side_effect=wait)

            def spawn(*_args, **_kwargs):
                if stage == "spawn":
                    now[0] = 41.0
                return child

            process = SimpleNamespace(DEVNULL=-3, PIPE=-1, Popen=spawn)
            with self.subTest(stage=stage), patch.object(m, "time", SimpleNamespace(monotonic=lambda: now[0])), \
                    patch.object(m, "subprocess", process), self.assertRaises(BaseExceptionGroup):
                m._command(["/fixed/fixture"], 100.0)
            if stage == "spawn":
                self.assertEqual(child.wait.call_args.kwargs["timeout"], 0.0)
                child.kill.assert_called_once_with()

    def test_public_fixture_read_failure_still_closes_original_descriptor(self):
        m = self.module
        fake_os = SimpleNamespace(O_RDONLY=0, O_NOFOLLOW=1, O_NONBLOCK=2, open=Mock(return_value=11),
                                  fstat=Mock(side_effect=OSError("stat")), close=Mock(side_effect=OSError("close")))
        with patch.object(m, "os", fake_os), self.assertRaises(BaseExceptionGroup) as raised:
            m._read_public(Path("/pure/synthetic.der"))
        self.assertEqual(len(raised.exception.exceptions), 2)
        fake_os.close.assert_called_once_with(11)

    def test_preparation_uses_only_fixed_local_openssl_and_removes_only_its_temporary_files(self):
        m = self.module
        for failure in (None, "child", "unlink"):
            events, writes, removed = [], {}, []

            class PurePath(PurePosixPath):
                @classmethod
                def cwd(cls):
                    return cls("/private/tmp/mrk-pure/work/native-authority-source/probes")

                def iterdir(self):
                    return iter(())

                def lstat(self):
                    return SimpleNamespace(st_mode=m.stat.S_IFREG | 0o600, st_nlink=1, st_uid=60123)

                def unlink(self):
                    removed.append(self.name)
                    if failure == "unlink" and len(removed) == 1:
                        raise OSError("synthetic unlink failure")

            def command(argv, deadline):
                events.append(argv)
                self.assertEqual(deadline, 100.0)
                if failure == "child":
                    raise OSError("synthetic child failure")

            native = Mock(side_effect=AssertionError("preparation must not evaluate or warm a native chain"))
            tokens = iter(f"{index:032x}" for index in range(4))
            with self.subTest(failure=failure), clock(m), patch.multiple(m, Path=PurePath,
                    os=SimpleNamespace(getuid=lambda: 60123), subprocess=SimpleNamespace(), _Trust=native,
                    secrets=SimpleNamespace(token_hex=lambda size: next(tokens))), \
                    patch.object(m, "_scratch", side_effect=lambda path: path), \
                    patch.object(m, "_command", side_effect=command), \
                    patch.object(m, "_write_new", side_effect=lambda path, data: writes.__setitem__(path.name, data)), \
                    patch.object(m, "_read_public", side_effect=lambda path: b"\x30" + path.name.encode()):
                if failure is None:
                    m.prepare_aia(60123, 100.0)
                else:
                    with self.assertRaises(OSError if failure == "child" else BaseExceptionGroup):
                        m.prepare_aia(60123, 100.0)
            native.assert_not_called()
            self.assertTrue(all(argv[0] == "/usr/bin/openssl" for argv in events))
            if failure == "child":
                self.assertEqual(removed, [])  # Unknown child completion is not removal authority.
            elif failure == "unlink":
                self.assertEqual(len(removed), 9)  # Independent cleanup of every original first-case file.
                self.assertNotIn("aia.json", writes)
            else:
                self.assertEqual(len(events), 36)
                self.assertEqual(sum(argv[1] == "verify" for argv in events), 4)
                self.assertEqual(len(removed), 36)
                self.assertTrue(all(name.endswith((".key", ".pem", ".csr", ".cnf")) for name in removed))
                manifest = json.loads(writes["aia.json"])
                self.assertEqual([row["case"] for row in manifest["cases"]], list(m._CASES))
                for index, case in enumerate(m._CASES):
                    expected = f"authorityInfoAccess=caIssuers;URI:http://127.0.0.1:60123/mrk-aia/{index:032x}/{case}.der\n"
                    self.assertIn(expected.encode(), writes[f"{case}.cnf"])
                for argv in (row for row in events if row[1] == "req"):
                    self.assertIn("-config", argv)
                    self.assertIn("-sha256", argv)
                    self.assertEqual(argv[argv.index("-newkey") + 1], "rsa:2048")

    def test_responder_setup_failure_does_not_lose_listener_close_error(self):
        m = self.module
        listener = SimpleNamespace(settimeout=Mock(), bind=Mock(side_effect=OSError("bind")),
                                   close=Mock(side_effect=OSError("close")))
        fake_socket = SimpleNamespace(AF_INET=2, SOCK_STREAM=1, socket=Mock(return_value=listener))
        with clock(m), patch.object(m, "socket", fake_socket), \
                patch.object(m, "threading", SimpleNamespace(Event=lambda: SimpleNamespace())), \
                self.assertRaises(BaseExceptionGroup) as raised:
            m._Responder(100.0)
        self.assertEqual(len(raised.exception.exceptions), 2)
        listener.close.assert_called_once_with()

    def test_responder_cleanup_independently_attempts_join_and_close(self):
        m = self.module
        responder = object.__new__(m._Responder)
        responder.deadline = 100.0
        responder.start_attempted = True
        responder.stop = SimpleNamespace(set=Mock())
        responder.thread = SimpleNamespace(ident=71, join=Mock(side_effect=OSError("join")), is_alive=Mock(return_value=True))
        responder.listener = SimpleNamespace(close=Mock(side_effect=OSError("close")))
        responder.errors = [OSError("serve")]
        with clock(m), self.assertRaises(BaseExceptionGroup) as raised:
            responder.close()
        self.assertEqual(len(raised.exception.exceptions), 3)
        responder.thread.join.assert_called_once_with(timeout=2.0)
        responder.listener.close.assert_called_once_with()
        responder.stop.set.assert_called_once_with()

    def test_unknown_thread_start_is_failure_even_without_ident(self):
        m = self.module
        responder = object.__new__(m._Responder)
        responder.deadline, responder.start_attempted, responder.errors = 100.0, True, []
        responder.stop = SimpleNamespace(set=Mock())
        responder.thread = SimpleNamespace(ident=None, join=Mock(side_effect=RuntimeError("start is unknown")),
                                           is_alive=Mock(return_value=False))
        responder.listener = SimpleNamespace(close=Mock())
        with clock(m), self.assertRaises(BaseExceptionGroup):
            responder.close()
        responder.thread.join.assert_called_once()
        responder.listener.close.assert_called_once_with()

    def test_thread_start_attempt_custody_precedes_start_publication(self):
        m = self.module
        responder = object.__new__(m._Responder)
        responder.thread, responder.start_attempted, responder.deadline = None, False, 100.0

        def interrupted_start():
            self.assertTrue(responder.start_attempted)
            raise KeyboardInterrupt()

        thread = SimpleNamespace(start=interrupted_start)
        fake_threads = SimpleNamespace(Thread=Mock(return_value=thread))
        fixtures = aia_fixtures(m)
        with clock(m), patch.object(m, "threading", fake_threads), self.assertRaises(KeyboardInterrupt):
            responder.start({row["route"]: row["issuer"] for row in fixtures})
        self.assertIs(responder.thread, thread)

    def test_responder_start_uses_original_cutoff_before_and_after_worker_acquisition(self):
        m = self.module
        for stage in ("entry", "constructor", "start"):
            responder = object.__new__(m._Responder)
            responder.thread, responder.start_attempted, responder.deadline = None, False, 100.0
            now = [101.0 if stage == "entry" else 10.0]
            thread = SimpleNamespace(start=Mock(side_effect=lambda: now.__setitem__(0, 101.0)))

            def construct(**_kwargs):
                if stage == "constructor":
                    now[0] = 101.0
                return thread

            threads = SimpleNamespace(Thread=Mock(side_effect=construct))
            with self.subTest(stage=stage), patch.object(m, "time", SimpleNamespace(monotonic=lambda: now[0])), \
                    patch.object(m, "threading", threads), self.assertRaises(m.NativeControlError):
                responder.start({row["route"]: row["issuer"] for row in aia_fixtures(m)})
            self.assertEqual(thread.start.call_count, int(stage == "start"))
            self.assertEqual(responder.start_attempted, stage == "start")
            self.assertEqual(threads.Thread.call_count, int(stage != "entry"))

    def test_responder_stop_failure_does_not_skip_join_or_original_listener_close(self):
        m = self.module
        responder = object.__new__(m._Responder)
        responder.deadline, responder.start_attempted, responder.errors = 100.0, True, []
        responder.stop = SimpleNamespace(set=Mock(side_effect=KeyboardInterrupt()))
        responder.thread = SimpleNamespace(join=Mock(), is_alive=Mock(return_value=False))
        pending = SimpleNamespace(close=Mock(side_effect=OSError("pending close")))
        responder.listener = SimpleNamespace(settimeout=Mock(), accept=Mock(return_value=(pending, None)),
                                             close=Mock(side_effect=OSError("listener close")))
        with clock(m), self.assertRaises(BaseExceptionGroup) as raised:
            responder.close()
        self.assertEqual(len(raised.exception.exceptions), 4)
        responder.thread.join.assert_called_once_with(timeout=2.0)
        pending.close.assert_called_once_with()
        responder.listener.close.assert_called_once_with()

    def test_request_and_response_are_literal_bounded_public_bytes(self):
        m = self.module
        responder = object.__new__(m._Responder)
        responder.deadline = 100.0
        route, body, stopped = "/mrk-aia/" + "a" * 32 + "/online.der", b"\x30public-synthetic-der", [False]
        responder.stop = SimpleNamespace(is_set=lambda: stopped[0])
        responder.responses, responder.requests, responder.errors = {route: body}, [], []
        connection = SimpleNamespace(settimeout=Mock(), recv=Mock(return_value=f"GET {route} HTTP/1.1\r\n\r\n".encode()),
                                     close=Mock())
        sent = []

        def send(data):
            sent.append(data)
            stopped[0] = True

        connection.sendall = send
        responder.listener = SimpleNamespace(settimeout=Mock(), accept=Mock(return_value=(connection, ("127.0.0.1", 60000))))
        with clock(m):
            responder._serve()
        self.assertEqual(responder.errors, [])
        self.assertEqual(responder.requests, [(route, m.hashlib.sha256(body).hexdigest())])
        self.assertTrue(sent[0].endswith(b"\r\n\r\n" + body))
        connection.close.assert_called_once_with()
        self.assertEqual(connection.settimeout.call_args_list[0].args, (1.0,))
        self.assertEqual(connection.settimeout.call_args_list[-1].args, (1.0,))

    def test_unexpected_request_and_connection_close_errors_are_retained(self):
        m = self.module
        responder = object.__new__(m._Responder)
        responder.deadline, responder.requests, responder.errors, responder.responses = 100.0, [], [], {}
        responder.stop = SimpleNamespace(is_set=lambda: False)
        connection = SimpleNamespace(settimeout=Mock(), recv=Mock(return_value=b"GET /not-the-fixture HTTP/1.1\r\n\r\n"),
                                     close=Mock(side_effect=OSError("close")), sendall=Mock())
        responder.listener = SimpleNamespace(settimeout=Mock(), accept=Mock(return_value=(connection, ("127.0.0.1", 60000))))
        with clock(m):
            responder._serve()
        self.assertEqual(len(responder.errors), 1)
        self.assertEqual(len(responder.errors[0].exceptions), 2)
        connection.sendall.assert_not_called()

    def test_every_aia_case_uses_same_real_flag_protocol_and_fresh_objects(self):
        m = self.module
        fixtures = aia_fixtures(m)
        records, _requests = aia_evidence(m, fixtures)
        objects = []

        class Trust:
            def __init__(self, leaf, root):
                index = len(objects)
                self.fixture, self.result = fixtures[index], records["cases"][index]
                self.calls, self.network, self.keychains = [], False, None
                self.closed = False
                self_test.assertEqual((leaf, root), (self.fixture["leaf"], self.fixture["root"]))
                objects.append(self)

            def set_network(self, value):
                self.calls.append(("set-network", value))
                self.network = value

            def get_network(self):
                self.calls.append(("get-network", self.network))
                return self.network

            def set_keychains(self, value):
                self.calls.append(("set-keychains", value))
                self.keychains = value

            def get_keychains(self):
                self.calls.append(("get-keychains", self.keychains))
                return self.keychains

            def evaluate(self):
                self.calls.append(("evaluate",))
                return {key: self.result[key] for key in ("accepted", "error", "result", "chain")}

            def close(self):
                self.closed = True

        self_test = self
        with clock(m), patch.object(m, "_Trust", Trust):
            observed = [m._evaluate_case(fixture, 100.0) for fixture in fixtures]
        self.assertEqual(observed, records["cases"])
        self.assertEqual(len(objects), 4)
        for case, instance in zip(m._CASES, objects):
            self.assertEqual(instance.calls[:2], [("set-network", True), ("get-network", True)])
            values = [call[1] for call in instance.calls if call[0] == "set-network"]
            self.assertEqual(values, [True] if case in ("online", "mutant") else [True, False])
            self.assertTrue(instance.closed)

    def test_aia_baseline_or_final_getter_mismatch_never_reaches_evaluation(self):
        m = self.module
        fixture = aia_fixtures(m)[1]
        for network_values, keychains in (([False], True), ([True, True], True), ([True, False], False)):
            trust = SimpleNamespace(set_network=Mock(), get_network=Mock(side_effect=network_values),
                                    set_keychains=Mock(), get_keychains=Mock(return_value=keychains),
                                    evaluate=Mock(), close=Mock())
            with self.subTest(network_values=network_values, keychains=keychains), clock(m), \
                    patch.object(m, "_Trust", return_value=trust), self.assertRaises(BaseExceptionGroup):
                m._evaluate_case(fixture, 100.0)
            trust.evaluate.assert_not_called()
            trust.close.assert_called_once_with()

    def test_native_evaluation_and_cf_cleanup_errors_both_survive(self):
        m = self.module
        trust = SimpleNamespace(set_network=Mock(), get_network=Mock(return_value=True),
                                set_keychains=Mock(), get_keychains=Mock(return_value=True),
                                evaluate=Mock(side_effect=OSError("evaluate")), close=Mock(side_effect=OSError("CF close")))
        with clock(m), patch.object(m, "_Trust", return_value=trust), self.assertRaises(BaseExceptionGroup) as raised:
            m._evaluate_case(aia_fixtures(m)[0], 100.0)
        self.assertEqual(len(raised.exception.exceptions), 2)
        trust.close.assert_called_once_with()

    def test_every_owned_cf_reference_release_is_attempted_independently(self):
        m = self.module
        trust = object.__new__(m._Trust)
        trust.owned = [21, 22, 23]
        trust.release = Mock(side_effect=[OSError("first"), None, OSError("third")])
        with self.assertRaises(BaseExceptionGroup) as raised:
            trust.close()
        self.assertEqual(len(raised.exception.exceptions), 2)
        self.assertEqual([call.args[0] for call in trust.release.call_args_list], [23, 22, 21])
        self.assertEqual(trust.owned, [])

    def test_oracle_requires_online_and_mutant_fetches_and_both_offline_negatives(self):
        m = self.module
        fixtures = aia_fixtures(m)
        record, requests = aia_evidence(m, fixtures)
        encode = lambda value: m.AIA_PREFIX + json.dumps(value).encode() + b"\n"
        result = m.require_aia_controls(encode(record), fixtures, requests)
        self.assertEqual(result["request_counts"], [1, 0, 1, 0])
        self.assertTrue(result["final_disable_mutation_detected"])
        for bad_requests in ([], requests[:1], requests[1:], requests * 2,
                             [requests[0], (fixtures[1]["route"], "0" * 64), requests[1]],
                             [requests[0], (requests[1][0], "0" * 64)]):
            with self.subTest(requests=bad_requests), self.assertRaises(m.NativeControlError):
                m.require_aia_controls(encode(record), fixtures, bad_requests)
        for index, key, bad in ((0, "accepted", False), (0, "chain", ["0" * 64] * 3),
                                (1, "network", True), (1, "result", 6), (1, "chain", ["0" * 64]),
                                (2, "network", False), (2, "baseline_network", False),
                                (3, "keychains", True), (3, "error", False), (3, "accepted", 0)):
            modified = json.loads(json.dumps(record))
            modified["cases"][index][key] = bad
            with self.subTest(index=index, key=key), self.assertRaises(m.NativeControlError):
                m.require_aia_controls(encode(modified), fixtures, requests)

    def test_fixture_manifest_rejects_reused_nonces_certificates_and_changed_bytes(self):
        m = self.module
        fixtures = aia_fixtures(m)
        base = Path("/private/tmp/mrk-pure/work/native-authority-source/probes")
        rows, files = [], {}
        for index, fixture in enumerate(fixtures):
            row = {"case": fixture["case"], "nonce": f"{index:032x}"}
            for role in ("root", "issuer", "leaf"):
                row[role] = m.hashlib.sha256(fixture[role]).hexdigest()
                files[f"{fixture['case']}-{role}.der"] = fixture[role]
            rows.append(row)
        manifest = {"schema": 1, "port": 60123, "cases": rows}

        for mutation in ("none", "nonce", "issuer", "bytes", "port", "extra"):
            changed = json.loads(json.dumps(manifest))
            current = dict(files)
            if mutation == "nonce":
                changed["cases"][1]["nonce"] = changed["cases"][0]["nonce"]
            elif mutation == "issuer":
                changed["cases"][1]["issuer"] = changed["cases"][0]["issuer"]
                current["offline-issuer.der"] = current["online-issuer.der"]
            elif mutation == "bytes":
                current["offline-issuer.der"] += b"changed"
            elif mutation == "port":
                changed["port"] += 1
            elif mutation == "extra":
                changed["cases"][0]["url"] = "https://not-permitted.invalid/"
            current["aia.json"] = json.dumps(changed).encode()
            with self.subTest(mutation=mutation), clock(m), patch.object(m, "_scratch", return_value=base), \
                    patch.object(m, "_read_public", side_effect=lambda path, maximum=m._MAX_DER: current[path.name]):
                if mutation == "none":
                    self.assertEqual(m._fixtures(base, 60123, 100.0), fixtures)
                else:
                    with self.assertRaises(m.NativeControlError):
                        m._fixtures(base, 60123, 100.0)

    def test_owner_orchestration_keeps_six_real_captures_and_finality_order(self):
        m = self.module
        fixtures = aia_fixtures(m)
        record, requests = aia_evidence(m, fixtures)
        events = []
        outputs = {name: m.MACH_PREFIX + json.dumps(row).encode() + b"\n" for name, row in (
            ("mach-baseline", mach_row([0, 1102, 0])), ("mach-ordinary", mach_row([1100] * 3)),
            ("mach-authority", mach_row([0, 1102, 1100])), ("mach-nonexpand", mach_row([1100] * 3)))}
        outputs["aia-prepare"] = b"MRK_AIA_PREPARED\n"
        outputs["aia-evaluate"] = m.AIA_PREFIX + json.dumps(record).encode() + b"\n"
        responder = SimpleNamespace(port=60123, requests=requests, start=lambda _rows: events.append("listener-start"),
                                    close=lambda: events.append("listener-close"))

        def launch(case, *, port=None):
            events.append(("capture", case, port))
            return SimpleNamespace(ok=True, stdout=outputs[case])

        def idle():
            events.append("idle")

        with clock(m), patch.object(m, "_scratch"), patch.object(m, "_fixtures", return_value=fixtures), \
                patch.object(m, "_Responder", return_value=responder):
            result = m.admit_controls(launch, idle, Path("/pure/probes"), deadline=100.0)
        self.assertTrue(result["cleanup_ok"])
        captures = [event for event in events if isinstance(event, tuple)]
        self.assertEqual(captures, [("capture", name, None if name.startswith("mach-") else 60123)
                                   for name in outputs])
        for index, event in enumerate(events):
            if isinstance(event, tuple):
                self.assertEqual(events[index + 1], "idle")
        self.assertEqual(events[-2:], ["listener-close", "idle"])

    def test_owner_failed_capture_still_collects_finality_and_responder_close_errors(self):
        m = self.module
        fixtures = aia_fixtures(m)
        responder = SimpleNamespace(port=60123, requests=[], start=Mock(), close=Mock(side_effect=OSError("listener close")))
        calls, last = [], [None]

        def launch(case, *, port=None):
            last[0] = case
            calls.append(case)
            if case == "aia-evaluate":
                raise OSError("original capture")
            if case == "aia-prepare":
                return SimpleNamespace(ok=True, stdout=b"MRK_AIA_PREPARED\n")
            codes = [0, 1102, 0] if case == "mach-baseline" else [0, 1102, 1100] if case == "mach-authority" else [1100] * 3
            return SimpleNamespace(ok=True, stdout=m.MACH_PREFIX + json.dumps(mach_row(codes)).encode() + b"\n")

        def idle():
            if last[0] == "aia-evaluate":
                raise OSError("unknown finality")

        with clock(m), patch.object(m, "_scratch"), patch.object(m, "_fixtures", return_value=fixtures), \
                patch.object(m, "_Responder", return_value=responder), self.assertRaises(BaseExceptionGroup) as raised:
            m.admit_controls(launch, idle, Path("/pure/probes"), deadline=100.0)
        self.assertEqual(len(raised.exception.exceptions), 2)
        self.assertEqual(len(raised.exception.exceptions[0].exceptions), 2)
        responder.close.assert_called_once_with()
        self.assertEqual(calls[-1], "aia-evaluate")


if __name__ == "__main__":
    unittest.main()
