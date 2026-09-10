"""Pure native-admission regressions: every reached native/resource effect is fake.

These tests are not macOS evidence. Loading the helper only defines its inert
functions; no probe entry, listener, subprocess, account or permission operation
is executed. Each test replaces the helper's namespace, not shared stdlib APIs.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import sys
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


def mach_application(role, *, returned=0, number=None, policy_sha256="a" * 64, after=None):
    """Synthetic records for parser/oracle tests, never native execution evidence."""
    row = {"schema": 1, "role": role, "policy_sha256": policy_sha256,
           "application": {"returned": returned, "errno": number},
           "after": mach_row([0, 1102, 1100] if role == "mach-initial" else [1100] * 3) if after is None else after}
    if role == "mach-nonexpand":
        row.update(before=mach_row([1100] * 3), child=mach_row([1100] * 3))
    return row


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
        initial = Mock(return_value=mach_application("mach-initial"))
        nested = Mock(return_value=mach_application("mach-nonexpand", returned=-1, number=1))
        prepare, evaluate, printed = Mock(), Mock(return_value={"schema": 1, "cases": []}), Mock()
        with clock(m), patch.multiple(m, Path=PurePath, __file__=str(prefix / "ci_native_authority.py"),
                                     os=identity, sys=SimpleNamespace(platform="darwin"), mach_probe=mach,
                                     mach_initial=initial, mach_nonexpand=nested, prepare_aia=prepare, evaluate_aia=evaluate), \
                patch.object(m, "print", printed, create=True):
            for args in (["--mach", "100.0"], ["--mach-initial", str(prefix / "native-authority-source.sb"), "100.0"],
                         ["--mach-nonexpand", str(prefix / "native-authority-source.sb"), "100.0"],
                         ["--aia-prepare", "60123", "100.0"], ["--aia-evaluate", "60123", "100.0"]):
                self.assertEqual(m._main(args), 0)
            for args in (["--mach-nonexpand", "100.0"], ["--mach", "extra", "100.0"],
                         ["--mach-initial", "100.0"], ["--mach-initial", "policy", "extra", "100.0"],
                         ["--aia-evaluate", "060123", "100.0"], ["--arbitrary-role", "100.0"]):
                with self.subTest(args=args), self.assertRaises(m.NativeControlError):
                    m._main(args)
        mach.assert_called_once_with(100.0)
        initial.assert_called_once_with(prefix / "native-authority-source.sb", 100.0)
        nested.assert_called_once_with(prefix / "native-authority-source.sb", 100.0)
        prepare.assert_called_once_with(60123, 100.0)
        evaluate.assert_called_once_with(60123, 100.0)
        self.assertEqual(printed.call_count, 5)
        for index, role in ((1, "mach-initial"), (2, "mach-nonexpand")):
            data = printed.call_args_list[index].args[0].encode() + b"\n"
            expected = initial.return_value if role == "mach-initial" else nested.return_value
            self.assertEqual(m.parse_mach_application(data, role), expected)

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

        # A private marker is neither an exception message nor a wait receipt.
        # Only one complete, correctly typed original observation is projected.
        for status in (-128, -6, 1, 255, -129, 256, 0, True, False, 1.0, "1", None):
            with self.subTest(original_child_scalar=status):
                observed = m.NativeControlError("PRIVATE-CHILD-MESSAGE /Users/private/signing.key")
                observed._child_returncode = status
                grouped = BaseExceptionGroup("PRIVATE-GROUP", [observed, OSError("PRIVATE-CLOSE")])
                note = m._failure_note(grouped, ["--mach-nonexpand", "PRIVATE-POLICY", "PRIVATE-CUTOFF"])
                valid = type(status) is int and -128 <= status <= 255 and status != 0
                self.assertEqual("child_returncode" in note, valid)
                if valid:
                    self.assertEqual(note["child_returncode"], status)
                self.assertEqual(note["error_count"], 2)
                raw = m._FAILURE_PREFIX + json.dumps(note).encode() + b"\n"
                self.assertEqual(m.parse_failure(raw, "mach-nonexpand"), note)
                for private in ("PRIVATE", "/Users/", "signing.key", str(ROOT), "_child_returncode"):
                    self.assertNotIn(private, raw.decode())
                for args in (["--mach", "100.0"], ["--mach-initial", "PRIVATE-POLICY", "100.0"],
                             ["--aia-evaluate", "12345", "100.0"], ["--mach-nonexpand", "missing"]):
                    self.assertNotIn("child_returncode", m._failure_note(grouped, args))
        initial = m._failure_note(native, ["--mach-initial", "PRIVATE-POLICY", "100.0"])
        self.assertEqual(initial["role"], "mach-initial")
        self.assertEqual(m.parse_failure(m._FAILURE_PREFIX + json.dumps(initial).encode() + b"\n", "mach-initial"), initial)
        first = m.NativeControlError("PRIVATE-FIRST")
        first._child_returncode = -6
        for other_status in (-6, 1, True):
            other = m.NativeControlError("PRIVATE-SECOND")
            other._child_returncode = other_status
            self.assertNotIn("child_returncode", m._failure_note(BaseExceptionGroup("PRIVATE-CONFLICT", [first, other]),
                             ["--mach-nonexpand", "PRIVATE-POLICY", "100.0"]))
        truncated = m._failure_note(BaseExceptionGroup("PRIVATE-TRUNCATED", [first, *([foreign] * 80)]),
                                    ["--mach-nonexpand", "PRIVATE-POLICY", "100.0"])
        self.assertTrue(truncated["truncated"])
        self.assertNotIn("child_returncode", truncated)
        foreign._child_returncode = -6
        self.assertNotIn("child_returncode", m._failure_note(foreign, ["--mach-nonexpand", "PRIVATE-POLICY", "100.0"]))

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

        nested = {**good, "role": "mach-nonexpand", "exceptions": [{"exception": "NativeControlError", "lines": [10, 20]}],
                  "child_returncode": -6}
        frame = encode(nested)
        recognized = {
            b"sandbox-exec: sandbox_apply: Operation not permitted\n": ("sandbox-apply", "operation-not-permitted"),
            b"sandbox-exec: sandbox_init: Operation not permitted\n": ("sandbox-init", "operation-not-permitted"),
            b"sandbox-exec: sandbox_apply: Permission denied\n": ("sandbox-apply", "permission-denied"),
            b"sandbox-exec: sandbox_init: Permission denied\n": ("sandbox-init", "permission-denied"),
        }
        self.assertEqual(m.parse_failure(frame, "mach-nonexpand"), nested)
        for preceding, (stage, text) in recognized.items():
            for have_status in (True, False):
                value = dict(nested)
                if not have_status:
                    del value["child_returncode"]
                with self.subTest(nonexpand_reported_text=(preceding, have_status)):
                    note = m.parse_failure(preceding + encode(value), "mach-nonexpand")
                    self.assertEqual(note, {**value, "reported_child_stage": stage, "reported_child_text": text})
                    self.assertNotIn(preceding.decode().strip(), json.dumps(note))
                    for other_role in ("mach", "mach-initial", "aia-prepare", "aia-evaluate"):
                        self.assertIsNone(m.parse_failure(preceding + encode({**value, "role": other_role}), other_role))
        preceding = next(iter(recognized))
        bad_frames = (preceding[:-1] + frame, preceding.replace(b"\n", b"\r\n") + frame,
            preceding + b"\n" + frame, preceding + frame[:-1], preceding + frame + b"suffix\n", preceding + frame + b"\n",
            frame + preceding, frame + frame, preceding + frame + frame, frame[:20] + preceding + frame[20:],
            b"PRIVATE-CHILD /Users/private/signing.key\n" + frame, b"\xff\n" + frame,
            b"sandbox-exec: sandbox_apply: Operation not permitted PRIVATE\n" + frame,
            b"x" * 4097 + frame, bytearray(frame), None,
            frame.replace(b'"child_returncode": -6', b'"child_returncode": -6, "child_returncode": 1'))
        for raw in bad_frames:
            with self.subTest(nonexpand_frame=repr(raw)[:90]):
                self.assertIsNone(m.parse_failure(raw, "mach-nonexpand"))
        for key, value in (("child_returncode", True), ("child_returncode", False), ("child_returncode", 0),
                           ("child_returncode", -129), ("child_returncode", 256), ("child_returncode", "1"), ("child_returncode", 1.0),
                           ("truncated", True), ("schema", True), ("role", "mach"), ("error_count", 2),
                           ("exceptions", [{"exception": "OSError", "lines": []}]),
                           ("reported_child_stage", "sandbox-apply"), ("reported_child_text", "operation-not-permitted"),
                           ("private-message", "PRIVATE-CHILD")):
            with self.subTest(nonexpand_bad_field=(key, value)):
                self.assertIsNone(m.parse_failure(preceding + encode({**nested, key: value}), "mach-nonexpand"))
        for status in (-128, 1, 255):
            value = {**nested, "child_returncode": status}
            self.assertEqual(m.parse_failure(encode(value), "mach-nonexpand"), value)
        # The complete transport, not just the extracted JSON suffix, owns 4KiB.
        padded = frame[:-1] + b" " * (4096 - len(preceding) - len(frame)) + b"\n"
        self.assertEqual(len(preceding + padded), 4096)
        self.assertIsNotNone(m.parse_failure(preceding + padded, "mach-nonexpand"))
        self.assertIsNone(m.parse_failure(preceding + padded[:-1] + b" \n", "mach-nonexpand"))

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

        self.assertEqual(m.MACH_APPLY_PREFIX, b"MRK_NATIVE_MACH_APPLY=")
        encode = lambda row: m.MACH_APPLY_PREFIX + json.dumps(row).encode() + b"\n"
        for role in ("mach-initial", "mach-nonexpand"):
            valid = mach_application(role)
            raw = encode(valid)
            self.assertEqual(m.parse_mach_application(raw, role), valid)
            changes = [("schema", True), ("schema", 2), ("role", "mach"), ("role", None),
                       ("policy_sha256", "A" * 64), ("policy_sha256", "a" * 63), ("policy_sha256", "z" * 64),
                       ("policy_sha256", True), ("policy_sha256", None), ("private", "PRIVATE-COMPILER-ERROR"),
                       ("application", None), ("application", {"returned": 0}),
                       ("application", {"returned": 0, "errno": 1}), ("application", {"returned": True, "errno": None}),
                       ("application", {"returned": False, "errno": None}), ("application", {"returned": 0.0, "errno": None}),
                       ("application", {"returned": "0", "errno": None}), ("application", {"returned": 1, "errno": None}),
                       ("application", {"returned": -1, "errno": 2}), ("application", {"returned": -1, "errno": True}),
                       ("application", {"returned": -1, "errno": 1.0}), ("application", {"returned": -1, "errno": None}),
                       ("application", {"returned": 0, "errno": None, "message": "PRIVATE-COMPILER-ERROR"})]
            changes.append(("child" if role == "mach-initial" else "before", None))
            for field, value in changes:
                with self.subTest(application_field=(role, field, value)), self.assertRaises(m.NativeControlError):
                    m.parse_mach_application(encode({**valid, field: value}), role)
            for field in valid:
                missing = dict(valid)
                del missing[field]
                with self.subTest(application_missing=(role, field)), self.assertRaises(m.NativeControlError):
                    m.parse_mach_application(encode(missing), role)
            for field in (("after",) if role == "mach-initial" else ("before", "after", "child")):
                for value in (None, [], {**mach_row([1100] * 3), "codes": [True, 1100, 1100]},
                              {**mach_row([0, 1102, 1100]), "released": [False] * 3},
                              {**mach_row([1100] * 3), "private": "PRIVATE-LOOKUP"}):
                    with self.subTest(application_nested=(role, field, value)), self.assertRaises(m.NativeControlError):
                        m.parse_mach_application(encode({**valid, field: value}), role)
            diagnostic = m._FAILURE_PREFIX + json.dumps({"schema": 1, "role": role, "error_count": 1,
                "truncated": False, "exceptions": [{"exception": "NativeControlError", "lines": []}]}).encode() + b"\n"
            malformed = (raw[:-1], raw + b"\n", raw + raw, b"prefix\n" + raw, raw + b"suffix\n", b"x" * 4097,
                         raw.replace(b'"schema": 1', b'"schema": 1,"schema": 1', 1),
                         raw.replace(b'"returned": 0', b'"returned": 0,"returned": 0', 1),
                         diagnostic, good, b"sandbox-exec: sandbox_apply: Operation not permitted\n" + diagnostic)
            for data in malformed:
                with self.subTest(application_frame=(role, repr(data)[:80])), self.assertRaises(m.NativeControlError):
                    m.parse_mach_application(data, role)
            for wrong_role in ("mach", "aia-prepare", "invalid", None, True, "mach-nonexpand" if role == "mach-initial" else "mach-initial"):
                with self.subTest(application_role=(role, wrong_role)), self.assertRaises(m.NativeControlError):
                    m.parse_mach_application(raw, wrong_role)
            with self.assertRaises(m.NativeControlError):
                m.parse_mach(raw)
        refused = mach_application("mach-nonexpand", returned=-1, number=1)
        self.assertEqual(m.parse_mach_application(encode(refused), "mach-nonexpand"), refused)
        with self.assertRaises(m.NativeControlError):
            m.parse_mach_application(encode(mach_application("mach-initial", returned=-1, number=1)), "mach-initial")

    def test_mach_negative_requires_real_matching_outside_positive(self):
        m = self.module
        positive, ordinary = mach_row([0, 1102, 0]), mach_row([1100] * 3)
        authority = mach_application("mach-initial")
        nonexpand = mach_application("mach-nonexpand", returned=-1, number=1)
        for negative in (nonexpand, mach_application("mach-nonexpand")):
            m.require_mach_controls(positive, ordinary, authority, negative, policy_sha256="a" * 64)
        bad = [(mach_row([1102] * 3), ordinary, authority, nonexpand),
               (mach_row([1102, 1102, 0]), ordinary, authority, nonexpand),
               (positive, mach_row([0, 1100, 1100]), authority, nonexpand)]
        for codes in ([1100, 1102, 1100], [0, 1102, 0], [0, 0, 1100]):
            bad.append((positive, ordinary, mach_application("mach-initial", after=mach_row(codes)), nonexpand))
        for phase in ("before", "after", "child"):
            for index in range(3):
                codes = [1100] * 3
                codes[index] = 0
                bad.append((positive, ordinary, authority, {**nonexpand, phase: mach_row(codes)}))
        bad += [(positive, ordinary, {**authority, "policy_sha256": "b" * 64}, nonexpand),
                (positive, ordinary, authority, {**nonexpand, "policy_sha256": "b" * 64}),
                (positive, ordinary, nonexpand, authority),
                (positive, ordinary, authority, {**nonexpand, "application": {"returned": -1, "errno": 2}}),
                (positive, ordinary, authority, {**nonexpand, "child": ordinary | {"released": [True] * 3}})]
        for baseline, plain, allowed, nested in bad:
            with self.subTest(rows=(baseline, plain, allowed, nested)), self.assertRaises(m.NativeControlError):
                m.require_mach_controls(baseline, plain, allowed, nested, policy_sha256="a" * 64)
        for owner_hash in (None, True, "a" * 63, "A" * 64, "z" * 64, "b" * 64):
            with self.subTest(owner_policy=owner_hash), self.assertRaises(m.NativeControlError):
                m.require_mach_controls(positive, ordinary, authority, nonexpand, policy_sha256=owner_hash)

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

    def test_application_api_binds_only_the_fixed_opaque_spi_without_native_effects(self):
        m = self.module
        symbols = ("sandbox_create_params", "sandbox_compile_string", "sandbox_apply",
                   "sandbox_free_profile", "sandbox_free_params", "sandbox_free_error")
        for case in ("valid", "pointer-width", "integer-width", "platform", "library", *symbols):
            with self.subTest(application_abi=case):
                pointer, integer, characters, pointer_pointer = object(), object(), object(), object()
                functions = {name: Mock() for name in symbols}
                library = SimpleNamespace(**{name: function for name, function in functions.items() if name != case})
                fake = SimpleNamespace(c_void_p=pointer, c_int=integer, c_char_p=characters,
                    POINTER=Mock(return_value=pointer_pointer), byref=Mock(), set_errno=Mock(), get_errno=Mock(),
                    CDLL=Mock(return_value=library, side_effect=OSError("PRIVATE-LIBRARY") if case == "library" else None),
                    sizeof=lambda kind: (4 if case == "pointer-width" else 8) if kind is pointer else
                                         (8 if case == "integer-width" else 4))
                # The import returns only this namespace: never actual ctypes,
                # a dynamic loader, a function pointer or a native allocation.
                with patch.dict(sys.modules, {"ctypes": fake}), \
                     patch.multiple(m, sys=SimpleNamespace(platform="linux" if case == "platform" else "darwin"),
                                    os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace()):
                    if case == "valid":
                        api = m._sandbox_api()
                    else:
                        with self.assertRaises((m.NativeControlError, AttributeError, OSError)):
                            m._sandbox_api()
                if case in {"platform", "pointer-width", "integer-width"}:
                    fake.CDLL.assert_not_called()
                else:
                    fake.CDLL.assert_called_once_with("/usr/lib/libsandbox.1.dylib", use_errno=True)
                for function in functions.values():
                    function.assert_not_called()
                if case == "valid":
                    expected = {"create_params": (pointer, []), "compile_string": (pointer, [characters, pointer, pointer_pointer]),
                                "apply": (integer, [pointer]), "free_profile": (None, [pointer]),
                                "free_params": (None, [pointer]), "free_error": (None, [pointer])}
                    for name, signature in expected.items():
                        self.assertIs(getattr(api, name), functions["sandbox_" + name])
                        self.assertEqual((getattr(api, name).restype, getattr(api, name).argtypes), signature)
                    self.assertIs(api.new_error, pointer)
                    self.assertIs(api.error_argument, fake.byref)
                    self.assertIs(api.set_errno, fake.set_errno)
                    self.assertIs(api.get_errno, fake.get_errno)
                    fake.POINTER.assert_called_once_with(pointer)

    def test_application_policy_uses_exact_complete_bytes_and_same_original_descriptor_custody(self):
        m = self.module
        base = PurePosixPath("/private/tmp/mrk-pure/bootstrap")
        maximum = 1024 * 1024
        changed_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode", "st_uid", "st_gid", "st_nlink")
        cases = ("valid", "maximum", "empty", "oversized", "nul", "non-ascii", "short-read", "long-read", "mode", "owner", "group",
                 "hardlink", "symlink", "wrong-policy", "path-alias", "wrong-origin", "platform", "expired", "late-read", "late-close",
                 "open-error", "read-error", "first-stat-error", "second-stat-error", "close-error", "read-close-error",
                 *("changed-" + field for field in changed_fields))
        for case in cases:
            with self.subTest(application_policy=case):
                events, now = [], [100.0 if case == "expired" else 10.0]

                class PurePath(PurePosixPath):
                    def resolve(self, *, strict):
                        self_test.assertTrue(strict)
                        return self.with_name("different.sb") if case == "path-alias" and self.name.endswith(".sb") else self

                self_test = self
                entry = PurePath(base / "ci_native_authority.py") if case != "wrong-origin" else PurePath("/unowned/bootstrap/ci_native_authority.py")
                policy = PurePath(base / ("wrong.sb" if case == "wrong-policy" else "native-authority-source.sb"))
                raw = b"(version 1)\n(deny mach-lookup)\n"
                raw = b"x" * maximum if case == "maximum" else b"" if case == "empty" else \
                      raw + b"\0" if case == "nul" else raw + b"\xff" if case == "non-ascii" else raw
                before = dict(st_dev=7, st_ino=91, st_size=maximum + 1 if case == "oversized" else len(raw),
                              st_mtime_ns=11, st_ctime_ns=12, st_mode=stat.S_IFREG | (0o440 if case == "mode" else 0o444),
                              st_uid=60001 if case == "owner" else 0, st_gid=20 if case == "group" else 0,
                              st_nlink=2 if case == "hardlink" else 1)
                if case == "symlink":
                    before["st_mode"] = stat.S_IFLNK | 0o444
                after = dict(before)
                if case.startswith("changed-"):
                    after[case.removeprefix("changed-")] += 1
                failure, closing = OSError("PRIVATE-POLICY-READ"), OSError("PRIVATE-POLICY-CLOSE")
                constants = {name: getattr(m.os, name) for name in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK")}

                def opened(path, flags):
                    self.assertEqual((path, flags), (policy, constants["O_RDONLY"] | constants["O_NOFOLLOW"] | constants["O_NONBLOCK"]))
                    events.append("open")
                    if case == "open-error":
                        raise failure
                    return 71

                def fstat(fd):
                    self.assertEqual(fd, 71)
                    index = events.count("stat")
                    self.assertLess(index, 2)
                    events.append("stat")
                    if case == ("first-stat-error" if index == 0 else "second-stat-error"):
                        raise failure
                    return SimpleNamespace(**(before if index == 0 else after))

                def read(fd, limit):
                    self.assertEqual((fd, limit), (71, maximum + 1))
                    events.append("read")
                    if case in {"read-error", "read-close-error"}:
                        raise failure
                    if case == "late-read":
                        now[0] = 100.0
                    return raw[:-1] if case == "short-read" else raw + b"x" if case == "long-read" else raw

                def close(fd):
                    self.assertEqual(fd, 71)
                    events.append("close")
                    if case == "late-close":
                        now[0] = 100.0
                    if case in {"close-error", "read-close-error"}:
                        raise closing

                error = None
                with patch.multiple(m, Path=PurePath, __file__=str(entry), time=SimpleNamespace(monotonic=lambda: now[0]),
                        os=SimpleNamespace(**constants, open=opened, fstat=fstat, read=read, close=close),
                        sys=SimpleNamespace(platform="linux" if case == "platform" else "darwin"), subprocess=SimpleNamespace(),
                        socket=SimpleNamespace(), threading=SimpleNamespace()):
                    if case in {"valid", "maximum"}:
                        self.assertEqual(m._mach_policy(policy, 100.0), raw)
                    else:
                        with self.assertRaises((m.NativeControlError, BaseExceptionGroup, OSError)) as caught:
                            m._mach_policy(policy, 100.0)
                        error = caught.exception
                unopened = case in {"wrong-policy", "path-alias", "wrong-origin", "platform", "expired", "open-error"}
                self.assertEqual(events.count("close"), int(not unopened))
                if case in {"valid", "maximum", "late-read", "late-close", "close-error"}:
                    self.assertEqual(events, ["open", "stat", "read", "stat", "close"])
                if case == "read-close-error":
                    self.assertEqual(error.exceptions, (failure, closing))
                if error is not None:
                    public = json.dumps(m._failure_note(error, ["--mach-initial", "PRIVATE-POLICY-PATH", "100.0"]))
                    self.assertNotIn("PRIVATE", public)
                    self.assertNotIn(str(base), public)

    def test_compiled_application_latches_original_errno_and_retires_each_owned_pointer_after_failures(self):
        m = self.module
        cases = ("initial-ok", "composed-ok", "permission-refused", "initial-refused", "stale-errno", "wrong-errno",
                 "bool-errno", "float-errno", "bool-return", "false-return", "float-return", "unknown-return",
                 "api-error", "error-prefilled", "params-none", "params-zero", "params-bool", "params-negative", "params-wide",
                 "params-error", "params-late", "compile-none", "compile-zero", "compile-bool", "compile-error",
                 "compiler-error-buffer", "compile-raises-with-buffer", "conflict", "compile-late", "apply-error", "apply-late",
                 "profile-close-error", "params-close-error", "conflict-all-close-errors", "profile-close-late")
        raw = b"(version 1)\n(deny mach-lookup)\n"
        for case in cases:
            with self.subTest(compiled_application_lifecycle=case):
                events, now, slot, returned_pointers = [], [10.0], [1], {}
                error_pointer = SimpleNamespace(value=103 if case == "error-prefilled" else None)
                original = OSError("PRIVATE-COMPILER-OR-APPLY-ERROR")
                release_errors = {name: OSError("PRIVATE-" + name) for name in ("profile", "error", "params")}
                params = {"params-none": None, "params-zero": 0, "params-bool": True,
                          "params-negative": -1, "params-wide": 2**64}.get(case, 101)
                profile = {"compile-none": None, "compile-zero": 0, "compile-bool": True,
                           "compiler-error-buffer": None}.get(case, 102)

                def monotonic():
                    self.assertLess(len(events), 100)
                    events.append(("clock", now[0]))
                    return now[0]

                def create_params():
                    events.append(("params",))
                    if case == "params-error":
                        raise original
                    returned_pointers["params"] = params
                    if case == "params-late":
                        now[0] = 100.0
                    return params

                def compile_string(source, pointer, error):
                    self.assertEqual((source, pointer), (raw, 101))
                    self.assertIs(error, error_pointer)
                    self.assertFalse(any(event[0].startswith("free-") for event in events))
                    events.append(("compile",))
                    if case in {"compiler-error-buffer", "compile-raises-with-buffer", "conflict", "conflict-all-close-errors"}:
                        error.value = 103
                    if case in {"compile-error", "compile-raises-with-buffer"}:
                        raise original
                    returned_pointers["profile"] = profile
                    if case == "compile-late":
                        now[0] = 100.0
                    return profile

                def set_errno(value):
                    self.assertEqual(value, 0)
                    events.append(("errno-reset", value))
                    slot[0] = value

                def apply(pointer):
                    self.assertEqual(pointer, 102)
                    self.assertEqual(events[-1], ("errno-reset", 0))
                    events.append(("apply", pointer))
                    if case == "apply-error":
                        raise original
                    if case != "stale-errno":
                        slot[0] = {"permission-refused": 1, "initial-refused": 1, "wrong-errno": 2,
                                   "bool-errno": True, "float-errno": 1.0}.get(case, 13)
                    if case == "apply-late":
                        now[0] = 100.0
                    return {"permission-refused": -1, "initial-refused": -1, "stale-errno": -1, "wrong-errno": -1,
                            "bool-errno": -1, "float-errno": -1, "bool-return": True, "false-return": False,
                            "float-return": 0.0, "unknown-return": 2}.get(case, 0)

                def get_errno():
                    self.assertEqual(events[-1], ("apply", 102))  # No intervening clock/native/cleanup operation.
                    events.append(("errno-read", slot[0]))
                    return slot[0]

                def release(name, pointer):
                    expected = {"profile": 102, "error": 103, "params": 101}[name]
                    self.assertEqual(pointer, expected)
                    self.assertNotIn(("free-" + name, pointer), events)
                    events.append(("free-" + name, pointer))
                    slot[0] = 99  # Cleanup errno must not replace the saved original apply observation.
                    if case == "profile-close-late" and name == "profile":
                        now[0] = 100.0
                    if case == "conflict-all-close-errors" or case == name + "-close-error":
                        raise release_errors[name]

                api = SimpleNamespace(new_error=lambda: error_pointer, error_argument=lambda pointer: pointer,
                    create_params=create_params, compile_string=compile_string, set_errno=set_errno, apply=apply, get_errno=get_errno,
                    free_profile=lambda pointer: release("profile", pointer), free_error=lambda pointer: release("error", pointer),
                    free_params=lambda pointer: release("params", pointer))
                factory = Mock(return_value=api, side_effect=original if case == "api-error" else None)
                error = None
                initial = case in {"initial-ok", "initial-refused"}
                with patch.multiple(m, _sandbox_api=factory, time=SimpleNamespace(monotonic=monotonic),
                                    os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace()):
                    if case in {"initial-ok", "composed-ok", "permission-refused"}:
                        result = m._apply_policy(raw, 100.0, initial=initial)
                        self.assertEqual(result, {"returned": -1, "errno": 1} if case == "permission-refused" else {"returned": 0, "errno": None})
                    else:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            m._apply_policy(raw, 100.0, initial=initial)
                        error = caught.exception
                factory.assert_called_once_with()
                pointer_values = {**returned_pointers, "error": error_pointer.value if case != "api-error" else None}
                expected_frees = [("free-" + name, pointer_values.get(name)) for name in ("profile", "error", "params")
                                  if type(pointer_values.get(name)) is int and 0 < pointer_values[name] < 2**64]
                self.assertEqual([event for event in events if event[0].startswith("free-")], expected_frees)
                applied = any(event[0] == "apply" for event in events)
                self.assertEqual(sum(event[0] == "errno-read" for event in events), int(applied and case != "apply-error"))
                if case in {"params-late", "compile-late"}:
                    self.assertFalse(applied)
                if error is not None:
                    leaves = list(error.exceptions)
                    for name, release_error in release_errors.items():
                        if case == "conflict-all-close-errors" or case == name + "-close-error":
                            self.assertIn(release_error, leaves)
                    if case in {"api-error", "params-error", "compile-error", "compile-raises-with-buffer", "apply-error"}:
                        self.assertIn(original, leaves)
                    self.assertNotIn("PRIVATE", json.dumps(m._failure_note(error,
                        ["--mach-initial" if initial else "--mach-nonexpand", "PRIVATE-POLICY", "100.0"])))
        factory = Mock(side_effect=AssertionError("invalid policy input may not acquire the native SPI"))
        for raw_input, initial, deadline in ((b"", True, 100.0), (b"x\0", False, 100.0), (b"\xff", False, 100.0),
                                            (bytearray(b"x"), False, 100.0), (b"x" * (1024 * 1024 + 1), False, 100.0),
                                            (b"x", 1, 100.0), (b"x", False, 10.0)):
            with self.subTest(invalid_application_input=(type(raw_input), initial, deadline)), clock(m), \
                 patch.object(m, "_sandbox_api", factory), self.assertRaises(m.NativeControlError):
                m._apply_policy(raw_input, deadline, initial=initial)
        factory.assert_not_called()

    def test_application_roles_observe_real_ordered_lookups_and_the_original_inherited_child(self):
        m = self.module
        raw = b"(version 1)\n(deny mach-lookup)\n"
        entry = PurePosixPath("/private/tmp/mrk-pure/bootstrap/ci_native_authority.py")
        policy = entry.parent / "native-authority-source.sb"
        cases = ("initial", "composed", "refused", "initial-error", "before-grant", "application-error", "after-grant",
                 "child-grant", "child-malformed", "child-nonzero", "child-timeout", "child-close-error", "child-close-late")
        for case in cases:
            with self.subTest(application_observation_order=case):
                events, now, queries = [], [10.0], []
                initial = case.startswith("initial")
                failure = m.NativeControlError("PRIVATE-APPLICATION-FAILURE")
                closing = OSError("PRIVATE-CHILD-CLOSE")
                timeout = m.subprocess.TimeoutExpired("PRIVATE-CHILD-COMMAND", 30)

                class PurePath(PurePosixPath):
                    def resolve(self, *, strict):
                        return self

                def bind(path, deadline):
                    self.assertEqual((path, deadline, events), (policy, 100.0, []))
                    events.append("policy")
                    return raw

                def apply(source, deadline, *, initial):
                    self.assertEqual((source, deadline), (raw, 100.0))
                    self.assertEqual(len(queries), 0 if initial else 3)
                    events.append("application")
                    if case in {"initial-error", "application-error"}:
                        raise failure
                    return {"returned": -1, "errno": 1} if case == "refused" else {"returned": 0, "errno": None}

                def query(name):
                    phase = "after" if "application" in events else "before"
                    index = len(queries) % 3
                    self.assertEqual(name, m.MACH_SERVICES[index])
                    self.assertFalse(initial and phase == "before")
                    codes = [0, 1102, 1100] if initial else [1100] * 3
                    if case == phase + "-grant":
                        codes[1] = 0
                    code = codes[index]
                    port = 700 + len(queries) if code == 0 else 0
                    queries.append((phase, name, code))
                    events.append(("lookup", phase, name, port))
                    return code, port

                def release(port):
                    self.assertEqual(events[-1][-1], port)
                    events.append(("release", port))
                    return 0

                child = SimpleNamespace(returncode=None, stdout=SimpleNamespace(close=Mock()))
                child_codes = [1100, 0, 1100] if case == "child-grant" else [1100] * 3
                child_bytes = b"PRIVATE-UNKNOWN-CHILD\n" if case == "child-malformed" else \
                              m.MACH_PREFIX + json.dumps(mach_row(child_codes)).encode() + b"\n"

                def communicate(*, timeout):
                    self.assertEqual(timeout, 30.0)
                    self.assertEqual(len(queries), 6)
                    events.append("child-communicate")
                    if case == "child-timeout":
                        raise child_timeout
                    child.returncode = 1 if case == "child-nonzero" else 0
                    return child_bytes, None

                child_timeout = timeout
                child.communicate = Mock(side_effect=communicate)
                child.wait = Mock(side_effect=lambda **_options: setattr(child, "returncode", 23) or 23)
                child.kill = Mock()

                def close_stdout():
                    events.append("child-close")
                    if case == "child-close-error":
                        raise closing
                    if case == "child-close-late":
                        now[0] = 100.0

                child.stdout.close.side_effect = close_stdout
                process = SimpleNamespace(DEVNULL=-3, PIPE=-1, Popen=Mock(return_value=child))
                with patch.multiple(m, Path=PurePath, __file__=str(entry), _mach_policy=bind, _apply_policy=apply,
                                    _mach_api=Mock(return_value=SimpleNamespace(lookup=query, release=release)),
                                    time=SimpleNamespace(monotonic=lambda: now[0]), os=SimpleNamespace(), subprocess=process,
                                    socket=SimpleNamespace(), threading=SimpleNamespace(),
                                    sys=SimpleNamespace(platform="darwin", executable="/fixture-tools/python/bin/python")):
                    if case in {"initial", "composed", "refused"}:
                        result = (m.mach_initial if initial else m.mach_nonexpand)(policy, 100.0)
                        self.assertEqual(result["policy_sha256"], m.hashlib.sha256(raw).hexdigest())
                        self.assertEqual(m.parse_mach_application(m.MACH_APPLY_PREFIX + json.dumps(result).encode() + b"\n",
                                         "mach-initial" if initial else "mach-nonexpand"), result)
                        if not initial:
                            self.assertEqual((result["before"], result["after"], result["child"]), (mach_row([1100] * 3),) * 3)
                    else:
                        with self.assertRaises((m.NativeControlError, BaseExceptionGroup)):
                            (m.mach_initial if initial else m.mach_nonexpand)(policy, 100.0)
                child_reached = case in {"composed", "refused", "child-grant", "child-malformed", "child-nonzero",
                                         "child-timeout", "child-close-error", "child-close-late"}
                self.assertEqual(process.Popen.call_count, int(child_reached))
                self.assertEqual(child.stdout.close.call_count, int(child_reached))
                self.assertEqual(child.kill.call_count, int(case == "child-timeout"))
                self.assertEqual(child.wait.call_count, int(case == "child-timeout"))
                if child_reached:
                    command = ["/fixture-tools/python/bin/python", "-I", "-S", "-B", str(entry), "--mach", "100.0"]
                    process.Popen.assert_called_once_with(command, stdin=-3, stdout=-1, stderr=None, close_fds=True)
                    self.assertNotIn("/usr/bin/sandbox-exec", command)
                if case == "initial-error":
                    self.assertEqual(queries, [])
                elif case in {"before-grant", "application-error"}:
                    self.assertEqual(len(queries), 3)
                elif initial:
                    self.assertEqual(len(queries), 3)
                else:
                    self.assertEqual(len(queries), 6)

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

        cases = [(True, "status", value) for value in (-128, -6, 1, 255, -129, 256, True, False, 1.0, 0.0, "1", None, 0)]
        cases += [(True, name, code) for name, code in (("nonzero-close", 1), ("zero-close", 0),
                    ("communicate-timeout", None), ("communicate-timeout-code", -6), ("communicate-io", None))]
        cases += [(False, "uncaptured", 0), (False, "uncaptured", 1)]
        for capture, case, status in cases:
            with self.subTest(original_child_observation=(capture, case, status)):
                events = []
                timeout_error = m.subprocess.TimeoutExpired("PRIVATE-NESTED-COMMAND", 30)
                read_error, close_error = OSError("PRIVATE-COMMUNICATE"), OSError("PRIVATE-STDOUT-CLOSE")
                inherited_close = Mock(side_effect=AssertionError("inherited stderr is not a new owned pipe"))
                child = SimpleNamespace(returncode=None, stderr=SimpleNamespace(close=inherited_close))

                def close_stdout():
                    events.append("stdout-close")
                    if case in {"nonzero-close", "zero-close"}:
                        raise close_error

                child.stdout = SimpleNamespace(close=Mock(side_effect=close_stdout)) if capture else None

                def communicate(*, timeout):
                    self.assertEqual(timeout, 30.0)
                    self.assertIsNone(child.returncode)
                    events.append("communicate-start")
                    if case == "communicate-timeout-code":
                        child.returncode = status
                    if case.startswith("communicate-timeout"):
                        raise timeout_error
                    if case == "communicate-io":
                        raise read_error
                    child.returncode = status
                    events.append("communicate-complete")
                    return b"synthetic original stdout", None

                def wait(*, timeout):
                    events.append("wait")
                    self.assertEqual(timeout, 2.0 if capture else 30.0)
                    # Cleanup's later status is not the original communicate
                    # observation and must never appear in the generated note.
                    child.returncode = 23 if capture else status
                    return child.returncode

                child.communicate = Mock(side_effect=communicate)
                child.wait = Mock(side_effect=wait)
                child.kill = Mock(side_effect=lambda: events.append("kill"))
                process = SimpleNamespace(DEVNULL=-3, PIPE=-1, Popen=Mock(return_value=child))
                failed = case.startswith("communicate-") or status != 0 or case == "zero-close"
                error = None
                with clock(m), patch.multiple(m, subprocess=process, os=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace()):
                    if failed:
                        with self.assertRaises(BaseExceptionGroup) as caught:
                            m._command(["/fixed/synthetic-child"], 100.0, capture=capture)
                        error = caught.exception
                    else:
                        self.assertEqual(m._command(["/fixed/synthetic-child"], 100.0, capture=capture),
                                         b"synthetic original stdout" if capture else b"")
                process.Popen.assert_called_once_with(["/fixed/synthetic-child"], stdin=-3,
                    stdout=-1 if capture else -3, stderr=None if capture else -3, close_fds=True)
                inherited_close.assert_not_called()
                self.assertEqual(child.communicate.call_count, int(capture))
                if capture:
                    child.stdout.close.assert_called_once_with()
                    self.assertEqual(events[-1], "stdout-close")
                cleanup_wait = capture and status is None
                self.assertEqual(child.wait.call_count, int(not capture or cleanup_wait))
                self.assertEqual(child.kill.call_count, int(cleanup_wait))
                if cleanup_wait:
                    self.assertLess(events.index("kill"), events.index("wait"))
                if error is not None:
                    note = m._failure_note(error, ["--mach-nonexpand", "PRIVATE-POLICY", "100.0"])
                    completed_nonzero = capture and case in {"status", "nonzero-close"} and type(status) is int and -128 <= status <= 255 and status != 0
                    self.assertEqual("child_returncode" in note, completed_nonzero)
                    if completed_nonzero:
                        self.assertIn("communicate-complete", events)
                        self.assertEqual(note["child_returncode"], status)
                        self.assertEqual(error.exceptions[0].__dict__["_child_returncode"], status)
                    if case in {"nonzero-close", "zero-close"}:
                        self.assertIs(error.exceptions[-1], close_error)
                    if case.startswith("communicate-timeout"):
                        self.assertIs(error.exceptions[0], timeout_error)
                    if case == "communicate-io":
                        self.assertIs(error.exceptions[0], read_error)
                    self.assertNotIn("AssertionError", json.dumps(note))
                    self.assertNotIn("PRIVATE", json.dumps(note))
                    self.assertNotIn("child_returncode", m._failure_note(error, ["--aia-prepare", "12345", "100.0"]))

    def test_per_child_deadline_is_not_renewed_by_spawn_or_late_wait(self):
        m = self.module
        for stage, capture in (("spawn", False), ("wait", False), ("spawn", True), ("communicate", True)):
            now = [10.0]
            child = SimpleNamespace(returncode=None, stdout=SimpleNamespace(close=Mock()) if capture else None, kill=Mock())

            def wait(*, timeout):
                if stage == "wait":
                    now[0] = 41.0  # Beyond original10+30, still before aggregate100.
                child.returncode = 0
                return 0

            child.wait = Mock(side_effect=wait)

            def communicate(*, timeout):
                self.assertEqual(timeout, 30.0)
                now[0], child.returncode = 41.0, 0
                return b"synthetic too-late stdout", None

            child.communicate = Mock(side_effect=communicate)

            def spawn(*_args, **_kwargs):
                if stage == "spawn":
                    now[0] = 41.0
                return child

            process = SimpleNamespace(DEVNULL=-3, PIPE=-1, Popen=spawn)
            with self.subTest(stage=(stage, capture)), patch.object(m, "time", SimpleNamespace(monotonic=lambda: now[0])), \
                    patch.object(m, "subprocess", process), self.assertRaises(BaseExceptionGroup) as caught:
                m._command(["/fixed/fixture"], 100.0, capture=capture)
            if stage == "spawn":
                self.assertEqual(child.wait.call_args.kwargs["timeout"], 0.0)
                child.kill.assert_called_once_with()
            self.assertEqual(child.communicate.call_count, int(stage == "communicate"))
            if capture:
                child.stdout.close.assert_called_once_with()
            self.assertNotIn("child_returncode", m._failure_note(caught.exception, ["--mach-nonexpand", "PRIVATE-POLICY", "100.0"]))

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
            ("mach-baseline", mach_row([0, 1102, 0])), ("mach-ordinary", mach_row([1100] * 3)))}
        applications = {"mach-authority": mach_application("mach-initial"),
                        "mach-nonexpand": mach_application("mach-nonexpand", returned=-1, number=1)}
        outputs.update({name: m.MACH_APPLY_PREFIX + json.dumps(row).encode() + b"\n" for name, row in applications.items()})
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
            result = m.admit_controls(launch, idle, Path("/pure/probes"), deadline=100.0, policy_sha256="a" * 64)
        self.assertTrue(result["cleanup_ok"])
        self.assertEqual(result["mach"]["authority"], applications["mach-authority"])
        self.assertEqual(result["mach"]["nonexpand"], applications["mach-nonexpand"])
        captures = [event for event in events if isinstance(event, tuple)]
        self.assertEqual(captures, [("capture", name, None if name.startswith("mach-") else 60123)
                                   for name in outputs])
        for index, event in enumerate(events):
            if isinstance(event, tuple):
                self.assertEqual(events[index + 1], "idle")
        self.assertEqual(events[-2:], ["listener-close", "idle"])

        diagnostic = b"sandbox-exec: sandbox_apply: Operation not permitted\n" + m._FAILURE_PREFIX + json.dumps({
            "schema": 1, "role": "mach-nonexpand", "error_count": 1, "truncated": False,
            "exceptions": [{"exception": "NativeControlError", "lines": []}], "child_returncode": 1}).encode() + b"\n"
        reported = m.parse_failure(diagnostic, "mach-nonexpand")
        self.assertIsNotNone(reported)
        refused_cases, idle = [], Mock()

        def refused_launch(case, *, port=None):
            self.assertIsNone(port)
            refused_cases.append(case)
            return SimpleNamespace(ok=case != "mach-nonexpand", stdout=outputs[case], stderr=diagnostic,
                                   native_control_error=reported)

        responder_factory = Mock(side_effect=AssertionError("a failed nested control may not advance to AIA"))
        fixtures_reader = Mock(side_effect=AssertionError("a diagnostic is not completed control authority"))
        with clock(m), patch.object(m, "_scratch"), patch.object(m, "_Responder", responder_factory), \
                patch.object(m, "_fixtures", fixtures_reader), self.assertRaises(m.NativeControlError):
            m.admit_controls(refused_launch, idle, Path("/pure/probes"), deadline=100.0, policy_sha256="a" * 64)
        self.assertEqual(refused_cases, ["mach-baseline", "mach-ordinary", "mach-authority", "mach-nonexpand"])
        self.assertEqual(idle.call_count, 5)  # Initial idle and each actual failed/successful capture remain required.
        responder_factory.assert_not_called()
        fixtures_reader.assert_not_called()
        with self.assertRaises(m.NativeControlError):
            m.parse_mach(diagnostic)  # Neither the error scalar nor reported English text is a denial record.
        for case in ("owner-hash-missing", "owner-hash-bool", "owner-hash-uppercase", "initial-hash", "negative-hash",
                     "initial-refused", "generic-refusal", "missing-child", "diagnostic-instead", "initial-unexecuted"):
            actual, saved = [], dict(outputs)
            owner_hash = {"owner-hash-missing": None, "owner-hash-bool": True, "owner-hash-uppercase": "A" * 64}.get(case, "a" * 64)
            if case in {"initial-hash", "initial-refused"}:
                record = mach_application("mach-initial", policy_sha256="b" * 64) if case == "initial-hash" else \
                         mach_application("mach-initial", returned=-1, number=1)
                saved["mach-authority"] = m.MACH_APPLY_PREFIX + json.dumps(record).encode() + b"\n"
            if case in {"negative-hash", "generic-refusal", "missing-child"}:
                record = mach_application("mach-nonexpand", returned=-1, number=2 if case == "generic-refusal" else 1,
                                          policy_sha256="b" * 64 if case == "negative-hash" else "a" * 64)
                if case == "missing-child":
                    del record["child"]
                saved["mach-nonexpand"] = m.MACH_APPLY_PREFIX + json.dumps(record).encode() + b"\n"
            if case == "diagnostic-instead":
                saved["mach-nonexpand"] = diagnostic

            def attempted(name, *, port=None):
                self.assertIsNone(port)
                actual.append(name)
                return SimpleNamespace(ok=not (case == "initial-unexecuted" and name == "mach-authority"), stdout=saved[name])

            with self.subTest(application_owner_mutation=case), clock(m), patch.object(m, "_scratch"), \
                 patch.object(m, "_Responder", responder_factory), patch.object(m, "_fixtures", fixtures_reader), \
                 self.assertRaises(m.NativeControlError):
                m.admit_controls(attempted, Mock(), Path("/pure/probes"), deadline=100.0, policy_sha256=owner_hash)
            self.assertFalse(any(name.startswith("aia-") for name in actual))
            if case.startswith("owner-hash-"):
                self.assertEqual(actual, [])
            responder_factory.assert_not_called()
            fixtures_reader.assert_not_called()

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
            if case in {"mach-authority", "mach-nonexpand"}:
                record = mach_application("mach-initial" if case == "mach-authority" else "mach-nonexpand")
                return SimpleNamespace(ok=True, stdout=m.MACH_APPLY_PREFIX + json.dumps(record).encode() + b"\n")
            codes = [0, 1102, 0] if case == "mach-baseline" else [1100] * 3
            return SimpleNamespace(ok=True, stdout=m.MACH_PREFIX + json.dumps(mach_row(codes)).encode() + b"\n")

        def idle():
            if last[0] == "aia-evaluate":
                raise OSError("unknown finality")

        with clock(m), patch.object(m, "_scratch"), patch.object(m, "_fixtures", return_value=fixtures), \
                patch.object(m, "_Responder", return_value=responder), self.assertRaises(BaseExceptionGroup) as raised:
            m.admit_controls(launch, idle, Path("/pure/probes"), deadline=100.0, policy_sha256="a" * 64)
        self.assertEqual(len(raised.exception.exceptions), 2)
        self.assertEqual(len(raised.exception.exceptions[0].exceptions), 2)
        responder.close.assert_called_once_with()
        self.assertEqual(calls[-1], "aia-evaluate")


if __name__ == "__main__":
    unittest.main()
