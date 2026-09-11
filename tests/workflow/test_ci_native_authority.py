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


def aia_chain_observations(module, fixtures):
    """Synthetic optional metadata; it cannot stand in for an original verdict."""
    return {"contrasts": [{"case": case, "network": False, "keychains": False, "accepted": True, "error": False, "result": 4,
                           "chain": [module.hashlib.sha256(fixtures[0][role]).hexdigest() for role in roles],
                           "trust_error": {"status": "no-error", "code": None}}
                          for case, roles in ((module._CONTRAST_CASE, ("leaf", "issuer", "root")),
                                              (module._ISSUER_ROOT_CONTRAST_CASE, ("issuer", "root")),
                                              (module._LEAF_ISSUER_CONTRAST_CASE, ("leaf", "issuer")))],
            "crypto": {"available": True, "keys": [{"key": role, "present": True, "block_bytes": 256, "verify_supported": True}
                                                  for role in ("issuer", "root")],
                       "checks": [{"case": case, "executed": True, "accepted": index != 3, "error": index == 3,
                                   "trust_error": {"status": "osstatus", "code": -50} if index == 3 else
                                   {"status": "no-error", "code": None}} for index, case in enumerate(module._SIGNATURE_CASES)]}}


def aia_baseline_evidence(module, originals, *, accepted=True):
    """One synthetic baseline record, never native execution or capture authority."""
    return {"schema": 1, "case": module._AIA_BASELINE_CASE, "network": False, "keychains": False,
            "accepted": accepted, "error": not accepted, "result": 4 if accepted else 5,
            "chain": [module.hashlib.sha256(raw).hexdigest() for raw in (originals if accepted else originals[:2])],
            "trust_error": {"status": "no-error", "code": None} if accepted else {"status": "osstatus", "code": -25318}}


def der_tlv(tag, body):
    """Test-authored definite-length envelope bytes, never a certificate library."""
    size = len(body)
    width = 1 if size <= 255 else 2
    length = bytes((size,)) if size < 128 else bytes((0x80 | width,)) + size.to_bytes(width, "big")
    return bytes((tag,)) + length + body


def signature_certificate(label, *, serial=b"\x01", opaque=None):
    # Only the fixed profile envelope is meaningful; remaining TBS bytes and the
    # signature are intentionally synthetic, not valid X.509 or cryptography.
    algorithm = bytes.fromhex("300d06092a864886f70d01010b0500")
    body = b"\xa0\x03\x02\x01\x02" + der_tlv(2, serial) + algorithm
    body += b"\x00opaque-" + label if opaque is None else opaque
    tbs, signature = der_tlv(0x30, body), label * 256
    return der_tlv(0x30, tbs + algorithm + der_tlv(3, b"\x00" + signature)), tbs, signature


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
        originals = tuple(aia_fixtures(m)[0][role] for role in ("leaf", "issuer", "root"))
        baseline = Mock(return_value=aia_baseline_evidence(m, originals))
        with clock(m), patch.multiple(m, Path=PurePath, __file__=str(prefix / "ci_native_authority.py"),
                                     os=identity, sys=SimpleNamespace(platform="darwin"), mach_probe=mach,
                                     mach_initial=initial, mach_nonexpand=nested, prepare_aia=prepare,
                                     evaluate_aia=evaluate, evaluate_aia_baseline=baseline), \
                patch.object(m, "print", printed, create=True):
            for args in (["--mach", "100.0"], ["--mach-initial", str(prefix / "native-authority-source.sb"), "100.0"],
                         ["--mach-nonexpand", str(prefix / "native-authority-source.sb"), "100.0"],
                         ["--aia-prepare", "60123", "100.0"], ["--aia-evaluate", "60123", "100.0"],
                         ["--aia-offline-baseline", "100.0"]):
                self.assertEqual(m._main(args), 0)
            for args in (["--mach-nonexpand", "100.0"], ["--mach", "extra", "100.0"],
                         ["--mach-initial", "100.0"], ["--mach-initial", "policy", "extra", "100.0"],
                         ["--aia-evaluate", "060123", "100.0"], ["--arbitrary-role", "100.0"],
                         ["--aia-offline-baseline", "60123", "100.0"], ["--aia-offline-baseline", "/private/input.der", "100.0"],
                         ["--aia-offline-baseline", "100.0", "extra", "100.0"], ["--aia-offline-baseline", "10.0"],
                         ["--aia-offline-baseline", "nan"], ["--aia-offline-baseline", "inf"],
                         ["--aia-offline-baseline", "-inf"], ["--aia-offline-baseline"]):
                with self.subTest(args=args), self.assertRaises(m.NativeControlError):
                    m._main(args)
        mach.assert_called_once_with(100.0)
        initial.assert_called_once_with(prefix / "native-authority-source.sb", 100.0)
        nested.assert_called_once_with(prefix / "native-authority-source.sb", 100.0)
        prepare.assert_called_once_with(60123, 100.0)
        evaluate.assert_called_once_with(60123, 100.0)
        baseline.assert_called_once_with(100.0)
        self.assertEqual(printed.call_count, 6)
        for index, role in ((1, "mach-initial"), (2, "mach-nonexpand")):
            data = printed.call_args_list[index].args[0].encode() + b"\n"
            expected = initial.return_value if role == "mach-initial" else nested.return_value
            self.assertEqual(m.parse_mach_application(data, role), expected)
        data = printed.call_args_list[-1].args[0].encode() + b"\n"
        self.assertTrue(m.baseline_comparison_note(data, originals)["chain_matches"])

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
                             ["--aia-evaluate", "12345", "100.0"], ["--aia-offline-baseline", "100.0"],
                             ["--mach-nonexpand", "missing"]):
                    self.assertNotIn("child_returncode", m._failure_note(grouped, args))
        initial = m._failure_note(native, ["--mach-initial", "PRIVATE-POLICY", "100.0"])
        self.assertEqual(initial["role"], "mach-initial")
        self.assertEqual(m.parse_failure(m._FAILURE_PREFIX + json.dumps(initial).encode() + b"\n", "mach-initial"), initial)
        baseline = m._failure_note(native, ["--aia-offline-baseline", "PRIVATE-DEADLINE"])
        self.assertEqual(baseline["role"], "aia-offline-baseline")
        raw = m._FAILURE_PREFIX + json.dumps(baseline).encode() + b"\n"
        self.assertEqual(m.parse_failure(raw, "aia-offline-baseline"), baseline)
        self.assertNotIn("PRIVATE", raw.decode())
        for args in (["--aia-offline-baseline"], ["--aia-offline-baseline", "PRIVATE-PATH", "100.0"]):
            self.assertEqual(m._failure_note(native, args)["role"], "invalid")
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
        baseline = {**good, "role": "aia-offline-baseline"}
        self.assertEqual(m.parse_failure(encode(baseline), "aia-offline-baseline"), baseline)
        self.assertIsNone(m.parse_failure(data, "aia-offline-baseline"))
        self.assertIsNone(m.parse_failure(encode(baseline), "aia-evaluate"))
        self.assertIsNone(m.parse_failure(encode({**baseline, "child_returncode": 1}), "aia-offline-baseline"))

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
                    for other_role in ("mach", "mach-initial", "aia-prepare", "aia-evaluate", "aia-offline-baseline"):
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

    def test_baseline_snapshots_require_fixed_immutable_original_descriptor_custody(self):
        m, test = self.module, self
        roles = ("leaf", "issuer", "root")
        changed_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        cases = [(mode, None, None) for mode in ("valid", "maximum", "before-cutoff", "entry-relative", "entry-alias",
                                                "entry-name", "entry-bootstrap", "entry-root", "duplicate-DER", "not-DER")]
        cases += [(mode, target, None) for target in ("session", "bootstrap", "entry") for mode in
                  ("origin-type", "origin-owner", "origin-group", "origin-mode", "origin-stat-error", "origin-stat-cutoff")]
        cases += [("origin-drift", target, field) for target in ("session", "bootstrap", "entry") for field in changed_fields]
        cases += [("origin-hardlink", "entry", None)]
        cases += [(mode, role, None) for role in roles for mode in
                  ("snapshot-alias", "snapshot-missing", "snapshot-type", "snapshot-owner", "snapshot-group", "snapshot-mode",
                   "snapshot-hardlink", "snapshot-empty", "snapshot-large", "snapshot-stat-error", "snapshot-stat-cutoff",
                   "open-error", "first-stat-error", "second-stat-error", "read-error", "read-cancel", "close-error",
                   "read-close-error", "short-read", "long-read", "late-read", "late-close", "descriptor-owner",
                   "descriptor-group", "descriptor-mode", "descriptor-type", "descriptor-hardlink")]
        cases += [("name-drift", role, field) for role in roles for field in changed_fields]
        cases += [("descriptor-drift", "issuer", field) for field in changed_fields]
        for mode, target, field in cases:
            with self.subTest(immutable_baseline=(mode, target, field)):
                events, stats, now, fd_stats = [], {}, [100.0 if mode == "before-cutoff" else 10.0], {}
                earlier = KeyboardInterrupt("PRIVATE-READ-CANCEL") if mode == "read-cancel" else OSError("PRIVATE-READ")
                closing = OSError("PRIVATE-CLOSE")

                class PurePath(PurePosixPath):
                    def resolve(self, *, strict):
                        test.assertTrue(strict)
                        if mode == "entry-alias" and self == entry:
                            return self.with_name("aliased.py")
                        if self in path_roles:
                            role = path_roles[self]
                            if mode == "snapshot-alias" and role == target:
                                return self.with_name("unadmitted.der")
                            if mode == "snapshot-missing" and role == target:
                                raise FileNotFoundError("PRIVATE-MISSING")
                        return self

                    def lstat(self):
                        key = path_keys[self]
                        index = stats.get(key, 0)
                        stats[key] = index + 1
                        events.append(("lstat", key))
                        if key == target and mode in {"origin-stat-error", "snapshot-stat-error"}:
                            raise earlier
                        if key == target and mode in {"origin-stat-cutoff", "snapshot-stat-cutoff"}:
                            now[0] = 100.0
                        value = node(key)
                        if index and key == target and mode in {"origin-drift", "name-drift"}:
                            value[field] += 1
                        return SimpleNamespace(**value)

                entry = PurePath({"entry-relative": "private/tmp/mrk-pure/bootstrap/ci_native_authority.py",
                                  "entry-name": "/private/tmp/mrk-pure/bootstrap/other.py",
                                  "entry-bootstrap": "/private/tmp/mrk-pure/other/ci_native_authority.py",
                                  "entry-root": "/unowned/tmp/mrk-pure/bootstrap/ci_native_authority.py"}.get(
                                      mode, "/private/tmp/mrk-pure/bootstrap/ci_native_authority.py"))
                paths = {role: entry.parent / f"native-aia-baseline-{role}.der" for role in roles}
                path_roles = {path: role for role, path in paths.items()}
                path_keys = {entry.parent.parent: "session", entry.parent: "bootstrap", entry: "entry", **path_roles}
                raw = {role: b"\x30" + role.encode() for role in roles}
                if mode == "maximum":
                    raw = {role: b"\x30" + role[:1].encode() * (m._MAX_DER - 1) for role in roles}
                if mode == "duplicate-DER":
                    raw["root"] = raw["issuer"]
                if mode == "not-DER":
                    raw["leaf"] = b"PRIVATE-NOT-DER"

                def node(key, *, descriptor=False):
                    regular = key not in {"session", "bootstrap"}
                    value = dict(st_dev=7, st_ino=90 + list(path_keys.values()).index(key),
                                 st_mode=(stat.S_IFREG | 0o444) if regular else (stat.S_IFDIR | 0o755),
                                 st_uid=0, st_gid=0, st_nlink=1 if regular else 2,
                                 st_size=len(raw[key]) if key in roles else 1024, st_mtime_ns=11, st_ctime_ns=12)
                    if key == target:
                        prefix = "descriptor-" if descriptor else "origin-" if key not in roles else "snapshot-"
                        kind = mode.removeprefix(prefix) if mode.startswith(prefix) else None
                        if kind == "type":
                            value["st_mode"] = stat.S_IFLNK | 0o444
                        if kind in {"owner", "group", "mode", "hardlink", "empty", "large"}:
                            name, replacement = {"owner": ("st_uid", 60123), "group": ("st_gid", 20),
                                "mode": ("st_mode", (stat.S_IFREG | 0o440) if regular else (stat.S_IFDIR | 0o775)),
                                "hardlink": ("st_nlink", 2), "empty": ("st_size", 0),
                                "large": ("st_size", m._MAX_DER + 1)}[kind]
                            value[name] = replacement
                    return value

                descriptors = {71 + index: role for index, role in enumerate(roles)}
                constants = {name: getattr(m.os, name) for name in ("O_RDONLY", "O_NOFOLLOW", "O_NONBLOCK")}

                def opened(path, flags):
                    self.assertIn(path, path_roles)
                    self.assertEqual(flags, constants["O_RDONLY"] | constants["O_NOFOLLOW"] | constants["O_NONBLOCK"])
                    role = path_roles[path]
                    events.append(("open", role))
                    if mode == "open-error" and role == target:
                        raise earlier
                    return 71 + roles.index(role)

                def fstat(fd):
                    role = descriptors[fd]
                    index = fd_stats.get(fd, 0)
                    self.assertLess(index, 2)
                    fd_stats[fd] = index + 1
                    events.append(("fstat", role))
                    if role == target and mode == ("first-stat-error" if index == 0 else "second-stat-error"):
                        raise earlier
                    value = node(role, descriptor=True)
                    if index and mode == "descriptor-drift" and role == target:
                        value[field] += 1
                    return SimpleNamespace(**value)

                def read(fd, maximum):
                    role = descriptors[fd]
                    self.assertEqual(maximum, m._MAX_DER + 1)
                    events.append(("read", role))
                    if role == target:
                        if mode in {"read-error", "read-cancel", "read-close-error"}:
                            raise earlier
                        if mode == "late-read":
                            now[0] = 100.0
                        if mode == "short-read":
                            return raw[role][:-1]
                        if mode == "long-read":
                            return raw[role] + b"x"
                    return raw[role]

                def close(fd):
                    role = descriptors[fd]
                    events.append(("close", role))
                    if role == target:
                        if mode in {"close-error", "read-close-error"}:
                            raise closing
                        if mode == "late-close":
                            now[0] = 100.0

                denied = Mock(side_effect=AssertionError("reader must not reach native/fixture/child operations"))
                with patch.multiple(m, Path=PurePath, __file__=str(entry), time=SimpleNamespace(monotonic=lambda: now[0]),
                    os=SimpleNamespace(**constants, open=opened, fstat=fstat, read=read, close=close),
                    subprocess=SimpleNamespace(TimeoutExpired=m.subprocess.TimeoutExpired), socket=SimpleNamespace(), threading=SimpleNamespace(),
                    _Trust=denied, _fixtures=denied, prepare_aia=denied, _command=denied):
                    if mode in {"valid", "maximum"}:
                        self.assertEqual(m._baseline_der(100.0), tuple(raw[role] for role in roles))
                        self.assertEqual([role for operation, role in events if operation == "open"], list(roles))
                        self.assertEqual([key for operation, key in events[-3:]], ["session", "bootstrap", "entry"])
                    else:
                        with self.assertRaises((m.NativeControlError, BaseExceptionGroup, OSError)) as caught:
                            m._baseline_der(100.0)
                        error = caught.exception
                        if mode == "read-close-error":
                            self.assertEqual(error.exceptions, (earlier, closing))
                        if mode == "read-cancel":
                            self.assertEqual(error.exceptions, (earlier,))
                        public = json.dumps(m._failure_note(error, ["--aia-offline-baseline", "PRIVATE-CUTOFF"]))
                        self.assertNotIn("PRIVATE", public)
                        self.assertNotIn(str(entry.parent), public)
                denied.assert_not_called()
                opened_roles = [role for operation, role in events if operation == "open"
                                and not (mode == "open-error" and role == target)]
                self.assertEqual([role for operation, role in events if operation == "close"], opened_roles)
                if mode == "before-cutoff" or mode.startswith("entry-"):
                    self.assertEqual(events, [])
                if mode.startswith("origin-") and mode != "origin-drift":
                    self.assertFalse(any(operation == "open" for operation, _ in events))
                if mode.startswith("snapshot-"):
                    self.assertNotIn(("open", target), events)
                if target in roles:
                    self.assertTrue(all(roles.index(role) <= roles.index(target)
                                        for operation, role in events if operation == "open"))

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

    def test_trust_error_observation_uses_borrowed_public_scalars_and_preserves_cancellation(self):
        m = self.module
        unavailable = {"status": "unavailable", "code": None}
        for mode in ("null", "zero", "osstatus", "minimum", "maximum", "foreign", "null-domain", "null-constant",
                     "missing-domain", "missing-equal", "missing-code", "missing-constant", "read-error",
                     "equal-invalid", "equal-bool", "equal-shape", "code-bool", "code-float", "code-low", "code-high",
                     "cancel", "system-exit"):
            with self.subTest(public_error_scalar=mode):
                domain, equal, code = Mock(return_value=201), Mock(return_value=1), Mock(return_value=-67818)
                for function in (domain, equal, code):
                    function.restype = function.argtypes = "unbound"
                library = SimpleNamespace(CFErrorGetDomain=domain, CFEqual=equal, CFErrorGetCode=code)
                pointer = SimpleNamespace(in_dll=Mock(return_value=SimpleNamespace(value=202)))
                C = SimpleNamespace(c_void_p=pointer, c_ubyte=object(), c_long=object(),
                                    CDLL=Mock(side_effect=AssertionError("no new library may be loaded")))
                trust = object.__new__(m._Trust)
                trust.C, trust.foundation, trust.owned, trust.release = C, library, [101], Mock()
                original = KeyboardInterrupt("PRIVATE-CANCEL") if mode == "cancel" else SystemExit(7)
                if mode.startswith("missing-") and mode != "missing-constant":
                    delattr(library, {"missing-domain": "CFErrorGetDomain", "missing-equal": "CFEqual",
                                      "missing-code": "CFErrorGetCode"}[mode])
                if mode == "missing-constant":
                    pointer.in_dll.side_effect = ValueError("PRIVATE-MISSING-CONSTANT")
                elif mode == "null-constant":
                    pointer.in_dll.return_value.value = None
                if mode == "null-domain":
                    domain.return_value = None
                elif mode in {"read-error", "cancel"}:
                    domain.side_effect = OSError("PRIVATE-READ-ERROR") if mode == "read-error" else original
                if mode in {"foreign", "equal-invalid", "equal-bool", "equal-shape"}:
                    equal.return_value = {"foreign": 0, "equal-invalid": 2, "equal-bool": True, "equal-shape": []}[mode]
                if mode in {"minimum", "maximum", "code-bool", "code-float", "code-low", "code-high"}:
                    code.return_value = {"minimum": -(2**31), "maximum": 2**31 - 1, "code-bool": True,
                                         "code-float": -1.0, "code-low": -(2**31) - 1, "code-high": 2**31}[mode]
                if mode == "system-exit":
                    code.side_effect = original
                error = None if mode == "null" else 0 if mode == "zero" else 101
                with patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                    threading=SimpleNamespace(), time=SimpleNamespace()):
                    if mode in {"cancel", "system-exit"}:
                        with self.assertRaises(type(original)) as raised:
                            trust._error_observation(error)
                        self.assertIs(raised.exception, original)
                    else:
                        observed = trust._error_observation(error)
                        expected = ({"status": "no-error", "code": None} if mode in {"null", "zero"} else
                                    {"status": "osstatus", "code": code.return_value} if mode in {"osstatus", "minimum", "maximum"} else
                                    {"status": "other-domain", "code": None} if mode == "foreign" else unavailable)
                        self.assertEqual(observed, expected)
                        self.assertNotIn("PRIVATE", json.dumps(observed))
                C.CDLL.assert_not_called()
                trust.release.assert_not_called()
                self.assertEqual(trust.owned, [101])  # Neither borrowed domain is a new owned reference.
                if mode in {"null", "zero"}:
                    pointer.in_dll.assert_not_called()
                    for function in (domain, equal, code):
                        function.assert_not_called()
                        self.assertEqual((function.restype, function.argtypes), ("unbound", "unbound"))
                if mode in {"osstatus", "minimum", "maximum", "foreign"}:
                    domain.assert_called_once_with(101)
                    equal.assert_called_once_with(201, 202)
                    pointer.in_dll.assert_called_once_with(library, "kCFErrorDomainOSStatus")
                    self.assertEqual((domain.restype, domain.argtypes), (pointer, [pointer]))
                    self.assertEqual((equal.restype, equal.argtypes), (C.c_ubyte, [pointer, pointer]))
                    if mode == "foreign":
                        code.assert_not_called()
                        self.assertEqual((code.restype, code.argtypes), ("unbound", "unbound"))
                    else:
                        code.assert_called_once_with(101)
                        self.assertEqual((code.restype, code.argtypes), (C.c_long, [pointer]))
                if mode in {"null-domain", "null-constant", "missing-constant", "read-error", "equal-invalid", "equal-bool", "equal-shape"}:
                    code.assert_not_called()

    def test_signature_envelope_preserves_original_tbs_and_rejects_noncanonical_boundaries(self):
        m = self.module
        algorithm = bytes.fromhex("300d06092a864886f70d01010b0500")
        version = b"\xa0\x03\x02\x01\x02"
        raw, tbs, signature = signature_certificate(b"L")
        prefix = version + der_tlv(2, b"\x01") + algorithm
        wrap = lambda signed, alg=algorithm, bits=b"\x00" + signature: der_tlv(0x30, signed + alg + der_tlv(3, bits))
        with patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                            threading=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace()):
            self.assertEqual(m._signature_envelope(raw), (tbs, signature))
            for serial in (b"\x01", b"\x7f", b"\x00\x80", b"\x7f" + b"\xff" * 19):
                for size in (0, 100, 240, 256):
                    # Opaque later TBS fields are not silently re-encoded, hashed,
                    # or parsed as a general certificate-validity contract.
                    original, signed, expected = signature_certificate(b"I", serial=serial, opaque=b"\x80" * size)
                    with self.subTest(canonical_envelope=(serial, size)):
                        self.assertEqual(m._signature_envelope(original), (signed, expected))
                        self.assertIn(signed, original)
            large, _signed, _signature = signature_certificate(b"R", opaque=b"x" * m._MAX_DER)
            maximum, signed, expected = signature_certificate(b"R", opaque=b"x" * (2 * m._MAX_DER - len(large)))
            self.assertEqual(len(maximum), m._MAX_DER)
            self.assertEqual(m._signature_envelope(maximum), (signed, expected))
            malformed = [None, raw.decode("latin1"), bytearray(raw), b"", raw[:3], raw[:-1], raw + b"\x00",
                         b"\x31" + raw[1:], b"\x30\x80" + raw[4:] + b"\x00\x00",
                         b"\x30\x83\x00" + raw[2:], b"\x30\x82\xff\xff" + raw[4:],
                         maximum + b"\x00", signature_certificate(b"R", opaque=b"x" * m._MAX_DER)[0],
                         wrap(der_tlv(0x31, prefix)), wrap(b"\x30\x81" + bytes((len(prefix),)) + prefix),
                         wrap(b"\x30\x82\x00" + bytes((len(prefix),)) + prefix),
                         wrap(b"\x30\x82\xff\xff" + prefix), wrap(b"\x30\x80" + prefix),
                         wrap(der_tlv(0x30, prefix), alg=algorithm[:-2]),
                         wrap(der_tlv(0x30, prefix), alg=algorithm.replace(b"\x0b", b"\x05")),
                         wrap(tbs, bits=b"\x01" + signature), wrap(tbs, bits=b"\x00" + signature[:-1]),
                         wrap(tbs, bits=b"\x00" + signature + b"x"), wrap(tbs, bits=signature),
                         der_tlv(0x30, tbs + algorithm + der_tlv(4, b"\x00" + signature)),
                         der_tlv(0x30, tbs + algorithm + der_tlv(3, b"\x00" + signature) + b"\x00")]
            for serial in (b"", b"\x00", b"\x80", b"\x00\x01", b"\x00\x00\x80", b"\x01" * 21):
                malformed.append(signature_certificate(b"L", serial=serial)[0])
            for body in (prefix[len(version):], b"\xa0\x03\x02\x01\x01" + prefix[len(version):],
                         b"\xa0\x81\x03\x02\x01\x02" + prefix[len(version):],
                         version + b"\x02\x81\x01\x01" + algorithm,
                         version + b"\x02\x82\xff\xff\x01" + algorithm,
                         version + der_tlv(2, b"\x01") + algorithm[:-2],
                         version + der_tlv(2, b"\x01") + algorithm.replace(b"\x0b", b"\x05")):
                malformed.append(wrap(der_tlv(0x30, body)))
            for index, data in enumerate(malformed):
                with self.subTest(noncanonical_envelope=index), self.assertRaises(m.NativeControlError):
                    m._signature_envelope(data)
            self.assertEqual(raw, signature_certificate(b"L")[0])

    def test_signature_observation_uses_exact_messages_eligible_keys_and_original_cf_custody(self):
        m = self.module
        profiles = {role: signature_certificate(label) for role, label in (("leaf", b"L"), ("issuer", b"I"), ("root", b"R"))}
        unavailable = {"available": False, "keys": None, "checks": None}
        valid = {"positive", "early-reject", "mutant-accept", "true-with-error", "issuer-absent", "root-absent", "both-absent",
                 "issuer-small", "root-zero", "root-large", "root-unsupported", "error-unavailable", "close-error"}
        modes = (*sorted(valid), "wrong-fixture", "malformed", "missing-key", "missing-verify", "missing-constant", "null-constant",
                 "bad-constant", "key-zero", "key-bool", "key-copy-error", "size-bool", "size-negative", "size-high", "size-float",
                 "supported-bool", "supported-invalid", "data-null", "result-bool", "result-invalid", "verify-error",
                 "verify-cancel", "verify-exit", "error-cancel", "error-exit")
        for mode in modes:
            with self.subTest(native_signature_batch=mode):
                fixture = {**aia_fixtures(m)[0], **{role: value[0] for role, value in profiles.items()}}
                if mode == "wrong-fixture":
                    fixture["case"] = "offline"
                if mode == "malformed":
                    fixture["root"] = b"\x30broken-envelope"
                original_fixture = dict(fixture)
                trust = object.__new__(m._Trust)
                trust.trust, trust.owned = 10, [10, 11]
                original_scalar = {"status": "osstatus", "code": -25318}
                trust.error_observation = original_scalar
                acquired, released, verified, data, certificates = [10, 11], [], [], {}, {}
                closing = OSError("PRIVATE-CF-CLOSE")
                interruption = SystemExit(7) if mode in {"verify-exit", "error-exit"} else KeyboardInterrupt("PRIVATE-CANCEL")
                original_error = OSError("PRIVATE-VERIFY-AFTER-EFFECT")
                present = {"issuer": mode not in {"issuer-absent", "both-absent"}, "root": mode not in {"root-absent", "both-absent"}}
                sizes = {"issuer": 128 if mode == "issuer-small" else 256,
                         "root": 0 if mode == "root-zero" else m._MAX_DER if mode == "root-large" else 256}
                supported = {"issuer": True, "root": mode != "root-unsupported"}
                eligible = {name: present[name] and sizes[name] == 256 and supported[name] for name in ("issuer", "root")}

                def acquire(pointer):
                    acquired.append(pointer)
                    return pointer

                def create_data(allocator, raw, size):
                    self.assertIsNone(allocator)
                    self.assertIs(type(raw), bytes)
                    self.assertEqual(size, len(raw))
                    self.assertEqual([call.args[0] for call in envelopes.call_args_list], [fixture[role] for role in ("leaf", "issuer", "root")])
                    if mode == "data-null" and raw == profiles["issuer"][2]:
                        return None
                    pointer = 1000 + len(data)
                    data[pointer] = raw
                    return acquire(pointer)

                def create_certificate(allocator, raw):
                    self.assertIsNone(allocator)
                    self.assertIn(raw, trust.owned)
                    self.assertIn(data[raw], (fixture["issuer"], fixture["root"]))
                    pointer = 2000 + len(certificates)
                    certificates[pointer] = "issuer" if data[raw] == fixture["issuer"] else "root"
                    return acquire(pointer)

                def copy_key(certificate):
                    self.assertIn(certificate, trust.owned)
                    name = certificates[certificate]
                    if name == "root" and mode == "key-copy-error":
                        raise OSError("PRIVATE-COPY-KEY")
                    if name == "issuer" and mode in {"key-zero", "key-bool"}:
                        return 0 if mode == "key-zero" else True
                    return acquire(501 if name == "issuer" else 502) if present[name] else None

                def block_size(pointer):
                    self.assertIn(pointer, trust.owned)
                    if pointer == 502:
                        return {"size-bool": True, "size-negative": -1, "size-high": m._MAX_DER + 1,
                                "size-float": 256.0}.get(mode, sizes["root"])
                    return sizes["issuer"]

                def algorithm_supported(pointer, operation, algorithm):
                    self.assertIn(pointer, trust.owned)
                    self.assertEqual((type(operation), operation, algorithm), (int, 1, 901))
                    if pointer == 502 and mode in {"supported-bool", "supported-invalid"}:
                        return True if mode == "supported-bool" else 2
                    return int(supported["issuer" if pointer == 501 else "root"])

                def verify(pointer, algorithm, message, signature, output):
                    self.assertEqual(algorithm, 901)
                    self.assertTrue(all(value in trust.owned for value in (pointer, message, signature)))
                    if data[message] == profiles["leaf"][1]:
                        index = 0
                    elif data[message] == profiles["root"][1]:
                        index = 2
                    else:
                        self.assertEqual(data[message], profiles["issuer"][1])
                        index = 1 if data[signature] == profiles["issuer"][2] else 3
                    role = ("leaf", "issuer", "root", "issuer")[index]
                    self.assertEqual(pointer, 501 if index == 0 else 502)
                    expected_signature = profiles[role][2]
                    if index == 3:
                        expected_signature = expected_signature[:-1] + bytes((expected_signature[-1] ^ 1,))
                        self.assertEqual([a ^ b for a, b in zip(data[signature], profiles["issuer"][2])], [0] * 255 + [1])
                    self.assertEqual(data[signature], expected_signature)
                    verified.append(index)
                    accepted = 0 if index == 3 and mode != "mutant-accept" or index == 0 and mode == "early-reject" else 1
                    failed_call = index == 1 and mode in {"result-bool", "result-invalid", "verify-error", "verify-cancel", "verify-exit"}
                    output.value = acquire(3000 + index) if not accepted or failed_call or mode == "true-with-error" and index == 0 else None
                    if index == 1 and mode in {"verify-cancel", "verify-exit"}:
                        raise interruption
                    if index == 1 and mode == "verify-error":
                        raise original_error
                    return True if index == 1 and mode == "result-bool" else 2 if index == 1 and mode == "result-invalid" else accepted

                def domain(pointer):
                    self.assertIn(pointer, trust.owned)  # Out-error custody precedes even public scalar reads.
                    self.assertIn(pointer, (3000, 3001, 3002, 3003))
                    return 902

                def code(pointer):
                    self.assertIn(pointer, trust.owned)
                    if mode in {"error-cancel", "error-exit"}:
                        raise interruption
                    if mode == "error-unavailable":
                        raise OSError("PRIVATE-ERROR-READ")
                    return -50

                def constant(library, name):
                    if library is security:
                        self.assertEqual(name, "kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256")
                        if mode == "missing-constant":
                            raise ValueError("PRIVATE-CONSTANT")
                        return SimpleNamespace(value=None if mode == "null-constant" else True if mode == "bad-constant" else 901)
                    self.assertIs(library, foundation)
                    self.assertEqual(name, "kCFErrorDomainOSStatus")
                    return SimpleNamespace(value=903)

                def release(pointer):
                    released.append(pointer)
                    if mode == "close-error" and pointer in (3003, 501):
                        raise closing

                P, pointer_type = Mock(side_effect=lambda: SimpleNamespace(value=None)), object()
                P.in_dll = Mock(side_effect=constant)
                C = SimpleNamespace(c_void_p=P, c_size_t=object(), c_long=object(), c_ubyte=object(),
                                    POINTER=Mock(return_value=pointer_type), byref=lambda pointer: pointer,
                                    CDLL=Mock(side_effect=AssertionError("no additional native library")))
                security = SimpleNamespace(SecCertificateCopyKey=Mock(side_effect=copy_key), SecKeyGetBlockSize=Mock(side_effect=block_size),
                    SecKeyIsAlgorithmSupported=Mock(side_effect=algorithm_supported), SecKeyVerifySignature=Mock(side_effect=verify))
                for function in vars(security).values():
                    function.restype = function.argtypes = "unbound"
                if mode in {"missing-key", "missing-verify"}:
                    delattr(security, "SecCertificateCopyKey" if mode == "missing-key" else "SecKeyVerifySignature")
                foundation = SimpleNamespace(CFErrorGetDomain=Mock(side_effect=domain), CFErrorGetCode=Mock(side_effect=code),
                                             CFEqual=Mock(return_value=1))
                trust.C, trust.security, trust.foundation = C, security, foundation
                trust.data_create, trust.cert_create, trust.release = Mock(side_effect=create_data), Mock(side_effect=create_certificate), Mock(side_effect=release)
                observer, envelopes = Mock(wraps=trust._error_observation), Mock(wraps=m._signature_envelope)
                trust._error_observation = observer
                trust.network_set, trust.keychains_set, trust.native_evaluate = Mock(), Mock(), Mock()
                with patch.multiple(m, _signature_envelope=envelopes, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                    threading=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace()):
                    if mode in {"verify-cancel", "verify-exit", "error-cancel", "error-exit"}:
                        with self.assertRaises(type(interruption)) as raised:
                            trust._signature_observation(fixture)
                        self.assertIs(raised.exception, interruption)
                    else:
                        observed = trust._signature_observation(fixture)
                        if mode in valid:
                            expected_keys = [{"key": name, "present": present[name], "block_bytes": sizes[name] if present[name] else None,
                                              "verify_supported": supported[name] if present[name] else None} for name in ("issuer", "root")]
                            expected_checks = []
                            for index, case in enumerate(m._SIGNATURE_CASES):
                                executed = eligible["issuer" if index == 0 else "root"]
                                accepted = not (index == 3 and mode != "mutant-accept" or index == 0 and mode == "early-reject")
                                has_error = not accepted or mode == "true-with-error" and index == 0
                                error = ({"status": "unavailable", "code": None} if mode == "error-unavailable" and has_error else
                                         {"status": "osstatus", "code": -50} if has_error else {"status": "no-error", "code": None})
                                expected_checks.append({"case": case, "executed": executed, "accepted": accepted if executed else None,
                                                        "error": has_error if executed else None, "trust_error": error if executed else None})
                            self.assertEqual(observed, {"available": True, "keys": expected_keys, "checks": expected_checks})
                            self.assertEqual(verified, [index for index, row in enumerate(expected_checks) if row["executed"]])
                            for private in ("PRIVATE", "opaque-", "0x1234", "signature_message", "route"):
                                self.assertNotIn(private, json.dumps(observed))
                        else:
                            self.assertEqual(observed, unavailable)  # Never publish a partially completed batch.
                self.assertIs(trust.error_observation, original_scalar)
                self.assertEqual(original_scalar, {"status": "osstatus", "code": -25318})
                self.assertEqual(fixture, original_fixture)
                self.assertEqual(trust.owned, acquired)
                trust.release.assert_not_called()
                if mode in {"result-bool", "result-invalid", "verify-error", "verify-cancel", "verify-exit"}:
                    self.assertIn(3001, trust.owned)
                    self.assertEqual(verified, [0, 1])
                    self.assertEqual(observer.call_count, 1)  # The after-effect output is adopted before a failing shape check.
                if mode in valid:
                    self.assertEqual((security.SecCertificateCopyKey.restype, security.SecCertificateCopyKey.argtypes), (P, [P]))
                    self.assertEqual((security.SecKeyGetBlockSize.restype, security.SecKeyGetBlockSize.argtypes), (C.c_size_t, [P]))
                    self.assertEqual((security.SecKeyIsAlgorithmSupported.restype, security.SecKeyIsAlgorithmSupported.argtypes), (C.c_ubyte, [P, C.c_long, P]))
                    self.assertEqual((security.SecKeyVerifySignature.restype, security.SecKeyVerifySignature.argtypes), (C.c_ubyte, [P, P, P, P, pointer_type]))
                    self.assertEqual([call.args[0] for call in security.SecKeyGetBlockSize.call_args_list],
                                     [pointer for name, pointer in (("issuer", 501), ("root", 502)) if present[name]])
                    self.assertEqual([call.args[0] for call in security.SecKeyIsAlgorithmSupported.call_args_list],
                                     [pointer for name, pointer in (("issuer", 501), ("root", 502)) if present[name]])
                if mode in {"wrong-fixture", "malformed", "missing-key", "missing-verify", "missing-constant", "null-constant", "bad-constant"}:
                    trust.data_create.assert_not_called()
                    self.assertEqual(verified, [])
                if mode == "close-error":
                    with self.assertRaises(BaseExceptionGroup) as raised:
                        trust.close()
                    self.assertEqual(raised.exception.exceptions, (closing, closing))
                else:
                    trust.close()
                self.assertEqual(released, list(reversed(acquired)))
                self.assertEqual(trust.owned, [])
                self.assertTrue(all(pointer not in released for pointer in (901, 902, 903)))
                for operation in (C.CDLL, trust.network_set, trust.keychains_set, trust.native_evaluate):
                    operation.assert_not_called()

    def test_trust_evaluation_observes_error_only_after_original_chain_and_keeps_custody(self):
        m = self.module
        fixture = aia_fixtures(m)[0]
        for mode in ("observed", "unavailable", "no-error", "native-error", "result-error", "chain-error",
                     "cancel", "system-exit", "cutoff", "close-error", "post-close-cutoff"):
            with self.subTest(original_trust_collection=mode):
                events, observations, now = [], [], [10.0]
                earlier, closing = OSError("PRIVATE-NATIVE-ERROR"), OSError("PRIVATE-CF-CLOSE")
                interruption = KeyboardInterrupt("PRIVATE-CANCEL") if mode == "cancel" else SystemExit(7)
                trust = object.__new__(m._Trust)
                trust.trust, trust.owned = 10, [10]
                trust.error_observation = {"status": "unavailable", "code": None}
                raw = {310: fixture["leaf"], 311: fixture["issuer"]}

                def evaluate(pointer, error):
                    self.assertEqual(pointer, 10)
                    events.append("evaluate")
                    error.value = None if mode == "no-error" else 110
                    if mode == "native-error":
                        raise earlier
                    return mode == "no-error"

                def result(pointer, value):
                    self.assertEqual(pointer, 10)
                    events.append("result")
                    value.value = 4 if mode == "no-error" else 5
                    return -1 if mode == "result-error" else 0

                def read(pointer, size):
                    events.append(("chain-bytes", pointer))
                    self.assertIn(pointer - 100, trust.owned)
                    self.assertEqual(size, len(raw[pointer - 100]))
                    if mode == "chain-error" and pointer == 411:
                        raise earlier
                    return raw[pointer - 100]

                def domain(pointer):
                    self.assertEqual(pointer, 110)
                    self.assertEqual(events[-2:], [("chain-bytes", 410), ("chain-bytes", 411)])
                    self.assertEqual(trust.owned, [10, 110, 210, 310, 311])
                    events.append("error-domain")
                    if mode == "cancel":
                        raise interruption
                    return 501

                def code(pointer):
                    self.assertEqual(pointer, 110)
                    events.append("error-code")
                    if mode == "unavailable":
                        raise ValueError("PRIVATE-OPTIONAL-ERROR")
                    if mode == "system-exit":
                        raise interruption
                    if mode == "cutoff":
                        now[0] = 100.0
                    return -67818

                def release(pointer):
                    events.append(("release", pointer))
                    if mode == "close-error" and pointer == 311:
                        raise closing
                    if mode == "post-close-cutoff" and pointer == 10:
                        now[0] = 100.0

                pointer = Mock(side_effect=lambda: SimpleNamespace(value=None))
                pointer.in_dll = Mock(return_value=SimpleNamespace(value=502))
                trust.C = SimpleNamespace(c_void_p=pointer, c_uint32=lambda: SimpleNamespace(value=0),
                    c_ubyte=object(), c_long=object(), byref=lambda value: value, string_at=read,
                    CDLL=Mock(side_effect=AssertionError("synthetic evaluation cannot load native libraries")))
                trust.foundation = SimpleNamespace(CFErrorGetDomain=Mock(side_effect=domain), CFEqual=Mock(return_value=1),
                                                   CFErrorGetCode=Mock(side_effect=code))
                trust.native_evaluate, trust.trust_result = Mock(side_effect=evaluate), Mock(side_effect=result)
                trust.copy_chain, trust.array_count = Mock(return_value=210), Mock(return_value=2)
                trust.array_item = Mock(side_effect=lambda _chain, index: 211 + index)
                trust.cert_data = Mock(side_effect=lambda certificate: certificate + 99)
                trust.data_length, trust.data_bytes = Mock(side_effect=lambda value: len(raw[value])), Mock(side_effect=lambda value: value + 100)
                trust.release = Mock(side_effect=release)
                trust.set_network, trust.get_network = Mock(), Mock(return_value=True)
                trust.set_keychains, trust.get_keychains = Mock(), Mock(return_value=True)
                observer = Mock(wraps=trust._error_observation)
                trust._error_observation = observer
                with patch.multiple(m, _Trust=Mock(return_value=trust), time=SimpleNamespace(monotonic=lambda: now[0]),
                                    os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace()):
                    if mode in {"observed", "unavailable", "no-error"}:
                        row = m._evaluate_case(fixture, 100.0, observations)
                        self.assertEqual(row, {"case": "online", "baseline_network": True, "network": True, "keychains": True,
                            "accepted": mode == "no-error", "error": mode != "no-error", "result": 4 if mode == "no-error" else 5,
                            "chain": [m.hashlib.sha256(raw[index]).hexdigest() for index in (310, 311)]})
                        scalar = ({"status": "osstatus", "code": -67818} if mode == "observed" else
                                  {"status": "no-error", "code": None} if mode == "no-error" else {"status": "unavailable", "code": None})
                        self.assertEqual(trust.error_observation, scalar)
                        self.assertEqual(observations, [{"case": "online", **scalar}])
                        trust.error_observation["code"] = 123
                        self.assertEqual(observations, [{"case": "online", **scalar}])  # Detached before publication.
                    else:
                        expected_error = m.NativeControlError if mode == "post-close-cutoff" else BaseExceptionGroup
                        with self.assertRaises(expected_error) as raised:
                            m._evaluate_case(fixture, 100.0, observations)
                        self.assertEqual(observations, [])
                        children = raised.exception.exceptions if isinstance(raised.exception, BaseExceptionGroup) else (raised.exception,)
                        leaves = [leaf for child in children for leaf in
                                  (child.exceptions if isinstance(child, BaseExceptionGroup) else (child,))]
                        if mode in {"native-error", "chain-error"}:
                            self.assertIn(earlier, leaves)
                        elif mode in {"cancel", "system-exit"}:
                            self.assertIn(interruption, leaves)
                        elif mode == "close-error":
                            self.assertIn(closing, leaves)
                        else:
                            self.assertTrue(any(isinstance(error, m.NativeControlError) for error in leaves))
                early = mode in {"native-error", "result-error", "chain-error"}
                self.assertEqual(observer.call_count, 0 if early else 1)
                if early or mode == "no-error":
                    trust.foundation.CFErrorGetDomain.assert_not_called()
                    trust.foundation.CFErrorGetCode.assert_not_called()
                    pointer.in_dll.assert_not_called()
                released = [event[1] for event in events if isinstance(event, tuple) and event[0] == "release"]
                self.assertEqual(released, [110, 10] if mode in {"native-error", "result-error"} else
                                 [311, 310, 210, *([] if mode == "no-error" else [110]), 10])
                self.assertEqual(trust.owned, [])
                self.assertNotIn(501, released)
                self.assertNotIn(502, released)
                trust.C.CDLL.assert_not_called()

    def test_trust_constructor_preserves_leaf_only_and_fixed_contrast_presentation(self):
        m = self.module
        fixture = aia_fixtures(m)[0]
        # Actual __init__, with a test-authored ctypes module; no CDLL can reach
        # the platform. The two small builders use the actual _own/close methods.
        for mode in ("leaf-only", "full-chain", "issuer-root", "leaf-issuer", "after-effect", "after-effect-close", "after-effect-cancel"):
            with self.subTest(presented_certificates=mode):
                acquired, released, certificates, arrays, instances = [], [], {}, {}, []
                earlier = KeyboardInterrupt("PRIVATE-CANCEL") if mode == "after-effect-cancel" else OSError("PRIVATE-TRUST-CREATE")
                closing = OSError("PRIVATE-CF-CLOSE")
                complete = mode not in {"leaf-only", "issuer-root", "leaf-issuer"}
                leaf = fixture["issuer"] if mode == "issuer-root" else fixture["leaf"]
                anchor = fixture["issuer"] if mode == "leaf-issuer" else fixture["root"]

                def acquire(pointer):
                    acquired.append(pointer)
                    return pointer

                def certificate(trust, raw):
                    if not instances:
                        instances.append(trust)
                    self.assertIs(trust, instances[0])
                    pointer = 101 + len(certificates)
                    certificates[pointer] = raw
                    return trust._own(acquire(pointer))

                def array(trust, values):
                    self.assertTrue(all(value in trust.owned for value in values))
                    pointer = 201 + len(arrays)
                    arrays[pointer] = list(values)
                    return trust._own(acquire(pointer))

                def create(presented, policy, output):
                    self.assertEqual((presented, policy), (201, 50))
                    self.assertIn(presented, instances[0].owned)
                    output.value = acquire(900)
                    if mode.startswith("after-effect"):
                        raise earlier
                    return 0

                def release(pointer):
                    released.append(pointer)
                    if mode == "after-effect-close" and pointer == 900:
                        raise closing

                foundation = SimpleNamespace(**{name: Mock(side_effect=AssertionError("unexpected synthetic CF operation"))
                    for name in ("CFRelease", "CFDataCreate", "CFDataGetLength", "CFDataGetBytePtr", "CFArrayCreate",
                                 "CFArrayGetCount", "CFArrayGetValueAtIndex")})
                security = SimpleNamespace(**{name: Mock(side_effect=AssertionError("unexpected synthetic Security operation"))
                    for name in ("SecCertificateCreateWithData", "SecCertificateCopyData", "SecPolicyCreateBasicX509",
                                 "SecTrustCreateWithCertificates", "SecTrustSetAnchorCertificates", "SecTrustSetAnchorCertificatesOnly",
                                 "SecTrustSetNetworkFetchAllowed", "SecTrustSetKeychainsAllowed", "SecTrustGetNetworkFetchAllowed",
                                 "SecTrustGetKeychainsAllowed", "SecTrustEvaluateWithError", "SecTrustGetTrustResult",
                                 "SecTrustCopyCertificateChain")})
                foundation.CFRelease = Mock(side_effect=release)
                security.SecPolicyCreateBasicX509 = Mock(side_effect=lambda: acquire(50))
                security.SecTrustCreateWithCertificates = Mock(side_effect=create)
                security.SecTrustSetAnchorCertificates, security.SecTrustSetAnchorCertificatesOnly = Mock(return_value=0), Mock(return_value=0)
                P, pointer_type = Mock(side_effect=lambda: SimpleNamespace(value=None)), object()
                C = SimpleNamespace(c_void_p=P, c_long=object(), c_int32=object(), c_ubyte=object(), c_bool=object(),
                                    c_uint32=object(), POINTER=Mock(return_value=pointer_type), byref=lambda pointer: pointer,
                                    CDLL=Mock(side_effect=[security, foundation]))
                arguments = {"issuer": fixture["issuer"]} if complete else {}
                with patch.dict(sys.modules, {"ctypes": C}), patch.object(m._Trust, "_certificate", certificate), \
                        patch.object(m._Trust, "_array", array), patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(),
                        socket=SimpleNamespace(), threading=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace()):
                    if mode.startswith("after-effect"):
                        expected_error = BaseExceptionGroup if mode == "after-effect-close" else type(earlier)
                        with self.assertRaises(expected_error) as raised:
                            m._Trust(leaf, anchor, **arguments)
                        if mode == "after-effect-close":
                            self.assertIs(raised.exception.exceptions[0], earlier)
                            self.assertEqual(raised.exception.exceptions[1].exceptions, (closing,))
                        else:
                            self.assertIs(raised.exception, earlier)
                        security.SecTrustSetAnchorCertificates.assert_not_called()
                        security.SecTrustSetAnchorCertificatesOnly.assert_not_called()
                    else:
                        trust = m._Trust(leaf, anchor, **arguments)
                        self.assertIs(trust, instances[0])
                        self.assertIs(trust.security, security)
                        self.assertIs(trust.foundation, foundation)
                        self.assertEqual(trust.error_observation, {"status": "unavailable", "code": None})
                        self.assertEqual([certificates[value] for value in arrays[202]], [anchor])
                        security.SecTrustSetAnchorCertificates.assert_called_once_with(900, 202)
                        security.SecTrustSetAnchorCertificatesOnly.assert_called_once_with(900, 1)
                        self.assertEqual(trust.owned, acquired)
                        trust.close()
                self.assertEqual([certificates[value] for value in arrays[201]],
                                 [fixture[role] for role in ("leaf", "issuer", "root")] if complete else [leaf])
                self.assertEqual(len(arrays), 1 if mode.startswith("after-effect") else 2)
                self.assertEqual(released, list(reversed(acquired)))
                self.assertEqual(instances[0].owned, [])
                self.assertIn(900, released)  # Nonnull trust out pointer survives every after-effect exception.
                self.assertEqual([call.args for call in C.CDLL.call_args_list],
                                 [("/System/Library/Frameworks/Security.framework/Security",),
                                  ("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",)])
                self.assertEqual((security.SecTrustCreateWithCertificates.restype, security.SecTrustCreateWithCertificates.argtypes),
                                 (C.c_int32, [P, P, pointer_type]))
                for name in ("SecTrustSetNetworkFetchAllowed", "SecTrustSetKeychainsAllowed", "SecTrustGetNetworkFetchAllowed",
                             "SecTrustGetKeychainsAllowed", "SecTrustEvaluateWithError", "SecTrustGetTrustResult", "SecTrustCopyCertificateChain"):
                    getattr(security, name).assert_not_called()

    def test_offline_full_chain_contrast_preserves_cutoff_flags_and_cleanup(self):
        m = self.module
        fixture = aia_fixtures(m)[0]
        chain = [m.hashlib.sha256(fixture[role]).hexdigest() for role in ("leaf", "issuer", "root")]
        test = self
        modes = [("full", mode) for mode in ("accepted", "rejected", "network-true", "network-number", "keys-true", "keys-number",
            "setter-error", "constructor-error", "constructor-cutoff", "evaluate-error", "cancel", "close-error", "evaluate-and-close",
            "before-cutoff", "evaluate-cutoff", "close-cutoff", "signature-unavailable", "signature-cancel", "signature-cutoff", "signature-and-close")]
        modes += [(role, mode) for role in ("issuer-root", "leaf-issuer") for mode in ("accepted", "rejected", "close-cutoff")]
        for role, mode in modes:
            with self.subTest(offline_contrast=(role, mode)):
                leaf_role, anchor_role, expected_chain, label = {
                    "full": ("leaf", "root", chain, m._CONTRAST_CASE),
                    "issuer-root": ("issuer", "root", chain[1:], m._ISSUER_ROOT_CONTRAST_CASE),
                    "leaf-issuer": ("leaf", "issuer", chain[:2], m._LEAF_ISSUER_CONTRAST_CASE)}[role]
                now, closed, events = [100.0 if mode == "before-cutoff" else 10.0], [False], []
                earlier = KeyboardInterrupt("PRIVATE-CANCEL") if mode in {"cancel", "signature-cancel"} else OSError("PRIVATE-CONTRAST")
                closing = OSError("PRIVATE-CLOSE")
                scalar = {"status": "osstatus", "code": -25318} if mode == "rejected" else {"status": "no-error", "code": None}
                original_chain = expected_chain[:1] if mode == "rejected" else list(expected_chain)
                result = {"accepted": mode != "rejected", "error": mode == "rejected", "result": 5 if mode == "rejected" else 4,
                          "chain": original_chain}
                crypto = ({"available": False, "keys": None, "checks": None} if mode == "signature-unavailable" else
                          aia_chain_observations(m, aia_fixtures(m))["crypto"])

                def evaluate():
                    events.append("evaluate")
                    self.assertFalse(closed[0])
                    trust.set_network.assert_called_once_with(False)
                    trust.set_keychains.assert_called_once_with(False)
                    trust.get_network.assert_called_once_with()
                    trust.get_keychains.assert_called_once_with()
                    if mode in {"evaluate-error", "evaluate-and-close", "cancel"}:
                        raise earlier
                    if mode == "evaluate-cutoff":
                        now[0] = 100.0
                    return result

                def observe(original):
                    self.assertIs(original, fixture)
                    self.assertEqual(role, "full")
                    self.assertFalse(closed[0])
                    self.assertEqual(events[-1], "evaluate")
                    events.append("signature")
                    if mode in {"signature-cancel", "signature-and-close"}:
                        raise earlier
                    if mode == "signature-cutoff":
                        now[0] = 100.0
                    return crypto

                def close():
                    events.append("close")
                    closed[0] = True
                    if mode in {"close-error", "evaluate-and-close", "signature-and-close"}:
                        raise closing
                    if mode == "close-cutoff":
                        now[0] = 100.0

                class Trust:
                    @property
                    def error_observation(self):
                        test.assertTrue(closed[0])
                        events.append("detached-observation")
                        return scalar

                trust = Trust()
                trust.set_network = Mock(side_effect=earlier if mode == "setter-error" else None)
                trust.set_keychains = Mock()
                trust.get_network = Mock(return_value=True if mode == "network-true" else 0 if mode == "network-number" else False)
                trust.get_keychains = Mock(return_value=True if mode == "keys-true" else 0 if mode == "keys-number" else False)
                trust.evaluate, trust.close = Mock(side_effect=evaluate), Mock(side_effect=close)
                trust._signature_observation = Mock(side_effect=observe)

                def construct(leaf, root, **kwargs):
                    self.assertEqual((leaf, root), (fixture[leaf_role], fixture[anchor_role]))
                    self.assertEqual(kwargs, {"issuer": fixture["issuer"]} if role == "full" else {})
                    events.append("construct")
                    if mode == "constructor-error":
                        raise earlier  # Constructor owns its own partial references (covered above).
                    if mode == "constructor-cutoff":
                        now[0] = 100.0
                    return trust

                constructor, remaining = Mock(side_effect=construct), Mock(wraps=m._remaining)
                with patch.multiple(m, _Trust=constructor, _remaining=remaining, time=SimpleNamespace(monotonic=lambda: now[0]),
                                    os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                    threading=SimpleNamespace(), Path=SimpleNamespace()):
                    if mode in {"accepted", "rejected", "signature-unavailable"}:
                        observed, diagnostic = m._evaluate_offline_contrast(fixture, 100.0, role=role)
                        expected = {"case": label,
                                    "network": False, "keychains": False, **result, "trust_error": dict(scalar)}
                        self.assertEqual(observed, expected)
                        self.assertEqual(diagnostic, crypto if role == "full" else None)
                        scalar["status"] = "unavailable"
                        self.assertEqual(observed, expected)
                        self.assertEqual(events, ["construct", "evaluate", *(["signature"] if role == "full" else []), "close", "detached-observation"])
                    else:
                        expected_error = m.NativeControlError if mode == "close-cutoff" else BaseExceptionGroup
                        with self.assertRaises(expected_error) as raised:
                            m._evaluate_offline_contrast(fixture, 100.0, role=role)
                        errors = raised.exception.exceptions if isinstance(raised.exception, BaseExceptionGroup) else (raised.exception,)
                        if mode in {"constructor-error", "setter-error", "evaluate-error", "evaluate-and-close", "cancel",
                                    "signature-cancel", "signature-and-close"}:
                            self.assertIs(errors[0], earlier)
                        if mode in {"close-error", "evaluate-and-close", "signature-and-close"}:
                            self.assertIs(errors[-1], closing)
                            self.assertEqual(len(errors), 2 if mode in {"evaluate-and-close", "signature-and-close"} else 1)
                        if mode.endswith("cutoff") or mode in {"network-true", "network-number", "keys-true", "keys-number"}:
                            self.assertTrue(any(isinstance(error, m.NativeControlError) for error in errors))
                        self.assertNotIn("detached-observation", events)
                self.assertTrue(remaining.called)
                self.assertTrue(all(call.args == (100.0,) and not call.kwargs for call in remaining.call_args_list))
                if mode == "before-cutoff":
                    constructor.assert_not_called()
                else:
                    constructor.assert_called_once_with(fixture[leaf_role], fixture[anchor_role],
                                                        **({"issuer": fixture["issuer"]} if role == "full" else {}))
                if mode in {"before-cutoff", "constructor-error"}:
                    trust.close.assert_not_called()
                    trust.set_network.assert_not_called()
                else:
                    trust.close.assert_called_once_with()
                    trust.set_network.assert_called_once_with(False)
                    if mode != "setter-error":
                        trust.set_keychains.assert_called_once_with(False)
                        trust.get_network.assert_called_once_with()
                        trust.get_keychains.assert_called_once_with()
                if mode in {"before-cutoff", "constructor-error", "constructor-cutoff", "setter-error", "network-true", "network-number",
                            "keys-true", "keys-number"}:
                    trust.evaluate.assert_not_called()
                else:
                    trust.evaluate.assert_called_once_with()
                if role == "full" and mode in {"accepted", "rejected", "close-error", "close-cutoff", "signature-unavailable",
                                               "signature-cancel", "signature-cutoff", "signature-and-close"}:
                    trust._signature_observation.assert_called_once_with(fixture)
                else:
                    trust._signature_observation.assert_not_called()
        constructor = Mock(side_effect=AssertionError("wrong fixture must reject before acquisition"))
        class Role(str):
            pass
        with clock(m), patch.object(m, "_Trust", constructor):
            for original, role in [(aia_fixtures(m)[1], "full"), *((fixture, value) for value in
                                  (None, 1, True, [], {}, "", "root-only", "Full", "unknown", Role("full")))]:
                with self.subTest(rejected_role=role), self.assertRaises(m.NativeControlError):
                    m._evaluate_offline_contrast(original, 100.0, role=role)
        constructor.assert_not_called()

    def test_baseline_evaluation_is_one_original_full_chain_without_replay(self):
        m, test = self.module, self
        originals = tuple(aia_fixtures(m)[0][role] for role in ("leaf", "issuer", "root"))
        modes = ("accepted", "rejected", "read-error", "read-cancel", "read-cutoff", "before-cutoff",
                 "constructor-error", "constructor-cancel", "constructor-cutoff", "network-set-error", "keys-set-error",
                 "network-get-error", "keys-get-error", "network-true", "network-number", "network-none",
                 "keys-true", "keys-number", "keys-none", "evaluate-error", "cancel", "system-exit", "close-error",
                 "close-cancel", "evaluate-and-close", "evaluate-cutoff", "close-cutoff")
        for mode in modes:
            with self.subTest(baseline_evaluation=mode):
                now, events, closed = [100.0 if mode == "before-cutoff" else 10.0], [], [False]
                earlier = (KeyboardInterrupt("PRIVATE-CANCEL") if mode in {"read-cancel", "constructor-cancel", "cancel"}
                           else SystemExit("PRIVATE-EXIT") if mode == "system-exit" else OSError("PRIVATE-EVALUATION"))
                closing = KeyboardInterrupt("PRIVATE-CLOSE-CANCEL") if mode == "close-cancel" else OSError("PRIVATE-CLOSE")
                raw = aia_baseline_evidence(m, originals, accepted=mode != "rejected")
                scalar = dict(raw["trust_error"])
                result = {key: raw[key] for key in ("accepted", "error", "result", "chain")}

                def read(deadline):
                    self.assertEqual(deadline, 100.0)
                    m._remaining(deadline)
                    events.append("read")
                    if mode in {"read-error", "read-cancel"}:
                        raise earlier
                    if mode == "read-cutoff":
                        now[0] = 100.0
                    return originals

                def evaluate():
                    self.assertFalse(closed[0])
                    trust.set_network.assert_called_once_with(False)
                    trust.set_keychains.assert_called_once_with(False)
                    trust.get_network.assert_called_once_with()
                    trust.get_keychains.assert_called_once_with()
                    events.append("evaluate")
                    if mode in {"evaluate-error", "cancel", "system-exit", "evaluate-and-close"}:
                        raise earlier
                    if mode == "evaluate-cutoff":
                        now[0] = 100.0
                    return result

                def close():
                    self.assertFalse(closed[0])
                    closed[0] = True
                    events.append("close")
                    if mode in {"close-error", "close-cancel", "evaluate-and-close"}:
                        raise closing
                    if mode == "close-cutoff":
                        now[0] = 100.0

                class Trust:
                    @property
                    def error_observation(self):
                        test.assertTrue(closed[0])
                        events.append("detached-observation")
                        return scalar

                trust = Trust()
                trust.set_network = Mock(side_effect=earlier if mode == "network-set-error" else None)
                trust.set_keychains = Mock(side_effect=earlier if mode == "keys-set-error" else None)
                trust.get_network = Mock(side_effect=earlier if mode == "network-get-error" else None,
                    return_value={"network-true": True, "network-number": 0, "network-none": None}.get(mode, False))
                trust.get_keychains = Mock(side_effect=earlier if mode == "keys-get-error" else None,
                    return_value={"keys-true": True, "keys-number": 0, "keys-none": None}.get(mode, False))
                trust.evaluate, trust.close = Mock(side_effect=evaluate), Mock(side_effect=close)
                denied = Mock(side_effect=AssertionError("baseline must not replay any other operation"))
                trust._signature_observation = denied

                def construct(leaf, root, *, issuer):
                    self.assertEqual((leaf, issuer, root), originals)
                    events.append("construct")
                    if mode in {"constructor-error", "constructor-cancel"}:
                        raise earlier
                    if mode == "constructor-cutoff":
                        now[0] = 100.0
                    return trust

                reader, constructor, remaining = Mock(side_effect=read), Mock(side_effect=construct), Mock(wraps=m._remaining)
                with patch.multiple(m, _baseline_der=reader, _Trust=constructor, _remaining=remaining,
                    time=SimpleNamespace(monotonic=lambda: now[0]), os=SimpleNamespace(), subprocess=SimpleNamespace(),
                    socket=SimpleNamespace(), threading=SimpleNamespace(), Path=SimpleNamespace(), _command=denied,
                    _fixtures=denied, prepare_aia=denied, evaluate_aia=denied, _evaluate_case=denied,
                    _evaluate_offline_contrast=denied, _signature_envelope=denied, _Responder=denied):
                    if mode in {"accepted", "rejected"}:
                        observed = m.evaluate_aia_baseline(100.0)
                        self.assertEqual(observed, raw)
                        scalar["status"] = "unavailable"
                        self.assertEqual(observed, raw)
                        self.assertEqual(events, ["read", "construct", "evaluate", "close", "detached-observation"])
                    else:
                        expected = (type(earlier) if mode in {"read-error", "read-cancel"} else
                                    m.NativeControlError if mode in {"before-cutoff", "close-cutoff"} else BaseExceptionGroup)
                        with self.assertRaises(expected) as caught:
                            m.evaluate_aia_baseline(100.0)
                        errors = caught.exception.exceptions if isinstance(caught.exception, BaseExceptionGroup) else (caught.exception,)
                        if mode in {"read-error", "read-cancel", "constructor-error", "constructor-cancel", "network-set-error",
                                    "keys-set-error", "network-get-error", "keys-get-error", "evaluate-error", "cancel",
                                    "system-exit", "evaluate-and-close"}:
                            self.assertIs(errors[0], earlier)
                        if mode in {"close-error", "close-cancel", "evaluate-and-close"}:
                            self.assertIs(errors[-1], closing)
                            self.assertEqual(len(errors), 2 if mode == "evaluate-and-close" else 1)
                        self.assertNotIn("detached-observation", events)
                reader.assert_called_once_with(100.0)
                self.assertTrue(remaining.called)
                self.assertTrue(all(call.args == (100.0,) and not call.kwargs for call in remaining.call_args_list))
                denied.assert_not_called()
                acquired = mode not in {"before-cutoff", "read-error", "read-cancel", "read-cutoff", "constructor-error", "constructor-cancel"}
                self.assertEqual(trust.close.call_count, int(acquired))
                if mode not in {"before-cutoff", "read-error", "read-cancel", "read-cutoff"}:
                    constructor.assert_called_once_with(originals[0], originals[2], issuer=originals[1])
                else:
                    constructor.assert_not_called()
                evaluated = mode in {"accepted", "rejected", "evaluate-error", "cancel", "system-exit", "close-error",
                                     "close-cancel", "evaluate-and-close", "evaluate-cutoff", "close-cutoff"}
                self.assertEqual(trust.evaluate.call_count, int(evaluated))

    def test_baseline_projection_is_closed_bounded_and_never_acceptance_authority(self):
        m = self.module
        originals = tuple(aia_fixtures(m)[0][role] for role in ("leaf", "issuer", "root"))
        self.assertEqual(m.AIA_BASELINE_PREFIX, b"MRK_NATIVE_AIA_BASELINE=")
        self.assertEqual(m._AIA_BASELINE_CASE, "online-full-chain-offline-baseline")
        encode = lambda value: m.AIA_BASELINE_PREFIX + json.dumps(value, separators=(",", ":")).encode() + b"\n"
        denied = Mock(side_effect=AssertionError("projection cannot acquire resources or run an acceptance oracle"))

        def project(data, original=originals):
            with patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                threading=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace(), _baseline_der=denied,
                _Trust=denied, _fixtures=denied, _Responder=denied, prepare_aia=denied, evaluate_aia=denied,
                evaluate_aia_baseline=denied, require_aia_controls=denied, _command=denied):
                return m.baseline_comparison_note(data, original)

        expected = {"schema": 1, "control": "aia-offline-baseline", "semantics": "comparison-observation-only",
                    "available": True, "case": "online-full-chain-offline-baseline", "network": False, "keychains": False,
                    "accepted": True, "error": False, "result": 4, "chain_count": 3, "chain_matches": True,
                    "chain_roles": ["leaf", "issuer", "root"], "trust_error": {"status": "no-error", "code": None}}
        row = aia_baseline_evidence(m, originals)
        self.assertEqual(project(encode(row)), expected)
        negative = aia_baseline_evidence(m, originals, accepted=False)
        note = project(encode(negative))
        self.assertEqual(note, {**expected, "accepted": False, "error": True, "result": 5, "chain_count": 2,
                                "chain_matches": False, "chain_roles": ["leaf", "issuer"],
                                "trust_error": {"status": "osstatus", "code": -25318}})
        for chain, labels in ((list(reversed(row["chain"])), ["root", "issuer", "leaf"]),
                              (["0" * 64], ["other"]), ([row["chain"][0]] * 3, ["leaf"] * 3)):
            note = project(encode({**row, "chain": chain}))
            self.assertTrue(note["available"])
            self.assertEqual(note["chain_roles"], labels)
            self.assertFalse(note["chain_matches"])
        note = project(encode(row), tuple(reversed(originals)))
        self.assertEqual(note["chain_roles"], ["root", "issuer", "leaf"])
        self.assertFalse(note["chain_matches"])
        for status, code in (("no-error", None), ("unavailable", None), ("other-domain", None),
                             ("osstatus", -(2**31)), ("osstatus", 2**31 - 1), ("osstatus", 0)):
            for result in (0, 0xffffffff):
                note = project(encode({**negative, "result": result, "trust_error": {"status": status, "code": code}}))
                self.assertTrue(note["available"])
                self.assertEqual(note["result"], result)
                self.assertEqual(note["trust_error"], {"status": status, "code": code})
                public = json.dumps(note)
                for private in ("PRIVATE", "synthetic-", "/mrk-aia/", ".der", '"chain"', *row["chain"], *(raw.decode() for raw in originals)):
                    self.assertNotIn(private, public)
                self.assertLess(len(public), 4096)

        frame = encode(row)
        malformed = [None, frame.decode(), bytearray(frame), b"", frame[:-1], frame + b"\n", frame + b"PRIVATE-OUTPUT\n",
                     frame + frame, b"prefix " + frame, m.AIA_PREFIX + frame[len(m.AIA_BASELINE_PREFIX):],
                     m.AIA_BASELINE_PREFIX + b"[]\n", m.AIA_BASELINE_PREFIX + b"null\n", b"x" * 4097,
                     m.AIA_BASELINE_PREFIX + b"[" * 1800 + b"]" * 1800 + b"\n",
                     frame.replace(b'"schema":1', b'"schema":1,"schema":1'),
                     frame.replace(b'"status":"no-error"', b'"status":"no-error","status":"no-error"'),
                     frame.replace(b'"code":null', b'"code":null,"code":null'),
                     frame.replace(b'"schema":1', b'"schema":NaN'), frame.replace(b'"result":4', b'"result":Infinity'),
                     frame.replace(b'"case":"online', b'"case":"\xffonline')]
        for key in row:
            changed = dict(row)
            del changed[key]
            malformed.append(encode(changed))
        for key, value in (("schema", True), ("schema", 2), ("case", True), ("case", m._CONTRAST_CASE),
            ("network", True), ("network", 0), ("keychains", True), ("keychains", None), ("accepted", 1), ("error", "false"),
            ("result", True), ("result", -1), ("result", 0x100000000), ("result", 4.0), ("chain", []),
            ("chain", ["0" * 64] * 4), ("chain", "PRIVATE-CHAIN"), ("chain", [True]), ("chain", ["A" * 64]),
            ("chain", ["0" * 63]), ("chain", ["0" * 65]), ("chain", ["g" * 64]), ("PRIVATE-FIELD", "/Users/private/signing.key"),
            ("trust_error", None), ("trust_error", []), ("trust_error", {"status": "osstatus"}),
            ("trust_error", {"status": "PRIVATE-STATUS", "code": None}), ("trust_error", {"status": True, "code": None}),
            ("trust_error", {"status": "no-error", "code": 0}), ("trust_error", {"status": "other-domain", "code": -1}),
            ("trust_error", {"status": "unavailable", "code": True}), ("trust_error", {"status": "osstatus", "code": None}),
            ("trust_error", {"status": "osstatus", "code": True}), ("trust_error", {"status": "osstatus", "code": 1.0}),
            ("trust_error", {"status": "osstatus", "code": -(2**31) - 1}),
            ("trust_error", {"status": "osstatus", "code": 2**31}),
            ("trust_error", {"status": "no-error", "code": None, "message": "PRIVATE-MESSAGE"})):
            malformed.append(encode({**row, key: value}))
        for data in malformed:
            with self.subTest(malformed_baseline=repr(data)[:80]), self.assertRaises(m.NativeControlError):
                project(data)
        for original in (None, list(originals), originals[:2], (*originals, originals[0]),
                         (originals[0], originals[0], originals[2]), (b"", *originals[1:]),
                         (b"PRIVATE-NOT-DER", *originals[1:]), (bytearray(originals[0]), *originals[1:]),
                         (b"\x30" * (m._MAX_DER + 1), *originals[1:]), (True, *originals[1:])):
            with self.subTest(malformed_original=type(original).__name__), self.assertRaises(m.NativeControlError):
                project(frame, original)
        maximum_originals = tuple(b"\x30" + bytes((index,)) * (m._MAX_DER - 1) for index in (1, 2, 3))
        maximum = {**aia_baseline_evidence(m, maximum_originals), "accepted": False, "error": False,
                   "result": 0xffffffff, "trust_error": {"status": "osstatus", "code": -(2**31)}}
        maximum_frame = encode(maximum)
        self.assertLess(len(maximum_frame), 4096)
        self.assertTrue(project(maximum_frame, maximum_originals)["chain_matches"])
        padded = maximum_frame[:-1] + b" " * (4096 - len(maximum_frame)) + b"\n"
        self.assertEqual(len(padded), 4096)
        self.assertEqual(project(padded, maximum_originals), project(maximum_frame, maximum_originals))
        with self.assertRaises(m.NativeControlError):
            project(padded[:-1] + b" \n", maximum_originals)
        denied.assert_not_called()

    def test_aia_error_observations_assemble_only_after_original_case_cleanup(self):
        m = self.module
        fixtures = aia_fixtures(m)
        record, _requests = aia_evidence(m, fixtures)
        chains = aia_chain_observations(m, fixtures)
        scalars = [{"status": status, "code": -67818 if status == "osstatus" else None}
                   for status in ("no-error", "osstatus", "other-domain", "unavailable")]
        events, instances, failure, now, negative = [], [], [None], [10.0], [False]
        original_fixtures = [dict(fixture) for fixture in fixtures]
        original_error = OSError("PRIVATE-ORIGINAL-CASE")
        test = self

        class Trust:
            def __init__(self, leaf, root, *, issuer=None):
                if issuer is not None:
                    self.index = 4
                    test.assertEqual((leaf, root, issuer), (fixtures[0]["leaf"], fixtures[0]["root"], fixtures[0]["issuer"]))
                elif (leaf, root) == (fixtures[0]["issuer"], fixtures[0]["root"]):
                    self.index = 5
                elif (leaf, root) == (fixtures[0]["leaf"], fixtures[0]["issuer"]):
                    self.index = 6
                else:
                    self.index = next(index for index, fixture in enumerate(fixtures) if fixture["leaf"] == leaf)
                    test.assertEqual(root, fixtures[self.index]["root"])
                if self.index >= 4:
                    test.assertEqual(len(instances), self.index)
                    test.assertTrue(all(instance.closed for instance in instances))
                    test.assertEqual(events[-1], (self.index - 1, "detached-observation"))
                    test.assertLess(now[0], 100.0)
                if self.index >= 5:
                    test.assertIsNone(issuer)
                self.network = self.keychains = self.closed = False
                self.scalar = dict(scalars[self.index] if self.index < 4 else chains["contrasts"][self.index - 4]["trust_error"])
                if negative[0] and self.index >= 4:
                    self.scalar = {"status": "osstatus", "code": -25318}
                instances.append(self)
                events.append((self.index, "construct"))

            def set_network(self, value):
                self.network = value

            def get_network(self):
                return self.network

            def set_keychains(self, value):
                self.keychains = value

            def get_keychains(self):
                return self.keychains

            def evaluate(self):
                events.append((self.index, "evaluate"))
                if failure[0] == (self.index, "evaluate"):
                    raise original_error
                if self.index >= 4:
                    test.assertIs(self.network, False)
                    test.assertIs(self.keychains, False)
                row = chains["contrasts"][self.index - 4] if self.index >= 4 else record["cases"][self.index]
                result = {key: row[key] for key in ("accepted", "error", "result", "chain")}
                if negative[0] and self.index >= 4:
                    result.update(accepted=False, error=True, result=5, chain=result["chain"][:1])
                return result

            def _signature_observation(self, original):
                test.assertEqual(self.index, 4)  # Never a live getter on the original four or either one-hop trust.
                test.assertFalse(self.closed)
                test.assertIs(original, fixtures[0])
                test.assertEqual(events[-1], (self.index, "evaluate"))
                events.append((self.index, "signature"))
                if failure[0] == (self.index, "signature"):
                    raise original_error
                return chains["crypto"]

            def close(self):
                events.append((self.index, "close"))
                self.closed = True
                if failure[0] == (self.index, "close"):
                    raise original_error
                if failure[0] == (self.index, "cutoff"):
                    now[0] = 100.0

            @property
            def error_observation(self):
                test.assertTrue(self.closed)
                events.append((self.index, "detached-observation"))
                return self.scalar

        location = Path("/pure/probes")
        paths = SimpleNamespace(cwd=Mock(return_value=location))
        reader = Mock(return_value=fixtures)
        with patch.multiple(m, time=SimpleNamespace(monotonic=lambda: now[0]), _Trust=Trust, _fixtures=reader, Path=paths, os=SimpleNamespace(),
                                      subprocess=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace()):
            result = m.evaluate_aia(60123, 100.0)
            expected = {**record, "error_observations": [{"case": fixture["case"], **scalar} for fixture, scalar in zip(fixtures, scalars)],
                        "chain_observations": chains}
            self.assertEqual(result, expected)
            self.assertEqual(events, [(index, event) for index in range(4)
                                     for event in ("construct", "evaluate", "close", "detached-observation")]
                             + [(4, event) for event in ("construct", "evaluate", "signature", "close", "detached-observation")]
                             + [(index, event) for index in (5, 6) for event in ("construct", "evaluate", "close", "detached-observation")])
            paths.cwd.assert_called_once_with()
            reader.assert_called_once_with(location, 60123, 100.0)
            self.assertEqual(len(instances), 7)
            instances[1].scalar["code"] = 123
            instances[4].scalar["status"] = "unavailable"
            self.assertEqual(result, expected)
            events.clear()
            self.assertEqual(m._evaluate_case(fixtures[0], 100.0), record["cases"][0])
            self.assertEqual(events, [(0, "construct"), (0, "evaluate"), (0, "close")])  # Legacy callers need no observations.
            events.clear()
            instances.clear()
            negative[0] = True
            observed = m.evaluate_aia(60123, 100.0)
            self.assertEqual(observed["cases"], record["cases"])
            self.assertEqual([row["accepted"] for row in observed["chain_observations"]["contrasts"]], [False] * 3)
            self.assertEqual(len(instances), 7)  # A completed negative is data, not an exception that skips the next role.
            self.assertTrue(all(instance.closed for instance in instances))
            negative[0] = False
            for index, failed_event in ((1, "evaluate"), (1, "close"), (4, "signature"), (4, "close"), (4, "cutoff"),
                                        (5, "evaluate"), (5, "close"), (5, "cutoff"), (6, "cutoff")):
                events.clear()
                instances.clear()
                now[0] = 10.0
                failure[0] = (index, failed_event)
                expected_error = m.NativeControlError if failed_event == "cutoff" else BaseExceptionGroup
                with self.subTest(original_failure=failure[0]), self.assertRaises(expected_error) as raised:
                    m.evaluate_aia(60123, 100.0)
                if failed_event != "cutoff":
                    self.assertIn(original_error, raised.exception.exceptions)
                self.assertEqual(len(instances), index + 1)  # No later original or contrast can run after this failure.
                self.assertTrue(all(instance.closed for instance in instances))
                self.assertNotIn((index, "detached-observation"), events)
            self.assertEqual(fixtures, original_fixtures)

    def test_aia_error_observation_extension_is_optional_strict_and_not_authority(self):
        m = self.module
        fixtures = aia_fixtures(m)
        record, requests = aia_evidence(m, fixtures)
        encode = lambda value: m.AIA_PREFIX + json.dumps(value).encode() + b"\n"
        unavailable = {"schema": 1, "control": "aia-comparison", "semantics": "comparison-observation-only", "available": False}
        absent = [{"case": case, "status": "unavailable", "code": None} for case in m._CASES]
        with patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                            threading=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace()):
            self.assertEqual(m._aia_record(encode(record)), (record, absent, None))
            original = m.require_aia_controls(encode(record), fixtures, requests)
            for status, code in (("no-error", None), ("osstatus", -(2**31)), ("osstatus", 2**31 - 1),
                                 ("other-domain", None), ("unavailable", None)):
                observations = [{"case": case, "status": status, "code": code} for case in m._CASES]
                extended = {**record, "error_observations": observations}
                with self.subTest(compatible_error_observation=(status, code)):
                    self.assertEqual(m._aia_record(encode(extended)), (record, observations, None))
                    self.assertEqual(m.require_aia_controls(encode(extended), fixtures, requests), original)
                    note = m._aia_comparison_note(encode(extended), fixtures, requests)
                    self.assertEqual([row["trust_error"] for row in note["cases"]], [{"status": status, "code": code}] * 4)
                    changed = json.loads(json.dumps(extended))
                    changed["cases"][0]["accepted"] = False
                    for raw, observed_requests in ((encode(changed), requests), (encode(extended), [])):
                        with self.assertRaises(m.NativeControlError):
                            m.require_aia_controls(raw, fixtures, observed_requests)
                        self.assertTrue(m._aia_comparison_note(raw, fixtures, observed_requests)["available"])
            malformed = [None, {}, [], absent[:3], absent + absent[:1], list(reversed(absent)), [absent[0], absent[0], *absent[2:]]]
            for key, value in (("case", "PRIVATE-CASE"), ("case", True), ("status", "PRIVATE-DOMAIN"), ("status", True),
                               ("code", 1), ("PRIVATE-FIELD", "/Users/private/signing.key")):
                malformed.append([{**absent[0], key: value}, *absent[1:]])
            for code in (None, True, False, 1.0, "-67818", -(2**31) - 1, 2**31):
                malformed.append([{**absent[0], "status": "osstatus", "code": code}, *absent[1:]])
            for observations in malformed:
                raw = encode({**record, "error_observations": observations})
                with self.subTest(malformed_error_extension=observations):
                    with self.assertRaises(m.NativeControlError):
                        m._aia_record(raw)
                    with self.assertRaises(m.NativeControlError):
                        m.require_aia_controls(raw, fixtures, requests)
                    self.assertEqual(m._aia_comparison_note(raw, fixtures, requests), unavailable)
            complete = encode({**record, "error_observations": absent})
            for raw in (complete[:-1], complete + b"PRIVATE-EXTRA\n", complete.replace(b'"status": "unavailable"',
                        b'"status": "unavailable", "status": "unavailable"'), b"x" * 4097):
                with self.assertRaises(m.NativeControlError):
                    m._aia_record(raw)
                self.assertEqual(m._aia_comparison_note(raw, fixtures, requests), unavailable)
            extra = {**record, "error_observations": absent, "PRIVATE-EXTENSION": "/Users/private/signing.key"}
            semantic, _observations, _chains = m._aia_record(encode(extra))
            self.assertIn("PRIVATE-EXTENSION", semantic)  # Strip ONLY the recognized optional field.
            with self.assertRaises(m.NativeControlError):
                m.require_aia_controls(encode(extra), fixtures, requests)
            self.assertEqual(m._aia_comparison_note(encode(extra), fixtures, requests), unavailable)

    def test_chain_observation_extension_is_strict_private_and_not_authority(self):
        m = self.module
        self.assertEqual((m._CONTRAST_CASE, m._ISSUER_ROOT_CONTRAST_CASE, m._LEAF_ISSUER_CONTRAST_CASE),
                         ("online-full-chain-offline", "online-issuer-root-offline", "online-leaf-issuer-offline"))
        self.assertEqual(m._SIGNATURE_CASES, ("leaf-by-issuer", "issuer-by-root", "root-by-root", "issuer-signature-mutant"))
        fixtures = aia_fixtures(m)
        record, requests = aia_evidence(m, fixtures)
        chains = aia_chain_observations(m, fixtures)
        clone = lambda value: json.loads(json.dumps(value))
        encode = lambda value: m.AIA_PREFIX + json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False).encode("ascii") + b"\n"
        absent = [{"case": case, "status": "unavailable", "code": None} for case in m._CASES]
        unavailable = {"schema": 1, "control": "aia-comparison", "semantics": "comparison-observation-only", "available": False}
        no_crypto = {"available": False, "keys": None, "checks": None}
        foreign_root, foreign_issuer = (m.hashlib.sha256(fixtures[2][role]).hexdigest() for role in ("root", "issuer"))
        variants = [("positive", clone(chains))]
        for label in ("negative", "unexpected-flags", "foreign", "unavailable", "issuer-absent", "root-absent", "root-unsupported",
                      "root-zero", "root-large", "mutant-accept"):
            value = clone(chains)
            if label == "negative":
                for row in value["contrasts"]:
                    row.update(accepted=False, error=True, result=5, chain=row["chain"][:1], trust_error={"status": "osstatus", "code": -25318})
                value["crypto"]["checks"][0].update(accepted=False, error=True, trust_error={"status": "osstatus", "code": -50})
            elif label == "unexpected-flags":
                value["contrasts"][0].update(network=True, keychains=True)
            elif label == "foreign":
                value["contrasts"][0]["chain"][1] = foreign_issuer
                value["contrasts"][1]["chain"][1] = foreign_root
                value["contrasts"][2]["chain"][1] = foreign_issuer
            elif label == "unavailable":
                value["crypto"] = dict(no_crypto)
            elif label == "mutant-accept":
                value["crypto"]["checks"][3].update(accepted=True, error=False, trust_error={"status": "no-error", "code": None})
            else:
                key_index = 0 if label == "issuer-absent" else 1
                key = value["crypto"]["keys"][key_index]
                if label.endswith("absent"):
                    key.update(present=False, block_bytes=None, verify_supported=None)
                elif label == "root-unsupported":
                    key["verify_supported"] = False
                else:
                    key["block_bytes"] = 0 if label == "root-zero" else m._MAX_DER
                for index in ((0,) if key_index == 0 else (1, 2, 3)):
                    value["crypto"]["checks"][index].update(executed=False, accepted=None, error=None, trust_error=None)
            variants.append((label, value))
        for status, code in (("osstatus", -(2**31)), ("osstatus", 2**31 - 1), ("other-domain", None), ("unavailable", None)):
            value = clone(chains)
            value["contrasts"][1]["trust_error"] = {"status": status, "code": code}
            value["crypto"]["checks"][0]["trust_error"] = {"status": status, "code": code}
            variants.append(((status, code), value))
        with patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace(),
                            secrets=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace()):
            original = m.require_aia_controls(encode(record), fixtures, requests)
            self.assertEqual(m._aia_record(encode(record)), (record, absent, None))
            missing = m._aia_comparison_note(encode(record), fixtures, requests)
            self.assertEqual((missing["contrasts"], missing["crypto"]), ([], no_crypto))
            for label, value in variants:
                with self.subTest(valid_chain_observation=label):
                    extended = {**record, "chain_observations": value}
                    raw = encode(extended)
                    self.assertEqual(m._aia_record(raw), (record, absent, value))
                    self.assertEqual(m.require_aia_controls(raw, fixtures, requests), original)
                    note = m._aia_comparison_note(raw, fixtures, requests)
                    self.assertTrue(note["available"])
                    self.assertTrue(note["requests_match"])
                    self.assertEqual(note["crypto"], value["crypto"])
                    self.assertEqual(len(note["contrasts"]), 3)
                    for index, row in enumerate(value["contrasts"]):
                        roles = [["leaf", "issuer", "root"], ["issuer", "root"], ["leaf", "issuer"]][index]
                        if label == "negative":
                            roles = roles[:1]
                        elif label == "foreign":
                            roles[1] = "other"
                        self.assertEqual(note["contrasts"][index], {"available": True,
                            **{key: row[key] for key in ("case", "network", "keychains", "accepted", "error", "result", "trust_error")},
                            "chain_count": len(row["chain"]), "chain_matches": label not in {"foreign", "negative"},
                            "chain_roles": roles})
                    # Missing/rejecting/unexpectedly accepting diagnostics retain
                    # their observation, never original acceptance authority.
                    changed = clone(extended)
                    changed["cases"][0]["accepted"] = False
                    for data, observed_requests in ((encode(changed), requests), (raw, [*requests, requests[0]])):
                        with self.assertRaises(m.NativeControlError):
                            m.require_aia_controls(data, fixtures, observed_requests)
                        self.assertTrue(m._aia_comparison_note(data, fixtures, observed_requests)["available"])
                    public = json.dumps(note)
                    for private in ("PRIVATE", "synthetic-", "/Users/", "/mrk-aia/", "0x1234", "TBS-BYTES", "SIGNATURE-BYTES",
                                    *(fixture["route"] for fixture in fixtures),
                                    *(fixture[role].decode() for fixture in fixtures for role in ("leaf", "issuer", "root")),
                                    *(m.hashlib.sha256(fixture[role]).hexdigest() for fixture in fixtures for role in ("leaf", "issuer", "root"))):
                        self.assertNotIn(private, public)
                    self.assertNotIn("anchor_observation", public)
                    self.assertLess(len(public), 4096)

            malformed = [None, [], {}, {"contrasts": chains["contrasts"]}, {**chains, "PRIVATE": "TBS-BYTES"},
                         {"anchors": [], "contrast": chains["contrasts"][0]}]  # Retired private schema cannot be a new receipt.
            retired = clone(chains)
            retired["contrasts"] = [retired["contrasts"][0], {**retired["contrasts"][1], "case": "online-root-only-offline",
                                     "chain": [m.hashlib.sha256(fixtures[0]["root"]).hexdigest()]}]
            malformed.append(retired)  # The former two-row full/root-only receipt is not current-source evidence.
            for contrasts in (None, {}, [], chains["contrasts"][:1], chains["contrasts"][:2], chains["contrasts"] + chains["contrasts"][:1],
                              chains["contrasts"] * 2, list(reversed(chains["contrasts"])), [chains["contrasts"][0]] * 3,
                              [None, *chains["contrasts"][1:]]):
                malformed.append({**chains, "contrasts": contrasts})
            for key, bad in (("case", "online"), ("case", True), ("network", 0), ("keychains", 0), ("accepted", 1), ("error", None),
                             ("result", True), ("result", -1), ("result", 2**32), ("result", 4.0),
                             ("chain", []), ("chain", ["a" * 64] * 4), ("chain", "PRIVATE-DER"),
                             ("chain", ["A" * 64]), ("chain", ["a" * 63]), ("chain", [False]), ("PRIVATE", "0x1234")):
                value = clone(chains)
                value["contrasts"][0][key] = bad
                malformed.append(value)
            for index in (1, 2):
                for key, bad in (("case", "online-root-only-offline"), ("chain", []), ("chain", ["a" * 64] * 3)):
                    value = clone(chains)
                    value["contrasts"][index][key] = bad
                    malformed.append(value)
            value = clone(chains)
            del value["contrasts"][0]["error"]
            malformed.append(value)
            for crypto in (None, [], {}, {**no_crypto, "available": 0}, {**no_crypto, "keys": []}, {**no_crypto, "checks": []},
                           {**chains["crypto"], "PRIVATE": "SIGNATURE-BYTES"}):
                malformed.append({**chains, "crypto": crypto})
            for name in ("keys", "checks"):
                for rows in (None, {}, [], chains["crypto"][name][:-1], chains["crypto"][name] * 2,
                             list(reversed(chains["crypto"][name])), [None, *chains["crypto"][name][1:]],
                             [chains["crypto"][name][0]] * len(chains["crypto"][name])):
                    value = clone(chains)
                    value["crypto"][name] = rows
                    malformed.append(value)
            for key, bad in (("key", "leaf"), ("key", True), ("present", 1), ("block_bytes", None), ("block_bytes", True),
                             ("block_bytes", -1), ("block_bytes", m._MAX_DER + 1), ("block_bytes", 256.0),
                             ("verify_supported", None), ("verify_supported", 1), ("PRIVATE", "PRIVATE-KEY")):
                value = clone(chains)
                value["crypto"]["keys"][0][key] = bad
                malformed.append(value)
            for key, bad in (("case", "issuer-by-issuer"), ("case", True), ("executed", 1), ("accepted", 1),
                             ("accepted", None), ("error", 0), ("error", None), ("PRIVATE", "TBS-BYTES")):
                value = clone(chains)
                value["crypto"]["checks"][0][key] = bad
                malformed.append(value)
            # Each eligibility contradiction fails closed; null results alone
            # cannot claim an eligible operation was unexecuted, or the inverse.
            for bad_key in ({"present": False, "block_bytes": None, "verify_supported": None}, {"block_bytes": 128},
                            {"verify_supported": False}, {"present": False}):
                value = clone(chains)
                value["crypto"]["keys"][0].update(bad_key)
                malformed.append(value)
            value = clone(chains)
            value["crypto"]["checks"][0].update(executed=False, accepted=None, error=None, trust_error=None)
            malformed.append(value)
            for key in ("accepted", "error", "trust_error"):
                value = clone(next(value for label, value in variants if label == "issuer-absent"))
                value["crypto"]["checks"][0][key] = {} if key == "trust_error" else False
                malformed.append(value)
            bad_errors = [None, [], {}, {"status": "no-error", "code": None, "PRIVATE": "/Users/private/signing.key"},
                          {"status": "PRIVATE-ERROR", "code": None}, {"status": True, "code": None}, {"status": "no-error", "code": 1}]
            bad_errors.extend({"status": "osstatus", "code": code} for code in (None, True, 1.0, "-25318", -(2**31) - 1, 2**31))
            for error in bad_errors:
                for collection in ("contrast", "check"):
                    value = clone(chains)
                    row = value["contrasts"][0] if collection == "contrast" else value["crypto"]["checks"][0]
                    row["trust_error"] = error
                    malformed.append(value)
            for index, value in enumerate(malformed):
                raw = encode({**record, "chain_observations": value})
                with self.subTest(malformed_chain_observation=index):
                    with self.assertRaises(m.NativeControlError):
                        m._aia_record(raw)
                    with self.assertRaises(m.NativeControlError):
                        m.require_aia_controls(raw, fixtures, requests)
                    self.assertEqual(m._aia_comparison_note(raw, fixtures, requests), unavailable)

            extra = {**record, "error_observations": absent, "chain_observations": chains, "PRIVATE-EXTENSION": "TBS-BYTES"}
            semantic, errors, observed_chains = m._aia_record(encode(extra))
            self.assertEqual(semantic, {**record, "PRIVATE-EXTENSION": "TBS-BYTES"})
            self.assertEqual((errors, observed_chains), (absent, chains))
            with self.assertRaises(m.NativeControlError):
                m.require_aia_controls(encode(extra), fixtures, requests)
            self.assertEqual(m._aia_comparison_note(encode(extra), fixtures, requests), unavailable)

            # Maximum permitted counts, unsigned results, signed error magnitude,
            # and longer false booleans still fit the ORIGINAL whole-record frame.
            # Keys remain eligible: ineligible large sizes shorten the check rows.
            maximum = clone({**record, "error_observations": absent, "chain_observations": chains})
            for row in maximum["cases"]:
                row.update({key: False for key in ("baseline_network", "network", "keychains", "accepted", "error")})
                row.update(result=0xffffffff, chain=["f" * 64] * 3)
            for row in maximum["error_observations"]:
                row.update(status="osstatus", code=-(2**31))
            for index, row in enumerate(maximum["chain_observations"]["contrasts"]):
                row.update(network=False, keychains=False, accepted=False, error=False, result=0xffffffff,
                           chain=["f" * 64] * (3 if index == 0 else 2), trust_error={"status": "osstatus", "code": -(2**31)})
            for row in maximum["chain_observations"]["crypto"]["checks"]:
                row.update(accepted=False, error=False, trust_error={"status": "osstatus", "code": -(2**31)})
            raw = encode(maximum)
            self.assertLessEqual(len(raw), 4096)
            expected = ({key: maximum[key] for key in ("schema", "cases")}, maximum["error_observations"], maximum["chain_observations"])
            self.assertEqual(m._aia_record(raw), expected)
            note = m._aia_comparison_note(raw, fixtures, requests)
            self.assertTrue(note["available"])
            self.assertEqual([row["chain_roles"] for row in note["contrasts"]], [["other"] * 3, ["other"] * 2, ["other"] * 2])
            self.assertEqual(note["crypto"], maximum["chain_observations"]["crypto"])
            self.assertNotIn("f" * 64, json.dumps(note))
            with self.assertRaises(m.NativeControlError):
                m.require_aia_controls(raw, fixtures, requests)
            boundary = raw[:-1] + b" " * (4096 - len(raw)) + b"\n"
            self.assertEqual(len(boundary), 4096)
            self.assertEqual(m._aia_record(boundary), expected)
            for invalid in (boundary[:-1] + b" \n", raw[:-1], raw + b"PRIVATE-EXTRA\n",
                            raw.replace(b'"executed":true', b'"executed":true,"executed":true', 1)):
                with self.assertRaises(m.NativeControlError):
                    m._aia_record(invalid)
                self.assertEqual(m._aia_comparison_note(invalid, fixtures, requests), unavailable)

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

    def test_aia_comparison_observation_is_closed_and_preserves_real_mismatches(self):
        m = self.module
        fixtures = aia_fixtures(m)
        record, requests = aia_evidence(m, fixtures)
        encode = lambda value: m.AIA_PREFIX + json.dumps(value).encode() + b"\n"
        unavailable = {"schema": 1, "control": "aia-comparison",
                       "semantics": "comparison-observation-only", "available": False}
        expected = unavailable | {"available": True, "cases": [
            {key: row[key] for key in ("case", "baseline_network", "network", "keychains", "accepted", "error", "result")}
            | {"chain_count": 3 if index in (0, 2) else 1, "chain_matches": True,
               "chain_roles": ["leaf", "issuer", "root"] if index in (0, 2) else ["leaf"],
               "trust_error": {"status": "unavailable", "code": None},
               "request_count": 1 if index in (0, 2) else 0} for index, row in enumerate(record["cases"])],
            "requests": [{"case": name, "issuer_matches": True} for name in ("online", "mutant")], "requests_match": True,
            "contrasts": [], "crypto": {"available": False, "keys": None, "checks": None}}

        def project(data, originals=fixtures, observed=requests):
            # No path, clock, native provider or resource operation is available
            # to this projection; only the three existing in-memory inputs.
            with patch.multiple(m, os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(),
                                threading=SimpleNamespace(), secrets=SimpleNamespace(), time=SimpleNamespace(), Path=SimpleNamespace()):
                return m._aia_comparison_note(data, originals, observed)

        self.assertEqual(project(encode(record)), expected)
        for index, key, value in ((0, "baseline_network", False), (1, "network", True), (3, "keychains", True),
                                  (0, "accepted", False), (3, "error", False), (0, "result", 0),
                                  (1, "result", 0xffffffff), (0, "chain", ["0" * 64] * 3),
                                  (1, "chain", [*record["cases"][1]["chain"], "0" * 64])):
            changed = json.loads(json.dumps(record))
            changed["cases"][index][key] = value
            with self.subTest(comparison_value=(index, key, value)):
                note = project(encode(changed))
                wanted = json.loads(json.dumps(expected))
                if key == "chain":
                    wanted["cases"][index].update(chain_count=len(value), chain_matches=False,
                                                  chain_roles=["other"] * 3 if index == 0 else ["leaf", "other"])
                else:
                    wanted["cases"][index][key] = value
                self.assertEqual(note, wanted)
                with self.assertRaises(m.NativeControlError):
                    m.require_aia_controls(encode(changed), fixtures, requests)
        absent = json.loads(json.dumps(record))
        for index in (0, 2):
            absent["cases"][index].update(accepted=False, error=True, result=5,
                                          chain=absent["cases"][index]["chain"][:1])
        note = project(encode(absent), observed=[])
        self.assertTrue(note["available"])
        self.assertEqual(note["requests"], [])
        self.assertFalse(note["requests_match"])
        self.assertEqual([row["request_count"] for row in note["cases"]], [0] * 4)
        for index in (0, 2):
            self.assertEqual({key: note["cases"][index][key] for key in ("accepted", "error", "result", "chain_count", "chain_matches")},
                             {"accepted": False, "error": True, "result": 5, "chain_count": 1, "chain_matches": False})
        with self.assertRaises(m.NativeControlError):
            m.require_aia_controls(encode(absent), fixtures, [])
        leaf, issuer, root = record["cases"][0]["chain"]
        foreign_issuer = record["cases"][2]["chain"][1]
        for chain, roles in (([leaf, issuer], ["leaf", "issuer"]), ([leaf, foreign_issuer], ["leaf", "other"]),
                             ([root, issuer, leaf], ["root", "issuer", "leaf"]), ([leaf, leaf], ["leaf", "leaf"])):
            changed = json.loads(json.dumps(record))
            changed["cases"][0]["chain"] = chain
            note = project(encode(changed))
            self.assertEqual(note["cases"][0]["chain_roles"], roles)
            self.assertFalse(note["cases"][0]["chain_matches"])
            for digest in (*chain, foreign_issuer):
                self.assertNotIn(digest, json.dumps(note))
            with self.assertRaises(m.NativeControlError):
                m.require_aia_controls(encode(changed), fixtures, requests)

        unknown = ("/mrk-aia/" + "f" * 32 + "/online.der", "e" * 64)
        for observed, labels, matches, counts in (
            ([], [], [], [0, 0, 0, 0]),
            (list(reversed(requests)), ["mutant", "online"], [True, True], [1, 0, 1, 0]),
            ([(requests[0][0], "0" * 64), requests[1]], ["online", "mutant"], [False, True], [1, 0, 1, 0]),
            ([*requests, unknown], ["online", "mutant", "unknown"], [True, True, False], [1, 0, 1, 0]),
            ([*requests, requests[0]], ["online", "mutant", "online"], [True] * 3, [2, 0, 1, 0]),
            (requests * 4, ["online", "mutant"] * 4, [True] * 8, [4, 0, 4, 0])):
            with self.subTest(comparison_requests=observed):
                note = project(encode(record), observed=observed)
                self.assertTrue(note["available"])
                self.assertFalse(note["requests_match"])
                self.assertEqual(note["requests"], [{"case": name, "issuer_matches": match} for name, match in zip(labels, matches)])
                self.assertEqual([row["request_count"] for row in note["cases"]], counts)
                with self.assertRaises(m.NativeControlError):
                    m.require_aia_controls(encode(record), fixtures, observed)
                public = json.dumps(note)
                for private in (unknown[0], unknown[1], "/mrk-aia/", "synthetic-", "chain\"", "route\"",
                                *(fixture["route"] for fixture in fixtures),
                                *(m.hashlib.sha256(fixture[role]).hexdigest() for fixture in fixtures for role in ("root", "issuer", "leaf"))):
                    self.assertNotIn(private, public)
                self.assertLess(len(public), 4096)

        data = encode(record)
        malformed = [None, data.decode(), bytearray(data), b"", data[:-1], data + b"PRIVATE-CAPTURE\n", b"prefix " + data,
                     b"x" * 4097, data.replace(b'"schema": 1', b'"schema": 1, "schema": 1'),
                     data.replace(b'"case": "online"', b'"case": "online", "case": "online"'),
                     data.replace(b'"schema": 1', b'"schema": true'), data.replace(b'"online"', b'"\xff"'),
                     encode({**record, "PRIVATE-FIELD": "/Users/private/signing.key"}),
                     encode({**record, "cases": record["cases"][:3]}), encode({**record, "cases": list(reversed(record["cases"]))})]
        for key, value in (("case", "PRIVATE-CASE"), ("baseline_network", 1), ("network", None), ("keychains", 0),
                           ("accepted", "false"), ("error", 1.0), ("result", True), ("result", -1),
                           ("result", 0x100000000), ("result", 4.0), ("chain", []), ("chain", ["0" * 64] * 4),
                           ("chain", "PRIVATE-CHAIN"), ("chain", ["A" * 64]), ("chain", ["0" * 63]),
                           ("chain", [True]), ("PRIVATE-FIELD", "PRIVATE-MESSAGE")):
            changed = json.loads(json.dumps(record))
            changed["cases"][0][key] = value
            malformed.append(encode(changed))
        for data in malformed:
            with self.subTest(comparison_malformed_capture=repr(data)[:60]):
                self.assertEqual(project(data), unavailable)
        for originals in (None, tuple(fixtures), fixtures[:3], [fixtures[0], fixtures[0], *fixtures[2:]]):
            self.assertEqual(project(encode(record), originals=originals), unavailable)
        for key, value in (("case", True), ("route", "/mrk-aia/PRIVATE-NONCE/online.der"),
                           ("route", fixtures[1]["route"]), ("root", b""), ("root", b"not-DER"),
                           ("root", b"\x30" * (m._MAX_DER + 1)), ("issuer", bytearray(b"\x30")),
                           ("leaf", "PRIVATE-DER"), ("PRIVATE-FIELD", "PRIVATE-MESSAGE")):
            originals = [dict(fixture) for fixture in fixtures]
            originals[0][key] = value
            with self.subTest(comparison_malformed_fixture=key):
                self.assertEqual(project(encode(record), originals=originals), unavailable)
        maximum = [dict(fixture) for fixture in fixtures]
        maximum[0]["root"] = b"\x30" + b"x" * (m._MAX_DER - 1)
        bounded_record, bounded_requests = aia_evidence(m, maximum)
        self.assertEqual(project(encode(bounded_record), maximum, bounded_requests), expected)
        for observed in (None, tuple(requests), requests * 4 + requests[:1], [list(requests[0])],
                         [(requests[0][0], requests[0][1], "PRIVATE-EXTRA")], [(None, requests[0][1])],
                         [("http://127.0.0.1:60123/PRIVATE-URL", requests[0][1])],
                         [(requests[0][0], "A" * 64)], [(requests[0][0], "0" * 63)], [(requests[0][0], b"0" * 64)]):
            with self.subTest(comparison_malformed_request=observed):
                self.assertEqual(project(encode(record), observed=observed), unavailable)

    def test_aia_comparison_failure_projection_requires_original_finality_and_preserves_error(self):
        from workflow.test_ci_sandbox import sandbox_module

        m, parent = self.module, sandbox_module()  # Inert definitions only; no Session construction.
        fixtures = aia_fixtures(m)
        record, original_requests = aia_evidence(m, fixtures)
        outputs = {name: m.MACH_PREFIX + json.dumps(row).encode() + b"\n" for name, row in (
            ("mach-baseline", mach_row([0, 1102, 0])), ("mach-ordinary", mach_row([1100] * 3)))}
        outputs.update({name: m.MACH_APPLY_PREFIX + json.dumps(row).encode() + b"\n" for name, row in (
            ("mach-authority", mach_application("mach-initial")),
            ("mach-nonexpand", mach_application("mach-nonexpand", returned=-1, number=1)))})
        extended = {**record, "chain_observations": aia_chain_observations(m, fixtures)}
        outputs.update({"aia-prepare": b"MRK_AIA_PREPARED\n", "aia-evaluate": m.AIA_PREFIX + json.dumps(extended).encode() + b"\n"})
        original_der = tuple(fixtures[0][role] for role in ("leaf", "issuer", "root"))
        outputs["aia-offline-baseline"] = m.AIA_BASELINE_PREFIX + json.dumps(aia_baseline_evidence(m, original_der)).encode() + b"\n"
        real_compare, real_project = m.require_aia_controls, m._aia_comparison_note
        scratch = Path("/pure/probes")
        for mode in ("comparison", "formatting-error", "formatting-cancel", "success", "capture-error", "capture-refused", "finality-error",
                     "close-error", "deadline", "post-close-idle-error", "final-idle-error"):
            with self.subTest(comparison_owner_gate=mode):
                events, originals, now, closed, last, compared = [], [], [10.0], [False], [None], [False]
                earlier = OSError("PRIVATE-EARLIER-ERROR /Users/private/signing.key")
                formatter = (KeyboardInterrupt("PRIVATE-FORMATTING-CANCEL") if mode == "formatting-cancel"
                             else ValueError("PRIVATE-FORMATTING-ERROR"))
                requests = original_requests if mode in {"success", "final-idle-error"} else []

                def launch(case, *, port=None):
                    events.append(("capture", case, port))
                    last[0] = case
                    if case == "aia-evaluate" and mode == "capture-error":
                        raise earlier
                    return SimpleNamespace(ok=not (case == "aia-evaluate" and mode == "capture-refused"), stdout=outputs[case])

                def idle():
                    events.append(("idle", last[0]))
                    if (mode == "finality-error" and last[0] == "aia-evaluate" and not closed[0]
                            or mode == "post-close-idle-error" and closed[0]
                            or mode == "final-idle-error" and compared[0]):
                        raise earlier

                def close():
                    events.append("close")
                    if mode == "close-error":
                        raise earlier
                    closed[0] = True
                    if mode == "deadline":
                        now[0] = 100.0

                def compare(data, actual_fixtures, actual_requests):
                    events.append("compare")
                    compared[0] = True
                    self.assertTrue(closed[0])
                    self.assertLess(now[0], 100.0)
                    self.assertIs(data, outputs["aia-evaluate"])
                    self.assertIs(actual_fixtures, fixtures)
                    self.assertIs(actual_requests, requests)
                    try:
                        return real_compare(data, actual_fixtures, actual_requests)
                    except m.NativeControlError as error:
                        originals.append(error)
                        raise

                def project(data, actual_fixtures, actual_requests):
                    events.append("project" if compared[0] else "preflight")
                    self.assertTrue(closed[0])
                    self.assertEqual(len(originals), int(compared[0]))
                    self.assertIs(data, outputs["aia-evaluate"])
                    self.assertIs(actual_fixtures, fixtures)
                    self.assertIs(actual_requests, requests)
                    if compared[0] and mode in {"formatting-error", "formatting-cancel"}:
                        raise formatter
                    return real_project(data, actual_fixtures, actual_requests)

                def freeze(original):
                    self.assertEqual(original, original_der)
                    self.assertFalse(compared[0])
                    self.assertTrue(closed[0])
                    self.assertEqual(projector.call_count, 1)
                    self.assertEqual(reader.call_count, 2)
                    events.append("snapshot")

                responder = SimpleNamespace(port=60123, requests=requests, start=Mock(side_effect=lambda rows: events.append("start")),
                                            close=Mock(side_effect=close))
                comparator, projector = Mock(side_effect=compare), Mock(side_effect=project)
                reader, snapshot = Mock(return_value=fixtures), Mock(side_effect=freeze)
                with patch.multiple(m, time=SimpleNamespace(monotonic=lambda: now[0]), os=SimpleNamespace(),
                    subprocess=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace(), secrets=SimpleNamespace(),
                    Path=SimpleNamespace(), _scratch=Mock(return_value=scratch), _fixtures=reader,
                    _Responder=Mock(return_value=responder), require_aia_controls=comparator, _aia_comparison_note=projector), \
                     patch.object(parent, "os", SimpleNamespace(path=SimpleNamespace(basename=lambda value: value.rsplit("/", 1)[-1]))):
                    if mode == "success":
                        result = m.admit_controls(launch, idle, scratch, deadline=100.0, policy_sha256="a" * 64,
                                                  freeze_baseline=snapshot)
                        self.assertTrue(result["cleanup_ok"])
                        self.assertTrue(result["aia"]["final_disable_mutation_detected"])
                        self.assertEqual(result["aia"]["request_counts"], [1, 0, 1, 0])
                        projector.assert_called_once_with(outputs["aia-evaluate"], fixtures, requests)
                    else:
                        expected_error = (m.NativeControlError if mode in {"comparison", "formatting-error", "formatting-cancel", "deadline"}
                                          else OSError if mode in {"post-close-idle-error", "final-idle-error"} else BaseExceptionGroup)
                        with self.assertRaises(expected_error) as raised:
                            m.admit_controls(launch, idle, scratch, deadline=100.0, policy_sha256="a" * 64,
                                             freeze_baseline=snapshot)
                        error = raised.exception
                        if mode in {"comparison", "formatting-error", "formatting-cancel"}:
                            self.assertEqual(len(originals), 1)
                            self.assertIs(error, originals[0])
                            self.assertEqual(projector.call_count, 2)
                            self.assertTrue(all(call.args == (outputs["aia-evaluate"], fixtures, requests)
                                                and not call.kwargs for call in projector.call_args_list))
                            self.assertEqual(events[-2:], ["compare", "project"])
                            if mode == "comparison":
                                self.assertEqual(error._ci_observation, real_project(outputs["aia-evaluate"], fixtures, requests))
                                self.assertFalse(error._ci_observation["requests_match"])
                                self.assertEqual(error._ci_observation["cases"][0]["chain_roles"], ["leaf", "issuer", "root"])
                                self.assertEqual(error._ci_observation["cases"][0]["trust_error"], {"status": "unavailable", "code": None})
                                self.assertEqual([row["chain_roles"] for row in error._ci_observation["contrasts"]],
                                                 [["leaf", "issuer", "root"], ["issuer", "root"], ["leaf", "issuer"]])
                                self.assertTrue(all(row["available"] for row in error._ci_observation["contrasts"]))
                                self.assertEqual(error._ci_observation["crypto"], extended["chain_observations"]["crypto"])
                                self.assertEqual(parent._exception_notes(error),
                                    [{"exception": "NativeControlError", "lines": [], "observation": error._ci_observation}])
                            else:
                                self.assertFalse(hasattr(error, "_ci_observation"))
                                self.assertIsNot(error, formatter)
                                self.assertEqual(parent._exception_notes(error), [{"exception": "NativeControlError", "lines": []}])
                        else:
                            self.assertEqual(projector.call_count, int(mode == "final-idle-error"))
                            self.assertFalse(hasattr(error, "_ci_observation"))
                            if mode in {"post-close-idle-error", "final-idle-error"}:
                                self.assertIs(error, earlier)
                            if isinstance(error, BaseExceptionGroup):
                                leaves = [leaf for child in error.exceptions for leaf in
                                          (child.exceptions if isinstance(child, BaseExceptionGroup) else (child,))]
                                self.assertTrue(all(not hasattr(leaf, "_ci_observation") for leaf in leaves))
                                if mode in {"capture-error", "finality-error", "close-error"}:
                                    self.assertIn(earlier, leaves)
                        public = json.dumps(parent._exception_notes(error))
                        for private in ("PRIVATE-", "/Users/", "signing.key", "/mrk-aia/", "synthetic-", str(error)):
                            self.assertNotIn(private, public)
                    if mode in {"comparison", "formatting-error", "formatting-cancel", "success", "final-idle-error"}:
                        comparator.assert_called_once_with(outputs["aia-evaluate"], fixtures, requests)
                    else:
                        comparator.assert_not_called()
                    responder.start.assert_called_once_with({fixture["route"]: fixture["issuer"] for fixture in fixtures})
                    responder.close.assert_called_once_with()
                captures = [event for event in events if isinstance(event, tuple) and event[0] == "capture"]
                reached_baseline = mode in {"comparison", "formatting-error", "formatting-cancel", "success", "final-idle-error"}
                self.assertEqual(captures, [("capture", case, 60123 if case in {"aia-prepare", "aia-evaluate"} else None)
                                            for case in list(outputs)[:7 if reached_baseline else 6]])
                self.assertEqual(reader.call_count, 2 if reached_baseline else 1)
                if reached_baseline:
                    snapshot.assert_called_once_with(original_der)
                    self.assertLess(events.index("close"), events.index("preflight"))
                    self.assertLess(events.index("preflight"), events.index("snapshot"))
                    self.assertLess(events.index("snapshot"), events.index(("capture", "aia-offline-baseline", None)))
                    self.assertLess(events.index(("idle", "aia-offline-baseline")), events.index("compare"))
                else:
                    snapshot.assert_not_called()
                for index, event in enumerate(events):
                    if isinstance(event, tuple) and event[0] == "capture":
                        self.assertEqual(events[index + 1], ("idle", event[1]))
                self.assertLess(events.index(("idle", "aia-evaluate")), events.index("close"))

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

    def test_owner_orchestration_keeps_original_six_then_baseline_and_finality_order(self):
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
        record["chain_observations"] = aia_chain_observations(m, fixtures)
        outputs["aia-evaluate"] = m.AIA_PREFIX + json.dumps(record).encode() + b"\n"
        originals = tuple(fixtures[0][role] for role in ("leaf", "issuer", "root"))
        # A completed negative baseline is valid observation data, not a new gate.
        outputs["aia-offline-baseline"] = (m.AIA_BASELINE_PREFIX
            + json.dumps(aia_baseline_evidence(m, originals, accepted=False)).encode() + b"\n")
        responder = SimpleNamespace(port=60123, requests=requests, start=lambda _rows: events.append("listener-start"),
                                    close=lambda: events.append("listener-close"))

        def launch(case, *, port=None):
            events.append(("capture", case, port))
            return SimpleNamespace(ok=True, stdout=outputs[case])

        def idle():
            events.append("idle")

        def read(scratch, port, deadline):
            self.assertEqual((scratch, port, deadline), (Path("/pure/probes"), 60123, 100.0))
            events.append("fixtures")
            return fixtures

        def freeze(raw):
            self.assertEqual(raw, originals)
            self.assertEqual(events[-3:], ["idle", "preflight", "fixtures"])
            events.append("snapshot")

        real_project, real_baseline, real_compare = m._aia_comparison_note, m.baseline_comparison_note, m.require_aia_controls

        def project(data, original, observed):
            events.append("preflight")
            return real_project(data, original, observed)

        def baseline(data, original):
            events.append("baseline-project")
            return real_baseline(data, original)

        def compare(data, original, observed):
            self.assertEqual(events[-3:], [("capture", "aia-offline-baseline", None), "idle", "baseline-project"])
            events.append("compare")
            return real_compare(data, original, observed)

        snapshot, reader, comparator = Mock(side_effect=freeze), Mock(side_effect=read), Mock(side_effect=compare)
        baseline_projector, projector = Mock(side_effect=baseline), Mock(side_effect=project)
        scratch = Path("/pure/probes")
        with clock(m), patch.multiple(m, _scratch=Mock(), _fixtures=reader, _Responder=Mock(return_value=responder),
            _aia_comparison_note=projector, baseline_comparison_note=baseline_projector, require_aia_controls=comparator,
            os=SimpleNamespace(), subprocess=SimpleNamespace(), socket=SimpleNamespace(), threading=SimpleNamespace(), Path=SimpleNamespace()):
            result = m.admit_controls(launch, idle, scratch, deadline=100.0, policy_sha256="a" * 64,
                                      freeze_baseline=snapshot)
        self.assertTrue(result["cleanup_ok"])
        self.assertEqual(result["mach"]["authority"], applications["mach-authority"])
        self.assertEqual(result["mach"]["nonexpand"], applications["mach-nonexpand"])
        captures = [event for event in events if isinstance(event, tuple)]
        self.assertEqual(captures, [("capture", name, 60123 if name in {"aia-prepare", "aia-evaluate"} else None)
                                   for name in outputs])
        for index, event in enumerate(events):
            if isinstance(event, tuple):
                self.assertEqual(events[index + 1], "idle")
        self.assertEqual(events[-10:], ["listener-close", "idle", "preflight", "fixtures", "snapshot",
                                       ("capture", "aia-offline-baseline", None), "idle", "baseline-project", "compare", "idle"])
        self.assertEqual(reader.call_count, 2)
        snapshot.assert_called_once_with(originals)
        projector.assert_called_once_with(outputs["aia-evaluate"], fixtures, requests)
        baseline_projector.assert_called_once_with(outputs["aia-offline-baseline"], originals)
        comparator.assert_called_once_with(outputs["aia-evaluate"], fixtures, requests)

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
        snapshot = Mock(return_value=None)
        with clock(m), patch.object(m, "_scratch"), patch.object(m, "_Responder", responder_factory), \
                patch.object(m, "_fixtures", fixtures_reader), self.assertRaises(m.NativeControlError):
            m.admit_controls(refused_launch, idle, Path("/pure/probes"), deadline=100.0, policy_sha256="a" * 64,
                             freeze_baseline=snapshot)
        self.assertEqual(refused_cases, ["mach-baseline", "mach-ordinary", "mach-authority", "mach-nonexpand"])
        self.assertEqual(idle.call_count, 5)  # Initial idle and each actual failed/successful capture remain required.
        responder_factory.assert_not_called()
        fixtures_reader.assert_not_called()
        snapshot.assert_not_called()
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
                m.admit_controls(attempted, Mock(), Path("/pure/probes"), deadline=100.0, policy_sha256=owner_hash,
                                 freeze_baseline=snapshot)
            self.assertFalse(any(name.startswith("aia-") for name in actual))
            if case.startswith("owner-hash-"):
                self.assertEqual(actual, [])
            responder_factory.assert_not_called()
            fixtures_reader.assert_not_called()
            snapshot.assert_not_called()

    def test_owner_baseline_structural_snapshot_and_capture_failures_stop_before_oracle(self):
        m = self.module
        semantic_failures = {"original-negative", "flags-mismatch", "request-digest"}
        successes = {"contrast-negative", "crypto-unavailable", "crypto-negative", "baseline-negative"}
        structural_failures = {"missing-contrasts", "short-contrasts", "bad-cases", "bad-framing", "malformed-fixture", "malformed-request"}
        preflight_failures = {"preflight-error", "preflight-cancel", "preflight-cutoff"}
        reread_failures = {"reread-DER-drift", "reread-route-drift", "reread-error", "reread-cutoff"}
        snapshot_failures = {"snapshot-error", "snapshot-cancel", "snapshot-return", "snapshot-cutoff"}
        capture_failures = {"baseline-launch-error", "baseline-capture-refused", "baseline-capture-missing", "baseline-finality-error",
                            "baseline-launch-and-finality", "baseline-finality-cancel", "baseline-malformed", "baseline-cutoff",
                            "baseline-projection-cutoff"}
        modes = ({"callback-invalid"} | semantic_failures | successes | structural_failures
                 | preflight_failures | reread_failures | snapshot_failures | capture_failures)
        real_project, real_baseline, real_compare = m._aia_comparison_note, m.baseline_comparison_note, m.require_aia_controls
        scratch = Path("/pure/probes")
        for mode in sorted(modes):
            with self.subTest(baseline_owner_boundary=mode):
                fixtures = aia_fixtures(m)
                originals = tuple(fixtures[0][role] for role in ("leaf", "issuer", "root"))
                record, requests = aia_evidence(m, fixtures)
                record["chain_observations"] = aia_chain_observations(m, fixtures)
                if mode == "original-negative":
                    record["cases"][0].update(accepted=False, error=True, result=5, chain=record["cases"][0]["chain"][:1])
                if mode == "flags-mismatch":
                    record["cases"][0]["network"] = False
                if mode == "request-digest":
                    requests[0] = (requests[0][0], "0" * 64)
                if mode == "contrast-negative":
                    contrast = record["chain_observations"]["contrasts"][0]
                    contrast.update(accepted=False, error=True, result=5, chain=contrast["chain"][:2],
                                    trust_error={"status": "osstatus", "code": -25318})
                if mode == "crypto-unavailable":
                    record["chain_observations"]["crypto"] = {"available": False, "keys": None, "checks": None}
                if mode == "crypto-negative":
                    record["chain_observations"]["crypto"]["checks"][0].update(accepted=False, error=True,
                        trust_error={"status": "osstatus", "code": -67808})
                if mode == "missing-contrasts":
                    del record["chain_observations"]
                if mode == "short-contrasts":
                    record["chain_observations"]["contrasts"].pop()
                if mode == "bad-cases":
                    record["cases"].pop()
                if mode == "malformed-fixture":
                    fixtures[0]["leaf"] = b"PRIVATE-NOT-DER"
                if mode == "malformed-request":
                    requests[0] = list(requests[0])
                outputs = {name: m.MACH_PREFIX + json.dumps(row).encode() + b"\n" for name, row in (
                    ("mach-baseline", mach_row([0, 1102, 0])), ("mach-ordinary", mach_row([1100] * 3)))}
                outputs.update({name: m.MACH_APPLY_PREFIX + json.dumps(row).encode() + b"\n" for name, row in (
                    ("mach-authority", mach_application("mach-initial")),
                    ("mach-nonexpand", mach_application("mach-nonexpand", returned=-1, number=1)))})
                outputs["aia-prepare"] = b"MRK_AIA_PREPARED\n"
                outputs["aia-evaluate"] = m.AIA_PREFIX + json.dumps(record, separators=(",", ":")).encode() + b"\n"
                if mode == "bad-framing":
                    outputs["aia-evaluate"] += b"PRIVATE-EXTRA\n"
                outputs["aia-offline-baseline"] = m.AIA_BASELINE_PREFIX + json.dumps(
                    aia_baseline_evidence(m, originals, accepted=mode != "baseline-negative")).encode() + b"\n"
                if mode == "baseline-malformed":
                    outputs["aia-offline-baseline"] = b"PRIVATE-NOT-BASELINE\n"
                now, events, last, closed, compared, original_errors = [10.0], [], [None], [False], [False], []
                earlier = KeyboardInterrupt("PRIVATE-CANCEL") if mode in {"preflight-cancel", "snapshot-cancel"} else OSError("PRIVATE-ORIGINAL")
                finality = KeyboardInterrupt("PRIVATE-FINALITY-CANCEL") if mode == "baseline-finality-cancel" else OSError("PRIVATE-FINALITY")

                def launch(case, *, port=None):
                    self.assertEqual(port, 60123 if case in {"aia-prepare", "aia-evaluate"} else None)
                    events.append(("capture", case))
                    last[0] = case
                    if case == "aia-offline-baseline":
                        self.assertTrue(closed[0])
                        self.assertFalse(compared[0])
                        snapshot.assert_called_once_with(originals)
                        if mode in {"baseline-launch-error", "baseline-launch-and-finality"}:
                            raise earlier
                        if mode == "baseline-capture-missing":
                            return None
                        if mode == "baseline-cutoff":
                            now[0] = 100.0
                    return SimpleNamespace(ok=not (case == "aia-offline-baseline" and mode == "baseline-capture-refused"), stdout=outputs[case])

                def idle():
                    events.append(("idle", last[0]))
                    if last[0] == "aia-offline-baseline" and mode in {
                            "baseline-finality-error", "baseline-finality-cancel", "baseline-launch-and-finality"}:
                        raise finality

                def close():
                    events.append("close")
                    closed[0] = True

                def read(path, port, deadline):
                    self.assertEqual((path, port, deadline), (scratch, 60123, 100.0))
                    events.append("fixtures")
                    if reader.call_count == 2:
                        self.assertTrue(closed[0])
                        self.assertFalse(compared[0])
                        if mode == "reread-error":
                            raise earlier
                        if mode == "reread-cutoff":
                            now[0] = 100.0
                        if mode in {"reread-DER-drift", "reread-route-drift"}:
                            changed = [dict(fixture) for fixture in fixtures]
                            # An offline (not snapshotted online) field changing still rejects.
                            changed[1]["root" if mode == "reread-DER-drift" else "route"] += b"changed" if mode == "reread-DER-drift" else "changed"
                            return changed
                    return fixtures

                def project(data, actual, observed):
                    self.assertTrue(closed[0])
                    self.assertIs(data, outputs["aia-evaluate"])
                    self.assertIs(actual, fixtures)
                    self.assertIs(observed, requests)
                    events.append("diagnostic" if compared[0] else "preflight")
                    if mode in {"preflight-error", "preflight-cancel"}:
                        raise earlier
                    note = real_project(data, actual, observed)
                    if mode == "preflight-cutoff":
                        now[0] = 100.0
                    return note

                def freeze(raw):
                    self.assertIs(type(raw), tuple)
                    self.assertEqual(raw, originals)
                    self.assertTrue(all(value is fixtures[0][role] for value, role in zip(raw, ("leaf", "issuer", "root"))))
                    self.assertTrue(closed[0])
                    self.assertFalse(compared[0])
                    self.assertEqual(reader.call_count, 2)
                    events.append("snapshot")
                    if mode in {"snapshot-error", "snapshot-cancel"}:
                        raise earlier
                    if mode == "snapshot-cutoff":
                        now[0] = 100.0
                    return False if mode == "snapshot-return" else None

                def baseline(data, original):
                    events.append("baseline-project")
                    note = real_baseline(data, original)
                    if mode == "baseline-projection-cutoff":
                        now[0] = 100.0
                    return note

                def compare(data, actual, observed):
                    self.assertIs(data, outputs["aia-evaluate"])
                    self.assertIs(actual, fixtures)
                    self.assertIs(observed, requests)
                    self.assertEqual(events[-1], "baseline-project")
                    events.append("compare")
                    compared[0] = True
                    try:
                        return real_compare(data, actual, observed)
                    except m.NativeControlError as error:
                        original_errors.append(error)
                        raise

                reader, snapshot = Mock(side_effect=read), Mock(side_effect=freeze)
                comparator, projector, baseline_projector = Mock(side_effect=compare), Mock(side_effect=project), Mock(side_effect=baseline)
                responder = SimpleNamespace(port=60123, requests=requests, start=Mock(), close=Mock(side_effect=close))
                denied = Mock(side_effect=AssertionError("fake owner may not run a native operation or acquire a real resource"))
                with patch.multiple(m, time=SimpleNamespace(monotonic=lambda: now[0]), os=SimpleNamespace(), subprocess=SimpleNamespace(),
                    socket=SimpleNamespace(), threading=SimpleNamespace(), secrets=SimpleNamespace(), Path=SimpleNamespace(),
                    _scratch=Mock(return_value=scratch), _fixtures=reader, _Responder=Mock(return_value=responder),
                    _aia_comparison_note=projector, baseline_comparison_note=baseline_projector, require_aia_controls=comparator,
                    _Trust=denied, _baseline_der=denied, prepare_aia=denied, evaluate_aia=denied, evaluate_aia_baseline=denied, _command=denied):
                    if mode in successes:
                        result = m.admit_controls(launch, idle, scratch, deadline=100.0, policy_sha256="a" * 64, freeze_baseline=snapshot)
                        self.assertTrue(result["cleanup_ok"])
                        self.assertTrue(result["aia"]["final_disable_mutation_detected"])
                    else:
                        grouped = mode in {"baseline-launch-error", "baseline-finality-error", "baseline-finality-cancel", "baseline-launch-and-finality"}
                        direct = mode in {"preflight-error", "preflight-cancel", "reread-error", "snapshot-error", "snapshot-cancel"}
                        expected = BaseExceptionGroup if grouped else type(earlier) if direct else m.NativeControlError
                        with self.assertRaises(expected) as caught:
                            m.admit_controls(launch, idle, scratch, deadline=100.0, policy_sha256="a" * 64,
                                             freeze_baseline=None if mode == "callback-invalid" else snapshot)
                        error = caught.exception
                        if grouped:
                            self.assertEqual(error.exceptions, (earlier, finality) if mode == "baseline-launch-and-finality" else
                                             (earlier,) if mode == "baseline-launch-error" else (finality,))
                        if direct:
                            self.assertIs(error, earlier)
                        if mode in semantic_failures:
                            self.assertEqual(original_errors, [error])
                            self.assertTrue(error._ci_observation["available"])
                        else:
                            self.assertFalse(hasattr(error, "_ci_observation"))
                denied.assert_not_called()
                reached_baseline = mode in successes | semantic_failures | capture_failures
                reached_snapshot = reached_baseline or mode in snapshot_failures
                reached_reread = reached_snapshot or mode in reread_failures
                self.assertEqual(reader.call_count, 0 if mode == "callback-invalid" else 2 if reached_reread else 1)
                self.assertEqual(snapshot.call_count, int(reached_snapshot))
                self.assertEqual(comparator.call_count, int(mode in successes | semantic_failures))
                captures = [event[1] for event in events if type(event) is tuple and event[0] == "capture"]
                self.assertEqual(captures, list(outputs)[:0 if mode == "callback-invalid" else 7 if reached_baseline else 6])
                for index, event in enumerate(events):
                    if type(event) is tuple and event[0] == "capture":
                        self.assertEqual(events[index + 1], ("idle", event[1]))
                if mode != "callback-invalid":
                    responder.close.assert_called_once_with()
                    self.assertLess(events.index(("idle", "aia-evaluate")), events.index("close"))
                    self.assertLess(events.index("close"), events.index("preflight"))
                if reached_snapshot:
                    self.assertLess(events.index("preflight"), events.index("snapshot"))
                if reached_baseline:
                    self.assertLess(events.index("snapshot"), events.index(("capture", "aia-offline-baseline")))
                if mode in successes | semantic_failures:
                    comparator.assert_called_once_with(outputs["aia-evaluate"], fixtures, requests)
                    baseline_projector.assert_called_once_with(outputs["aia-offline-baseline"], originals)
                    self.assertLess(events.index(("idle", "aia-offline-baseline")), events.index("compare"))

        # Required keyword custody is checked before any callback or resource use.
        launch, idle = Mock(), Mock()
        with self.assertRaises(TypeError):
            m.admit_controls(launch, idle, scratch, deadline=100.0, policy_sha256="a" * 64)
        launch.assert_not_called()
        idle.assert_not_called()

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

        snapshot = Mock(return_value=None)
        with clock(m), patch.object(m, "_scratch"), patch.object(m, "_fixtures", return_value=fixtures), \
                patch.object(m, "_Responder", return_value=responder), self.assertRaises(BaseExceptionGroup) as raised:
            m.admit_controls(launch, idle, Path("/pure/probes"), deadline=100.0, policy_sha256="a" * 64,
                             freeze_baseline=snapshot)
        self.assertEqual(len(raised.exception.exceptions), 2)
        self.assertEqual(len(raised.exception.exceptions[0].exceptions), 2)
        responder.close.assert_called_once_with()
        self.assertEqual(calls[-1], "aia-evaluate")
        snapshot.assert_not_called()


if __name__ == "__main__":
    unittest.main()
