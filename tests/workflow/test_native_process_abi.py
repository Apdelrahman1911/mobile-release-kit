"""Pure native-ABI record parser contracts, not native-platform evidence.

These independent DATA vectors import only the fixed inert ci_checks helper.
They do not compile/run the C reporter, import either runtime binding, load a
native library, acquire descriptors, or create processes.  Actual public-header,
language-API and source/wheel origin evidence belongs to distinct completed
captures under the reviewed disposable owner, before process-bearing suites.
"""
from __future__ import annotations

import copy
import functools
import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAX_RECORD_BYTES = 8192
PRIVATE_MARKER = "abi-private-input-marker"


@functools.lru_cache(maxsize=1)
def checks_module():
    """The established known-helper seam; no product or test-module import."""
    name = "_mrk_native_abi_contracts_ci_checks"
    spec = importlib.util.spec_from_file_location(name, ROOT / ".github/scripts/ci_checks.py")
    if spec is None or spec.loader is None:
        raise AssertionError("required inert CI helper is missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def signature(*arguments, variadic=False):
    return {"return": "int", "args": list(arguments), "variadic": variadic}


def abi_fixture(family="linux-glibc", architecture="x86_64"):
    """Independent source-backed sample, never the implementation's template.

    This describes supported public LP64 declarations, not an observed machine.
    Linux's unused attributes stay null.  Darwin's slots describe only the
    public pointer typedefs, never storage for their opaque private pointees.
    """
    if family not in {"linux-glibc", "darwin"} or architecture not in {"x86_64", "arm64"}:
        raise ValueError("unsupported test fixture")
    linux = family == "linux-glibc"
    return {
        "schema": "mrk-native-process-abi-v1",
        "family": family,
        "architecture": architecture,
        "byteorder": "little",
        "scalars": {
            "pointer": {"size": 8, "align": 8},
            "int": {"size": 4, "align": 4},
            "short": {"size": 2, "align": 2},
            "long": {"size": 8, "align": 8},
            "pid_t": {"size": 4, "align": 4, "signed": True},
        },
        "sigaction": {
            "size": 152 if linux else 16,
            "align": 8,
            "fields": {
                "handler": {"offset": 0, "size": 8},
                "mask": {"offset": 8, "size": 128 if linux else 4},
                "flags": {"offset": 136 if linux else 12, "size": 4},
                "restorer": {"offset": 144, "size": 8} if linux else None,
            },
        },
        "file_actions": {
            "kind": "struct" if linux else "pointer_slot",
            "size": 80 if linux else 8,
            "align": 8,
            "fields": {
                "allocated": {"offset": 0, "size": 4},
                "used": {"offset": 4, "size": 4},
                "actions": {"offset": 8, "size": 8},
                "pad": {"offset": 16, "size": 64},
            } if linux else {},
        },
        "spawn_attributes": None if linux else {
            "kind": "pointer_slot", "size": 8, "align": 8, "fields": {},
        },
        "constants": {
            "SIG_IGN": 1,
            "SA_NOCLDWAIT": 2 if linux else 32,
            "SIGCHLD": 17 if linux else 20,
            "NSIG": 65 if linux else 32,
            "F_DUPFD_CLOEXEC": 1030 if linux else 67,
            "F_GETFD": 1,
            "F_GETFL": 3,
            "FD_CLOEXEC": 1,
            "O_RDONLY": 0,
            "O_WRONLY": 1,
            "O_RDWR": 2,
            "O_ACCMODE": 3,
            "POSIX_SPAWN_CLOEXEC_DEFAULT": None if linux else 16384,
        },
        "functions": {
            "fcntl": signature("int", "int", variadic=True),
            "close": signature("int"),
            "sigaction": signature("int", "pointer", "pointer"),
            "posix_spawn": signature(*(["pointer"] * 6)),
            "posix_spawn_file_actions_init": signature("pointer"),
            "posix_spawn_file_actions_destroy": signature("pointer"),
            "posix_spawn_file_actions_adddup2": signature("pointer", "int", "int"),
            "posix_spawn_file_actions_addclosefrom_np": signature("pointer", "int") if linux else None,
            "posix_spawnattr_init": None if linux else signature("pointer"),
            "posix_spawnattr_destroy": None if linux else signature("pointer"),
            "posix_spawnattr_setflags": None if linux else signature("pointer", "short"),
            "posix_spawnattr_getflags": None if linux else signature("pointer", "pointer"),
        },
    }


def wire(value, *, sorted_keys=False):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=sorted_keys).encode("ascii") + b"\n"


def nodes(value, path=()):
    yield path, value
    if type(value) is dict:
        for key, child in value.items():
            yield from nodes(child, path + (key,))
    elif type(value) is list:
        for index, child in enumerate(value):
            yield from nodes(child, path + (index,))


def replaced(value, path, replacement):
    result = copy.deepcopy(value)
    if not path:
        return copy.deepcopy(replacement)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = copy.deepcopy(replacement)
    return result


def duplicate_wire(value, target):
    """Insert a duplicate at the exact object path, including repeated shapes."""
    def render(node, path):
        if type(node) is dict:
            pairs = list(node.items())
            if path == target:
                pairs.insert(0, pairs[0])
            return "{" + ",".join(json.dumps(key) + ":" + render(child, path + (key,))
                                  for key, child in pairs) + "}"
        if type(node) is list:
            return "[" + ",".join(render(child, path + (index,))
                                  for index, child in enumerate(node)) + "]"
        return json.dumps(node, ensure_ascii=True)
    return render(value, ()).encode("ascii") + b"\n"


class NativeProcessABITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.checks = checks_module()

    def assert_record_rejected(self, data):
        with self.assertRaises(ValueError) as caught:
            self.checks.parse_abi_record(data)
        self.assertNotIn(PRIVATE_MARKER, str(caught.exception))

    def test_supported_native_abi_records_match(self):
        for family in ("linux-glibc", "darwin"):
            for architecture in ("x86_64", "arm64"):
                with self.subTest(family=family, architecture=architecture):
                    expected = abi_fixture(family, architecture)
                    data = wire(expected)
                    self.assertLess(len(data), MAX_RECORD_BYTES)
                    self.assertEqual(self.checks.parse_abi_record(data), expected)
                    self.assertIsNone(self.checks.compare_abi_records(data, data, data))

    def test_json_key_order_does_not_change_abi(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            original, reordered = wire(expected), wire(expected, sorted_keys=True)
            with self.subTest(family=family):
                self.assertNotEqual(original, reordered)
                self.assertEqual(self.checks.parse_abi_record(reordered), expected)
                self.assertIsNone(self.checks.compare_abi_records(original, reordered, original))
                self.assertIsNone(self.checks.compare_abi_records(reordered, original, reordered))

    def test_accepts_record_at_exact_byte_limit(self):
        expected = abi_fixture()
        data = wire(expected)
        # Interior JSON spaces are printable ASCII; outer framing stays exact.
        padded = data[:1] + b" " * (MAX_RECORD_BYTES - len(data)) + data[1:]
        self.assertEqual(len(padded), MAX_RECORD_BYTES)
        self.assertEqual(self.checks.parse_abi_record(padded), expected)

    def test_rejects_oversize_record(self):
        data = wire(abi_fixture())
        for extra in (1, 2, MAX_RECORD_BYTES):
            padded = data[:1] + b" " * (MAX_RECORD_BYTES + extra - len(data)) + data[1:]
            with self.subTest(extra=extra):
                self.assert_record_rejected(padded)

    def test_rejects_missing_or_extra_newlines(self):
        data = wire(abi_fixture())
        for candidate in (
            b"", data[:-1], data + b"\n", data + data, b"\n" + data,
            data[:-1] + b"\r\n", data[:1] + b"\n" + data[1:],
            data + b"suffix", b"prefix" + data, b" " + data, data[:-1] + b" \n",
        ):
            with self.subTest(length=len(candidate)):
                self.assert_record_rejected(candidate)

    def test_rejects_non_bytes_and_non_ascii_records(self):
        data = wire(abi_fixture())
        class BytesSubclass(bytes):
            pass
        for candidate in (None, 1, data.decode("ascii"), bytearray(data), memoryview(data), BytesSubclass(data)):
            with self.subTest(kind=type(candidate).__name__):
                self.assert_record_rejected(candidate)
        for byte_sequence in (b"\x00", b"\t", b"\r", b"\x1f", b"\x7f", b"\xff", "\u2603".encode("utf-8")):
            with self.subTest(byte_sequence=byte_sequence.hex()):
                self.assert_record_rejected(data[:1] + byte_sequence + data[1:])
        self.assert_record_rejected(b"\xef\xbb\xbf" + data)

    def test_rejects_duplicate_keys_at_every_level(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            for path, value in nodes(expected):
                if type(value) is dict and value:
                    with self.subTest(family=family, path=path):
                        self.assert_record_rejected(duplicate_wire(expected, path))
        # Duplicate detection is on decoded keys, not their source spelling.
        data = wire(abi_fixture()).replace(b'"size":8', b'"size":8,"\\u0073ize":8', 1)
        self.assert_record_rejected(data)

    def test_rejects_non_object_and_invalid_json(self):
        for candidate in (b"null\n", b"[]\n", b"true\n", b"1\n", b'"object"\n',
                          b"{\n", b"{} trailing\n", b'{"x":}\n', b'{"x":1,}\n'):
            with self.subTest(candidate=candidate):
                self.assert_record_rejected(candidate)

    def test_rejects_non_finite_numbers_and_excessive_nesting(self):
        data = wire(abi_fixture())
        for number in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(number=number):
                self.assert_record_rejected(data.replace(b'"SIG_IGN":1', b'"SIG_IGN":' + number, 1))
        deeply_nested = b'{"schema":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}\n"
        self.assertLess(len(deeply_nested), MAX_RECORD_BYTES)
        self.assert_record_rejected(deeply_nested)

    def test_rejects_unknown_or_missing_fields(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            for path, value in nodes(expected):
                if type(value) is not dict:
                    continue
                with self.subTest(family=family, path=path, mutation="extra"):
                    altered = dict(value, **{PRIVATE_MARKER: PRIVATE_MARKER})
                    self.assert_record_rejected(wire(replaced(expected, path, altered)))
                for key in value:
                    with self.subTest(family=family, path=path, mutation="missing", key=key):
                        altered = dict(value)
                        del altered[key]
                        self.assert_record_rejected(wire(replaced(expected, path, altered)))

    def test_rejects_unsupported_platform_architecture_or_byteorder(self):
        expected = abi_fixture()
        for key, values in {
            "schema": ("mrk-native-process-abi-v0", "mrk-native-process-abi-v2", None, True, 1),
            "family": ("linux", "linux-musl", "windows", "", None),
            "architecture": ("aarch64", "i686", "ppc64", "", None),
            "byteorder": ("big", "native", "", None),
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.assert_record_rejected(wire(replaced(expected, (key,), value)))

    def test_rejects_boolean_float_string_and_null_in_integer_fields(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            for path, value in nodes(expected):
                if type(value) is not int:
                    continue
                for bad in (False, True, float(value), str(value), None):
                    with self.subTest(family=family, path=path, kind=type(bad).__name__):
                        self.assert_record_rejected(wire(replaced(expected, path, bad)))

    def test_rejects_wrong_scalar_width_alignment_or_pid_signedness(self):
        expected = abi_fixture()
        for scalar, properties in expected["scalars"].items():
            for field in ("size", "align"):
                for bad in (0, -1, properties[field] + 1):
                    with self.subTest(scalar=scalar, field=field, bad=bad):
                        self.assert_record_rejected(wire(replaced(expected, ("scalars", scalar, field), bad)))
        for bad in (False, 0, 1, "true", None):
            with self.subTest(signed=bad):
                self.assert_record_rejected(wire(replaced(expected, ("scalars", "pid_t", "signed"), bad)))

    def test_rejects_wrong_sigaction_layout_and_private_darwin_shape(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            for path, value in nodes(expected["sigaction"], ("sigaction",)):
                if type(value) is int:
                    with self.subTest(family=family, path=path):
                        self.assert_record_rejected(wire(replaced(expected, path, value + 8)))
        # Excluded generic glibc one-word sigset layout is NOT Linux's public ABI.
        one_word = abi_fixture()
        one_word["sigaction"]["size"] = 32
        one_word["sigaction"]["fields"]["mask"]["size"] = 8
        one_word["sigaction"]["fields"]["flags"]["offset"] = 16
        one_word["sigaction"]["fields"]["restorer"]["offset"] = 24
        self.assert_record_rejected(wire(one_word))
        # Darwin's kernel-facing __sigaction trampoline is not struct sigaction.
        kernel = abi_fixture("darwin")
        kernel["sigaction"]["size"] = 24
        kernel["sigaction"]["fields"]["trampoline"] = {"offset": 8, "size": 8}
        kernel["sigaction"]["fields"]["mask"]["offset"] = 16
        kernel["sigaction"]["fields"]["flags"]["offset"] = 20
        self.assert_record_rejected(wire(kernel))
        for family, restorer in (("linux-glibc", None), ("darwin", {"offset": 16, "size": 8})):
            self.assert_record_rejected(wire(replaced(abi_fixture(family), ("sigaction", "fields", "restorer"), restorer)))

    def test_rejects_wrong_file_action_containers_or_unused_attributes(self):
        for family, other in (("linux-glibc", "darwin"), ("darwin", "linux-glibc")):
            expected = abi_fixture(family)
            other_record = abi_fixture(other)
            for key in ("file_actions", "spawn_attributes"):
                with self.subTest(family=family, key=key, mutation="other-family"):
                    self.assert_record_rejected(wire(replaced(expected, (key,), other_record[key])))
            for path, value in nodes(expected["file_actions"], ("file_actions",)):
                if type(value) is int:
                    with self.subTest(family=family, path=path):
                        self.assert_record_rejected(wire(replaced(expected, path, value + 4)))
        darwin = abi_fixture("darwin")
        for key in ("file_actions", "spawn_attributes"):
            for field, bad in (("kind", "opaque_pointee"), ("size", 80), ("align", 4),
                               ("fields", {"private": {"offset": 0, "size": 8}})):
                with self.subTest(key=key, field=field):
                    self.assert_record_rejected(wire(replaced(darwin, (key, field), bad)))

    def test_rejects_wrong_public_constants(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            for key, value in expected["constants"].items():
                with self.subTest(family=family, constant=key):
                    bad = 0 if value is None else value + 1
                    self.assert_record_rejected(wire(replaced(expected, ("constants", key), bad)))
            for key, bad in (("F_DUPFD_CLOEXEC", 67 if family == "linux-glibc" else 1030),
                             ("NSIG", 32 if family == "linux-glibc" else 65), ("SIG_IGN", 0)):
                with self.subTest(family=family, constant=key, mutation="foreign-or-fallback"):
                    self.assert_record_rejected(wire(replaced(expected, ("constants", key), bad)))

    def test_rejects_wrong_signatures_or_fixed_fcntl_approximation(self):
        for family in ("linux-glibc", "darwin"):
            expected = abi_fixture(family)
            for name, declaration in expected["functions"].items():
                if declaration is None:
                    with self.subTest(family=family, name=name, mutation="unsupported"):
                        self.assert_record_rejected(wire(replaced(expected, ("functions", name), signature("pointer"))))
                    continue
                for field, bad in (("return", "long"), ("args", declaration["args"] + ["int"]),
                                   ("args", "pointer"), ("variadic", not declaration["variadic"]),
                                   ("variadic", int(declaration["variadic"])), ("variadic", None)):
                    with self.subTest(family=family, name=name, field=field, bad=bad):
                        self.assert_record_rejected(wire(replaced(expected, ("functions", name, field), bad)))
            for bad in (signature("int", "int", "int"), signature("int", "int")):
                with self.subTest(family=family, mutation="fixed-fcntl"):
                    self.assert_record_rejected(wire(replaced(expected, ("functions", "fcntl"), bad)))
        darwin = abi_fixture("darwin")
        self.assert_record_rejected(wire(replaced(darwin, ("functions", "posix_spawnattr_setflags"), signature("pointer", "int"))))

    def test_rejects_mismatched_platforms_or_architectures(self):
        baseline = wire(abi_fixture())
        for other in (wire(abi_fixture("darwin")), wire(abi_fixture(architecture="arm64"))):
            self.checks.parse_abi_record(other)  # Individually supported, not equal.
            for index in range(3):
                records = [baseline, baseline, baseline]
                records[index] = other
                with self.subTest(index=index, family=json.loads(other)["family"]), self.assertRaises(ValueError):
                    self.checks.compare_abi_records(*records)

    def test_rejects_each_language_declaration_mismatch(self):
        expected = abi_fixture()
        baseline = wire(expected)
        mutations = (
            (("scalars", "pointer", "size"), 4),
            (("sigaction", "fields", "mask", "size"), 8),
            (("constants", "F_DUPFD_CLOEXEC"), 0),
            (("functions", "fcntl"), signature("int", "int", "int")),
            (("functions", "close", "return"), "void"),
        )
        for path, value in mutations:
            corrupt = wire(replaced(expected, path, value))
            for index in (1, 2):
                records = [baseline, baseline, baseline]
                records[index] = corrupt
                with self.subTest(language=("header", "python", "ruby")[index], path=path), self.assertRaises(ValueError):
                    self.checks.compare_abi_records(*records)
            # Identical wrong declarations/header claims cannot self-confirm.
            with self.subTest(path=path, mutation="all-identical-wrong"), self.assertRaises(ValueError):
                self.checks.compare_abi_records(corrupt, corrupt, corrupt)

    def test_comparison_returns_no_evidence_object(self):
        data = wire(abi_fixture())
        self.assertIsNone(self.checks.compare_abi_records(data, data, data))
        for authority_key in ("passed", "exit_status", "eof", "domain_finality", "origin", "compiler"):
            record = abi_fixture()
            record[authority_key] = True
            with self.subTest(authority_key=authority_key):
                self.assert_record_rejected(wire(record))


if __name__ == "__main__":
    unittest.main()
