"""Bounded DATA/SOURCE checks; no Apple tool, vendor image or filesystem fixture."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("macos_intel_os_provider_data", ROOT / "desktop/tools/macos_intel_os_providers.py")
PROBE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PROBE)


def image_text(path, arch="x86_64", *, uuid=True, attrs=("weak-link", "re-export")):
    attribute_text = "".join(name + " " for name in attrs)
    return (path + " [" + arch + "]:\n"
            "    -platform:\n"
            "        platform     minOS      sdk\n"
            + f" {'macOS':>15}     {'11.0':<7}   {'26.6':<7}\n"
            + "    -uuid:\n"
            + ("        01234567-89AB-CDEF-0123-456789ABCDEF\n" if uuid else "")
            + "    -linked_dylibs:\n"
            "        attributes     load path\n"
            + "        " + f"{attribute_text:<12}" + "   /usr/lib/libSystem.B.dylib\n"
            + "    -rpaths:\n"
            "        @loader_path/../lib\n").encode("ascii")


def context_timeout(deadline, now, maximum):
    # Inert boundary double: the unchanged real function is SOURCE-pinned by the driver.
    if type(deadline) is not int or type(now) is not int or not now < deadline:
        raise RuntimeError("deadline")
    remaining = (deadline - now) // 1_000_000_000
    if remaining < 1:
        raise RuntimeError("deadline")
    return min(maximum, remaining)


def completed(result, argv, limit):
    if (type(result) is not subprocess.CompletedProcess or result.args != argv
            or type(result.returncode) is not int or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes or len(result.stdout) + len(result.stderr) > limit):
        raise RuntimeError("completed-original")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


class MemoryBook:
    """No FDs or file access: only driver-to-existing-custody boundary observations."""
    def __init__(self):
        self.directories, self.entries, self.events = {}, [], []
        self.files = {}
        self.close_known = True

    def directory(self, path):
        path = Path(path)
        if path not in self.directories:
            parent = None if path == Path("/") else self.directory(path.parent)
            n = len(self.entries) + 1
            value = {"path": path, "fd": n, "closed": False, "parent": parent,
                     "identity": (1, n, stat.S_IFDIR | 0o755, 0, 0)}
            self.directories[path] = value
            self.entries.append(value)
        self.check_one(self.directories[path])
        return self.directories[path]

    def file(self, path, maximum, *, uid, modes):
        path = Path(path)
        parent = self.directory(path.parent)
        body = self.files.setdefault(path, b"inert Apple-tool ORIGINAL DATA")
        n = len(self.entries) + 1
        value = {"path": path, "fd": n, "closed": False, "parent": parent,
                 "identity": (1, n, stat.S_IFREG | 0o755, 0, 0, 1, len(body), 7, 7)}
        assert uid == 0 and modes == (0o555, 0o755) and len(body) <= maximum
        self.entries.append(value)
        return value, body

    def check_one(self, entry):
        assert entry["fd"] is not None and not entry["closed"]
        self.events.append("check")

    def check(self):
        for entry in self.entries:
            self.check_one(entry)

    def read(self, entry):
        self.check_one(entry)
        self.events.append("read")
        return self.files[entry["path"]]

    def finish(self):
        self.events.append("finish")
        for entry in self.entries:
            entry.update(fd=None, closed=True)
        return self.close_known


def memory_os(book, *, alias=None):
    state = SimpleNamespace(link=alias, writes=[], bundle_uid=0)

    def named(name, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False and dir_fd == book.directory(PROBE.APPLICATIONS)["fd"]
        symbolic = name == "Xcode.app" and state.link is not None
        mode = (stat.S_IFLNK | 0o777) if symbolic else (stat.S_IFDIR | 0o755)
        return SimpleNamespace(st_dev=1, st_ino=900, st_mode=mode, st_uid=state.bundle_uid,
                               st_gid=0, st_nlink=1, st_size=len(state.link) if symbolic else 0,
                               st_mtime_ns=8, st_ctime_ns=8)

    def readlink(name, *, dir_fd):
        assert name == "Xcode.app" and dir_fd == book.directory(PROBE.APPLICATIONS)["fd"]
        return state.link

    def write(fd, body):
        assert fd in (1, 2) and type(body) is bytes
        state.writes.append(body)
        return len(body)

    return SimpleNamespace(path=os.path, stat=named, readlink=readlink, write=write), state


class IntelOSProviderData(unittest.TestCase):
    def test_exact_selected_images_and_normal_missing_never_infer_from_exit_zero(self):
        for path in PROBE.PROVIDERS:
            for arch in PROBE.ARCHES:
                for uuid in (False, True):
                    with self.subTest(path=path, arch=arch, uuid=uuid):
                        body = image_text(path, arch, uuid=uuid)
                        row = PROBE.observation(path, 0, body, b"")
                        self.assertEqual(row["state"], "observed")
                        self.assertIs(row["selectedIntelImageObserved"], True)
                        self.assertEqual(row["images"][0]["architecture"], arch)
                        self.assertEqual(row["images"][0]["platform"], "macOS")
                        self.assertEqual(row["images"][0]["uuid"] is not None, uuid)
                        self.assertEqual(row["images"][0]["loads"], [{"attributes": ["weak-link", "re-export"],
                                                                     "path": "/usr/lib/libSystem.B.dylib"}])
                        self.assertEqual(row["images"][0]["rpaths"], ["@loader_path/../lib"])
            for attributes in ((), ("upward", "delay-init", "weak-link", "re-export"), ("lazy-load",)):
                row = PROBE.observation(path, 0, image_text(path, attrs=attributes), b"")
                self.assertEqual(row["images"][0]["loads"][0]["attributes"], list(attributes))
            both = PROBE.observation(path, 0, image_text(path) + image_text(path, "x86_64h"), b"")
            self.assertEqual([x["architecture"] for x in both["images"]], ["x86_64", "x86_64h"])
            missing = ("dyld_info: '" + path + "' file not found\n").encode()
            no_arch = ("dyld_info: '" + path + "' does not contain specified arch(s)\n").encode()
            for code, error in ((0, missing), (1, missing), (1, no_arch)):
                row = PROBE.observation(path, code, b"", error)
                self.assertEqual(row["state"], "not-observed")
                self.assertIs(row["selectedIntelImageObserved"], False)
                self.assertEqual(row["images"], [])
            valid = image_text(path)
            for code, out, err in [
                (0, b"", b""), (0, b"", no_arch), (2, b"", missing),
                (0, b"", missing.replace(path.encode(), b"/wrong")), (1, valid, b""),
                (0, valid, b"unexpected\n"), (0, valid[:-1], b""), (0, valid + b"extra\n", b""),
                (0, valid.replace(b"[x86_64]", b"[arm64]"), b""),
                (0, valid.replace(path.encode(), b"/wrong", 1), b""),
                (0, valid + valid, b""), (0, valid.replace(b"macOS", b"iOS"), b""),
                (0, valid.replace(b"weak-link re-export ", b"re-export weak-link "), b""),
                (0, valid.replace(b"01234567", b"0123456g"), b""), (0, valid + b"\xff", b""),
                (True, valid, b""), (0, b"x" * (PROBE.CAPTURE_LIMIT + 1), b""),
            ]:
                with self.subTest(code=code, prefix=out[:35], error=err[:35]):
                    with self.assertRaises((RuntimeError, UnicodeDecodeError)):
                        PROBE.observation(path, code, out, err)
        selected = b"/Applications/Xcode_26.6.app/" + PROBE.TOOL_SUFFIX.encode() + b"\n"
        self.assertEqual(PROBE.selected_tool_path(selected), Path(selected.decode().rstrip("\n")))
        self.assertEqual(PROBE.alias_bundle("Xcode_26.6.app"), Path("/Applications/Xcode_26.6.app"))
        self.assertEqual(PROBE.alias_bundle("/Applications/Xcode_26.6.app"), Path("/Applications/Xcode_26.6.app"))
        for value in (selected[:-1], selected + b"\n", selected.replace(b"26.6", b"26.6_beta"),
                      selected.replace(b"XcodeDefault", b"untrusted"), b"/usr/bin/dyld_info\n",
                      b"/Library/Developer/CommandLineTools/usr/bin/dyld_info\n",
                      selected.replace(b"/Applications/", b"/tmp/"), selected.replace(b"/Contents/", b"/../Contents/")):
            with self.assertRaises(RuntimeError):
                PROBE.selected_tool_path(value)
        for value in ("../Xcode_26.6.app", "/tmp/Xcode_26.6.app", "Xcode.app", "Xcode_26.6.app/..", "Xcode_26.6_beta.app"):
            with self.assertRaises(RuntimeError):
                PROBE.alias_bundle(value)

    def test_four_originals_selected_tool_post_and_finality_share_one_endpoint(self):
        selected = Path("/Applications/Xcode_26.6.app") / PROBE.TOOL_SUFFIX
        book = MemoryBook()
        fake_os, state = memory_os(book, alias="/Applications/Xcode_26.6.app")
        with mock.patch.object(PROBE, "os", fake_os):
            tool = PROBE.selected_tool(book, Path("/Applications/Xcode.app") / PROBE.TOOL_SUFFIX)
            self.assertEqual(tool["path"], selected)
            PROBE.tool_post(book, tool)
            evidence = PROBE.tool_evidence(tool)
            self.assertEqual(evidence["originalIdentity"], tool["entry"]["identity"])
            self.assertEqual(evidence["oneHopAlias"]["parent"], "/Applications")
            self.assertTrue(all(row["directoryIdentity"][3] == 0 for row in evidence["ancestors"]))
            state.link = "/Applications/Xcode_26.7.app"
            with self.assertRaisesRegex(RuntimeError, "selected-alias-changed"):
                PROBE.tool_post(book, tool)
        book = MemoryBook()
        fake_os, state = memory_os(book)
        state.bundle_uid = 501
        with mock.patch.object(PROBE, "os", fake_os), self.assertRaisesRegex(RuntimeError, "selected-bundle-original"):
            PROBE.selected_tool(book, selected)
        book = MemoryBook()
        applications = book.directory(PROBE.APPLICATIONS)
        applications["identity"] = (*applications["identity"][:3], 501, 0)
        with self.assertRaisesRegex(RuntimeError, "system-tool-root-ancestor"):
            PROBE.system_tool(book, selected)

        fixture = SimpleNamespace(context_timeout=context_timeout, completed=completed, canonical=canonical)
        for mode in ("observed", "missing-first", "unparsed-first", "resolver-foreign", "wrong-original", "unknown", "late"):
            with self.subTest(mode=mode):
                book, calls, tools, dispatched = MemoryBook(), [], {}, []
                progress = {"stage": "host-admission", "role": None, "sourceSlot": None}
                fake_os, state = memory_os(book)
                clock = SimpleNamespace(CLOCK_MONOTONIC=1, now=0)
                clock.clock_gettime_ns = lambda which: clock.now
                deadline = 120_000_000_000

                def run(argv, **kwargs):
                    dispatched.append((list(argv), dict(kwargs)))
                    self.assertEqual(kwargs["output_limit"], 65536)
                    self.assertIs(kwargs["capture"], True)
                    self.assertIs(kwargs["text"], False)
                    self.assertEqual(kwargs["cwd"], Path("/private/test"))
                    self.assertEqual(set(kwargs["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"})
                    self.assertLessEqual(kwargs["timeout"], 30)
                    self.assertGreaterEqual(kwargs["timeout"], 1)
                    self.assertTrue(book.events and tools)
                    clock.now += 3_000_000_000
                    if len(dispatched) == 1:
                        output = (str(selected) + "\n").encode() if mode != "resolver-foreign" else b"/tmp/dyld_info\n"
                        return subprocess.CompletedProcess(argv, 0, output, b"")
                    if mode == "unknown":
                        raise RuntimeError("inert original outcome unknown")
                    path = argv[-1]
                    output, error, code = image_text(path), b"", 0
                    if len(dispatched) == 2:
                        if mode == "missing-first":
                            output, error = b"", ("dyld_info: '" + path + "' file not found\n").encode()
                        elif mode == "unparsed-first":
                            output = b""
                        elif mode == "late":
                            clock.now = deadline
                    return subprocess.CompletedProcess(["wrong"] if mode == "wrong-original" else argv, code, output, error)

                with mock.patch.object(PROBE, "os", fake_os), mock.patch.object(PROBE, "time", clock):
                    if mode in ("resolver-foreign", "wrong-original", "unknown", "late"):
                        with self.assertRaises(RuntimeError):
                            PROBE.observe_providers(fixture, book, SimpleNamespace(run_owned=run), deadline,
                                                    Path("/private/test"), calls, tools, progress)
                        self.assertEqual(len(dispatched), 1 if mode == "resolver-foreign" else 2)
                        self.assertEqual(progress["stage"], {"resolver-foreign": "selected-tool-path",
                                                           "wrong-original": "call-return", "unknown": "call",
                                                           "late": "call-post"}[mode])
                        self.assertEqual(progress["role"], PROBE.ROLES[len(dispatched) - 1])
                        if mode in ("wrong-original", "unknown"):
                            self.assertIs(calls[-1]["originalReturned"], False)
                        if mode == "late":
                            self.assertIs(calls[-1]["originalReturned"], True)
                    else:
                        observations = PROBE.observe_providers(fixture, book, SimpleNamespace(run_owned=run), deadline,
                                                               Path("/private/test"), calls, tools, progress)
                        self.assertEqual(len(dispatched), 4)
                        self.assertEqual(progress, {"stage": "observations-post", "role": None, "sourceSlot": None})
                        self.assertEqual([x["role"] for x in calls], list(PROBE.ROLES))
                        self.assertTrue(all(x["originalReturned"] for x in calls))
                        self.assertEqual(dispatched[0][0], ["/usr/bin/xcrun", "--find", "dyld_info"])
                        for (argv, _), path in zip(dispatched[1:], PROBE.PROVIDERS):
                            self.assertEqual(argv, [str(selected), *PROBE.OPTIONS, path])
                        self.assertEqual(observations[0]["state"], {"observed": "observed", "missing-first": "not-observed",
                                                                   "unparsed-first": "unresolved"}[mode])
                        self.assertEqual([x["state"] for x in observations[1:]], ["observed", "observed"])
                        self.assertEqual(calls[0]["stdoutSha256"], hashlib.sha256((str(selected) + "\n").encode()).hexdigest())
                        self.assertNotIn("DEVELOPER_DIR", dispatched[0][1]["environ"])

        publication_root = Path("/private/test/report")
        identities = {p: (1, n, stat.S_IFDIR | 0o700, 501, 0)
                      for n, p in enumerate((publication_root, *publication_root.parents), 1)}
        publications = []

        class Publisher:
            def __init__(self):
                self.directories = {}
                self.events = []
                self.closed = True
                publications.append(self)

            def directory(self, path):
                self.events.append("directory")
                self.directories = {p: {"identity": value} for p, value in identities.items()}

            def publish(self, path, body):
                self.events.append("publish")
                self.body = body
                self.assertion = (path == publication_root / "result.json" and type(body) is bytes)

            def finish(self):
                self.events.append("finish")
                return self.closed

        fixture.Originals = Publisher
        record = {"diagnosticCompleted": True, "questionsSettled": True, "source": "a" * 40,
                  "originalCalls": [{"originalReturned": True}]}
        clock = SimpleNamespace(CLOCK_MONOTONIC=1, clock_gettime_ns=lambda which: 1)
        fake_os, state = memory_os(MemoryBook())
        with mock.patch.object(PROBE, "time", clock), mock.patch.object(PROBE, "os", fake_os):
            for field in ("source_post_known", "source_closed", "bootstrap_closed"):
                arguments = dict(source_post_known=True, source_closed=True, bootstrap_closed=True)
                arguments[field] = False
                with self.assertRaisesRegex(RuntimeError, "publication-original-finality"):
                    PROBE.publish_record(fixture, publication_root, identities, dict(record), 120_000_000_000, **arguments)
            self.assertEqual(publications, [])
            with self.assertRaisesRegex(RuntimeError, "publication-original-finality"):
                PROBE.publish_record(fixture, publication_root, identities,
                                     dict(record, originalCalls=[{"originalReturned": False}]), 120_000_000_000,
                                     source_post_known=True, source_closed=True, bootstrap_closed=True)
            self.assertEqual(publications, [])
            passed = PROBE.publish_record(fixture, publication_root, identities, dict(record), 120_000_000_000,
                                          source_post_known=True, source_closed=True, bootstrap_closed=True)
            self.assertIs(passed, True)
            self.assertTrue(publications[-1].assertion)
            self.assertEqual(publications[-1].events, ["directory", "publish", "finish", "finish"])
            self.assertEqual(len(state.writes), 1)
            self.assertEqual(json.loads(publications[-1].body)["sourceAndInputClosesKnown"], True)
            self.assertIs(PROBE.publish_record(fixture, publication_root, identities, dict(record, questionsSettled=False),
                                              120_000_000_000, source_post_known=True, source_closed=True, bootstrap_closed=True), False)
            before_writes = len(state.writes)
            def unclosed_publisher():
                value = Publisher()
                value.closed = False
                return value
            fixture.Originals = unclosed_publisher
            with self.assertRaisesRegex(RuntimeError, "publication-close"):
                PROBE.publish_record(fixture, publication_root, identities, dict(record), 120_000_000_000,
                                     source_post_known=True, source_closed=True, bootstrap_closed=True)
            self.assertEqual(len(state.writes), before_writes)
            self.assertEqual(publications[-1].events, ["directory", "publish", "finish", "finish"])
            fixture.Originals = Publisher
            ticks = iter((1, 1, 120_000_000_000))
            clock.clock_gettime_ns = lambda which: next(ticks)
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                PROBE.publish_record(fixture, publication_root, identities, dict(record), 120_000_000_000,
                                     source_post_known=True, source_closed=True, bootstrap_closed=True)
            self.assertEqual(len(state.writes), before_writes + 1)  # Printed bytes remain provisional on late return.
            clock.clock_gettime_ns = lambda which: 1
            fixture.Originals = lambda: SimpleNamespace(directories={}, directory=lambda path: None, finish=lambda: True)
            with self.assertRaisesRegex(RuntimeError, "publication-original-directories"):
                PROBE.publish_record(fixture, publication_root, identities, dict(record), 120_000_000_000,
                                     source_post_known=True, source_closed=True, bootstrap_closed=True)

        # Refusal DATA is independent of result publication and never serializes
        # arbitrary error text, paths, captures, objects or untyped flags.
        stderr = []
        def stderr_write(fd, body):
            self.assertEqual(fd, 2)
            self.assertIs(type(body), bytes)
            stderr.append(body)
            return len(body)
        diagnostic_os = SimpleNamespace(write=stderr_write)
        flags = dict(record_prepared=False, source_post_known=False, source_closed=False,
                     bootstrap_closed=False, post_failed=True, close_failed=True)
        fixed = {"stage": "selected-tool-admission", "role": PROBE.ROLES[0], "sourceSlot": None}
        originals = [{"role": role, "originalReturned": index == 0,
                      "dispatched": index > 0, "contained": None, "cleanupComplete": False}
                     for index, role in enumerate(PROBE.ROLES)]
        secret = "NEVER-PRINT-secret/path/raw-output/exception"
        with mock.patch.object(PROBE, "os", diagnostic_os):
            for reason in PROBE.DIAGNOSTIC_REASONS:
                PROBE.emit_refusal(RuntimeError(reason), "fixed-observations", fixed, originals, {"xcrun": {}}, **flags)
                value = json.loads(stderr[-1])
                self.assertEqual(value["reason"], reason)
                self.assertEqual(value["stage"], "selected-tool-admission")
                self.assertIs(value["postFailureSeen"], True)
                self.assertIs(value["closeFailureSeen"], True)
                self.assertIs(value["resolverAdmitted"], True)
                self.assertIs(value["selectedToolAdmitted"], False)
                self.assertEqual([row["returned"] for row in value["originalCalls"]], [True, False, False, False])
            for error in (RuntimeError(secret), RuntimeError("source-pin", secret),
                          ValueError({secret: secret}), OSError(PROBE.errno.EACCES, secret, secret), None):
                PROBE.emit_refusal(error, secret, {"stage": secret, "role": secret, "sourceSlot": True},
                                   [{"role": PROBE.ROLES[0], "originalReturned": 1, "dispatched": secret}], {}, **flags)
                value = json.loads(stderr[-1])
                self.assertEqual(value["reason"], "unclassified")
                self.assertEqual(value["phase"], "unknown")
                self.assertEqual(value["stage"], "unknown")
                self.assertIsNone(value["role"])
                self.assertIsNone(value["sourceSlot"])
                self.assertFalse(any(row["returned"] for row in value["originalCalls"]))
                self.assertTrue(all(row["dispatched"] is None for row in value["originalCalls"]))
                if isinstance(error, OSError):
                    self.assertEqual(value["errnoName"], "EACCES")
            for source_slot in (-1, 0, len(PROBE.SOURCE_PINS) + 1, len(PROBE.SOURCE_PINS) + 2, secret):
                PROBE.emit_refusal(RuntimeError("source-pin"), "source-admission",
                                   dict(fixed, sourceSlot=source_slot), [], {}, **flags)
                value = json.loads(stderr[-1])
                self.assertEqual(value["sourceSlot"], source_slot if type(source_slot) is int
                                 and 0 <= source_slot < len(PROBE.SOURCE_PINS) + 2 else None)
            # Actual main exits before any filesystem or loader call. This is
            # an inert local module binding, not a patch to shared sys/os/time.
            fake_sys = SimpleNamespace(version_info=(0, 0, 0))
            clock = SimpleNamespace(CLOCK_MONOTONIC=1, clock_gettime_ns=lambda which: 0)
            before = len(stderr)
            with mock.patch.object(PROBE, "sys", fake_sys), mock.patch.object(PROBE, "time", clock):
                self.assertEqual(PROBE.main(), 1)
            self.assertEqual(len(stderr), before + 1)
            value = json.loads(stderr[-1])
            self.assertEqual((value["phase"], value["stage"], value["reason"]),
                             ("host-admission", "host-admission", "python-route"))
            self.assertFalse(any(row["attempted"] for row in value["originalCalls"]))
            self.assertTrue(all(value[name] is False for name in
                                ("recordPrepared", "sourcePostKnown", "sourceClosesKnown", "bootstrapCloseKnown")))
        for body in stderr:
            self.assertLessEqual(len(body), PROBE.DIAGNOSTIC_LIMIT)
            self.assertEqual(body.count(b"\n"), 1)
            self.assertNotIn(secret.encode(), body)
            value = json.loads(body)
            self.assertIs(value["diagnosticOnly"], True)
            self.assertIs(value["completeEvidence"], False)
            self.assertIs(value["supplierAuthority"], False)
            self.assertEqual(len(value["originalCalls"]), 4)
        # A partial/failed stderr write is not retried and cannot raise a raw
        # diagnostic error or turn the original refusal into success.
        write_calls = []
        def failed_write(fd, body):
            write_calls.append((fd, len(body)))
            raise OSError(secret)
        with mock.patch.object(PROBE, "os", SimpleNamespace(write=failed_write)):
            self.assertIsNone(PROBE.emit_refusal(RuntimeError("python-route"), "host-admission",
                                                fixed, [], {}, **flags))
        self.assertEqual(len(write_calls), 1)

    def test_tiny_intel_workflow_binds_exact_source_without_build_or_authority(self):
        helper = (ROOT / "desktop/tools/macos_intel_os_providers.py").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/desktop-macos-intel-os-providers.yml").read_text(encoding="utf-8")
        tree = ast.parse(helper)
        functions = {node.name: ast.get_source_segment(helper, node) for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertEqual(len(PROBE.SOURCE_PINS), 11)
        self.assertEqual(sum(row[0] for row in PROBE.SOURCE_PINS.values()), 1057880)
        self.assertEqual(PROBE.ROLES, ("resolve-dyld-info", "provider-javavm", "provider-libgcc", "provider-ncurses"))
        self.assertEqual(PROBE.REF, "refs/heads/verify/desktop-macos-intel-os-providers")
        self.assertEqual(PROBE.OPTIONS, ("-arch", "x86_64", "-arch", "x86_64h", "-platform", "-uuid", "-linked_dylibs", "-rpaths"))
        self.assertEqual(PROBE.CAPTURE_LIMIT, 65536)
        self.assertEqual(PROBE.RECORD_LIMIT, 524288)
        self.assertEqual(PROBE.DIAGNOSTIC_LIMIT, 1536)
        self.assertEqual(functions["main"].count("emit_refusal("), 2)
        self.assertIn("failure_phase, failure_progress = phase, dict(progress)", functions["main"])
        self.assertEqual(functions["main"].count("if failure is None:"), 3)
        self.assertIn("failure if failure is not None else error", functions["main"])
        self.assertNotIn("str(error)", functions["emit_refusal"])
        self.assertNotIn("repr(error)", functions["emit_refusal"])
        self.assertIn("os.write(2, body)", functions["emit_refusal"])
        self.assertIn("len(body) <= DIAGNOSTIC_LIMIT", functions["emit_refusal"])
        self.assertIn('deadline = started + 120 * 1_000_000_000', functions["main"])
        self.assertLess(functions["main"].index('source_closed = book.finish()'), functions["main"].index('passed = publish_record('))
        self.assertIn('head == (commit + "\\n").encode("ascii")', functions["main"])
        self.assertIn('"RUNNER_ARCH": "X64"', functions["main"])
        self.assertIn('os.uname().machine == "x86_64"', functions["main"])
        self.assertIn('qualification.load_owner(CHECKOUT)', functions["main"])
        self.assertIn('source_post_known is True and source_closed is True and bootstrap_closed is True', functions["publish_record"])
        self.assertIn('parent["identity"][3] == 0', functions["root_ancestors"])
        self.assertIn('output_limit=CAPTURE_LIMIT', functions["observe_providers"])
        self.assertNotIn('DEVELOPER_DIR', functions["observe_providers"])
        self.assertNotIn('TOOLCHAINS', functions["observe_providers"])
        for key in ('vendorPayloadExecuted', 'requestedProviderDlopen', 'runtimeQualified', 'supplierAuthority', 'privateScratchRetired'):
            self.assertIn('"' + key + '": False', functions["main"])
        self.assertIn('"publicationProvisionalUntilOriginalCallerZero": True', functions["main"])
        self.assertEqual(workflow.count('runs-on:'), 1)
        self.assertIn('runs-on: macos-26-intel\n', workflow)
        self.assertIn('timeout-minutes: 5\n', workflow)
        self.assertIn('timeout-minutes: 3\n', workflow)
        self.assertIn('branches: [verify/desktop-macos-intel-os-providers]', workflow)
        self.assertIn("github.event_name == 'push'", workflow)
        self.assertIn("github.ref == 'refs/heads/verify/desktop-macos-intel-os-providers'", workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('ref: ${{ github.sha }}', workflow)
        for action in ('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                       'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97',
                       'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'):
            self.assertEqual(workflow.count(action), 1)
        self.assertIn('"$MRK_PYTHON" -I -S -B -u', workflow)
        self.assertIn('exec /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin', workflow)
        self.assertIn('ulimit -n 512 || exit 1', workflow)
        self.assertIn('ulimit -c 0 || exit 1', workflow)
        self.assertIn('/report/result.json', workflow)
        for forbidden in ('secrets.', 'environment:', 'DEVELOPER_DIR=', 'SDKROOT=', 'TOOLCHAINS=',
                          'cargo ', 'npm ', 'java ', 'sudo ', 'codesign ', 'dyld_info -all',
                          'workflow_dispatch:', 'ubuntu-', 'runs-on: macos-26\n'):
            self.assertNotIn(forbidden, workflow)
        direct_process_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                                and isinstance(node.func, ast.Attribute) and node.func.attr in ('Popen', 'run', 'system')]
        self.assertEqual(direct_process_calls, [])


if __name__ == "__main__":
    unittest.main()
