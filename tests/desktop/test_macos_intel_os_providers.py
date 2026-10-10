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


def memory_os(book):
    state = SimpleNamespace(writes=[])

    def write(fd, body):
        assert fd in (1, 2) and type(body) is bytes
        state.writes.append(body)
        return len(body)

    return SimpleNamespace(path=os.path, write=write), state


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
        # Exact public Apple metadata from run37592121242/1, source4d0f566.
        # Golden DATA replays do not claim dlopen, supplier authority or a passed native run.
        captured = (
            ('/System/Library/Frameworks/JavaVM.framework/Versions/A/JavaVM', b'/System/Library/Frameworks/JavaVM.framework/Versions/A/JavaVM [x86_64]:\n    -platform:\n        platform     minOS      sdk\n           macOS     26.6      26.6   \n    -uuid:\n        8E63DFCA-94E5-3274-A174-4AFAAA25B923\n    -linked_dylibs:\n        attributes     load path\n                       /System/Library/Frameworks/Foundation.framework/Versions/C/Foundation\n                       /usr/lib/libobjc.A.dylib\n                       /usr/lib/libSystem.B.dylib\n                       /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation\n    -rpaths:\n', '7e39464fd3ac6c45d3230cef0b04a4e9278691b295437d8c2bb69f5173a99300', 'macOS', '8E63DFCA-94E5-3274-A174-4AFAAA25B923', 4),
            ('/usr/lib/libgcc_s.1.dylib', b'/usr/lib/libgcc_s.1.dylib [x86_64]:\n    -platform:\n        platform     minOS      sdk\n zippered(macOS/Catalyst)     26.6      26.6   \n    -uuid:\n        D56A3632-DC79-3455-B0E2-9196AAF2A974\n    -linked_dylibs:\n        attributes     load path\n        re-export      /usr/lib/system/libcache.dylib\n        re-export      /usr/lib/system/libcommonCrypto.dylib\n        re-export      /usr/lib/system/libcompiler_rt.dylib\n        re-export      /usr/lib/system/libcopyfile.dylib\n        re-export      /usr/lib/system/libcorecrypto.dylib\n        re-export      /usr/lib/system/libdispatch.dylib\n        re-export      /usr/lib/system/libdyld.dylib\n        re-export      /usr/lib/system/libkeymgr.dylib\n        re-export      /usr/lib/system/libmacho.dylib\n        re-export      /usr/lib/system/libquarantine.dylib\n        re-export      /usr/lib/system/libremovefile.dylib\n        re-export      /usr/lib/system/libsystem_asl.dylib\n        re-export      /usr/lib/system/libsystem_blocks.dylib\n        re-export      /usr/lib/system/libsystem_c.dylib\n        re-export      /usr/lib/system/libsystem_collections.dylib\n        re-export      /usr/lib/system/libsystem_configuration.dylib\n        re-export      /usr/lib/system/libsystem_containermanager.dylib\n        re-export      /usr/lib/system/libsystem_coreservices.dylib\n        re-export      /usr/lib/system/libsystem_darwin.dylib\n        re-export      /usr/lib/system/libsystem_darwindirectory.dylib\n        re-export      /usr/lib/system/libsystem_dnssd.dylib\n        re-export      /usr/lib/system/libsystem_eligibility.dylib\n        re-export      /usr/lib/system/libsystem_featureflags.dylib\n        re-export      /usr/lib/system/libsystem_info.dylib\n        re-export      /usr/lib/system/libsystem_m.dylib\n        re-export      /usr/lib/system/libsystem_malloc.dylib\n        re-export      /usr/lib/system/libsystem_networkextension.dylib\n        re-export      /usr/lib/system/libsystem_notify.dylib\n        re-export      /usr/lib/system/libsystem_sandbox.dylib\n        re-export      /usr/lib/system/libsystem_sanitizers.dylib\n        re-export      /usr/lib/system/libsystem_secinit.dylib\n        re-export      /usr/lib/system/libsystem_kernel.dylib\n        re-export      /usr/lib/system/libsystem_platform.dylib\n        re-export      /usr/lib/system/libsystem_pthread.dylib\n        re-export      /usr/lib/system/libsystem_symptoms.dylib\n        re-export      /usr/lib/system/libsystem_trace.dylib\n        re-export      /usr/lib/system/libsystem_trial.dylib\n        re-export      /usr/lib/system/libunwind.dylib\n        re-export      /usr/lib/system/libxpc.dylib\n    -rpaths:\n', 'a2f174ae4525da440eb7bd2ba86d144ec4bf24e8bfa9281f4814727e6fc06ac4', 'zippered(macOS/Catalyst)', 'D56A3632-DC79-3455-B0E2-9196AAF2A974', 39),
            ('/usr/lib/libncurses.5.4.dylib', b'/usr/lib/libncurses.5.4.dylib [x86_64]:\n    -platform:\n        platform     minOS      sdk\n zippered(macOS/Catalyst)     26.6      26.6   \n    -uuid:\n        C777C16F-8119-3E1C-B313-D75BF1047B94\n    -linked_dylibs:\n        attributes     load path\n                       /usr/lib/libSystem.B.dylib\n    -rpaths:\n', '6863147dd970c5b5ece3d2d62b6ce705b16e3d6db16134e53f77834665b085fc', 'zippered(macOS/Catalyst)', 'C777C16F-8119-3E1C-B313-D75BF1047B94', 1),
        )
        for path, body, digest, platform, uuid, loads in captured:
            with self.subTest(captured=path):
                self.assertEqual(hashlib.sha256(body).hexdigest(), digest)
                image = PROBE.observation(path, 0, body, b"")["images"][0]
                self.assertEqual(image["architecture"], "x86_64")
                self.assertEqual(image["platform"], platform)
                self.assertEqual((image["minimumOS"], image["sdk"]), ("26.6", "26.6"))
                self.assertEqual(image["uuid"], uuid)
                self.assertEqual(len(image["loads"]), loads)
                self.assertEqual(image["rpaths"], [])
                if platform != "macOS":
                    for bad in (b"macCatalyst", b"iOS", b"zippered(Catalyst/macOS)",
                                b"zippered(macOS/iOS)", b"zippered(macOS/Catalyst)extra"):
                        with self.subTest(platform=bad), self.assertRaises(RuntimeError):
                            PROBE.observation(path, 0, body.replace(platform.encode(), bad), b"")
                    for bad in (body[:-1], body + body, body.replace(b"[x86_64]", b"[arm64]"),
                                body.replace(b"     26.6", b"    26.6", 1),
                                body.replace(b"26.6", b"26.x", 1)):
                        with self.subTest(malformed=True), self.assertRaises(RuntimeError):
                            PROBE.observation(path, 0, bad, b"")
        selected = b"/Library/Developer/CommandLineTools/usr/bin/dyld_info\n"
        self.assertEqual(PROBE.selected_tool_path(selected), PROBE.SELECTED_TOOL)
        self.assertEqual(PROBE.DEVELOPER_DIR, Path("/Library/Developer/CommandLineTools"))
        old_suffix = "Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_info"
        invalid = (selected[:-1], selected + b"\n", selected.replace(b"CommandLineTools", b"CommandLineTools-beta"),
                   selected.replace(b"/usr/", b"/../usr/"), selected.replace(b"/Library/", b"/tmp/"),
                   selected.replace(b"/bin/", b"//bin/"), b"/usr/bin/dyld_info\n", b"dyld_info\n", b"x" * 513)
        invalid += tuple((name + "/" + old_suffix + "\n").encode() for name in
                         ("/Applications/Xcode.app", "/Applications/Xcode_26.6.app", "/Applications/Xcode_26.6_beta.app",
                          "/tmp/Xcode_26.6.app", "../Xcode_26.6.app", "Xcode.app", "Xcode_26.6.app/.."))
        for value in invalid:
            with self.subTest(selected=value), self.assertRaises(RuntimeError):
                PROBE.selected_tool_path(value)

    def test_four_originals_selected_tool_post_and_finality_share_one_endpoint(self):
        selected = PROBE.SELECTED_TOOL
        book = MemoryBook()
        tool = PROBE.selected_tool(book, selected)
        self.assertEqual(tool["path"], selected)
        self.assertIsNone(tool["alias"])
        PROBE.tool_post(book, tool)
        evidence = PROBE.tool_evidence(tool)
        self.assertEqual(evidence["originalIdentity"], tool["entry"]["identity"])
        self.assertEqual(evidence["selectedPath"], str(selected))
        self.assertIsNone(evidence["oneHopAlias"])
        self.assertTrue(all(row["directoryIdentity"][3] == 0 for row in evidence["ancestors"]))
        tool["alias"] = {"name": "not-an-admissible-alias"}
        with self.assertRaisesRegex(RuntimeError, "selected-tool-admission"):
            PROBE.tool_post(book, tool)
        tool["alias"] = None
        book.files[selected] = b"changed original tool"
        with self.assertRaisesRegex(RuntimeError, "system-tool-post"):
            PROBE.tool_post(book, tool)
        self.assertTrue(book.finish())
        for path in PROBE.DIRECTORY_PATHS:
            for mode in ("wrong-owner", "group-write", "other-write", "not-directory"):
                with self.subTest(ancestor=path, mode=mode):
                    book = MemoryBook()
                    ancestor = book.directory(path)
                    facts = list(ancestor["identity"])
                    if mode == "wrong-owner":
                        facts[3] = 501
                    elif mode == "not-directory":
                        facts[2] = stat.S_IFLNK | 0o755
                    else:
                        facts[2] |= 0o020 if mode == "group-write" else 0o002
                    ancestor["identity"] = tuple(facts)
                    with self.assertRaisesRegex(RuntimeError, "system-tool-root-ancestor"):
                        PROBE.system_tool(book, selected)
                    self.assertTrue(book.finish())
        book = MemoryBook()
        alias_error = OSError(PROBE.errno.ELOOP, "inert no-follow rejection")
        with mock.patch.object(book, "file", side_effect=alias_error), self.assertRaises(OSError) as refusal:
            PROBE.selected_tool(book, selected)
        self.assertIs(refusal.exception, alias_error)
        self.assertTrue(book.finish())

        # The real admission failure is never converted into tool authority by
        # a later metadata sample, including a safe-looking after-refusal mode.
        class DirectoryRefused(ValueError):
            pass

        fixture = SimpleNamespace(context_timeout=context_timeout, completed=completed, canonical=canonical,
                                  Refused=DirectoryRefused)
        deadline = 120_000_000_000
        # An absent, linked or unsafe developer directory cannot trigger even
        # the resolver, and never authorizes an installation or a fallback.
        for rejected in (Path("/Library"), PROBE.DEVELOPER_DIR):
            for mode in ("absent", "alias", "wrong-owner", "group-write", "other-write", "not-directory"):
                with self.subTest(developer=rejected, mode=mode):
                    book, calls, tools, dispatched = MemoryBook(), [], {}, []
                    original_directory = book.directory
                    progress = {"stage": "host-admission", "role": None, "sourceSlot": None}
                    clock = SimpleNamespace(CLOCK_MONOTONIC=1, clock_gettime_ns=lambda which: 1)

                    def refused_developer(path):
                        path = Path(path)
                        if path == rejected and mode in ("absent", "alias"):
                            raise OSError(PROBE.errno.ENOENT if mode == "absent" else PROBE.errno.ELOOP, "inert CLT refusal")
                        entry = original_directory(path)
                        if path == rejected:
                            facts = list(entry["identity"])
                            if mode == "wrong-owner":
                                facts[3] = 501
                            elif mode == "not-directory":
                                facts[2] = stat.S_IFREG | 0o755
                            else:
                                facts[2] |= 0o020 if mode == "group-write" else 0o002
                            entry["identity"] = tuple(facts)
                        return entry

                    def forbidden_dispatch(argv, **kwargs):
                        dispatched.append(argv)
                        self.fail("resolver dispatched after rejected fixed CLT root")

                    with mock.patch.object(book, "directory", side_effect=refused_developer), \
                            mock.patch.object(PROBE, "time", clock):
                        with self.assertRaises((OSError, RuntimeError)):
                            PROBE.observe_providers(fixture, book, SimpleNamespace(run_owned=forbidden_dispatch), deadline,
                                                    Path("/private/test"), calls, tools, progress)
                    self.assertEqual(dispatched, [])
                    self.assertEqual(calls, [])
                    self.assertEqual(set(tools), {"xcrun"})
                    self.assertEqual(progress["stage"], "resolver-admission")
                    self.assertTrue(book.finish())

        for mode in ("group-write", "wrong-owner", "safe-after", "changed-named", "changed-fd",
                     "missing-parent", "closed", "expired", "observation-error", "no-new-entry", "foreign-path"):
            with self.subTest(directory_refusal=mode):
                book, calls, tools, dispatched = MemoryBook(), [], {}, []
                clock = SimpleNamespace(CLOCK_MONOTONIC=1, now=0)
                clock.clock_gettime_ns = lambda which: clock.now
                progress = {"stage": "host-admission", "role": None, "sourceSlot": None}
                primary = DirectoryRefused("directory-owner-mode")
                state = SimpleNamespace(entry=None, parent=None, samples=[], info=None)
                original_directory = book.directory

                def rejected_directory(path):
                    if Path(path) != PROBE.SELECTED_TOOL.parent:
                        return original_directory(path)
                    if mode == "no-new-entry":
                        raise primary
                    parent = original_directory(PROBE.SELECTED_TOOL.parent.parent)
                    state.parent = parent
                    state.entry = {"fd": 900, "path": PROBE.SELECTED_TOOL.parent, "kind": "directory",
                                   "identity": None, "closed": False}
                    book.entries.append(state.entry)
                    permissions = 0o755 if mode in ("wrong-owner", "safe-after") else 0o775
                    state.info = SimpleNamespace(st_dev=1, st_ino=900, st_mode=stat.S_IFDIR | permissions,
                                                 st_uid=502 if mode == "wrong-owner" else 0, st_gid=0,
                                                 st_nlink=2, st_size=64, st_mtime_ns=8, st_ctime_ns=8)
                    if mode == "missing-parent":
                        del book.directories[PROBE.SELECTED_TOOL.parent.parent]
                    elif mode == "closed":
                        state.entry.update(fd=None, closed=True)
                    elif mode == "expired":
                        clock.now = deadline
                    elif mode == "foreign-path":
                        state.entry["path"] = Path("/private/NEVER-PRINT-directory")
                    raise primary

                def sampled(fd):
                    self.assertEqual(fd, 900)
                    state.samples.append("fstat")
                    if mode == "observation-error":
                        raise OSError("NEVER-PRINT-fstat-error")
                    if mode == "changed-fd" and state.samples.count("fstat") == 2:
                        return SimpleNamespace(**dict(vars(state.info), st_ctime_ns=9))
                    return state.info

                def named_directory(name, *, dir_fd, follow_symlinks):
                    self.assertEqual((name, dir_fd, follow_symlinks),
                                     ("bin", state.parent["fd"], False))
                    state.samples.append("named")
                    return (SimpleNamespace(**dict(vars(state.info), st_ino=901))
                            if mode == "changed-named" else state.info)

                fake_os = SimpleNamespace(path=os.path, fstat=sampled, stat=named_directory, getuid=lambda: 501)

                def resolver(argv, **kwargs):
                    self.assertEqual(argv, ["/usr/bin/xcrun", "--find", "dyld_info"])
                    self.assertEqual(kwargs["output_limit"], 65536)
                    self.assertLessEqual(kwargs["timeout"], 30)
                    dispatched.append(list(argv))
                    return subprocess.CompletedProcess(argv, 0, (str(selected) + "\n").encode("ascii"), b"")

                with mock.patch.object(book, "directory", side_effect=rejected_directory), \
                        mock.patch.object(PROBE, "os", fake_os), mock.patch.object(PROBE, "time", clock):
                    with self.assertRaises(DirectoryRefused) as refusal:
                        PROBE.observe_providers(fixture, book, SimpleNamespace(run_owned=resolver), deadline,
                                                Path("/private/test"), calls, tools, progress)
                self.assertIs(refusal.exception, primary)
                self.assertEqual(len(dispatched), 1)
                self.assertEqual([row["role"] for row in calls], [PROBE.ROLES[0]])
                self.assertIs(calls[0]["originalReturned"], True)
                self.assertEqual(set(tools), {"xcrun"})
                self.assertEqual((progress["stage"], progress["role"]), ("selected-tool-admission", PROBE.ROLES[0]))
                data = progress["directoryAfterRefusal"]
                if mode in ("group-write", "wrong-owner", "safe-after"):
                    self.assertEqual(data, {"when": "after-refusal", "ancestorSlot": "bin", "sameOriginal": True,
                                           "permissionBits": stat.S_IMODE(state.info.st_mode), "isDirectory": True,
                                           "ownerIsRoot": mode != "wrong-owner", "ownerIsCurrent": False,
                                           "groupWritable": mode == "group-write", "otherWritable": False})
                    self.assertEqual(state.samples, ["fstat", "named", "fstat"])
                else:
                    self.assertIsNone(data)
                if mode in ("missing-parent", "closed", "expired", "no-new-entry", "foreign-path"):
                    self.assertEqual(state.samples, [])
                if state.entry is not None:
                    self.assertIsNone(state.entry["identity"])
                    self.assertNotIn("parent", state.entry)
                self.assertTrue(book.finish())
                self.assertTrue(all(entry["fd"] is None and entry["closed"] for entry in book.entries))

        # Only the fixed ancestor slots are observable; no rejected path is
        # serialized or reopened, and the original dictionary stays unbound.
        directory_paths = PROBE.DIRECTORY_PATHS
        self.assertEqual(len(directory_paths), len(PROBE.DIRECTORY_SLOTS))
        for slot, path in zip(PROBE.DIRECTORY_SLOTS, directory_paths):
            book = MemoryBook()
            parent = book.directory(path.parent)
            mark = len(book.entries)
            entry = {"fd": 900, "path": path, "kind": "directory", "identity": None, "closed": False}
            book.entries.append(entry)
            info = SimpleNamespace(st_dev=1, st_ino=900, st_mode=stat.S_IFDIR | 0o777, st_uid=501, st_gid=0,
                                   st_nlink=2, st_size=64, st_mtime_ns=8, st_ctime_ns=8)
            def same_named(name, *, dir_fd, follow_symlinks):
                self.assertEqual((name, dir_fd, follow_symlinks), (path.name, parent["fd"], False))
                return info
            def same_fd(fd):
                self.assertEqual(fd, 900)
                return info
            clock = SimpleNamespace(CLOCK_MONOTONIC=1, clock_gettime_ns=lambda which: 1)
            fake_os = SimpleNamespace(path=os.path, stat=same_named, fstat=same_fd, getuid=lambda: 501)
            with mock.patch.object(PROBE, "os", fake_os), mock.patch.object(PROBE, "time", clock):
                value = PROBE.directory_refusal_data(fixture, book, deadline, mark, DirectoryRefused("directory-owner-mode"))
                self.assertEqual(value["ancestorSlot"], slot)
                self.assertIs(value["ownerIsCurrent"], True)
                self.assertIs(value["ownerIsRoot"], False)
                self.assertIs(value["groupWritable"], True)
                self.assertIs(value["otherWritable"], True)
                for bad_mark in (-1, True, len(book.entries), len(book.entries) + 1):
                    self.assertIsNone(PROBE.directory_refusal_data(fixture, book, deadline, bad_mark,
                                                                   DirectoryRefused("directory-owner-mode")))
                self.assertIsNone(PROBE.directory_refusal_data(fixture, book, deadline, mark,
                                                               DirectoryRefused("directory-owner-mode", "NEVER-PRINT")))
                self.assertIsNone(PROBE.directory_refusal_data(fixture, book, deadline, mark, RuntimeError("other")))
                for wrong_type in (RuntimeError, ValueError):
                    self.assertIsNone(PROBE.directory_refusal_data(fixture, book, deadline, mark,
                                                                   wrong_type("directory-owner-mode")))
                del entry["identity"]
                self.assertIsNone(PROBE.directory_refusal_data(fixture, book, deadline, mark,
                                                               DirectoryRefused("directory-owner-mode")))
                entry["identity"] = None
                entry["parent"] = parent
                self.assertIsNone(PROBE.directory_refusal_data(fixture, book, deadline, mark,
                                                               DirectoryRefused("directory-owner-mode")))
                del entry["parent"]
            self.assertIsNone(entry["identity"])
            self.assertNotIn("parent", entry)
            self.assertTrue(book.finish())

        fixture = SimpleNamespace(context_timeout=context_timeout, completed=completed, canonical=canonical)
        class OutcomeUnknown(RuntimeError):
            dispatched, contained, cleanup_complete = True, True, False

        class Interrupted(RuntimeError):
            dispatched, contained, cleanup_complete = True, True, True

        for mode in ("observed", "missing-first", "unparsed-first", "resolver-foreign", "resolver-xcode",
                     "resolver-nonzero", "resolver-stderr", "wrong-original", "unknown", "outcome-unknown", "interrupted",
                     "tool-changed", "ancestor-changed", "late"):
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
                    self.assertEqual(set(kwargs["environ"]), {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "DEVELOPER_DIR"})
                    self.assertEqual(kwargs["environ"]["DEVELOPER_DIR"], "/Library/Developer/CommandLineTools")
                    self.assertIn(PROBE.DEVELOPER_DIR, book.directories)
                    self.assertLessEqual(kwargs["timeout"], 30)
                    self.assertGreaterEqual(kwargs["timeout"], 1)
                    self.assertTrue(book.events and tools)
                    clock.now += 3_000_000_000
                    if len(dispatched) == 1:
                        output = (str(selected) + "\n").encode()
                        if mode == "resolver-foreign":
                            output = b"/tmp/dyld_info\n"
                        elif mode == "resolver-xcode":
                            output = b"/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/dyld_info\n"
                        return subprocess.CompletedProcess(argv, 1 if mode == "resolver-nonzero" else 0, output,
                                                           b"inert resolver stderr" if mode == "resolver-stderr" else b"")
                    if mode == "unknown":
                        raise RuntimeError("inert original outcome unknown")
                    if mode == "outcome-unknown":
                        raise OutcomeUnknown("inert unknown original lifetime")
                    if mode == "interrupted":
                        raise Interrupted("inert original cancellation")
                    if mode == "tool-changed":
                        book.files[selected] = b"changed tool original during query"
                    if mode == "ancestor-changed":
                        entry = book.directories[PROBE.DEVELOPER_DIR]
                        facts = list(entry["identity"]); facts[2] |= 0o020
                        entry["identity"] = tuple(facts)
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

                owner = SimpleNamespace(run_owned=run, ProcessOutcomeUnknown=OutcomeUnknown, ProcessInterrupted=Interrupted)
                with mock.patch.object(PROBE, "os", fake_os), mock.patch.object(PROBE, "time", clock):
                    if mode not in ("observed", "missing-first", "unparsed-first"):
                        with self.assertRaises(RuntimeError):
                            PROBE.observe_providers(fixture, book, owner, deadline,
                                                    Path("/private/test"), calls, tools, progress)
                        self.assertEqual(len(dispatched), 1 if mode.startswith("resolver-") else 2)
                        self.assertEqual(progress["stage"], {"resolver-foreign": "selected-tool-path", "resolver-xcode": "selected-tool-path",
                                                           "resolver-nonzero": "resolver-return", "resolver-stderr": "resolver-return",
                                                           "wrong-original": "call-return", "unknown": "call",
                                                           "outcome-unknown": "call", "interrupted": "call",
                                                           "tool-changed": "call-post", "ancestor-changed": "call-post", "late": "call-post"}[mode])
                        self.assertEqual(progress["role"], PROBE.ROLES[len(dispatched) - 1])
                        if mode in ("wrong-original", "unknown", "outcome-unknown", "interrupted"):
                            self.assertIs(calls[-1]["originalReturned"], False)
                        if mode in ("tool-changed", "ancestor-changed", "late"):
                            self.assertIs(calls[-1]["originalReturned"], True)
                        if mode in ("outcome-unknown", "interrupted"):
                            self.assertEqual(calls[-1]["errorType"], "ProcessOutcomeUnknown" if mode == "outcome-unknown" else "ProcessInterrupted")
                            self.assertIs(calls[-1]["dispatched"], True)
                            self.assertIs(calls[-1]["contained"], True)
                            self.assertIs(calls[-1]["cleanupComplete"], mode == "interrupted")
                    else:
                        observations = PROBE.observe_providers(fixture, book, owner, deadline,
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
                        self.assertEqual(dispatched[0][1]["environ"]["DEVELOPER_DIR"], str(PROBE.DEVELOPER_DIR))

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
            directory = {"when": "after-refusal", "ancestorSlot": "command-line-tools", "sameOriginal": True,
                         "permissionBits": 0o7777, "isDirectory": True, "ownerIsRoot": False,
                         "ownerIsCurrent": False, "groupWritable": True, "otherWritable": True}
            for slot in PROBE.DIRECTORY_SLOTS:
                row = dict(directory, ancestorSlot=slot)
                PROBE.emit_refusal(RuntimeError("directory-owner-mode"), "fixed-observations",
                                   dict(fixed, directoryAfterRefusal=row), originals, {"xcrun": {}}, **flags)
                self.assertEqual(json.loads(stderr[-1])["directoryAfterRefusal"], row)
            for bad in (dict(directory, when=secret), dict(directory, ancestorSlot=secret),
                        dict(directory, permissionBits=True), dict(directory, permissionBits=-1),
                        dict(directory, permissionBits=0o10000), dict(directory, sameOriginal=1),
                        dict(directory, ownerIsRoot=1), dict(directory, rawPath=secret), secret, None):
                PROBE.emit_refusal(RuntimeError("directory-owner-mode"), "fixed-observations",
                                   dict(fixed, directoryAfterRefusal=bad), originals, {"xcrun": {}}, **flags)
                self.assertIsNone(json.loads(stderr[-1])["directoryAfterRefusal"])
            for reason, phase, stage, tools in (("source-pin", "fixed-observations", "selected-tool-admission", {}),
                                               ("directory-owner-mode", "private-work", "selected-tool-admission", {}),
                                               ("directory-owner-mode", "fixed-observations", "source-post", {}),
                                               ("directory-owner-mode", "fixed-observations", "selected-tool-admission", {"dyld_info": {}})):
                PROBE.emit_refusal(RuntimeError(reason), phase,
                                   dict(fixed, stage=stage, directoryAfterRefusal=directory), originals, tools, **flags)
                self.assertIsNone(json.loads(stderr[-1])["directoryAfterRefusal"])
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
        self.assertEqual(sum(row[0] for row in PROBE.SOURCE_PINS.values()), 1168959)
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
        self.assertEqual(PROBE.DIRECTORY_SLOTS, ("library", "developer", "command-line-tools", "usr", "bin"))
        self.assertEqual(PROBE.DIRECTORY_PATHS, (Path("/Library"), Path("/Library/Developer"), PROBE.DEVELOPER_DIR,
                                               PROBE.DEVELOPER_DIR / "usr", PROBE.SELECTED_TOOL.parent))
        refusal = ast.parse(functions["directory_refusal_data"])
        calls = [node for node in ast.walk(refusal) if isinstance(node, ast.Call)]
        self.assertEqual(sum(isinstance(node.func, ast.Attribute) and node.func.attr == "fstat" for node in calls), 2)
        self.assertEqual(sum(isinstance(node.func, ast.Attribute) and node.func.attr == "stat" for node in calls), 1)
        self.assertEqual(functions["directory_refusal_data"].count("fixture.context_timeout(deadline,"), 2)
        self.assertNotIn("book.check()", functions["directory_refusal_data"])
        self.assertNotIn("book.register(", functions["directory_refusal_data"])
        self.assertNotIn("os.open(", functions["directory_refusal_data"])
        self.assertNotIn("os.close(", functions["directory_refusal_data"])
        self.assertIn('"when": "after-refusal"', functions["directory_refusal_data"])
        self.assertIn("type(error) is not fixture.Refused", functions["directory_refusal_data"])
        self.assertIn('entry["identity"] is not None', functions["directory_refusal_data"])
        self.assertIn('progress["directoryAfterRefusal"] = directory_refusal_data(', functions["observe_providers"])
        handlers = [node for node in ast.walk(ast.parse(functions["observe_providers"]))
                    if isinstance(node, ast.ExceptHandler) and any(isinstance(child, ast.Call)
                    and isinstance(child.func, ast.Name) and child.func.id == "directory_refusal_data"
                    for child in ast.walk(node))]
        self.assertEqual(len(handlers), 1)
        self.assertIsInstance(handlers[0].body[-1], ast.Raise)
        self.assertIsNone(handlers[0].body[-1].exc)
        self.assertIn('deadline = started + 120 * 1_000_000_000', functions["main"])
        self.assertLess(functions["main"].index('source_closed = book.finish()'), functions["main"].index('passed = publish_record('))
        self.assertIn('head == (commit + "\\n").encode("ascii")', functions["main"])
        self.assertIn('"RUNNER_ARCH": "X64"', functions["main"])
        self.assertIn('os.uname().machine == "x86_64"', functions["main"])
        self.assertIn('qualification.load_owner(CHECKOUT)', functions["main"])
        self.assertIn('source_post_known is True and source_closed is True and bootstrap_closed is True', functions["publish_record"])
        self.assertIn('parent["identity"][3] == 0', functions["root_ancestors"])
        self.assertIn('output_limit=CAPTURE_LIMIT', functions["observe_providers"])
        self.assertIn('"DEVELOPER_DIR": str(DEVELOPER_DIR)', functions["observe_providers"])
        self.assertLess(functions["observe_providers"].index('developer = book.directory(DEVELOPER_DIR)'),
                        functions["observe_providers"].index('result = command(ROLES[0]'))
        self.assertIn('developer["identity"][3] == 0', functions["observe_providers"])
        self.assertIn('not developer["identity"][2] & 0o022', functions["observe_providers"])
        self.assertIn('root_ancestors(book, developer)', functions["observe_providers"])
        self.assertIn('text[:-1] == str(SELECTED_TOOL)', functions["selected_tool_path"])
        self.assertIn('system_tool(book, selected)', functions["selected_tool"])
        self.assertIn('tool["alias"] is None', functions["tool_post"])
        self.assertNotIn('alias_bundle', functions)
        for forbidden in ('TOOLCHAINS', 'SDKROOT', 'os.environ', 'xcode-select', 'softwareupdate', 'chmod', 'copy', 'retry'):
            self.assertNotIn(forbidden, functions["observe_providers"])
        self.assertIn('uid=0, modes=(0o555, 0o755)', functions["system_tool"])
        self.assertIn('not parent["identity"][2] & 0o022', functions["root_ancestors"])
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
