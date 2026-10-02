"""Pure DATA parser coverage, not macOS/Xcode execution or product evidence."""
import ast
import importlib.util
import json
import pathlib
from pathlib import Path
from contextlib import ExitStack, nullcontext
from types import SimpleNamespace
import textwrap
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / "desktop/tools/macos_xcode_build_facts.py"
SPEC = importlib.util.spec_from_file_location("macos_xcode_build_facts", PATH)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


def fixture(**changes):
    body = {"procName": "XCBBuildService", "procPath": "/Applications/Xcode.app/Contents/SharedFrameworks/XCBBuildService",
            "procLaunch": "2026-10-02 12:00:00.000 +0000", "captureTime": "2026-10-02 12:00:01.000 +0000",
            "exception": {"type": "EXC_CRASH", "signal": "SIGXFSZ"},
            "termination": {"namespace": "SIGNAL", "code": 25},
            "asi": {"private": "PRIVATE-MUST-NOT-LEAVE"}, "usedImages": [{"path": "PRIVATE-MUST-NOT-LEAVE"}]}
    body.update(changes)
    return (json.dumps({"bug_type": "309", "name": "XCBBuildService"}) + "\n" + json.dumps(body)).encode()


def retained_build():
    begin = M.timestamp("2026-10-02T12:00:00Z")
    before = {"schemaVersion": 1, "scope": M.SCOPE, "originalDirectory": "1:2:501",
              "beginEpochSeconds": begin, "productQualified": False, "serviceLimitsObserved": False}
    after = {"schemaVersion": 1, "scope": M.SCOPE, "beginEpochSeconds": begin, "endEpochSeconds": begin + 2,
             "originalBuildExit": 65, "productQualified": False, "serviceLimitsObserved": False,
             "processOwnershipOrFinalityEstablished": False}
    return {"source-commit.txt": b"a" * 40 + b"\n", "source-tree.txt": b"b" * 40 + b"\n",
            "run-attempt.txt": b"31/1\n", "build.status": b"65\n",
            "build-infrastructure-before.json": json.dumps(before).encode(),
            "build-infrastructure-after.json": json.dumps(after).encode()}


class SyntheticDerivedTree:
    """In-memory stat/FD DATA only; never creates files, sparse arenas or FDs."""
    root_fd = 36

    def __init__(self):
        self.nodes, self.fds = {}, {self.root_fd: ""}
        self.opened, self.closed = [], []
        self.named_override, self.held_override = {}, {}
        self.clock, self.late_on_stat = 1, None
        self.add("", directory=True)
        self.add("DerivedData", directory=True)

    def add(self, path, *, directory=False, **changes):
        if "/" in path:
            parent = path.rsplit("/", 1)[0]
            if parent not in self.nodes:
                self.add(parent, directory=True)
        values = dict(st_dev=7, st_ino=len(self.nodes) + 101,
                      st_mode=(M.stat.S_IFDIR | 0o700) if directory else (M.stat.S_IFREG | 0o600),
                      st_uid=501, st_gid=20, st_nlink=1, st_size=0, st_blocks=0,
                      st_mtime_ns=1, st_ctime_ns=1)
        values.update(changes)
        self.nodes[path] = SimpleNamespace(**values)
        return path

    def file(self, relative, **changes):
        return self.add("DerivedData/" + relative, **changes)

    def named(self, name, directory):
        prefix = self.fds[directory]
        return prefix + "/" + name if prefix else name

    def open(self, name, flags, *, dir_fd):
        required = M.os.O_RDONLY | M.os.O_DIRECTORY | M.os.O_NOFOLLOW | M.os.O_CLOEXEC
        if flags != required:
            raise AssertionError("only original no-follow directory opens are allowed")
        path = self.named(name, dir_fd)
        if not M.stat.S_ISDIR(self.nodes[path].st_mode):
            raise NotADirectoryError("synthetic directory shape")
        fd = self.root_fd + 1 + len(self.opened)
        self.fds[fd] = path
        self.opened.append(fd)
        return fd

    def close(self, fd):
        if fd == self.root_fd or fd not in self.opened or fd in self.closed:
            raise AssertionError("only one close of an owned synthetic descriptor")
        self.closed.append(fd)

    def fstat(self, fd):
        path = self.fds[fd]
        return self.held_override.get(path, self.nodes[path])

    def stat(self, name, *, dir_fd, follow_symlinks):
        if follow_symlinks is not False:
            raise AssertionError("named observation must not follow links")
        path = self.named(name, dir_fd)
        if path == self.late_on_stat:
            self.clock = 10
        return self.named_override.get(path, self.nodes[path])

    def scandir(self, fd):
        prefix = self.fds[fd] + "/"
        entries = []
        for path in self.nodes:
            if path.startswith(prefix) and "/" not in path[len(prefix):]:
                def observe(*, follow_symlinks, path=path):
                    if follow_symlinks is not False:
                        raise AssertionError("entry observation must not follow links")
                    return self.nodes[path]
                entries.append(SimpleNamespace(name=path[len(prefix):], stat=observe))
        return nullcontext(entries)

    def run(self):
        with ExitStack() as stack:
            for name in ("open", "close", "fstat", "stat", "scandir"):
                stack.enter_context(patch.object(M.os, name, side_effect=getattr(self, name)))
            stack.enter_context(patch.object(M.time, "monotonic", side_effect=lambda: self.clock))
            result = M.derived_sizes(self.root_fd, 32 * 1024**3, 10)
        if sorted(self.closed) != sorted(self.opened):
            raise AssertionError("every owned synthetic directory must close")
        return result


class XcodeBuildFactsDataTests(unittest.TestCase):
    def parse(self, raw):
        begin = M.timestamp("2026-10-02T12:00:00Z")
        return M.closed_crash_facts(raw, begin, begin + 2, "/Applications/Xcode.app/Contents")

    def test_signal_is_closed_correlation_not_identity_or_cause(self):
        value = self.parse(fixture())
        self.assertEqual(value["signal"], "SIGXFSZ")
        self.assertEqual(value["terminationCode"], 25)
        self.assertTrue(value["captureInBuildInterval"] and value["launchInBuildInterval"] and value["sameToolchainContents"])
        self.assertFalse(value["processOwnershipEstablished"] or value["rawReportRetained"])
        self.assertNotIn("PRIVATE", json.dumps(value))
        self.assertNotIn("procPath", value)
        for signal in ("SIGABRT", "SIGSEGV", "PRIVATE-MUST-NOT-LEAVE", None):
            value = self.parse(fixture(exception={"type": "PRIVATE", "signal": signal}, termination={"namespace": "PRIVATE", "code": True}))
            self.assertEqual(value["signal"], signal if signal in M.SIGNALS else "unavailable-or-other")
            self.assertEqual(value["exception"], "unavailable-or-other")
            self.assertIsNone(value["terminationCode"])
            self.assertNotIn("PRIVATE", json.dumps(value))

    def test_time_or_toolchain_mismatch_is_not_reclassified_as_matching(self):
        value = self.parse(fixture(procLaunch="2026-10-02T11:00:00Z", captureTime="2026-10-02T12:00:05Z"))
        self.assertFalse(value["captureInBuildInterval"] or value["launchInBuildInterval"])
        for path in ("/Applications/Xcode.app/Contents-other/service", "/Applications/Xcode.app/Contents/../service", "PRIVATE", None):
            self.assertFalse(self.parse(fixture(procPath=path))["sameToolchainContents"])

    def test_nonfatal_and_simulated_are_explicit_not_inferred_from_a_signal(self):
        missing = self.parse(fixture())
        self.assertIsNone(missing["isNonFatal"])
        self.assertIsNone(missing["isSimulated"])
        for nonfatal, simulated in ((True, False), (False, True)):
            value = self.parse(fixture(isNonFatal=nonfatal, isSimulated=simulated))
            self.assertEqual((value["isNonFatal"], value["isSimulated"]), (nonfatal, simulated))
            self.assertFalse(value["processOwnershipEstablished"])
        for key in ("isNonFatal", "isSimulated"):
            for value in (1, "PRIVATE-MUST-NOT-LEAVE", None):
                with self.assertRaises(ValueError):
                    self.parse(fixture(**{key: value}))

    def test_late_report_keeps_original_failed_result_and_capture_interval(self):
        original = M.late_build_inputs(retained_build(), "1:2:501", "a" * 40, "b" * 40, "31/1")
        self.assertEqual(original["originalBuildExit"], 65)
        self.assertEqual(original["endEpochSeconds"] - original["beginEpochSeconds"], 2)
        self.assertFalse(original["productQualified"] or original["processOwnershipOrFinalityEstablished"])
        # Publication twenty seconds later does not make a later crash match.
        for capture, matches in (("2026-10-02T12:00:01Z", True), ("2026-10-02T12:00:05Z", False)):
            facts = M.closed_crash_facts(fixture(captureTime=capture), original["beginEpochSeconds"],
                                        original["endEpochSeconds"], "/Applications/Xcode.app/Contents")
            self.assertEqual(facts["captureInBuildInterval"], matches)

    def test_late_observation_refuses_changed_bindings_success_or_conflicting_originals(self):
        for name, replacement in (("source-commit.txt", b"c" * 40 + b"\n"),
                                  ("source-tree.txt", b"c" * 40 + b"\n"),
                                  ("run-attempt.txt", b"31/2\n"), ("build.status", b"0\n")):
            raw = retained_build()
            raw[name] = replacement
            with self.subTest(name=name), self.assertRaises(ValueError):
                M.late_build_inputs(raw, "1:2:501", "a" * 40, "b" * 40, "31/1")
        for key, value in (("originalBuildExit", 0), ("originalBuildExit", True),
                           ("beginEpochSeconds", 0), ("endEpochSeconds", float("nan")),
                           ("productQualified", True), ("schemaVersion", True)):
            raw = retained_build()
            after = json.loads(raw["build-infrastructure-after.json"])
            after[key] = value
            raw["build-infrastructure-after.json"] = json.dumps(after).encode()
            if key == "originalBuildExit" and type(value) is int:
                raw["build.status"] = (str(value) + "\n").encode()
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                M.late_build_inputs(raw, "1:2:501", "a" * 40, "b" * 40, "31/1")
        with self.assertRaises(ValueError):
            M.late_build_inputs(retained_build(), "1:3:501", "a" * 40, "b" * 40, "31/1")

    def test_malformed_ambiguous_or_oversize_reports_are_unavailable(self):
        for raw in (b"", fixture() + b"{}", fixture()[:-1], b"x" * (M.MAX_REPORT_BYTES + 1),
                    fixture().replace(b'"code": 25', b'"code": 25, "code": 25'),
                    fixture().replace(b'"code": 25', b'"code": NaN'),
                    fixture(procName="PRIVATE"), fixture(procLaunch="invalid"),
                    fixture(captureTime="2026-10-02T12:00:01"), fixture(exception=[])):
            with self.assertRaises((ValueError, OverflowError)):
                self.parse(raw)

    def test_empty_scans_recheck_the_original_endpoint(self):
        for observed in (9, 10, 11):
            tree = SyntheticDerivedTree()
            tree.clock = observed
            derived = tree.run()
            with patch.object(M.os, "open", return_value=37), \
                    patch.object(M.os, "close"), \
                    patch.object(M.os, "scandir", side_effect=lambda _: nullcontext([])), \
                    patch.object(M.time, "monotonic", return_value=observed):
                crashes = M.crash_snapshot(0, 2, "/Applications/Xcode.app/Contents", 10)
            self.assertEqual(derived["complete"], observed < 10)
            self.assertEqual(derived["casBackingFiles"]["complete"], observed < 10)
            self.assertEqual(crashes["complete"], observed < 10)
            self.assertEqual(derived["largestFiles"], [])
            self.assertEqual(crashes["facts"], [])

    def test_last_report_finishing_late_retains_only_provisional_facts(self):
        entry = SimpleNamespace(name="XCBBuildService-synthetic.ips",
                                stat=lambda **_: SimpleNamespace(st_mode=M.stat.S_IFREG, st_mtime=1))
        with patch.object(M.os, "open", return_value=37), patch.object(M.os, "close"), \
                patch.object(M.os, "scandir", side_effect=[nullcontext([entry]), nullcontext([])]), \
                patch.object(M, "read_at", return_value=fixture()), \
                patch.object(M.time, "time", return_value=2), \
                patch.object(M.time, "monotonic", side_effect=[9, 10]):
            value = M.crash_snapshot(0, 2, "/Applications/Xcode.app/Contents", 10)
        self.assertFalse(value["complete"])
        self.assertEqual(len(value["facts"]), 1)
        self.assertEqual(value["facts"][0]["signal"], "SIGXFSZ")
        self.assertFalse(value["facts"][0]["processOwnershipEstablished"])

    def test_compiler_budget_requires_exact_measured_pair_before_build_only(self):
        limit = 32 * 1024**3
        self.assertTrue(M.compiler_file_budget([limit, limit]))
        for pair in (None, [], [limit], [limit, limit, limit], (limit, limit),
                     [True, limit], [float(limit), limit], [limit, -1], [-1, -1],
                     [1024**3, 1024**3], [32 * 1024**2, limit], [limit, limit + 1]):
            with self.subTest(pair=pair):
                self.assertFalse(M.compiler_file_budget(pair))
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-ui-host.yml").read_text()
        self.assertEqual(workflow.count("ulimit -f 33554432"), 1)
        self.assertEqual(workflow.count("ulimit -f 32768"), 2)
        before = workflow.split("      - name: Build only the unchanged external XCTest target", 1)[1].split("      - name:", 1)[0]
        ordered = ("ulimit -f 33554432", "file_limit_status=$?", '[[ "$file_limit_status" == 0 ]]',
                   'macos_xcode_build_facts.py before "$MRK_UI_HOST_WORK"', "before_status=$?",
                   '[[ "$before_status" == 0 ]] || exit "$before_status"', "xcodebuild build-for-testing")
        self.assertEqual([before.index(value) for value in ordered], sorted(before.index(value) for value in ordered))
        source = PATH.read_text()
        measured = source.split('if phase == "before":', 1)[1].split('elif phase == "after":', 1)[0]
        self.assertIn('admitted = compiler_file_budget(limits["RLIMIT_FSIZE"])', measured)
        self.assertLess(measured.index('"compilerFileBudgetAdmitted": admitted'), measured.index("if not admitted:"))
        self.assertIn('"serviceLimitsObserved": False', measured)

    def test_cas_snapshot_keeps_sparse_and_zero_backing_files_outside_top_twelve(self):
        tree = SyntheticDerivedTree()
        tree.file("CompilationCache.noindex/generic/v1.0/data.v1", st_size=24 * 1024**3, st_blocks=16)
        tree.file("CompilationCache.noindex/generic/v1.0/index.v1", st_size=0, st_blocks=0)
        for i in range(13):
            tree.file(f"other/PRIVATE-{i}", st_size=100 + i, st_blocks=8)
        result = tree.run()
        cas = result["casBackingFiles"]
        self.assertTrue(result["complete"] and cas["complete"] and cas["snapshotOnly"] and cas["supportedLayoutObserved"])
        self.assertEqual(len(cas["roles"]), 6)
        rows = {(row["family"], row["role"]): row for row in cas["roles"]}
        self.assertEqual((rows["generic", "data"]["files"], rows["generic", "data"]["logicalBytes"],
                          rows["generic", "data"]["allocatedBytes"]), (1, 24 * 1024**3, 8192))
        self.assertEqual((rows["generic", "index"]["files"], rows["generic", "index"]["logicalBytes"]), (1, 0))
        self.assertEqual(len(result["largestFiles"]), 12)
        self.assertFalse(any(row["relativePath"].endswith("index.v1") for row in result["largestFiles"]))
        self.assertNotIn("PRIVATE", json.dumps(cas))
        self.assertNotIn("relativePath", json.dumps(cas))

    def test_cas_scope_and_changed_or_unowned_metadata_are_refused(self):
        for name in ("CompilationCache.noindex/generic/index.v1", "CompilationCache.noindex/builtin/v1.18446744073709551615/actions.v1"):
            self.assertIsNotNone(M.cas_role(name))
        for name in ("/CompilationCache.noindex/generic/index.v1", "CompilationCache.noindex-other/generic/index.v1",
                     "CompilationCache.noindex/generic/../index.v1", "CompilationCache.noindex/PRIVATE/index.v1",
                     "CompilationCache.noindex/generic/v2.0/index.v1", "CompilationCache.noindex/generic/v1.PRIVATE/index.v1",
                     "CompilationCache.noindex/generic/v1./index.v1", "CompilationCache.noindex/generic/v1.-1/index.v1",
                     "CompilationCache.noindex/generic/v1.18446744073709551616/index.v1",
                     "CompilationCache.noindex/generic/v1.000000000000000000000/index.v1",
                     "CompilationCache.noindex/generic/v1.1/index.v2", "other/CompilationCache.noindex/generic/index.v1"):
            with self.subTest(name=name):
                self.assertIsNone(M.cas_role(name))
        for changes in ({"st_mode": M.stat.S_IFLNK | 0o700}, {"st_mode": M.stat.S_IFDIR | 0o700},
                        {"st_uid": 0}, {"st_nlink": 2}, {"st_mode": M.stat.S_IFREG | 0o620},
                        {"st_dev": 8}, {"st_size": -1}, {"st_size": True}, {"st_blocks": -1}, {"st_blocks": True}):
            tree = SyntheticDerivedTree()
            tree.file("CompilationCache.noindex/generic/index.v1", **changes)
            with self.subTest(changes=changes):
                result = tree.run()
                cas = result["casBackingFiles"]
                self.assertFalse(result["complete"])
                self.assertFalse(cas["complete"] or cas["supportedLayoutObserved"])
                self.assertEqual(sum(row["files"] for row in cas["roles"]), 0)
        for target, field in (("file", "st_ino"), ("file", "st_blocks"), ("directory", "st_ino"), ("root", "st_uid")):
            tree = SyntheticDerivedTree()
            path = tree.file("CompilationCache.noindex/generic/index.v1")
            path = "DerivedData/CompilationCache.noindex" if target == "directory" else "DerivedData" if target == "root" else path
            changed = vars(tree.nodes[path]).copy(); changed[field] += 1
            (tree.named_override if target == "file" else tree.held_override)[path] = SimpleNamespace(**changed)
            with self.subTest(target=target, field=field):
                result = tree.run()
                cas = result["casBackingFiles"]
                self.assertFalse(result["complete"])
                self.assertFalse(cas["complete"] or cas["supportedLayoutObserved"])
        tree = SyntheticDerivedTree()
        tree.file("CompilationCache.noindex/generic/v2.0/PRIVATE.v1")
        cas = tree.run()["casBackingFiles"]
        self.assertFalse(cas["supportedLayoutObserved"])
        self.assertEqual(cas["unclassifiedEntries"], 1)
        self.assertNotIn("PRIVATE", json.dumps(cas))

    def test_cas_last_metadata_cannot_publish_after_the_original_endpoint(self):
        tree = SyntheticDerivedTree()
        tree.late_on_stat = tree.file("CompilationCache.noindex/generic/index.v1", st_size=12 * 1024**3)
        result = tree.run()
        self.assertFalse(result["complete"] or result["casBackingFiles"]["complete"])
        self.assertEqual(sum(row["files"] for row in result["casBackingFiles"]["roles"]), 0)
        self.assertEqual(sum(row["refused"] for row in result["casBackingFiles"]["roles"]), 1)

    def test_cache_settings_projection_is_closed_lexical_not_ownership(self):
        workflow = (PATH.parents[2] / ".github/workflows/desktop-macos-ui-host.yml").read_text()
        body = textwrap.dedent(workflow.split("<<'PY_INSPECT'\n", 1)[1].split("          PY_INSPECT", 1)[0])
        function = next(node for node in ast.parse(body).body
                        if isinstance(node, ast.FunctionDef) and node.name == "compilation_cache_facts")
        namespace = {"pathlib": pathlib}
        # Execute only this reviewed pure projection, never the workflow body.
        exec(compile(ast.Module(body=[function], type_ignores=[]), "<closed-cache-projection>", "exec"), namespace)
        project = namespace["compilation_cache_facts"]
        base = "/owned/DerivedData"
        for value, expected in ((base + "/CompilationCache.noindex/PRIVATE", "lexically-within-owned-derived-data"),
                                (base + "-other/PRIVATE", "outside-owned-derived-data"), ("/elsewhere/PRIVATE", "outside-owned-derived-data"),
                                (base + "/../PRIVATE", "unavailable"), ("relative/PRIVATE", "unavailable"), (None, "unavailable")):
            result = project({"COMPILATION_CACHE_CAS_PATH": value}, base)
            self.assertEqual(result["casPathClassification"], expected)
            self.assertFalse(result["pathOwnershipEstablished"] or result["cachingSettingPresent"])
            self.assertIsNone(result["cachingEnabled"])
            self.assertNotIn("PRIVATE", json.dumps(result))
            self.assertEqual(set(result), {"casPathClassification", "pathOwnershipEstablished", "cachingSettingPresent", "cachingEnabled"})
        for value, expected in (("YES", True), ("NO", False), ("PRIVATE", None), (True, None), (None, None)):
            result = project({"COMPILATION_CACHE_ENABLE_CACHING": value}, base)
            self.assertTrue(result["cachingSettingPresent"])
            self.assertIs(result["cachingEnabled"], expected)
            self.assertNotIn("PRIVATE", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
