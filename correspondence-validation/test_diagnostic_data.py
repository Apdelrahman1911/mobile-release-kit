"""Inert DATA checks only: no Installer, credentials, files under protected roots, or compiler."""
import ast
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

HERE = Path(__file__).parent
ROOT = HERE.parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner = load("_diagnostic_data_runner", HERE / "diagnostic_runner.py")
bootstrap = load("_diagnostic_data_bootstrap", HERE / "diagnostic_bootstrap.py")
binding = json.loads((ROOT / "PARTIAL_DIAGNOSTIC_BINDING.json").read_text())
sites = set(binding["diagnosticSites"])
site = min(sites)
COMPLETED = ("MRK_MACOS_INSTALL_COMPLETED_REFUSED=reasonSha256=" + runner.CORRESPONDENCE_REASON
             + ";exit=1;originals=1;native=1;timely=1;unknown=0\n").encode()


def context(origin="parent", **changes):
    values = dict(site=site, check_pass=1, role=0, original=17, parent=16, category=0, exact=1, named=0, expected=1024)
    values.update(changes)
    return ("MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC=origin=" + origin
            + ";basis=first-observed;site={site};pass={check_pass};role={role};original={original};parent={parent}"
            ";category={category};exact={exact};heldNamed={named};heldExpected={expected}\n".format(**values)).encode()


def parse(body):
    return runner.parse_diagnostic_lines(body, line_limit=16384, selected_limit=65536, valid_sites=sites)[0]


class DiagnosticData(unittest.TestCase):
    def test_failed_prepared_owner_retains_closure_without_replacing_primary(self):
        records, emitted = [], []
        outputs = SimpleNamespace(publish=lambda path, body: records.append((path, json.loads(body))))
        op = SimpleNamespace(outputs=outputs, work=Path("/inert"))
        owner = SimpleNamespace(receipt={"originalClosesKnown": False, "targetRetired": False,
            "originalCalls": [{"entered": True, "returned": False}]}, phase="package-install", target="fixed", stager=None)
        helper = SimpleNamespace(emit_failure_diagnostic=lambda *args, **kwargs: emitted.append(args[0]))
        primary = ValueError("not-for-raw-publication")
        bootstrap.preserve_prepared_owner_evidence(op, helper, "acquisition", owner, primary)
        self.assertEqual(records[0][1]["receipt"], owner.receipt)
        self.assertFalse(records[0][1]["returnedNormally"])
        self.assertNotIn("not-for-raw-publication", json.dumps(records[0][1]))
        self.assertIs(emitted[0], primary)
        def refused(*args): raise OSError("inert publication failure")
        outputs.publish = refused
        bootstrap.preserve_prepared_owner_evidence(op, helper, "hydration", owner, primary)
        self.assertIn("prepared-owner-evidence-publication-refused", primary.__notes__)
        self.assertIs(emitted[-1], primary)

    def test_closed_entry_refuses_before_host_or_owner_effects(self):
        with self.assertRaises(ValueError):
            bootstrap.main()
        source = ast.parse((HERE / "diagnostic_producer_prefix.py").read_text())
        source.body = [node for node in source.body
                       if not isinstance(node, ast.ImportFrom) or node.module != "desktop.tools"]
        fake = SimpleNamespace(Operation=object, need=runner.need, digest=runner.sha,
            build_environment=None, package_timeout_data=None, REMOVAL_REF="unused")
        scope = {"helper": fake}
        exec(compile(source, "inert-prefix-data", "exec"), scope)
        with self.assertRaises(runner.Refused):
            scope["PrefixOwner"]().execute_prefix()

    def test_context_origin_and_absence_are_explicit(self):
        parsed = parse(COMPLETED + context() + context("writer-ready-frame"))
        self.assertEqual([r["origin"] for r in parsed["contexts"]], ["parent", "writer-ready-frame"])
        missing = b"MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC_UNAVAILABLE=origin=writer;basis=no-valid-decoded-hint\n"
        self.assertEqual(parse(COMPLETED + context() + missing)["unavailable"],
                         [{"origin": "writer", "basis": "no-valid-decoded-hint"}])
        for bad in (COMPLETED + context() * 2,
                    COMPLETED + context("writer-ready-frame") + context("writer-result-frame"),
                    COMPLETED + context("writer-result-frame") + missing,
                    COMPLETED + missing + context("writer-result-frame")):
            with self.assertRaises(runner.Refused): parse(bad)

    def test_context_fields_match_original_predicate_and_frozen_sites(self):
        for changes in (dict(site=600000), dict(site=100000), dict(original=196608), dict(parent=196608),
                        dict(category=16), dict(named=4096), dict(expected=4096), dict(check_pass=3),
                        dict(expected=0), dict(exact=0, expected=1024)):
            with self.assertRaises(runner.Refused): parse(COMPLETED + context(**changes))
        self.assertEqual(parse(COMPLETED + context(exact=0, expected=1))["contexts"][0]["heldExpected"], 1)
        with self.assertRaises(runner.Refused): parse(context())

    def test_unqualified_markers_survive_bad_schema_and_remain_bounded(self):
        malformed = b"prefix MRK_MACOS_INSTALL_CORRESPONDENCE_DIAGNOSTIC=broken\n"
        raw, metadata = runner.unqualified_marker_data(malformed)
        self.assertEqual(raw, malformed[len(b"prefix "):])
        self.assertFalse(metadata["qualified"])
        with self.assertRaises(runner.Refused): parse(COMPLETED + raw)
        raw, metadata = runner.unqualified_marker_data(malformed * 40)
        self.assertEqual(metadata["markerLinesObserved"], 40)
        self.assertEqual(metadata["markerLinesRetained"], 16)
        self.assertTrue(metadata["truncated"])
        self.assertLessEqual(len(raw), 8192)

    def test_actual_package_allocation_quote_not_rss_claim(self):
        value = dict(binding, controls={"diagnostic": {"bytes": 16 * 1024 * 1024}})
        quote = runner.prefix_resource_quote(value)
        self.assertLessEqual(quote["memoryBytes"], 3 * 1024 ** 3)
        self.assertEqual(quote["packageBytes"], 126981541)
        self.assertFalse(quote["observedRssEnforcement"])
        value["package"] = {"bytes": 1}
        with self.assertRaises(runner.Refused): runner.prefix_resource_quote(value)

    def test_one_installer_original_only(self):
        old = runner.original_call
        calls = []
        runner.original_call = lambda *args, **kwargs: calls.append(args)
        try:
            op = SimpleNamespace(work=Path("/inert"))
            b = {"job": "correspondence-diagnostic", "commandEnvironment": {}}
            runner.installer_original(op, b, "diagnostic", Path("/inert/diagnostic.pkg"))
            with self.assertRaises(runner.Refused):
                runner.installer_original(op, b, "diagnostic", Path("/inert/diagnostic.pkg"))
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][2][:5], ["/usr/bin/sudo", "-n", "--", "/usr/sbin/installer", "-dumplog"])
        finally:
            runner.original_call = old

    def test_preserved_stager_exception_literal_and_no_ordinary_prefix(self):
        source = (HERE / "diagnostic_producer_prefix.py").read_text()
        self.assertIn('__dict__.get("Refused")', source)
        self.assertNotIn('__dict__.get("helper.Refused")', source)
        self.assertIn("helper.emit_failure_diagnostic(error", source)
        tree = ast.parse(source)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef))
        prefix = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == "producer_prefix")
        calls = [node for node in ast.walk(prefix) if isinstance(node, ast.Call)]
        self.assertFalse(any(isinstance(node.func, ast.Attribute) and node.func.attr in ("package_install", "execute", "package_image") for node in calls))
        self.assertFalse(any(isinstance(node, ast.Constant) and node.value == "/usr/sbin/installer" for node in ast.walk(prefix)))

    def test_host_branch_and_disabled_workflow_match(self):
        self.assertEqual(bootstrap.BRANCH, "codex/macos-correspondence-diagnostic")
        workflow = (HERE / "macos-correspondence-diagnostic.workflow.disabled.yml").read_text()
        self.assertEqual(workflow.count("if: ${{ false }}"), 1)
        self.assertIn("branches: [" + bootstrap.BRANCH + "]", workflow)
        self.assertNotIn("ordinary-carrier", workflow)
        self.assertNotIn("torn-refusal", workflow)
        self.assertNotIn("write-recovery", workflow)
        self.assertIsNone(bootstrap.EXECUTION_BINDING)
        self.assertIsNone(runner.EXECUTION_BINDING)
        self.assertFalse(binding["executionApproved"])


class DiagnosticHostPrerequisitesData(unittest.TestCase):
    """Exercise collection and real metadata policy with synthetic observations."""

    def _host_and_book(self, bad_role=None):
        host = load("_diagnostic_host_scope_data", HERE / "fresh_host_prerequisite.py")

        class DataBook(host.Originals):
            def __init__(self):
                super().__init__(None, {"uid": 501}, SimpleNamespace(check=lambda: None))
                self.unused_xcode = SimpleNamespace(st_mode=host.stat.S_IFDIR | 0o755,
                    st_uid=501, st_gid=20, st_nlink=1, st_size=0)

            def open(self, parent, name, kind, policy, role):
                path = "/" if parent is None else parent.path.rstrip("/") + "/" + name
                node = host.Node(path, role, parent, name, kind, policy)
                mode = host.stat.S_IFDIR | 0o755 if kind == "directory" else host.stat.S_IFREG | 0o755
                if policy == "sudo": mode |= host.stat.S_ISUID
                current = SimpleNamespace(st_dev=1, st_ino=len(self.nodes) + 1,
                    st_mode=mode, st_uid=501 if role == bad_role or "Xcode" in path else 0,
                    st_gid=80 if policy == "applications" else 0, st_nlink=1,
                    st_size=0, st_mtime_ns=1, st_ctime_ns=1)
                # These numbers are inert availability sentinels, never OS descriptors.
                node.fd = 100 + len(self.nodes)
                node.pre = {"full9": host.full9(current)}
                self.nodes[path] = node
                self.metadata(node, current, "initial")
                return node

            def absence(self, parent, name, role):
                self.absences.append((None, {"role": role, "absent": True}))

        return host, DataBook()

    def test_unused_runner_owned_xcode_does_not_block_diagnostic_ancestors(self):
        from unittest.mock import patch
        host, book = self._host_and_book()
        with patch.object(host.os, "stat", return_value=book.unused_xcode) as query:
            host._collect_prerequisites(book)
        self.assertEqual(book.errors, [])
        self.assertEqual(host._eligible_action(book), "noop")
        query.assert_not_called()
        self.assertEqual(len(book.absences), 3)
        report = host._report(book, book.context, {"claimed": False}, "inert-data")
        self.assertFalse(report["xcodeQualified"])
        self.assertFalse(report["nativeQualified"])
        self.assertEqual(report["scope"],
                         "dedicated-disposable-macos-diagnostic-applications-ancestor-preparation")

    def test_required_ancestor_and_tool_owners_still_block_eligibility(self):
        from unittest.mock import patch
        for role in ("root", "applications", "fixed-system-bin:0", "fixed-system-bin:1",
                     "signing-recovery:security", "signing-recovery:codesign",
                     "signing-recovery:openssl", "os-provisioner-sudo", "fixed-os-bin",
                     "os-provisioner-chmod"):
            with self.subTest(role=role):
                host, book = self._host_and_book(bad_role=role)
                with patch.object(host.os, "stat", return_value=book.unused_xcode):
                    host._collect_prerequisites(book)
                self.assertTrue(any(error["role"] == role and error["code"] == "root-owner-required"
                                    for error in book.errors))
                self.assertIsNone(host._eligible_action(book))


if __name__ == "__main__":
    unittest.main(verbosity=2)
