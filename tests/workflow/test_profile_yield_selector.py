"""Inert source/object selection only; never import or run the native fixture."""
from __future__ import annotations

import ast
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]


class ProfileYieldSelectorContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "tests/workflow/profile_installation_fixture.py"
        names = {"_scope_yield_lines", "_scope_yield_binding"}
        selected = [node for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name in names]
        assert len(selected) == len(names) and {node.name for node in selected} == names
        # Execute only these pure definitions, not fixture imports/run_case or
        # any production function. Real signal/finality evidence remains native.
        namespace = {"ast": ast, "textwrap": textwrap}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), "exec"), namespace)
        cls.select = staticmethod(namespace["_scope_yield_lines"])
        cls.bind = staticmethod(namespace["_scope_yield_binding"])

    def test_actual_three_source_functions_select_their_owned_publication(self):
        for module, name, publication, compatibility_yields in (
            ("credentials", "_temporary_profile_installation", "yield", 0),
            ("credentials", "_temporary_apple_signing_environment",
             'yield {"MOBILE_RELEASE_IOS_PROFILE_SPECIFIER": profile_uuid}', 1),
            ("local_signing", "local_signing_lease", "yield lease", 0),
        ):
            with self.subTest(function=name):
                path = ROOT / "src/mobile_release" / (module + ".py")
                source = path.read_text()
                roots = [node for node in ast.parse(source).body
                         if isinstance(node, ast.FunctionDef) and node.name == name]
                self.assertEqual(len(roots), 1)
                function = roots[0]
                first = min([function.lineno, *[node.lineno for node in function.decorator_list]])
                lines = source.splitlines(keepends=True)
                selected = "".join(lines[first - 1:function.end_lineno])
                owner, yielded = self.select(selected, function_name=name, first_line=first)
                self.assertEqual(lines[owner - 1].strip(), "with scope:")
                self.assertEqual(lines[yielded - 1].strip(), publication)
                self.assertLess(owner, yielded)
                all_yields = [first + index for index, line in enumerate(selected.splitlines())
                              if line.strip().startswith("yield")]
                self.assertEqual(len(all_yields), 1 + compatibility_yields)
                if compatibility_yields:
                    self.assertLess(all_yields[0], owner)
                    self.assertNotEqual(yielded, all_yields[0])

    def test_compatibility_and_nested_scopes_cannot_steal_the_selected_line(self):
        source = textwrap.dedent("""\
            @decorator
            def selected():
                if compatibility:
                    yield updates
                def nested():
                    with scope:
                        yield nested_updates
                class Nested:
                    def run(self):
                        with scope:
                            yield nested_updates
                with scope:  # original
                    def callback():
                        yield nested_updates
                    deferred = lambda: (yield nested_updates)
                    yield owned_updates
        """)
        first = 507
        lines = source.splitlines()
        expected = (first + lines.index("    with scope:  # original"),
                    first + lines.index("        yield owned_updates"))
        self.assertEqual(self.select(source, function_name="selected", first_line=first), expected)

    def test_missing_or_ambiguous_original_scope_publication_refuses(self):
        sources = (
            "def selected():\n    yield compatibility\n",
            "def selected():\n    with scope:\n        pass\n",
            "def selected():\n    with scope:\n        yield first\n    with scope:\n        yield second\n",
            "def selected():\n    with scope:\n        yield first\n        yield second\n",
            "def selected():\n    with scope:\n        def nested(argument=(yield first)):\n            pass\n        yield second\n",
            "def selected():\n    def nested():\n        with scope:\n            yield nested_updates\n",
            "def selected():\n    with scope:\n        yield from updates\n",
            "def selected():\n    with scope, other:\n        yield updates\n",
            "def wrong():\n    with scope:\n        yield updates\n",
            "def selected():\n    with scope:\n        yield updates\ndef extra():\n    pass\n",
        )
        for index, source in enumerate(sources):
            with self.subTest(case=index), self.assertRaises(AssertionError):
                self.select(source, function_name="selected", first_line=1)

    @staticmethod
    def signing_values():
        guard = object()
        scope = SimpleNamespace(cancellation=guard, claimed=False)
        owner = SimpleNamespace(cancellation=guard)
        session = SimpleNamespace(cancellation=guard, lease=owner, closed=False)
        owner.active = session
        scratch = SimpleNamespace(cancellation=guard, active=True, claimed=False,
                                  snapshots={}, tokens={}, records={})
        values = dict(scope=scope, cancellation=guard, owner=owner, session=session,
                      scratch=scratch, directory=scratch)
        for name, role in (("p12", "distribution-p12"), ("profile", "apple-profile")):
            token = object()
            snapshot = SimpleNamespace(_owner=scratch, _role=role, _token=token, size=7, sha256="inert")
            scratch.snapshots[role], scratch.tokens[role] = snapshot, token
            scratch.records[role] = {"binding": {"size": snapshot.size, "sha256": snapshot.sha256}}
            values[name] = snapshot
        return values

    def test_original_scope_session_guard_and_selected_inputs_are_not_reselected(self):
        changes = (
            ("scope", lambda v: v.update(scope=SimpleNamespace(cancellation=v["cancellation"], claimed=False))),
            ("active-session", lambda v: setattr(v["owner"], "active", object())),
            ("session-lease", lambda v: setattr(v["session"], "lease", object())),
            ("scope-guard", lambda v: setattr(v["scope"], "cancellation", object())),
            ("owner-guard", lambda v: setattr(v["owner"], "cancellation", object())),
            ("session-guard", lambda v: setattr(v["session"], "cancellation", object())),
            ("scratch-guard", lambda v: setattr(v["scratch"], "cancellation", object())),
            ("directory", lambda v: v.update(directory=object())),
            ("scratch-retired", lambda v: setattr(v["scratch"], "claimed", True)),
            ("profile-owner", lambda v: setattr(v["profile"], "_owner", object())),
            ("profile-role", lambda v: setattr(v["profile"], "_role", "distribution-p12")),
            ("profile-token", lambda v: v["scratch"].tokens.update({"apple-profile": object()})),
            ("profile-record", lambda v: v["scratch"].records.update(
                {"apple-profile": {"binding": dict(v["scratch"].records["apple-profile"]["binding"])}})),
        )
        for name, change in changes:
            with self.subTest(binding=name):
                values = self.signing_values()
                original = self.bind(values, signing=True)
                self.assertEqual(self.bind(dict(values), signing=True, expected=original), original)
                change(values)
                with self.assertRaises(AssertionError):
                    self.bind(values, signing=True, expected=original)
        # A wholly consistent new graph still cannot replace the observed one.
        original = self.bind(self.signing_values(), signing=True)
        with self.assertRaises(AssertionError):
            self.bind(self.signing_values(), signing=True, expected=original)

    def test_standalone_scope_uses_the_same_guard_without_signing_authority(self):
        guard = object()
        values = {"scope": SimpleNamespace(cancellation=guard, claimed=False), "cancellation": guard}
        original = self.bind(values, signing=False)
        self.assertEqual(self.bind(values, signing=False, expected=original), original)
        values["scope"] = SimpleNamespace(cancellation=guard, claimed=False)
        with self.assertRaises(AssertionError):
            self.bind(values, signing=False, expected=original)
