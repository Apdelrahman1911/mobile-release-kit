"""Pure source-loader custody contracts, not native execution evidence."""
from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from . import local_signing_matrix_contract as contract


class SigningCatalogAdmissionTests(unittest.TestCase):
    def test_capacity_canary_adds_each_platforms_maximum_planned_command_shard(self):
        catalog = contract.layered_catalog()
        for operating_system, heavy_shard in (("ubuntu-24.04", 11), ("macos-26", 7)):
            with self.subTest(operating_system=operating_system):
                cases = {item.identifier: item for item in catalog.cases_for(operating_system)}
                groups, _weights = catalog.assignment(operating_system)
                estimates = [sum(cases[identifier].estimated_commands for identifier in group)
                             for group in groups]
                self.assertEqual(estimates[heavy_shard], max(estimates))
                self.assertGreater(estimates[heavy_shard], estimates[12])
                # The other canary cell keeps an actual fatal G before a later
                # semantic fork and the original seven-cut bare-home G fork.
                ordered = [cases[identifier] for identifier in groups[12]]
                names = [(catalog.REGRESSION.case(item.name).original_method
                          if item.kind == "regression" else "") for item in ordered]
                bare, = (index for index, name in enumerate(names)
                         if name.endswith(".test_seven_bare_home_parent_and_empty_native_prefix_cuts_recover_automatically"))
                fatal = [index for index, name in enumerate(names)
                         if name.endswith(".test_genuine_nonzero_command_result_cannot_hide_later_independent_fatal_close")
                         or name.endswith(".test_actual_handler_restoration_cannot_mask_retained_resource_failure")]
                self.assertTrue(any(index < bare and any(item.kind == "semantic"
                    for item in ordered[index + 1:bare]) for index in fatal))
                # Planning arithmetic selects useful probes; it is not measured
                # capacity or permission to omit the complete sixteen shards.

    def loaders(self):
        catalog = contract.layered_catalog()
        yield contract, contract.layered_catalog, "_LAYERED_CATALOG", None, catalog, "_mrk_layered_"
        for name in ("local_signing_semantic_catalog", "local_signing_regression_catalog"):
            yield (catalog, lambda name=name: catalog._peer(name), "_PEER_BINDINGS", {},
                   catalog._peer(name), "_mrk_signing_data_")

    def test_original_objects_are_reused_without_leaving_aliases_or_accepting_filename_lookalikes(self):
        for module, load, _cache, _empty, original, prefix in self.loaders():
            with self.subTest(source=original.__file__):
                path = Path(original.__file__).resolve()
                alias = prefix + hashlib.sha256(str(path).encode()).hexdigest()
                self.assertNotIn(alias, sys.modules)
                self.assertIs(load(), original)
                foreign = SimpleNamespace(__file__=str(path))
                with patch.dict(sys.modules, {alias: foreign}):
                    with self.assertRaisesRegex(ValueError, "alias occupied"):
                        load()
                    self.assertIs(sys.modules[alias], foreign)
                self.assertIs(load(), original)
                self.assertNotIn(alias, sys.modules)

    def test_failed_original_load_never_caches_or_removes_a_replacement_binding(self):
        for module, load, cache, empty, original, prefix in self.loaders():
            path = Path(original.__file__).resolve()
            alias = prefix + hashlib.sha256(str(path).encode()).hexdigest()
            for replacement, raise_original in ((False, True), (True, False), (True, True)):
                with self.subTest(source=path.name, replacement=replacement, raise_original=raise_original):
                    candidate = SimpleNamespace(__file__=str(path))
                    foreign = SimpleNamespace(__file__=str(path))
                    failure = RuntimeError("inert original loader failure")

                    def execute(value):
                        self.assertIs(value, candidate)
                        self.assertIs(sys.modules[alias], candidate)
                        if replacement:
                            sys.modules[alias] = foreign
                        if raise_original:
                            raise failure

                    spec = SimpleNamespace(loader=SimpleNamespace(exec_module=execute))
                    with patch.object(module, cache, empty), patch.dict(sys.modules), \
                            patch.object(module.importlib.util, "spec_from_file_location", return_value=spec), \
                            patch.object(module.importlib.util, "module_from_spec", return_value=candidate):
                        with self.assertRaises(RuntimeError if raise_original else ValueError) as raised:
                            load()
                        if raise_original:
                            self.assertIs(raised.exception, failure)
                        else:
                            self.assertIn("binding changed", str(raised.exception))
                        if replacement:
                            self.assertIs(sys.modules[alias], foreign)
                        else:
                            self.assertNotIn(alias, sys.modules)
                        self.assertEqual(getattr(module, cache), empty)
                self.assertIs(load(), original)
