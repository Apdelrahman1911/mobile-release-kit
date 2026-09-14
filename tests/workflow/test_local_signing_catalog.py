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
