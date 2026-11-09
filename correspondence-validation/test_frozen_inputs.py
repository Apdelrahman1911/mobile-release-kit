"""Check frozen producer admission and packaging directory policy with inert fixtures."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
ROOT = Path(sys.argv.pop(1)).resolve()
HERE = Path(__file__).resolve().parent
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
bootstrap = load('_frozen_inputs_bootstrap', HERE / 'diagnostic_bootstrap.py')
stager = load('_frozen_inputs_stager', ROOT / 'desktop/tools/stage_macos_installed.py')
class ReachedPackage(Exception): pass
class FrozenInputs(unittest.TestCase):
    def setUp(self):
        self.binding = copy.deepcopy(bootstrap.EXECUTION_BINDING)
        self.bodies = {('runner', 'correspondence-validation/bound-producer/' + p.name): p.read_bytes()
                       for p in (HERE / 'bound-producer').iterdir()}
        self.book = SimpleNamespace(file=Mock(side_effect=ReachedPackage), check=Mock())
    def invoke(self):
        return bootstrap.frozen_producer_inputs(self.book, self.bodies, self.binding, stager, Path('/inert'))
    def test_retained_proof_and_real_descriptor_parser_admit_package_acquisition(self):
        with self.assertRaises(ReachedPackage): self.invoke()
        self.book.file.assert_called_once_with(Path('/inert/package-final/MobileReleaseKit.pkg'),
                                              512 * 1024 * 1024, modes=(0o444,))
    def test_wrong_product_refused_before_package_read(self):
        self.binding['productSource'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'frozen-producer-current'): self.invoke()
        self.book.file.assert_not_called()
    def test_modified_signature_rejected_by_exact_pin(self):
        self.bodies[('runner', 'correspondence-validation/bound-producer/producer.sig')] = b'changed'
        with self.assertRaises(ValueError): self.invoke()
        self.book.file.assert_not_called()
    def test_incomplete_original_result_cannot_authorize_reuse(self):
        key = ('runner', 'correspondence-validation/bound-producer/provenance.json')
        v = json.loads(self.bodies[key]); v['receipt']['targetRetired'] = False
        body = json.dumps(v).encode(); self.bodies[key] = body
        self.binding['sourceFiles']['runner'][key[1]] = {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        with self.assertRaisesRegex(ValueError, 'frozen-producer-original-proof'): self.invoke()
        self.book.file.assert_not_called()
    def test_real_packaging_root_preserves_sealed_descendant_policy(self):
        with tempfile.TemporaryDirectory(prefix='mrk-packaging-root-') as temp:
            root = Path(temp).resolve(); scripts = root / 'scripts'; scripts.mkdir(mode=0o755)
            nested = scripts / 'input'; nested.mkdir(mode=0o755)
            for path in [scripts/'postinstall', scripts/'mrk-macos-install', nested/'fixture']:
                path.write_bytes(b'x'); path.chmod(0o444)
            nested.chmod(0o555)
            try:
                # Local OS-added attributes are outside this directory-mode test.
                with patch.object(stager, 'no_xattrs'):
                    with self.assertRaisesRegex(stager.Refused, 'packager-directory-mode-owner'):
                        stager.tree(nested, packager=True)
                    result = bootstrap.prepared_input_files(stager, root, {'preparedInputFacts':{'inputFileBytes':1}})
                    self.assertEqual(result, {'fixture':(b'x',0o444)})
                    self.assertEqual(nested.stat().st_mode & 0o777, 0o555)
                    nested.chmod(0o755)
                    with self.assertRaisesRegex(stager.Refused, 'packager-directory-mode-owner'):
                        bootstrap.prepared_input_files(stager, root, {'preparedInputFacts':{'inputFileBytes':1}})
            finally: nested.chmod(0o755)
if __name__ == '__main__': unittest.main(verbosity=2)
