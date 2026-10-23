"""Source-loaded parser failure DATA only; no package/native qualification."""
from contextlib import contextmanager
from pathlib import Path
import sys
from types import FunctionType, ModuleType, SimpleNamespace, TracebackType
import unittest
from unittest import mock

from desktop.tools import macos_candidate_consumer as C
from desktop.tools import macos_fixed_carrier_resume as R
from tests.desktop.test_macos_candidate_consumer import mounted_fixture


NAME = '_mrk_candidate_stager'
EXPECTED = C.ROOT / C.STAGER_PATH
PRIVATE = 'PRIVATE-STAGER-INPUT-NOT-FOR-OUTPUT'


@contextmanager
def loaded_stager():
    # The same source loader and real parser/Refused class as production. Only
    # preceding metadata DATA ports are inert, not the XAR parser under test.
    prior = sys.modules.pop(NAME, None)
    try:
        stage = R.load_module(NAME, EXPECTED, (C.ROOT / C.STAGER_PATH).read_bytes())
        originals, row, ports = mounted_fixture('aarch64-apple-darwin')
        with mock.patch.object(C, 'CANDIDATE_ROOT', C.ROOT), \
                mock.patch.object(stage, 'distribution_layout_data', ports.distribution_layout_data), \
                mock.patch.object(stage, 'maintenance_producer_data', ports.maintenance_producer_data), \
                mock.patch.object(stage, 'source_build_selection', ports.source_build_selection):
            yield stage, originals, row
    finally:
        sys.modules.pop(NAME, None)
        if prior is not None: sys.modules[NAME] = prior


def refused(stage, originals, row, *, budget=None, retained=False):
    try:
        R.mounted_data(originals, row, row['target'], stage, allocation_budget=budget,
                       candidate=True, retained_observer=retained)
    except BaseException as error:
        return error
    raise AssertionError('inert package must not parse or reach native work')


def baseline(error):
    with mock.patch.object(C.candidate, 'stager_failure_data', side_effect=lambda error, value, *args: value):
        return C.failure_data(error)


def chain(rows):
    result = None
    for tb in reversed(rows):
        result = TracebackType(result, tb.tb_frame, tb.tb_lasti, tb.tb_lineno)
    return result


class StagerFailureDiagnosticTests(unittest.TestCase):
    def test_real_mounted_data_loaded_parser_refusal_is_finite_and_preserves_original(self):
        with loaded_stager() as (stage, originals, row):
            budget = mock.Mock()
            error = refused(stage, originals, row, budget=budget)
            self.assertIs(type(error), stage.Refused)
            self.assertEqual(error.args, ('install-product-xar-bound',))
            before = (error.args, error.__traceback__, error.__cause__, error.__context__)
            value = C.failure_data(error)
            self.assertEqual((error.args, error.__traceback__, error.__cause__, error.__context__), before)
            self.assertEqual(value['reason'], 'install-product-xar-bound')
            self.assertEqual(value['exceptionClass'], 'Refused')
            self.assertEqual([(v['file'], v['function']) for v in value['sourceFrames']], [
                ('macos_fixed_carrier_resume.py', 'mounted_data'),
                ('stage_macos_installed.py', 'install_product_members'),
                ('stage_macos_installed.py', 'need')])
            self.assertFalse(value['rawOutputExported'] or value['cleanupAuthorized'])
            self.assertIsNone(value['resourceAdmission'])
            self.assertIsNone(value['systemTool'])
            budget.assert_not_called()
            self.assertLess(len(R.canonical(value)), 4096)
            self.assertNotIn(str(EXPECTED), R.canonical(value).decode())

    def test_real_retained_flat_mounted_data_refusal_uses_same_stager_binding(self):
        with loaded_stager() as (stage, originals, row):
            budget = mock.Mock()
            error = refused(stage, originals, row, budget=budget, retained=True)
            self.assertIs(type(error), stage.Refused)
            self.assertEqual(error.args, ('xar-header',))
            before = (error.args, error.__traceback__, error.__cause__, error.__context__)
            old, value = baseline(error), C.failure_data(error)
            self.assertEqual((error.args, error.__traceback__, error.__cause__, error.__context__), before)
            self.assertEqual(value['reason'], 'xar-header')
            self.assertEqual(value['exceptionClass'], 'Refused')
            self.assertEqual([(v['file'], v['function']) for v in value['sourceFrames']], [
                ('macos_fixed_carrier_resume.py', 'mounted_data'),
                ('stage_macos_installed.py', 'xar_members'),
                ('stage_macos_installed.py', 'need')])
            for key in set(old) - {'reason', 'exceptionClass', 'sourceFrames'}:
                self.assertEqual(value[key], old[key])
            self.assertFalse(value['rawOutputExported'] or value['cleanupAuthorized'])
            self.assertLess(len(R.canonical(value)), 4096)
            self.assertNotIn(str(EXPECTED), R.canonical(value).decode())
            budget.assert_not_called()

    def test_unknown_private_or_nonsingle_args_cannot_become_public_labels(self):
        with loaded_stager() as (stage, originals, row):
            for parts in ((PRIVATE,), ('install-product-xar-new-private-field',),
                          ('candidate-source-identity',), ('x' * 1024,),
                          ('install-product-xar-bound', PRIVATE), (object(),), ()):
                error = stage.Refused(*parts)
                error.__cause__ = RuntimeError(PRIVATE)
                error.__context__ = RuntimeError(PRIVATE)
                with self.subTest(parts_count=len(parts)), mock.patch.object(stage, 'need', side_effect=error):
                    observed = refused(stage, originals, row)
                self.assertIs(observed, error)
                value = C.failure_data(error)
                self.assertEqual(value['exceptionClass'], 'Refused')
                self.assertEqual(value['reason'], 'unavailable')
                self.assertTrue(any(v['function'] == 'install_product_members' for v in value['sourceFrames']))
                public = R.canonical(value).decode()
                self.assertNotIn(PRIVATE, public)
                self.assertNotIn('new-private-field', public)
                self.assertNotIn('x' * 96, public)

    def test_only_exact_loaded_refused_class_is_classified_without_accessors(self):
        with loaded_stager() as (stage, originals, row):
            class PrivateError(stage.Refused):
                def __str__(self): raise AssertionError('never format an exception')
                def __getattribute__(self, key):
                    if key in ('args', '__traceback__'): raise AssertionError('use BaseException descriptors')
                    return super().__getattribute__(key)
            for error, label in ((PrivateError(PRIVATE), 'other'),
                                 (ValueError(PRIVATE), 'ValueError'),
                                 (R.Refused('candidate-source-identity'), 'Refused')):
                with self.subTest(label=label), mock.patch.object(stage, 'need', side_effect=error):
                    observed = refused(stage, originals, row)
                self.assertIs(observed, error)
                value = C.failure_data(error)
                self.assertEqual(value['exceptionClass'], label)
                self.assertEqual(value['reason'], 'candidate-source-identity' if type(error) is R.Refused else 'unavailable')
                self.assertNotIn(PRIVATE, R.canonical(value).decode())

    def test_wrong_module_path_shape_or_class_binding_cannot_promote(self):
        with loaded_stager() as (stage, originals, row):
            error = refused(stage, originals, row)
            old = baseline(error)
            for module in (None, SimpleNamespace(__file__=str(EXPECTED)), ModuleType(NAME)):
                with self.subTest(module_type=type(module).__name__), mock.patch.dict(sys.modules, {NAME: module}):
                    self.assertEqual(C.failure_data(error), old)
            for key, value in (('__file__', '/private/' + PRIVATE), ('__name__', 'foreign'),
                               ('INSTALL_PRODUCT_AUDIT_REASONS', {'install-product-xar-bound'}),
                               ('INSTALL_PRODUCT_AUDIT_REASONS', frozenset({PRIVATE})),
                               ('INSTALL_PRODUCT_AUDIT_REASONS', frozenset('label-' + str(i) for i in range(65)))):
                with self.subTest(key=key), mock.patch.dict(vars(stage), {key: value}):
                    self.assertEqual(C.failure_data(error), old)
            # A valid parser location does not turn some other class into its
            # exact source-loaded Refused class.
            with mock.patch.dict(vars(stage), {'Refused': ValueError}):
                self.assertEqual(C.failure_data(error)['exceptionClass'], 'other')

    def test_filename_globals_and_real_caller_boundary_are_all_required(self):
        with loaded_stager() as (stage, originals, row):
            real = stage.install_product_members
            foreign_globals = dict(vars(stage))
            cases = (FunctionType(real.__code__, foreign_globals),
                     FunctionType(real.__code__.replace(co_filename='/private/' + PRIVATE), vars(stage)))
            for function in cases:
                with self.subTest(filename=function.__code__.co_filename), \
                        mock.patch.object(stage, 'install_product_members', function):
                    error = refused(stage, originals, row)
                    self.assertEqual(C.failure_data(error), baseline(error))
            # Calling the real parser directly is not this consumer's original
            # mounted_data -> parser failure boundary.
            try: real(b'package')
            except stage.Refused as error:
                self.assertEqual(C.failure_data(error), baseline(error))
            else: self.fail('short inert XAR must refuse')
            error = refused(stage, originals, row)
            fake = FunctionType(R.mounted_data.__code__, dict(vars(R)))
            with mock.patch.object(R, 'mounted_data', fake):
                self.assertEqual(C.failure_data(error), baseline(error))

    def test_original_traceback_scan_and_emitted_frames_stay_bounded(self):
        with loaded_stager() as (stage, originals, row):
            error = refused(stage, originals, row)
            rows = []
            tb = error.__traceback__
            while tb is not None:
                rows.append(tb); tb = tb.tb_next
            mounted = next(tb for tb in rows if tb.tb_frame.f_code is R.mounted_data.__code__)
            parser = next(tb for tb in rows if tb.tb_frame.f_code is stage.install_product_members.__code__)
            need = next(tb for tb in rows if tb.tb_frame.f_code is stage.need.__code__)
            error.__traceback__ = chain([mounted, parser] + [need] * 64)
            value = C.failure_data(error)
            self.assertEqual(value['reason'], 'install-product-xar-bound')
            self.assertEqual(len(value['sourceFrames']), 8)
            self.assertTrue(all(v['file'] == 'stage_macos_installed.py' and v['function'] == 'need'
                                and type(v['line']) is int and 0 < v['line'] < 1000000 for v in value['sourceFrames']))
            error.__traceback__ = chain([mounted] * 32 + [parser, need])
            self.assertEqual(C.failure_data(error), baseline(error))
            error.__traceback__ = chain([parser, mounted, need])
            self.assertEqual(C.failure_data(error), baseline(error))

    def test_diagnostic_failure_returns_original_projection_and_does_not_mutate_exception(self):
        with loaded_stager() as (stage, originals, row):
            error = refused(stage, originals, row)
            old = baseline(error)
            before = (error.args, error.__traceback__)
            origins = ((vars(C), C.__file__), (vars(R), R.__file__), (vars(C.candidate), C.candidate.__file__))
            for failure in (RuntimeError(PRIVATE), KeyboardInterrupt()):
                class BrokenPath:
                    def __eq__(self, other): raise failure
                with self.subTest(kind=type(failure).__name__), mock.patch.dict(vars(stage), {'__file__': BrokenPath()}):
                    self.assertIs(C.candidate.stager_failure_data(error, old, origins, EXPECTED), old)
                    self.assertEqual(C.failure_data(error), old)
                self.assertEqual((error.args, error.__traceback__), before)
            self.assertNotIn(PRIVATE, R.canonical(old).decode())

    def test_consumer_and_already_held_child_source_caps_remain_unchanged(self):
        self.assertLessEqual(Path(C.__file__).stat().st_size, 96 << 10)
        bodies = {name: (C.ROOT / name).read_bytes() for name in (C.LEGACY_PATH, C.PARSER_PATH)}
        self.assertLessEqual(len(bodies[C.PARSER_PATH]), C.PARSER_SOURCE_LIMIT)
        bootstrap = C.acquisition_bootstrap(C.HELPER_ROOT, bodies)
        self.assertLessEqual(len(bootstrap.encode()), C.CHILD_SOURCE_LIMIT)
        compile(bootstrap, '<inert-held-child>', 'exec')


if __name__ == '__main__':
    unittest.main()
