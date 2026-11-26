import importlib.util, pathlib, sys, unittest, ast
O=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('assembly',O/'desktop/tools/assemble_ubuntu_deb.py')
A=importlib.util.module_from_spec(spec);spec.loader.exec_module(A)
class AssemblyData(unittest.TestCase):
 def test_closure_keeps_every_elf(self):
  paths=[pathlib.Path('/fixture/shell'),pathlib.Path('/fixture/python/bin/python3'),pathlib.Path('/fixture/python/lib/ext.so')]
  cmd=A.closure_command(paths)
  self.assertEqual([p[2:] for p in cmd if p.startswith('-e')],[str(p) for p in paths])
  self.assertNotIn('--ignore-missing-info',cmd)
 def test_closure_deduplicates_library_paths(self):
  cmd=A.closure_command([pathlib.Path('/f/a.so'),pathlib.Path('/f/b.so')])
  self.assertEqual(cmd.count('-l/f'),1)
 def test_dependency_output(self):
  self.assertEqual(A.closure_output('shlibs:Depends=libc6 (>= 2.39), libgcc-s1\n'),'libc6 (>= 2.39), libgcc-s1')
 def test_dependency_injection_and_empty_refused(self):
  for value in ['', 'shlibs:Depends=','shlibs:Depends=libc6\nPre-Depends: injected','shlibs:Depends=${shlibs:Depends}','wrong=libc6']:
   with self.assertRaises(ValueError): A.closure_output(value)
 def test_non_linux_refuses_before_mutation(self):
  from unittest.mock import patch
  with patch.object(A.platform,'system',return_value='Darwin'):
   with self.assertRaises(ValueError): A.assemble({},pathlib.Path('/absent'),'0'*64,O/'must-not-exist')
  self.assertFalse((O/'must-not-exist').exists())
 def test_python_syntax(self):
  ast.parse((O/'desktop/tools/assemble_ubuntu_deb.py').read_text())
if __name__=='__main__': unittest.main(verbosity=2)
