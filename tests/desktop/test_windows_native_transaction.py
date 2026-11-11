"""Portable generation contract tests, never Windows native acceptance."""
import importlib.util
from pathlib import Path
import sys
import unittest
import xml.etree.ElementTree as ET
TOOLS=Path(__file__).resolve().parents[2]/'desktop/tools'
sys.path.insert(0,str(TOOLS))
import build_windows_transaction as n
import prepare_windows_msi as p

class NativeAssembly(unittest.TestCase):
 def binding(self):
  return {'version':'0.1.4','sourceCommit':'a'*40,'sourceTree':'b'*40,'manifestSha256':'c'*64,
          'files':{p.PUBLISHER:{'size':8,'sha256':'d'*64},**{'runtime/'+k:{'size':i+1,'sha256':'e'*64}
                for i,k in enumerate(['manifest.json']+['python/file%d.dll'%i for i in range(64)])}}}
 def test_lifecycle_order_and_privilege(self):
  root=ET.fromstring(n.assembly(self.binding())); ns={'w':p.NS}
  actions={a.get('Id'):a.attrib for a in root.findall('.//w:CustomAction',ns)}
  self.assertEqual(set(actions),{'GuardRuntime','PublishRuntime'})
  for a in actions.values():
   self.assertEqual((a['Execute'],a['Impersonate'],a['Return']),('deferred','no','check'))
   self.assertEqual(a['BinaryRef'],'MrkTransaction')
  seq={a.get('Action'):a.attrib for a in root.findall('.//w:InstallExecuteSequence/w:Custom',ns)}
  self.assertEqual(seq['GuardRuntime']['Before'],'ProcessComponents')
  self.assertEqual(seq['GuardRuntime']['Condition'],'1')
  self.assertEqual(seq['PublishRuntime']['After'],'InstallFiles')
  self.assertEqual(seq['PublishRuntime']['Condition'],'NOT REMOVE~="ALL"')
  self.assertEqual(root.find('.//w:Launch',ns).get('Condition'),'0')
 def test_header_binds_package_source_and_runtime(self):
  b=self.binding();h=n.header(b)
  for value in (p.identity(b)['assemblyBindingSha256'],b['sourceCommit'],b['sourceTree'],b['manifestSha256']):self.assertIn(value,h)
  changed=self.binding();changed['sourceTree']='f'*40
  self.assertNotEqual(n.header(changed),h)
  changed=self.binding();changed['files'][p.PUBLISHER]['sha256']='f'*64
  self.assertNotEqual(n.header(changed),h)
  self.assertIn('L"python\\\\file0.dll"',h)
 def test_incomplete_roster_refused(self):
  b=self.binding();del b['files']['runtime/manifest.json']
  with self.assertRaises(p.Refused):n.header(b)
if __name__=='__main__':unittest.main()
