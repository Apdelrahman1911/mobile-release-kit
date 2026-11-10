"""New standard-route memory-lifetime adaptation checks; DATA only."""
import importlib.util,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('standard_memory_runner',HERE/'fresh_hosted_runner.py');r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
class StandardMemoryLifetimes(unittest.TestCase):
 def binding(self,job):
  return dict(job=job,inputPath=Path('/private/memory-DATA/input'),packageBody=b'p'*100,producerBody=b'd',signatureBody=b's',sourceBytes=1000,inputFiles={'a':(b'input',0o444)},controlBodies={'census':b'c','write':b'w','torn':b't'})
 def packages(self,job,sizes):
  labels={'cut':'write' if job=='write-recovery' else 'torn','frontier':'frontier'}
  if job=='write-recovery':labels['completed']='completed'
  return {role:dict(path='/private/memory-DATA/Fresh-'+label+'.pkg',bytes=size,sha256='a'*64) for (role,label),size in zip(labels.items(),sizes)}
 def test_both_standard_routes_charge_one_live_body_and_all_disk_packages(self):
  for job,small,large,calls in [('write-recovery',(10,20,300),(100,200,300),4),('torn-refusal',(10,300),(200,300),3)]:
   with self.subTest(job=job):
    b=self.binding(job);prior=dict(b,builtPackageBytes={'write':10000000,'frontier':20000000})
    self.assertEqual(r.control_build_fixed_bytes(b),r.control_build_fixed_bytes(prior))
    a=r.route_resource_quote(b,self.packages(job,small));z=r.route_resource_quote(b,self.packages(job,large))
    self.assertEqual(a['memoryBytes'],z['memoryBytes']);self.assertGreater(z['diskBytes'],a['diskBytes']);self.assertEqual(z['installerCalls'],calls)
    self.assertEqual(z['postCutPackageBuilds'],0);self.assertFalse(z['capacityIsReservation'])
    with self.assertRaises(r.Refused):r.route_resource_quote(dict(b,sourceBytes=3*1024**3),self.packages(job,small))
 def test_actual_capacity_guard_keeps_exact_memory_and_disk_boundaries(self):
  spec=importlib.util.spec_from_file_location('resource_guard',HERE.parent/'desktop/tools/macos_fixed_carrier_resume.py');guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)
  for job,sizes in [('write-recovery',(10,20,300)),('torn-refusal',(10,300))]:
   required=r.route_resource_quote(self.binding(job),self.packages(job,sizes))['memoryBytes']
   self.assertFalse(guard.resource_admission_data(required-1,required,100,100)['memorySufficient']);self.assertTrue(guard.resource_admission_data(required,required,100,100)['memorySufficient']);self.assertFalse(guard.resource_admission_data(required,required,99,100)['diskSufficient'])
 def test_carrier_body_is_released_only_after_known_detach(self):
         from types import SimpleNamespace
         from unittest import mock
         import time
         for succeeds in (True,False):
             with self.subTest(succeeds=succeeds):
                 carrier=object.__new__(r.Carrier)
                 carrier.members={"fixture.pkg":b"retained DATA"}
                 carrier.detached=False;carrier.cleanup_grace_entered=False;carrier.label="cut";carrier.device="DATA-only"
                 carrier.op=SimpleNamespace(fresh_deadline=time.monotonic_ns()+300*10**9,
                     work=Path("/private/memory-DATA"),outputs=SimpleNamespace(publish=lambda *args:None))
                 carrier.book=SimpleNamespace(finish=lambda:True)
                 carrier.mount=SimpleNamespace(exists=lambda:False,is_symlink=lambda:False)
                 carrier.post=lambda:self.assertTrue(carrier.members)
                 def detach(*args):
                     self.assertTrue(carrier.members)
                     if not succeeds:raise r.Refused("original-nonzero")
                 carrier.call=detach
                 with mock.patch.object(r.time,"sleep",lambda _:None):
                     if succeeds:carrier.detach()
                     else:
                         with self.assertRaises(r.Refused):carrier.detach()
                 self.assertEqual(carrier.detached,succeeds)
                 self.assertEqual(bool(carrier.members),not succeeds)
if __name__=='__main__':unittest.main(verbosity=2)
