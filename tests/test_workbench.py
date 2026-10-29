"""Workbench checks against the exact final archive and actual attack equation."""
import base64
import hashlib
import json
import unittest
from api import research

class WorkbenchTests(unittest.TestCase):
    def body(self,data,mode='adaptive_arx',**extra):
        return dict(data=base64.b64encode(data).decode(),key=bytes(range(16)).hex(),mode=mode,**extra)

    def test_supplied_files_unchanged(self):
        for name,digest in research.MANIFEST['files'].items():
            self.assertEqual(hashlib.sha256((research.SOURCE/name).read_bytes()).hexdigest(),digest,name)

    def test_actual_modes_and_trace_agree(self):
        for mode in research.MODES:
            for size in (1,16,128,129,512,513,1024,1025):
                with self.subTest(mode=mode,size=size):
                    data=bytes(i%256 for i in range(size))
                    r=research.encrypt_request(self.body(data,mode))
                    self.assertTrue(r['verified'])
                    self.assertEqual(base64.b64decode(r['recovered']),data)
                    self.assertEqual(r['trace'][-1]['hex'],r['ciphertext'][:32])
                    self.assertEqual(any('ARX' in s['name'] for s in r['trace']),r['config']['arx'])

    def test_binary_second_block_and_bit_flip(self):
        data=bytes(range(256));r=research.encrypt_request(self.body(data,block=1,bit=127))
        self.assertEqual(r['trace'][0]['hex'],data[16:32].hex())
        self.assertEqual(r['trace'][-1]['hex'],r['ciphertext'][32:64])
        self.assertEqual(r['diffusion']['percent'],r['diffusion']['changed_bits']/128*100)

    def test_reject_bad_inputs(self):
        for body in (self.body(b''),self.body(b'x',mode='unknown'),self.body(b'x',block=2),self.body(b'x',bit=128),{'data':'invalid','key':'123'}):
            with self.assertRaises(ValueError):research.encrypt_request(body)

    def test_actual_integral_recovery_and_no_forced_success(self):
        progress=[]
        r=research.experiments('integral',20261029,1,progress.append)
        self.assertEqual(r['rows'][0]['verified_recoveries'],1)
        self.assertEqual(r['rows'][0]['final_candidates'],16)
        self.assertEqual(r['rows'][1]['final_candidates'],0)
        self.assertIsNone(r['rows'][1]['verified_recoveries'])
        self.assertEqual(progress[-1]['completed'],progress[-1]['total'])

    def test_substitution_is_not_misreported_as_protection(self):
        r=research.experiments('substitution',42,1,lambda _:None)
        for row in r['rows']:
            self.assertEqual(row['accepted'],1)
            d=row['details'][0]
            self.assertEqual(d['source_first_block'],d['delivered_first_block'])
            self.assertTrue(d['repeated_blocks_visible'])

    def test_recorded_data_has_provenance(self):
        r=research.recorded()
        self.assertIn('figures/active_attacker_results.csv',r['datasets'])
        self.assertEqual(r['sha256'],'45654d304decdae8fd0730606691d974802f3e8580192fd44e5565ce0257337c')

if __name__=='__main__':unittest.main()
