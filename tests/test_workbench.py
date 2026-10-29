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

    def test_diffusion_trace_matches_final_count(self):
        r=research.encrypt_request(self.body(b'Hello, AdaptAES!'))
        stages=r['diffusion']['stages']
        self.assertEqual(stages[0]['changed_bits'],1)
        self.assertEqual(stages[-1]['changed_bits'],r['diffusion']['changed_bits'])
        self.assertTrue(any('ARX' in row['name'] for row in stages))
        self.assertTrue(all(0<=row['changed_bits']<=128 for row in stages))

    def test_packet_stream_policy_and_totals(self):
        sizes=[128,129,512,513,1024,1025]
        r=research.stream_request({'sizes':sizes,'seed':42})
        self.assertEqual([row['rounds'] for row in r['rows']],[4,6,6,8,8,10])
        self.assertEqual([row['arx'] for row in r['rows']],[True,False,False,False,False,False])
        self.assertEqual(r['total_bytes'],sum(sizes))
        self.assertTrue(r['verified'])
        self.assertAlmostEqual(r['adaptive_total_ms'],sum(row['adaptive_ms'] for row in r['rows']))
        self.assertAlmostEqual(r['speedup'],r['aes10_total_ms']/r['adaptive_total_ms'])

    def test_packet_stream_rejects_unbounded_work(self):
        for body in ({'sizes':[]},{'sizes':[1]*13},{'sizes':[4097]},{'sizes':[1.5]},{'sizes':[True]},{'sizes':[1],'seed':-1}):
            with self.assertRaises(ValueError):research.stream_request(body)

    def test_all_round_comparison_has_real_decryption_and_statistics(self):
        r=research.compare_request(self.body(b'Information security lab'))
        self.assertEqual({row['mode'] for row in r['rows']},{'aes4','hybrid','aes5','aes6','aes8','aes10','adaptive','adaptive_arx'})
        baseline=next(row for row in r['rows'] if row['mode']=='aes10')
        for row in r['rows']:
            self.assertTrue(row['verified'])
            self.assertGreater(row['decryption_ms'],0)
            self.assertEqual(len(row['encryption_samples_ms']),r['repeats'])
            self.assertLessEqual(row['min_ms'],row['median_ms'])
            self.assertLessEqual(row['median_ms'],row['max_ms'])
            self.assertGreater(row['cpu_ms'],0)
            self.assertAlmostEqual(row['us_per_block'],row['median_ms']*1000/row['blocks'])
            self.assertAlmostEqual(row['encryptions_per_second'],1000/row['median_ms'])
            self.assertGreaterEqual(row['stddev_ms'],0)
            self.assertAlmostEqual(row['speedup'],baseline['median_ms']/row['median_ms'])
            self.assertTrue(0<=row['plaintext_avalanche_percent']<=100)
            self.assertTrue(0<=row['key_avalanche_percent']<=100)
            self.assertTrue(0<=row['block_entropy']<=4)

    def test_comparison_repetitions_are_bounded(self):
        for repeats in (0,2,16,True,5.5):
            with self.assertRaises(ValueError):research.compare_request(self.body(b'x',repeats=repeats))

    def test_report_reference_contains_original_round_statistics(self):
        r=research.recorded()['original_study']
        rows=r['roundwise_security_summary.csv']
        self.assertEqual([int(row['rounds']) for row in rows],[4,6,8,10])
        self.assertEqual(sum(int(row['sample_count']) for row in rows),90000)
        small=next(row for row in r['bucket_security_performance_summary.csv'] if row['mode']=='adaptaes' and row['payload_bucket']=='1-128')
        self.assertAlmostEqual(float(small['mean_encryption_time_ns'])/1e6,.6005300943396227)

    def test_probe_evidence_matches_measured_samples(self):
        for kind in ('differential','linear'):
            r=research.experiments(kind,42,1,lambda _:None)
            for row in r['rows']:
                sample=row['details'][0]
                self.assertEqual(len(bytes.fromhex(sample['plaintext'])),16)
                if kind=='differential':
                    a=bytes.fromhex(sample['ciphertext']);b=bytes.fromhex(sample['changed_ciphertext'])
                    self.assertEqual(sample['changed_bits'],sum((x^y).bit_count() for x,y in zip(a,b)))
                else:self.assertAlmostEqual(abs(sample['correlation']),row['max_abs_correlation'])

    def test_reject_bad_inputs(self):
        for body in (self.body(b''),self.body(b'x',mode='unknown'),self.body(b'x',block=2),self.body(b'x',bit=128),{'data':'invalid','key':'123'}):
            with self.assertRaises(ValueError):research.encrypt_request(body)

    def test_actual_integral_recovery_and_no_forced_success(self):
        progress=[]
        r=research.experiments('integral',20261029,1,progress.append)
        self.assertEqual(r['rows'][0]['verified_recoveries'],1)
        detail=r['rows'][0]['details'][0]
        self.assertEqual(detail['lab_master_key'],detail['recovered_master_key'])
        self.assertTrue(detail['aes10_challenge_verified'])
        self.assertEqual(len(detail['oracle_samples']),2)
        self.assertEqual(len(r['rows']),6)
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
