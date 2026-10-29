"""Adapters around the unchanged final teammate archive; no import-time experiments."""
from __future__ import annotations
import ast
import base64
import csv
import hashlib
import importlib.util
import json
import math
import random
import statistics
import sys
import time
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'research/hybrid_final'
MANIFEST = json.loads((SOURCE / 'SOURCE_MANIFEST.json').read_text())


def load_source(name):
    spec = importlib.util.spec_from_file_location('teammate_' + name, SOURCE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


aes = load_source('aes_core')
_previous_core = sys.modules.get('aes_core')
sys.modules['aes_core'] = aes
try:
    hybrid = load_source('aes_hybrid')
    adaptive = load_source('aes_adaptive')
finally:
    if _previous_core is None:
        sys.modules.pop('aes_core', None)
    else:
        sys.modules['aes_core'] = _previous_core

# Compile only the supplied pure function definitions. The plotting and experiment
# loops in evaluate_hybrid.py are never imported or run as server side effects.
_tree = ast.parse((SOURCE / 'evaluate_hybrid.py').read_text())
_functions = ast.Module(body=[n for n in _tree.body if isinstance(n, ast.FunctionDef)
                             and n.name in ('square_attack', 'original_key')], type_ignores=[])
_attack_globals = {'aes_core': aes, 'RNG': random.Random(20261029)}
exec(compile(_functions, str(SOURCE / 'evaluate_hybrid.py'), 'exec'), _attack_globals)

MODES = {
    'adaptive_arx': 'AdaptAES–ARX', 'adaptive': 'Original AdaptAES',
    'hybrid': 'AES-4 + ARX', 'aes4': 'AES-4', 'aes5': 'AES-5',
    'aes6': 'AES-6', 'aes8': 'AES-8', 'aes10': 'AES-10',
}


def selection(mode, length):
    if mode not in MODES:
        raise ValueError('Choose a supported cipher configuration.')
    if not 0 < length <= 65536:
        raise ValueError('Payload must contain 1–65,536 bytes.')
    rounds = adaptive.select_rounds(length) if mode.startswith('adaptive') else 4 if mode == 'hybrid' else int(mode[3:])
    arx = mode == 'hybrid' or (mode == 'adaptive_arx' and rounds == 4)
    return {'mode': mode, 'label': MODES[mode], 'rounds': rounds, 'arx': arx,
            'algorithm': f'AES-{rounds}' + (' + ARX' if arx else ''),
            'scope': 'New adaptive integration' if mode == 'adaptive_arx' else 'Final teammate implementation'}


def block_functions(config, key):
    if config['arx']:
        return lambda b: hybrid.encrypt_block(b, key), lambda b: hybrid.decrypt_block(b, key)
    return lambda b: aes.encrypt_block(b, key, config['rounds']), lambda b: aes.decrypt_block(b, key, config['rounds'])


def crypt(data, key, config, decrypt=False):
    # Exact supplied wrappers where they exist; fixed reduced references use the
    # supplied padding and block primitive without changing its transformations.
    if config['arx']:
        return hybrid.decrypt(data, key) if decrypt else hybrid.encrypt(data, key)
    if config['mode'] == 'adaptive':
        return adaptive.adaptaes_decrypt(data, key, config['original_length'])[0] if decrypt else adaptive.adaptaes_encrypt(data, key)[0]
    if config['rounds'] == 10:
        return aes.decrypt_data(data, key) if decrypt else aes.encrypt_data(data, key)
    enc, dec = block_functions(config, key)
    if decrypt:
        return aes.unpad_data(b''.join(dec(data[i:i+16]) for i in range(0, len(data), 16)))
    padded = aes.pad_data(data)
    return b''.join(enc(padded[i:i+16]) for i in range(0, len(padded), 16))


def trace(block, key, config):
    keys = aes.expand_key(key)
    stages = []
    def save(name, state, **extra):
        stages.append({'name': name, 'hex': bytes(state).hex(), 'bytes': list(state), **extra})
    state = list(block)
    save('Input block', state)
    state = aes.add_round_key(state, keys[0]); save('Initial AddRoundKey', state)
    for r in range(1, config['rounds'] + 1):
        state = aes.sub_bytes(state); save(f'Round {r} · SubBytes', state)
        state = aes.shift_rows(state); save(f'Round {r} · ShiftRows', state)
        if r < config['rounds']:
            state = aes.mix_columns(state); save(f'Round {r} · MixColumns', state)
        state = aes.add_round_key(state, keys[r]); save(f'Round {r} · AddRoundKey', state)
        if config['arx'] and r == 2:
            before = [f'{int.from_bytes(bytes(state[i:i+4]), "little"):08x}' for i in range(0, 16, 4)]
            state = hybrid.arx(state, key)
            after = [f'{int.from_bytes(bytes(state[i:i+4]), "little"):08x}' for i in range(0, 16, 4)]
            save('ARX · two mixing iterations', state, words_before=before, words_after=after,
                 rotations=[7, 11, 17, 23], iterations=2)
    expected = block_functions(config, key)[0](block)
    if bytes(state) != expected:
        raise ValueError('Trace did not match supplied cipher.')
    return stages


def decode_request(body):
    try:
        key = bytes.fromhex(body.get('key', ''))
        if len(key) != 16: raise ValueError()
    except (ValueError, TypeError):
        raise ValueError('Key must contain exactly 32 hexadecimal characters.')
    try:
        data = base64.b64decode(body.get('data', ''), validate=True)
    except Exception:
        raise ValueError('Input bytes must be valid base64.')
    config = selection(body.get('mode', 'adaptive_arx'), len(data))
    config['original_length'] = len(data)
    return data, key, config


def encrypt_request(body):
    data, key, config = decode_request(body)
    start = time.perf_counter_ns(); ciphertext = crypt(data, key, config); enc_ns = time.perf_counter_ns() - start
    start = time.perf_counter_ns(); recovered = crypt(ciphertext, key, config, True); dec_ns = time.perf_counter_ns() - start
    if recovered != data: raise ValueError('Exact round-trip verification failed.')
    padded = aes.pad_data(data)
    index = int(body.get('block', 0))
    if not 0 <= index < len(padded) // 16: raise ValueError('Selected block does not exist.')
    block = padded[index*16:index*16+16]
    stages = trace(block, key, config)
    changed = bytearray(block); bit = int(body.get('bit', 0))
    if not 0 <= bit < 128: raise ValueError('Select a bit from 0 to 127.')
    changed[bit//8] ^= 1 << (bit % 8)
    fn = block_functions(config, key)[0]
    left, right = fn(block), fn(bytes(changed))
    changed_trace = trace(bytes(changed), key, config)
    diffusion_stages = [{"name": a["name"], "changed_bits": sum((x ^ y).bit_count() for x,y in zip(a["bytes"], b["bytes"]))} for a,b in zip(stages,changed_trace)]
    changed_bits = sum((x ^ y).bit_count() for x, y in zip(left, right))
    return {'config': config, 'original_bytes': len(data), 'padding_bytes': len(padded)-len(data),
            'ciphertext_bytes': len(ciphertext), 'blocks': len(padded)//16, 'block_index': index,
            'ciphertext': ciphertext.hex(), 'recovered': base64.b64encode(recovered).decode(), 'verified': True,
            'encryption_ms': enc_ns/1e6, 'decryption_ms': dec_ns/1e6,
            'throughput_mib_s': len(data)/2**20/(enc_ns/1e9), 'trace': stages,
            'diffusion': {'bit': bit, 'left': left.hex(), 'right': right.hex(), 'changed_bits': changed_bits,
                          'percent': changed_bits/128*100, 'stages': diffusion_stages},
            'measurement': 'Single run; trace and diffusion collection excluded from timing'}


def compare_request(body):
    data,key,_=decode_request(body)
    if len(data)>4096:raise ValueError('Comparison is limited to 4,096 bytes.')
    names=['aes4','hybrid','aes5','aes6','aes8','aes10','adaptive','adaptive_arx']
    repeats=body.get('repeats',5)
    if type(repeats) is not int or not 3<=repeats<=15:raise ValueError('Choose 3–15 timed repetitions.')
    samples={m:[] for m in names};dec_samples={m:[] for m in names};cpu_samples={m:[] for m in names};outputs={}
    for repeat in range(repeats+1):
        order=names[repeat%len(names):]+names[:repeat%len(names)]
        if repeat%2:order=list(reversed(order))
        for mode in order:
            config=selection(mode,len(data));config['original_length']=len(data)
            cpu_start=time.thread_time_ns();start=time.perf_counter_ns();ct=crypt(data,key,config);elapsed=time.perf_counter_ns()-start;cpu_elapsed=time.thread_time_ns()-cpu_start
            start=time.perf_counter_ns();recovered=crypt(ct,key,config,True);dec_elapsed=time.perf_counter_ns()-start
            if recovered!=data:raise ValueError('Comparison verification failed.')
            outputs[mode]=ct
            if repeat:samples[mode].append(elapsed);dec_samples[mode].append(dec_elapsed);cpu_samples[mode].append(cpu_elapsed)
    baseline=statistics.median(samples['aes10']);rows=[];block=aes.pad_data(data)[:16]
    for mode in names:
        config=selection(mode,len(data));fn=block_functions(config,key)[0];cipher=fn(block);plain_ae=[];key_ae=[]
        for bit in range(8):
            changed=bytearray(block);changed[bit//8]^=1<<(bit%8)
            plain_ae.append(sum((a^b).bit_count() for a,b in zip(cipher,fn(bytes(changed))))/128*100)
            changed_key=bytearray(key);changed_key[bit//8]^=1<<(bit%8)
            key_ct=block_functions(config,bytes(changed_key))[0](block)
            key_ae.append(sum((a^b).bit_count() for a,b in zip(cipher,key_ct))/128*100)
        ct=outputs[mode];entropies=[]
        for offset in range(0,len(ct),16):
            counts=Counter(ct[offset:offset+16]);entropies.append(-sum((v/16)*math.log2(v/16) for v in counts.values()))
        enc_ms=statistics.median(samples[mode])/1e6;dec_ms=statistics.median(dec_samples[mode])/1e6
        rows.append({'design':MODES[mode],'mode':mode,'rounds':config['rounds'],'arx':config['arx'],
                     'median_ms':enc_ms,'decryption_ms':dec_ms,'throughput_mib_s':len(data)/2**20/(enc_ms/1000),
                     'decryption_mib_s':len(data)/2**20/(dec_ms/1000),'speedup':baseline/(enc_ms*1e6),
                     'reduction_percent':(1-enc_ms*1e6/baseline)*100,'verified':True,
                     'plaintext_avalanche_percent':statistics.mean(plain_ae),'key_avalanche_percent':statistics.mean(key_ae),
                     'block_entropy':statistics.mean(entropies),'diffusion_samples':8,
                     'cpu_ms':statistics.median(cpu_samples[mode])/1e6,
                     'mean_ms':statistics.mean(samples[mode])/1e6,'min_ms':min(samples[mode])/1e6,'max_ms':max(samples[mode])/1e6,
                     'stddev_ms':statistics.stdev(samples[mode])/1e6,'cv_percent':statistics.stdev(samples[mode])/statistics.mean(samples[mode])*100,
                     'roundtrip_ms':statistics.median([a+b for a,b in zip(samples[mode],dec_samples[mode])])/1e6,
                     'us_per_block':enc_ms*1000/(len(ct)//16),'us_per_byte':enc_ms*1000/len(data),
                     'encryptions_per_second':1000/enc_ms,'saved_ms':baseline/1e6-enc_ms,
                     'blocks':len(ct)//16,'ciphertext_bytes':len(ct),'padding_bytes':len(ct)-len(data),
                     'padding_overhead_percent':(len(ct)-len(data))/len(data)*100,'sample_count':repeats,
                     'encryption_samples_ms':[n/1e6 for n in samples[mode]]})
    return {'rows':rows,'bytes':len(data),'repeats':repeats,
            'scope':'Same payload and key; one warm-up excluded; rotating execution order; configured number of timed repetitions; medians. Padding and key expansion included. Encryption and decryption timed separately; round-trip verified.',
            'statistical_scope':'Eight single-bit plaintext flips and eight single-bit key flips on the first padded block. Entropy averaged over individual 16-byte ciphertext blocks (empirical maximum 4 bits/byte). Statistical indicators, not attack resistance.'}


def recorded():
    catalog = {}
    for path in sorted(SOURCE.rglob('*.csv')):
        with path.open(newline='') as handle: rows = list(csv.DictReader(handle))
        catalog[str(path.relative_to(SOURCE))] = rows
    study={}
    for path in sorted((ROOT/'research/report_reference').glob('*.csv')):
        with path.open(newline='') as handle:study[path.name]=list(csv.DictReader(handle))
    return {'original_study':study,'archive': MANIFEST['archive'], 'sha256': MANIFEST['sha256'], 'datasets': catalog,
            'files': list(MANIFEST['files']), 'environment': 'Not recorded in supplied archive'}


def experiments(kind, seed, trials, emit):
    """Bounded live adapters; mathematics follows the named source script.

    Integral calls the actual supplied pure functions. Other loops follow supplied
    definitions with reduced live sample budgets, explicitly returned in results.
    """
    rng = random.Random(seed)
    configs = [('AES-4',4,False),('AES-4 + ARX',4,True),('AES-5',5,False),('AES-6',6,False),('AES-8',8,False),('AES-10',10,False)]
    rows = []
    for design, rounds, arx in configs:
        curves=[]; successes=0; per_trial=[]; biases=[]; linear=[]; counts=[]
        for trial in range(trials):
            key=rng.randbytes(16)
            enc = (lambda b: hybrid.encrypt_block(b,key)) if arx else (lambda b: aes.encrypt_block(b,key,rounds))
            dec = (lambda b: hybrid.decrypt_block(b,key)) if arx else (lambda b: aes.decrypt_block(b,key,rounds))
            if kind=='integral':
                _attack_globals['RNG'] = rng
                oracle_samples=[]
                def oracle(b,k):
                    ct=enc(b)
                    if len(oracle_samples)<2:oracle_samples.append({'plaintext':b.hex(),'ciphertext':ct.hex()})
                    return ct
                survivors, curve = _attack_globals['square_attack'](oracle, key)
                curves.append(curve)
                verified=False
                if design=='AES-4' and all(len(s)==1 for s in survivors):
                    recovered=_attack_globals['original_key'](bytes(next(iter(s)) for s in survivors))
                    verified=recovered==key
                successes+=verified
                proof={}
                if design=='AES-4' and verified:
                    challenge=b'AdaptAES laboratory challenge'
                    sealed=aes.encrypt_data(challenge,key)
                    unsealed=aes.decrypt_data(sealed,recovered)
                    proof={'lab_master_key':key.hex(),'recovered_master_key':recovered.hex(),
                           'aes10_ciphertext':sealed.hex(),'aes10_recovered_text':unsealed.decode(),
                           'aes10_challenge_verified':unsealed==challenge}
                per_trial.append({'trial':trial+1,'candidates':[len(s) for s in survivors],
                                  'verified_master_key_recovered': verified if design=='AES-4' else None,'oracle_samples':oracle_samples,'candidate_curve':curve,**proof})
            elif kind=='substitution':
                a,b=rng.randbytes(32),rng.randbytes(32)
                def seal(p):
                    p=aes.pad_data(p);return b''.join(enc(p[i:i+16]) for i in range(0,len(p),16))
                ca,cb=seal(a),seal(b); altered=ca[:16]+cb[16:]
                got=aes.unpad_data(b''.join(dec(altered[i:i+16]) for i in range(0,len(altered),16)))
                successes+=got==a[:16]+b[16:]
                p=rng.randbytes(16);repeat=seal(p*2)
                per_trial.append({'source_first_block':a[:16].hex(),'target_first_block':b[:16].hex(),
                                  'delivered_first_block':got[:16].hex(),'source_ciphertext_block':ca[:16].hex(),
                                  'target_ciphertext_block':cb[:16].hex(),'modified_ciphertext_block':altered[:16].hex(),'modified_accepted':True,
                                  'repeated_blocks_visible':repeat[:16]==repeat[16:32]})
            elif kind=='differential':
                n=256;hist=[[0]*256 for _ in range(16)];ones=[0]*128
                for _ in range(n):
                    p=rng.randbytes(16);q=bytearray(p);q[0]^=1
                    left,right=enc(p),enc(bytes(q))
                    if _==0:per_trial.append({'plaintext':p.hex(),'changed_plaintext':bytes(q).hex(),'ciphertext':left.hex(),'changed_ciphertext':right.hex(),'changed_bits':sum((a^b).bit_count() for a,b in zip(left,right))})
                    for j,(x,y) in enumerate(zip(left,right)):
                        d=x^y;hist[j][d]+=1
                        for bit in range(8):ones[j*8+bit]+=(d>>bit)&1
                counts.append(max(max(h) for h in hist));biases.append(max(abs(x/n-.5) for x in ones))
            elif kind=='linear':
                n=256; px=[0]*16;cy=[0]*128
                # Exact selected masks from probe_linear.py: first bit of each
                # plaintext byte against all output bits, using bitset parity.
                for i in range(n):
                    p=rng.randbytes(16);c=enc(p)
                    if i==0:per_trial.append({'plaintext':p.hex(),'ciphertext':c.hex()})
                    for j in range(16):px[j]|=((p[j]>>7)&1)<<i
                    for j in range(128):cy[j]|=((c[j//8]>>(7-j%8))&1)<<i
                best=max(((1-2*(x^y).bit_count()/n,pi,ci) for pi,x in enumerate(px) for ci,y in enumerate(cy)),key=lambda item:abs(item[0]))
                linear.append(abs(best[0]));per_trial[-1].update(input_bit=best[1]*8,output_bit=best[2],correlation=best[0])
            else: raise ValueError('Unsupported experiment.')
            emit({'completed':len(rows)*trials+trial+1,'total':len(configs)*trials,'design':design})
        entry={'design':design,'rounds':rounds,'arx':arx,'trials':trials}
        if kind=='integral':entry.update(curve=[statistics.mean(c[i] for c in curves) for i in range(4)],
                                         queries_per_trial=1024, verified_recoveries=successes if design=='AES-4' else None,
                                         final_candidates=statistics.mean(c[-1] for c in curves), details=per_trial)
        elif kind=='substitution':entry.update(accepted=successes,details=per_trial)
        elif kind=='differential':entry.update(pairs_per_key=256,max_difference_count=statistics.mean(counts),max_bit_bias=statistics.mean(biases),details=per_trial)
        else:entry.update(plaintexts_per_key=256,max_abs_correlation=statistics.mean(linear),details=per_trial)
        rows.append(entry)
    return {'kind':kind,'seed':seed,'trials':trials,'rows':rows,'source':'Live bounded adapter of final teammate code',
            'scope': 'Original integral equation; only AES-4 has supplied master-key recovery verification' if kind=='integral' else
                     'Unauthenticated independent-block wrapper test' if kind=='substitution' else
                     'Reduced live sample budget; not directly comparable to recorded full-sample probes',
            'archive_sha256':MANIFEST['sha256']}


def stream_request(body):
    """Measured synthetic packet workload; no network traffic or payload capture."""
    sizes = body.get('sizes', [64,128,129,512,513,1024,1025])
    if not isinstance(sizes,list) or not 1 <= len(sizes) <= 12:
        raise ValueError('Choose 1–12 packet sizes.')
    if any(type(size) is not int or not 1 <= size <= 4096 for size in sizes):
        raise ValueError('Each packet size must be an integer from 1 to 4096 bytes.')
    seed = body.get('seed',20261029)
    if type(seed) is not int or not 0 <= seed <= 2**32-1:
        raise ValueError('Seed must be an integer from 0 to 4294967295.')
    rng = random.Random(seed); key = rng.randbytes(16); rows=[]
    for index,size in enumerate(sizes):
        data=rng.randbytes(size); timings={}; verified=True
        configs={mode:selection(mode,size) for mode in ['adaptive_arx','aes10']}
        for config in configs.values():config['original_length']=size
        samples={mode:[] for mode in configs}
        for repeat in range(4):
            order=list(configs) if (repeat+index)%2 == 0 else list(reversed(configs))
            for mode in order:
                start=time.perf_counter_ns();ciphertext=crypt(data,key,configs[mode]);elapsed=time.perf_counter_ns()-start
                if crypt(ciphertext,key,configs[mode],True)!=data:raise ValueError('Packet verification failed.')
                if repeat:samples[mode].append(elapsed/1e6)
        adaptive_ms=statistics.median(samples['adaptive_arx']);aes10_ms=statistics.median(samples['aes10'])
        rows.append({'packet':index+1,'bytes':size,'algorithm':configs['adaptive_arx']['algorithm'],
                     'rounds':configs['adaptive_arx']['rounds'],'arx':configs['adaptive_arx']['arx'],
                     'adaptive_ms':adaptive_ms,'aes10_ms':aes10_ms,'speedup':aes10_ms/adaptive_ms,
                     'adaptive_mib_s':size/2**20/(adaptive_ms/1000),'aes10_mib_s':size/2**20/(aes10_ms/1000),'verified':verified})
    total_bytes=sum(sizes);adaptive_total=sum(r['adaptive_ms'] for r in rows);aes_total=sum(r['aes10_ms'] for r in rows)
    return {'rows':rows,'seed':seed,'packets':len(rows),'total_bytes':total_bytes,'repeats':3,
            'adaptive_total_ms':adaptive_total,'aes10_total_ms':aes_total,'speedup':aes_total/adaptive_total,
            'adaptive_mib_s':total_bytes/2**20/(adaptive_total/1000),'aes10_mib_s':total_bytes/2**20/(aes_total/1000),
            'verified':all(r['verified'] for r in rows),
            'methodology':'Generated byte payloads; shared key; one warm-up plus three timed encryptions per method per packet; rotating order; medians; padding and key expansion included; decryption verified outside timing. Totals sum packet medians. No network timing.',
            'archive_sha256':MANIFEST['sha256']}
