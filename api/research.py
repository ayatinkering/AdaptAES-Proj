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
    changed_bits = sum((x ^ y).bit_count() for x, y in zip(left, right))
    return {'config': config, 'original_bytes': len(data), 'padding_bytes': len(padded)-len(data),
            'ciphertext_bytes': len(ciphertext), 'blocks': len(padded)//16, 'block_index': index,
            'ciphertext': ciphertext.hex(), 'recovered': base64.b64encode(recovered).decode(), 'verified': True,
            'encryption_ms': enc_ns/1e6, 'decryption_ms': dec_ns/1e6,
            'throughput_mib_s': len(data)/2**20/(enc_ns/1e9), 'trace': stages,
            'diffusion': {'bit': bit, 'left': left.hex(), 'right': right.hex(), 'changed_bits': changed_bits,
                          'percent': changed_bits/128*100},
            'measurement': 'Single run; trace and diffusion collection excluded from timing'}


def compare_request(body):
    data, key, _ = decode_request(body)
    if len(data) > 4096: raise ValueError('Live comparison is limited to 4,096 bytes.')
    names = ['aes10', 'adaptive', 'adaptive_arx', 'aes5']
    samples = {m: [] for m in names}
    for repeat in range(6):
        for mode in names[repeat % 4:] + names[:repeat % 4]:
            config = selection(mode, len(data)); config['original_length'] = len(data)
            start = time.perf_counter_ns(); ct = crypt(data, key, config); elapsed = time.perf_counter_ns()-start
            if crypt(ct, key, config, True) != data: raise ValueError('Comparison verification failed.')
            if repeat: samples[mode].append(elapsed)
    baseline = statistics.median(samples['aes10'])
    return {'rows': [{'design': MODES[m], 'median_ms': statistics.median(v)/1e6,
                      'throughput_mib_s': len(data)/2**20/(statistics.median(v)/1e9),
                      'reduction_percent': (1-statistics.median(v)/baseline)*100} for m,v in samples.items()],
            'bytes': len(data), 'repeats': 5, 'scope': 'Local padded-message encryption; rotating order; one warm-up'}


def recorded():
    catalog = {}
    for path in sorted(SOURCE.rglob('*.csv')):
        with path.open(newline='') as handle: rows = list(csv.DictReader(handle))
        catalog[str(path.relative_to(SOURCE))] = rows
    return {'archive': MANIFEST['archive'], 'sha256': MANIFEST['sha256'], 'datasets': catalog,
            'files': list(MANIFEST['files']), 'environment': 'Not recorded in supplied archive'}


def experiments(kind, seed, trials, emit):
    """Bounded live adapters; mathematics follows the named source script.

    Integral calls the actual supplied pure functions. Other loops follow supplied
    definitions with reduced live sample budgets, explicitly returned in results.
    """
    rng = random.Random(seed)
    configs = [('AES-4',4,False),('AES-4 + ARX',4,True),('AES-5',5,False),('AES-10',10,False)]
    rows = []
    for design, rounds, arx in configs:
        curves=[]; successes=0; per_trial=[]; biases=[]; linear=[]; counts=[]
        for trial in range(trials):
            key=rng.randbytes(16)
            enc = (lambda b: hybrid.encrypt_block(b,key)) if arx else (lambda b: aes.encrypt_block(b,key,rounds))
            dec = (lambda b: hybrid.decrypt_block(b,key)) if arx else (lambda b: aes.decrypt_block(b,key,rounds))
            if kind=='integral':
                _attack_globals['RNG'] = rng
                survivors, curve = _attack_globals['square_attack'](lambda b,k: enc(b), key)
                curves.append(curve)
                verified=False
                if design=='AES-4' and all(len(s)==1 for s in survivors):
                    recovered=_attack_globals['original_key'](bytes(next(iter(s)) for s in survivors))
                    verified=recovered==key
                successes+=verified
                per_trial.append({'trial':trial+1,'candidates':[len(s) for s in survivors], 'verified_master_key_recovered': verified if design=='AES-4' else None})
            elif kind=='substitution':
                a,b=rng.randbytes(32),rng.randbytes(32)
                def seal(p):
                    p=aes.pad_data(p);return b''.join(enc(p[i:i+16]) for i in range(0,len(p),16))
                ca,cb=seal(a),seal(b); altered=ca[:16]+cb[16:]
                got=aes.unpad_data(b''.join(dec(altered[i:i+16]) for i in range(0,len(altered),16)))
                successes+=got==a[:16]+b[16:]
                p=rng.randbytes(16);repeat=seal(p*2)
                per_trial.append({'source_first_block':a[:16].hex(),'target_first_block':b[:16].hex(),
                                  'delivered_first_block':got[:16].hex(),'modified_accepted':True,
                                  'repeated_blocks_visible':repeat[:16]==repeat[16:32]})
            elif kind=='differential':
                n=256;hist=[[0]*256 for _ in range(16)];ones=[0]*128
                for _ in range(n):
                    p=rng.randbytes(16);q=bytearray(p);q[0]^=1
                    for j,(x,y) in enumerate(zip(enc(p),enc(bytes(q)))):
                        d=x^y;hist[j][d]+=1
                        for bit in range(8):ones[j*8+bit]+=(d>>bit)&1
                counts.append(max(max(h) for h in hist));biases.append(max(abs(x/n-.5) for x in ones))
            elif kind=='linear':
                n=256; px=[0]*16;cy=[0]*128
                # Exact selected masks from probe_linear.py: first bit of each
                # plaintext byte against all output bits, using bitset parity.
                for i in range(n):
                    p=rng.randbytes(16);c=enc(p)
                    for j in range(16):px[j]|=((p[j]>>7)&1)<<i
                    for j in range(128):cy[j]|=((c[j//8]>>(7-j%8))&1)<<i
                linear.append(max(abs(1-2*(x^y).bit_count()/n) for x in px for y in cy))
            else: raise ValueError('Unsupported experiment.')
            emit({'completed':len(rows)*trials+trial+1,'total':4*trials,'design':design})
        entry={'design':design,'trials':trials}
        if kind=='integral':entry.update(curve=[statistics.mean(c[i] for c in curves) for i in range(4)],
                                         queries_per_trial=1024, verified_recoveries=successes if design=='AES-4' else None,
                                         final_candidates=statistics.mean(c[-1] for c in curves), details=per_trial)
        elif kind=='substitution':entry.update(accepted=successes,details=per_trial)
        elif kind=='differential':entry.update(pairs_per_key=256,max_difference_count=statistics.mean(counts),max_bit_bias=statistics.mean(biases))
        else:entry.update(plaintexts_per_key=256,max_abs_correlation=statistics.mean(linear))
        rows.append(entry)
    return {'kind':kind,'seed':seed,'trials':trials,'rows':rows,'source':'Live bounded adapter of final teammate code',
            'scope': 'Original integral equation; only AES-4 has supplied master-key recovery verification' if kind=='integral' else
                     'Unauthenticated independent-block wrapper test' if kind=='substitution' else
                     'Reduced live sample budget; not directly comparable to recorded full-sample probes',
            'archive_sha256':MANIFEST['sha256']}
