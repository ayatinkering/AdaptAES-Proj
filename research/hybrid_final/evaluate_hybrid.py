"""Reproducible local attack and performance comparison. Run in this folder."""
import csv
import random
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt

import aes_core
import aes_hybrid

OUT = Path('figures')
OUT.mkdir(exist_ok=True)
RNG = random.Random(20261029)
TRIALS = 20


def square_attack(encrypt, key):
    candidates = [set(range(256)) for _ in range(16)]
    counts = []
    for _ in range(4):
        base = bytearray(RNG.randbytes(16))
        ciphertexts = []
        for x in range(256):
            base[0] = x
            ciphertexts.append(encrypt(bytes(base), key))
        for j in range(16):
            candidates[j] = {g for g in candidates[j]
                             if __import__('functools').reduce(
                                 lambda a, ct: a ^ aes_core.INV_S_BOX[ct[j] ^ g],
                                 ciphertexts, 0) == 0}
        counts.append(sum(len(c) for c in candidates))
    return candidates, counts


def original_key(round_key):
    words = [None] * 20
    for i in range(4):
        words[16+i] = list(round_key[4*i:4*i+4])
    for i in range(19, 3, -1):
        temp = words[i-1][:]
        if i % 4 == 0:
            temp = aes_core.sub_word(aes_core.rot_word(temp))
            temp[0] ^= aes_core.RCON[i//4]
        words[i-4] = [a ^ b for a,b in zip(words[i], temp)]
    return bytes(sum(words[:4], []))


rows = []
curves = {}
for name, fn in [('AES-4', lambda b,k: aes_core.encrypt_block(b,k,4)),
                 ('AES-4 + ARX', aes_hybrid.encrypt_block),
                 ('AES-5', lambda b,k: aes_core.encrypt_block(b,k,5)),
                 ('AES-6', lambda b,k: aes_core.encrypt_block(b,k,6)),
                 ('AES-10', lambda b,k: aes_core.encrypt_block(b,k,10))]:
    successes = 0
    all_counts = []
    times = []
    for trial in range(TRIALS):
        key = RNG.randbytes(16)
        t = time.perf_counter()
        candidates, counts = square_attack(fn,key)
        times.append(time.perf_counter()-t)
        all_counts.append(counts)
        if name == 'AES-4' and all(len(c)==1 for c in candidates):
            recovered = original_key(bytes(next(iter(c)) for c in candidates))
            successes += (recovered == key)
        elif name != 'AES-4':
            # The final-round-key inversion formula is specific to unmodified
            # four-round AES. Zero survivors means this attack's condition fails.
            successes += False
    curves[name] = [statistics.mean(c[i] for c in all_counts) for i in range(4)]
    rows.append({'design':name, 'trials':TRIALS,
                 'key_recoveries_by_this_attack':successes,
                 'mean_attack_seconds':round(statistics.mean(times),3),
                 'mean_surviving_guesses_after_1024_queries':round(curves[name][-1],2)})

with (OUT/'attack_results.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)

plt.figure(figsize=(8,5))
for name in curves:
    plt.plot([256,512,768,1024],curves[name],marker='o',label=name)
plt.yscale('symlog',linthresh=1)
plt.xlabel('Chosen messages encrypted')
plt.ylabel('Remaining byte-key guesses (total across 16 positions)')
plt.title('Four-round integral attack: candidate filtering')
plt.legend();plt.grid(alpha=.2);plt.tight_layout()
plt.savefig(OUT/'attack_candidates.png',dpi=180);plt.close()

sizes=[16,64,256,768,1536]
bench=[]
for size in sizes:
    payload=RNG.randbytes(size)
    key=RNG.randbytes(16)
    padded=aes_core.pad_data(payload)
    for name,fn in [('AES-4',lambda b: aes_core.encrypt_block(b,key,4)),
                    ('AES-4 + ARX',lambda b: aes_hybrid.encrypt_block(b,key)),
                    ('AES-5',lambda b: aes_core.encrypt_block(b,key,5)),
                    ('AES-6',lambda b: aes_core.encrypt_block(b,key,6)),
                    ('AES-10',lambda b: aes_core.encrypt_block(b,key,10))]:
        samples=[]
        for _ in range(7):
            start=time.perf_counter()
            for i in range(0,len(padded),16): fn(padded[i:i+16])
            samples.append((time.perf_counter()-start)*1000)
        bench.append({'bytes':size,'design':name,'median_ms':round(statistics.median(samples),3)})
with (OUT/'speed_results.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=bench[0]);w.writeheader();w.writerows(bench)
plt.figure(figsize=(8,5))
for name in curves:
    pts=[r for r in bench if r['design']==name]
    plt.plot(sizes,[r['median_ms'] for r in pts],marker='o',label=name)
plt.xlabel('Payload size (bytes)');plt.ylabel('Encryption time (ms)')
plt.title('Pure-Python encryption speed (median of 7 runs)')
plt.legend();plt.grid(alpha=.2);plt.tight_layout()
plt.savefig(OUT/'speed_comparison.png',dpi=180);plt.close()

for row in rows: print(row)
print('Graphs and CSV files saved in',OUT.resolve())
