"""Direct, repeatable hybrid-vs-five-round comparison."""
import csv
import random
import statistics
import time
from pathlib import Path

import matplotlib.pyplot as plt
import aes_core
import aes_hybrid

OUT=Path('figures'); OUT.mkdir(exist_ok=True)
rng=random.Random(77229)
versions={
    'AES-4':lambda b,k:aes_core.encrypt_block(b,k,4),
    'AES-4 + ARX':aes_hybrid.encrypt_block,
    'AES-5':lambda b,k:aes_core.encrypt_block(b,k,5),
}

# Matched input/key pairs and random execution order make comparisons fairer.
timing=[]
for size in (16,64,256,768,1536):
    key=rng.randbytes(16)
    blocks=[rng.randbytes(16) for _ in range((size+15)//16)]
    samples={name:[] for name in versions}
    for _ in range(40):
        order=list(versions); rng.shuffle(order)
        for name in order:
            fn=versions[name]
            start=time.perf_counter_ns()
            for block in blocks: fn(block,key)
            samples[name].append((time.perf_counter_ns()-start)/1e6)
    for name in versions:
        timing.append({'bytes':size,'design':name,
                       'median_ms':round(statistics.median(samples[name]),4),
                       'min_ms':round(min(samples[name]),4),
                       'max_ms':round(max(samples[name]),4)})

with (OUT/'direct_timing.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=timing[0]);w.writeheader();w.writerows(timing)

# Flip one random plaintext bit; count changed ciphertext bits.
diffusion={name:[] for name in versions}
for _ in range(1500):
    key=rng.randbytes(16)
    original=rng.randbytes(16)
    changed=bytearray(original)
    bit=rng.randrange(128);changed[bit//8]^=1<<(bit%8)
    for name,fn in versions.items():
        left=fn(original,key);right=fn(bytes(changed),key)
        diffusion[name].append(sum((a^b).bit_count() for a,b in zip(left,right)))

rows=[]
for name,values in diffusion.items():
    rows.append({'design':name,'pairs':len(values),
                 'mean_changed_bits':round(statistics.mean(values),3),
                 'std_changed_bits':round(statistics.pstdev(values),3),
                 'min_changed_bits':min(values),'max_changed_bits':max(values)})
with (OUT/'direct_diffusion.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)

plt.figure(figsize=(8,5))
for name in versions:
    pts=[r for r in timing if r['design']==name]
    plt.plot([r['bytes'] for r in pts],[r['median_ms'] for r in pts],marker='o',label=name)
plt.title('Direct speed comparison: same inputs, 40 runs')
plt.xlabel('Message size (bytes)');plt.ylabel('Median encryption time (ms)')
plt.grid(alpha=.25);plt.legend();plt.tight_layout()
plt.savefig(OUT/'direct_speed.png',dpi=180);plt.close()

plt.figure(figsize=(8,5))
plt.boxplot([diffusion[name] for name in versions],tick_labels=list(versions),showfliers=False)
plt.axhline(64,color='gray',linestyle='--',label='Half of 128 bits')
plt.title('One-bit input changes: 1,500 matched cases')
plt.ylabel('Ciphertext bits changed');plt.legend();plt.tight_layout()
plt.savefig(OUT/'direct_diffusion.png',dpi=180);plt.close()

for row in timing:print(row)
for row in rows:print(row)
