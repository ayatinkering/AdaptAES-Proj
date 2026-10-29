"""Exploratory differential and linear probes; no security proof or key recovery."""
import csv,random,statistics,math
from pathlib import Path
import matplotlib.pyplot as plt
import aes_core as aes
import aes_hybrid as hybrid

OUT=Path('figures');OUT.mkdir(exist_ok=True)
rng=random.Random(716903)
versions={'AES-4':lambda p,k:aes.encrypt_block(p,k,4),
          'AES-4 + ARX':hybrid.encrypt_block,
          'AES-5':lambda p,k:aes.encrypt_block(p,k,5),
          'AES-10':lambda p,k:aes.encrypt_block(p,k,10)}
KEYS=8;PAIRS=2048

# Chosen difference: flip one input bit. For every output byte, ask whether
# any XOR difference occurs unusually often. Compare with a random-looking
# baseline of PAIRS/256 occurrences per byte value.
rows=[]
for name,enc in versions.items():
    maxima=[];chis=[];bit_bias=[]
    for _ in range(KEYS):
        key=rng.randbytes(16)
        hist=[[0]*256 for _ in range(16)]
        bit_ones=[0]*128
        for _ in range(PAIRS):
            p=rng.randbytes(16);q=bytearray(p);q[0]^=1
            c=enc(p,key);d=enc(bytes(q),key)
            for j,(x,y) in enumerate(zip(c,d)):
                diff=x^y;hist[j][diff]+=1
                for bit in range(8):bit_ones[j*8+bit]+=(diff>>bit)&1
        expected=PAIRS/256
        maxima.append(max(max(h) for h in hist))
        chis.append(max(sum((v-expected)**2/expected for v in h) for h in hist))
        bit_bias.append(max(abs(v/PAIRS-.5) for v in bit_ones))
    rows.append({'design':name,'keys':KEYS,'pairs_per_key':PAIRS,
                 'mean_largest_byte_difference_count':round(statistics.mean(maxima),2),
                 'largest_byte_difference_count_seen':max(maxima),
                 'mean_max_byte_chi_square':round(statistics.mean(chis),2),
                 'mean_max_bit_bias':round(statistics.mean(bit_bias),4),
                 'largest_bit_bias_seen':round(max(bit_bias),4)})

# Monte Carlo null: independent uniform output-byte differences and bits.
# Maximum statistics automatically account for searching many positions.
null_max=[];null_chi=[];null_bias=[]
for _ in range(200):
    h=[[0]*256 for _ in range(16)]
    ones=[0]*128
    for _ in range(PAIRS):
        for j in range(16):
            v=rng.randrange(256);h[j][v]+=1
            for b in range(8):ones[8*j+b]+=(v>>b)&1
    null_max.append(max(max(x) for x in h))
    null_chi.append(max(sum((v-PAIRS/256)**2/(PAIRS/256) for v in x) for x in h))
    null_bias.append(max(abs(v/PAIRS-.5) for v in ones))
rows.append({'design':'random reference (simulation)','keys':200,
             'pairs_per_key':PAIRS,
             'mean_largest_byte_difference_count':round(statistics.mean(null_max),2),
             'largest_byte_difference_count_seen':max(null_max),
             'mean_max_byte_chi_square':round(statistics.mean(null_chi),2),
             'mean_max_bit_bias':round(statistics.mean(null_bias),4),
             'largest_bit_bias_seen':round(max(null_bias),4)})
with (OUT/'differential_linear_probe.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)

fig,axes=plt.subplots(1,2,figsize=(11,4))
names=[r['design'] for r in rows]
axes[0].bar(names,[r['mean_largest_byte_difference_count'] for r in rows])
axes[0].set_title('Most frequent output-byte difference')
axes[0].set_ylabel('Count among 2,048 chosen pairs')
axes[1].bar(names,[r['mean_max_bit_bias'] for r in rows])
axes[1].set_title('Largest output-bit change bias')
axes[1].set_ylabel('Distance from 50%')
for ax in axes:ax.tick_params(axis='x',rotation=20)
plt.tight_layout();plt.savefig(OUT/'differential_linear_probe.png',dpi=180)
for r in rows:print(r)
