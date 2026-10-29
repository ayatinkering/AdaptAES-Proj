"""Simple linear-correlation search over plaintext/ciphertext bit pairs."""
import csv,random
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt
import aes_core as aes
import aes_hybrid as hybrid

out=Path('figures');out.mkdir(exist_ok=True)
rng=random.Random(11832)
versions={'AES-4':lambda p,k:aes.encrypt_block(p,k,4),
          'AES-4 + ARX':hybrid.encrypt_block,
          'AES-5':lambda p,k:aes.encrypt_block(p,k,5),
          'AES-10':lambda p,k:aes.encrypt_block(p,k,10)}
N=2048;KEYS=4
rows=[]
for name,enc in versions.items():
    maxima=[]
    for _ in range(KEYS):
        key=rng.randbytes(16)
        plaintexts=[rng.randbytes(16) for _ in range(N)]
        cts=[enc(p,key) for p in plaintexts]
        pb=np.unpackbits(np.frombuffer(b''.join(plaintexts),dtype=np.uint8).reshape(N,16),axis=1)
        cb=np.unpackbits(np.frombuffer(b''.join(cts),dtype=np.uint8).reshape(N,16),axis=1)
        # Search 16 input bits spread across the block against all 128 output bits.
        xs=(1-2*pb[:,::8].astype(np.int16)).T
        ys=1-2*cb.astype(np.int16)
        corr=np.abs(xs@ys)/N
        maxima.append(float(corr.max()))
    rows.append({'design':name,'keys':KEYS,'plaintexts_per_key':N,
                 'max_abs_correlation_mean':round(sum(maxima)/KEYS,4),
                 'max_abs_correlation_seen':round(max(maxima),4)})

null=[]
for _ in range(200):
    xs=rng.randbytes(N*16)
    ys=rng.randbytes(N*128)
    x=np.unpackbits(np.frombuffer(xs,dtype=np.uint8)).reshape(N,128)[:,::8]
    y=np.unpackbits(np.frombuffer(ys,dtype=np.uint8)).reshape(N,1024)[:,::8]
    null.append(float(np.abs((1-2*x.astype(np.int16)).T@(1-2*y.astype(np.int16))).max()/N))
rows.append({'design':'independent random bits','keys':200,
             'plaintexts_per_key':N,'max_abs_correlation_mean':round(sum(null)/200,4),
             'max_abs_correlation_seen':round(max(null),4)})
with (out/'linear_probe.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
plt.figure(figsize=(8,4));plt.bar([r['design'] for r in rows],[r['max_abs_correlation_mean'] for r in rows])
plt.title('Strongest simple input/output bit correlation')
plt.ylabel('Absolute correlation (16 x 128 bit pairs)')
plt.xticks(rotation=15,ha='right');plt.tight_layout();plt.savefig(out/'linear_probe.png',dpi=180)
for r in rows:print(r)
