"""Exploratory chosen-plaintext probes of the ARX middle step.

This is not exhaustive cryptanalysis or a security proof.
"""
import csv,random,statistics
from pathlib import Path
import matplotlib.pyplot as plt
import aes_core as a
import aes_hybrid as h

out=Path('figures');out.mkdir(exist_ok=True)
rng=random.Random(93471)
def all_xor(values):
    v=0
    for x in values:v^=x
    return v

results=[]
for design in ('AES-4','AES-4 + ARX','AES-5'):
    zeros=[]
    recoveries=0
    final_counts=[]
    # Try all 16 choices of the variable input byte. Reuse one unknown key
    # across all structures, as a chosen-plaintext attacker would.
    for trial in range(5):
        key=rng.randbytes(16)
        survivor=[set(range(256)) for _ in range(16)]
        for variable_byte in range(16):
            base=bytearray(rng.randbytes(16))
            cts=[]
            for value in range(256):
                base[variable_byte]=value
                if design=='AES-4':ct=a.encrypt_block(bytes(base),key,4)
                elif design=='AES-5':ct=a.encrypt_block(bytes(base),key,5)
                else:ct=h.encrypt_block(bytes(base),key)
                cts.append(ct)
            for j in range(16):
                # Same last-round attack equation, now tried with every
                # possible active input-byte position.
                keep=set()
                for guess in survivor[j]:
                    value=0
                    for ct in cts:value^=a.INV_S_BOX[ct[j]^guess]
                    if value==0:keep.add(guess)
                survivor[j]=keep
            zeros.append(sum(len(s) for s in survivor))
        if design=='AES-4' and all(len(s)==1 for s in survivor):recoveries+=1
        final_counts.append(sum(len(s) for s in survivor))
    results.append({'design':design,'keys':5,'chosen_blocks_per_key':4096,
                    'master_key_candidate_trials':recoveries,
                    'mean_remaining_byte_guesses':statistics.mean(final_counts),
                    'final_remaining_byte_guesses':final_counts[-1]})

with (out/'arx_probe_results.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=results[0]);w.writeheader();w.writerows(results)

# Show the exact internal point where the 4-round integral property changes.
# This is white-box diagnostic information; an attacker only sees ciphertexts.
internal=[]
for trial in range(10):
    key=rng.randbytes(16);keys=a.expand_key(key)
    base=bytearray(rng.randbytes(16))
    before=[[],[],[],[]]
    for value in range(256):
        base[0]=value
        s=a.add_round_key(list(base),keys[0])
        for r in range(1,4):
            s=a.add_round_key(a.mix_columns(a.shift_rows(a.sub_bytes(s))),keys[r])
            if r==2:
                before[0].append(s[:])
                s=h.arx(s,key)
                before[1].append(s[:])
            if r==3:before[2].append(s[:])
        before[3].append(a.add_round_key(a.shift_rows(a.sub_bytes(s)),keys[4]))
    for stage,states in zip(('after AES round 2','after ARX','after AES round 3','ciphertext'),before):
        balanced=sum(all_xor(state[j] for state in states)==0 for j in range(16))
        internal.append({'trial':trial,'stage':stage,'balanced_byte_positions':balanced})
with (out/'arx_internal_balance.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=internal[0]);w.writeheader();w.writerows(internal)

labels=['after AES round 2','after ARX','after AES round 3','ciphertext']
means=[statistics.mean(r['balanced_byte_positions'] for r in internal if r['stage']==x) for x in labels]
plt.figure(figsize=(8,5));plt.bar(labels,means)
plt.ylabel('Mean byte positions with zero XOR (out of 16)')
plt.title('Where the integral pattern disappears (10 chosen sets)')
plt.xticks(rotation=15,ha='right');plt.tight_layout()
plt.savefig(out/'arx_internal_balance.png',dpi=180);plt.close()
for r in results:print(r)
print('internal balance means:',dict(zip(labels,means)))
