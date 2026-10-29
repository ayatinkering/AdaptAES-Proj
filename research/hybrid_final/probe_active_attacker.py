"""Simulated active network attacker against the project's block-by-block wrappers.

The first ciphertext block from one 32-byte message is substituted into
another ciphertext under the same key. No network stack is claimed here.
"""
import csv,random
from pathlib import Path
import matplotlib.pyplot as plt
import aes_core as aes
import aes_hybrid as hybrid

out=Path('figures');out.mkdir(exist_ok=True)
rng=random.Random(44119)
versions={
 'AES-4':(lambda b,k:aes.encrypt_block(b,k,4),lambda b,k:aes.decrypt_block(b,k,4)),
 'AES-4 + ARX':(hybrid.encrypt_block,hybrid.decrypt_block),
 'AES-5':(lambda b,k:aes.encrypt_block(b,k,5),lambda b,k:aes.decrypt_block(b,k,5)),
 'AES-10':(lambda b,k:aes.encrypt_block(b,k,10),lambda b,k:aes.decrypt_block(b,k,10))}

def enc(msg,key,fn):
 p=aes.pad_data(msg)
 return b''.join(fn(p[i:i+16],key) for i in range(0,len(p),16))

def dec(ct,key,fn):
 p=b''.join(fn(ct[i:i+16],key) for i in range(0,len(ct),16))
 return aes.unpad_data(p)

rows=[]
for name,(encrypt,decrypt) in versions.items():
 accepted=controlled=repeats=0
 for _ in range(100):
  key=rng.randbytes(16)
  a_msg=rng.randbytes(32);b_msg=rng.randbytes(32)
  ca=enc(a_msg,key,encrypt);cb=enc(b_msg,key,encrypt)
  # Intercept message B and replace its first encrypted block with A's.
  changed=ca[:16]+cb[16:]
  try:
   got=dec(changed,key,decrypt);accepted+=1
   controlled+=(got[:16]==a_msg[:16] and got[16:]==b_msg[16:])
  except ValueError:pass
  # Identical plaintext blocks become identical ciphertext blocks.
  repeated=rng.randbytes(16)*2
  ct=enc(repeated,key,encrypt)
  repeats+=(ct[:16]==ct[16:32])
 rows.append({'design':name,'trials':100,'substituted_message_accepted':accepted,
              'attacker_selected_block_delivered':controlled,
              'repeated_blocks_visible':repeats})
with (out/'active_attacker_results.csv').open('w',newline='') as f:
 w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
fig,ax=plt.subplots(figsize=(8,4))
xs=range(len(rows));w=.25
ax.bar([x-w for x in xs],[r['substituted_message_accepted'] for r in rows],w,label='Modified message accepted')
ax.bar(xs,[r['attacker_selected_block_delivered'] for r in rows],w,label='Chosen block delivered')
ax.bar([x+w for x in xs],[r['repeated_blocks_visible'] for r in rows],w,label='Repeated blocks visible')
ax.set_xticks(list(xs),[r['design'] for r in rows]);ax.set_ylim(0,110)
ax.set_ylabel('Successful trials out of 100');ax.set_title('Simulated active attacker against block-by-block encryption')
ax.legend(loc='upper center',bbox_to_anchor=(.5,-.12),ncol=2)
fig.tight_layout();fig.savefig(out/'active_attacker_results.png',dpi=180)
for r in rows:print(r)
