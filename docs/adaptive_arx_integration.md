# AdaptAES–ARX integration

The original AdaptAES implementation and historical results remain the baseline.
The new experimental policy changes only the smallest payload category:

| Original payload bytes | Original | New experiment |
|---|---|---|
| 1–128 | AES-4 | AES-4 with two ARX mixing iterations after AES round 2 |
| 129–512 | AES-6 | AES-6 |
| 513–1024 | AES-8 | AES-8 |
| >1024 | AES-10 | AES-10 |

`scripts/aes_hybrid.py` is imported from the teammate-supplied
`AdaptAES_hybrid_research.zip`. It uses the same master key for AES and ARX.
This is a custom research cipher, not standardized AES or authenticated encryption.
The original length and selection of the original versus ARX variant must be known
to the receiver; the ciphertext does not encode or authenticate those choices.

## Run

From the repository root, using Python 3.10+:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/benchmark_adaptive_arx.py --limit 50 --repeats 5
python3 scripts/evaluate_arx_integral.py --trials 20 --sets 4
```

The benchmark needs existing payload manifests and matching binary blobs in
`results/payloads`. Regenerate those using the original README instructions if
necessary. It samples the first N manifest records per dataset, not balanced
categories or chronological PCAP prefixes. Confirm category coverage in results.
The attack experiment generates its own structured blocks and needs no dataset.
Both scripts use only the Python standard library.

Outputs go to `results/adaptive_arx/`; existing plots and timing CSVs are not
overwritten. Use `--out-dir` for benchmark runs and `--out` for attack experiments
to preserve multiple configurations. Repeating a run at the same path replaces
that experiment's output.

## Use from Python

With `scripts` on the Python import path:

```python
from aes_adaptive_arx import adaptaes_arx_encrypt, adaptaes_arx_decrypt

key = bytes(range(16))  # Public example key, not a deployed key.
message = b"AdaptAES research payload"
ciphertext, rounds = adaptaes_arx_encrypt(message, key)
recovered, _ = adaptaes_arx_decrypt(ciphertext, key, len(message))
assert recovered == message
```

## What the measurements mean

The benchmark compares AES-10, original AdaptAES, AdaptAES–ARX, and an adaptive
five-round-minimum policy on identical payloads. Padding and key expansion are
included for every mode. After a warm-up it rotates method order and records
per-payload median encryption/decryption times. Throughput is total input bytes
divided by the sum of those medians. This is a local educational implementation
comparison, not optimized-library AES performance or live-network throughput.

The integral experiment uses identical keys and chosen plaintext sets across
AES-4, AES-4+ARX, AES-5, and AES-10. The attack function receives an encryption
callable and public structures; only the evaluator sees reference round keys.
It reports candidate counts, retention of correct bytes, and actual equality to
the final-round key. It does not invert the key schedule or claim master-key
recovery. Zero surviving candidates means this equation failed, not that other
attacks fail. The bundled teammate results are not copied into current results.

## Build on this in order

1. Run the four-method benchmark and confirm how often the ARX branch executes.
2. Run the integral experiment for all 16 active-byte positions, using separate
   output names, and repeat with additional independently seeded keys.
3. Compare one versus two ARX iterations, insertion positions, and an XOR-only
   control. Keep these as named variants; do not silently change the default.
4. Select parameters on one set of seeds and evaluate on held-out seeds. Compare
   against AES-5 at matched cost, not just AES-10.
5. Repeat on existing network-derived workloads with balanced category experiments
   reported separately. Save raw repetitions and uncertainty for final research.
6. Add frontend views of actual benchmark JSON and candidate-filtering outputs.
   Display measured performance and attack-specific outcomes, not security scores.

A defensible question is whether an inexpensive ARX insertion disrupts the tested
integral property at lower cost than adding an AES round. Establishing broad
cryptanalytic strength would require further analysis of the custom construction.
