# Security and Performance Analysis

Run from `AdaptAES-Proj`:

```bash
python scripts/security_performance_analysis.py \
  --payload-dir results/payloads \
  --timing-dir results/timings \
  --out-dir results/analysis
```

The default analyzes every payload for which an existing manifest and binary
are present. It never creates plaintext payloads. An optional
`--max-payloads-per-dataset N` limits analysis to the first N manifest entries
for a quick run. Existing timing rows are joined by dataset, payload ID, and
mode; payloads without a matching timing remain in security summaries and do
not contribute to performance averages.

## Outputs

- `roundwise_security_summary.csv`: averages for 4, 6, 8, and 10 rounds.
- `bucket_security_performance_summary.csv`: all three modes grouped by the
  four payload-size ranges, including available timing counts, mean payload
  size, encryption/decryption time and throughput, speedup and time reduction
  against AES-10, and security metrics.
- `security_per_payload.csv`: individual security measurements.
- `byte_frequency_by_round.csv` and, when Matplotlib is installed,
  `byte_frequency_by_round.png`.
- `security_performance_summary.json`: machine-readable summaries and coverage
  notes.

## Measurement definitions and limits

Security measurements use the first 16-byte block of each stored plaintext,
with PKCS#7 padding applied when the payload is shorter than one block. A
single plaintext bit and a single key bit are flipped independently. The
reported avalanche is changed ciphertext bits divided by 128; NPCR is the
percentage of changed ciphertext bytes; UACI is the mean absolute byte-value
difference normalized by 255. These are byte/block-level adaptations of
image-analysis metrics, not image NPCR/UACI.

Entropy and chi-square use the 16 ciphertext bytes for each sample and are
averaged. At this block sample size, they are descriptive summaries, not
powerful randomness tests or proof of cryptographic security. Correlation is
Pearson correlation between corresponding bytes in the plaintext and
ciphertext block. The four rounds in the round-wise table are pooled wherever
that round count occurs in the compared modes and payload policy. The
payload-bucket table retains separate mode rows, so its round count follows
the comparison policy: AES-10, fixed AES-4, or the AdaptAES bucket selection.

The timing CSVs are reused as completed; this analysis does not re-encrypt
payloads for timing. Speedup is AES-10 mean encryption time divided by the
mode's mean encryption time. Throughput is total measured payload MiB divided
by total measured time, which avoids averaging per-payload rates.

HIKARI anonymized captures used by this project preserve payload lengths, not
the original payload bytes. Existing generated `.bin` data therefore represents
deterministic synthetic plaintext of real HIKARI-derived lengths. Security
results must be described as measurements on those stored benchmark plaintexts,
not as analysis of original HIKARI application contents.
