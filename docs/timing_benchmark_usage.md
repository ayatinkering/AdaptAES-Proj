# AES Timing Benchmark Usage

## Purpose

This stage runs AES timing measurements on the payloads generated from
PCAP-derived payload lengths.

It uses the AES implementation files in `scripts/`:

```text
aes_core.py       -> standard AES-128, 10 rounds
aes_reduced.py    -> fixed reduced AES, 4 rounds
aes_adaptive.py   -> AdaptAES, selected by payload size
```

No avalanche testing is performed in this stage.

## Input

```text
results/payloads/*_payload_manifest.csv
results/payloads/*_payloads.bin
```

The manifest provides:

```text
payload_id
payload_length
byte_offset
adaptaes_rounds
```

The binary file stores generated plaintext payload bytes.

## Command

Run a small test:

```bash
python3 scripts/benchmark_dataset_timings.py \
  --payload-dir results/payloads \
  --out-dir results/timings \
  --limit 5
```

Run the current project benchmark:

```bash
python3 scripts/benchmark_dataset_timings.py \
  --payload-dir results/payloads \
  --out-dir results/timings \
  --limit 50
```

Increase `--limit` for stronger final measurements. Pure Python AES is slow, so
increase gradually.

## Output

Per dataset:

```text
results/timings/<dataset>_timings.csv
results/timings/<dataset>_timing_summary.json
```

Combined:

```text
results/timings/combined_timing_summary.json
```

## Measured Modes

```text
standard_aes_10      -> 10 rounds for all payloads
fixed_reduced_aes_4  -> 4 rounds for all payloads
adaptaes             -> 4/6/8/10 rounds based on payload length
```

## Metrics

```text
encryption_time_ns
decryption_time_ns
throughput_mb_s
rounds_used
```

Each encryption result is decrypted immediately and checked against the original
payload. A mismatch raises an error and stops the run.
