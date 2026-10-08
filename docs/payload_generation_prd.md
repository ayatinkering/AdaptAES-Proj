# Synthetic Payload Generation PRD

## Goal

Prepare plaintext payload inputs for the AES benchmarking scripts without
implementing the AES algorithms in this stage.

This stage reads extracted payload-length CSV files and generates deterministic
synthetic plaintext payloads with matching lengths.

## Input

Extraction outputs:

```text
results/extracted/*_payload_lengths.csv
```

Each row already contains:

```text
packet_index
timestamp_seconds
protocol
src_ip
dst_ip
src_port
dst_port
payload_length
adaptaes_rounds
```

## Output

For each extracted CSV:

```text
results/payloads/<dataset>_payloads.bin
results/payloads/<dataset>_payload_manifest.csv
results/payloads/<dataset>_payload_summary.json
```

Combined summary:

```text
results/payloads/combined_payload_summary.json
```

## Output Design

Payload bytes are stored in one binary file per dataset instead of thousands of
small files.

The manifest CSV tells the algorithm scripts how to read each payload:

```text
payload_id
dataset_name
source_packet_index
timestamp_seconds
protocol
src_ip
dst_ip
src_port
dst_port
payload_length
adaptaes_rounds
byte_offset
sha256
```

To read one payload:

```python
with open(payload_bin, "rb") as f:
    f.seek(byte_offset)
    payload = f.read(payload_length)
```

## Generation Rule

For each sampled row:

```text
payload_length = row["payload_length"]
plaintext = deterministic random bytes of payload_length
```

The generated plaintext length must exactly match the extracted payload length.

## Reproducibility

Default seed:

```text
42
```

The generator uses:

```text
seed + dataset_name
```

This means the same dataset, sample size, and seed will always produce the same
payload files and hashes.

## Default Sampling

Default:

```text
5,000 payloads per dataset
```

This is enough for algorithm testing and avoids creating very large local files.

For final benchmarking, use:

```text
50,000 payloads per dataset
```

Generate every payload only if storage is available:

```text
--all
```

## Exact Command

Generate default test payloads:

```bash
python3 scripts/generate_plaintext_payloads.py \
  --input-dir results/extracted \
  --out-dir results/payloads \
  --sample-size 5000 \
  --seed 42
```

Generate final larger payloads:

```bash
python3 scripts/generate_plaintext_payloads.py \
  --input-dir results/extracted \
  --out-dir results/payloads \
  --sample-size 50000 \
  --seed 42
```

## Handoff To Algorithm Scripts

The AES scripts should take:

```text
payload binary path
payload manifest CSV path
```

For each manifest row:

```text
read bytes from byte_offset for payload_length
run AES mode
record results using payload_id and dataset_name
```

The algorithm scripts should not recalculate payload lengths from PCAP files.
They should trust the manifest.

## Validation Checklist

This stage is correct when:

```text
every manifest row has payload_length > 0
payload file size equals sum(payload_length)
each row's sha256 matches the bytes read from the payload file
payload_count equals requested sample size unless the source CSV has fewer rows
outputs are reproducible with the same seed
```
