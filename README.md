# AdaptAES-Proj

AdaptAES-Proj is an Information Security lab project that prepares anonymized
HIKARI PCAP traffic for packet-size-adaptive AES benchmarking.

This repository currently contains the extraction stage:

- Parse HIKARI anonymized PCAP files.
- Extract TCP/UDP packet metadata.
- Recover original payload lengths from packet headers.
- Assign AdaptAES round buckets based on payload size.
- Produce CSV benchmark inputs and JSON dataset summaries.

## Why Payload Length Extraction Is Needed

The anonymized HIKARI PCAPs preserve packet headers and original length metadata,
but payload bytes may not be available in the capture. For AdaptAES, the critical
input is payload size, so the project calculates original transport-layer payload
lengths from TCP/UDP headers.

## Payload Length Formulas

TCP:

```text
payload_length = IP total length - IP header length - TCP header length
```

UDP:

```text
payload_length = UDP length - 8
```

## AdaptAES Round Policy

```text
1-128 bytes      -> 4 rounds
129-512 bytes    -> 6 rounds
513-1024 bytes   -> 8 rounds
>1024 bytes      -> 10 rounds
```

## Run Extraction

For all PCAP files:

```bash
python3 scripts/batch_extract_payload_lengths.py \
  --pcap-dir "/path/to/data/raw" \
  --out-dir results/extracted
```

For one PCAP file:

```bash
python3 scripts/extract_payload_lengths.py \
  --pcap "/path/to/file.pcap" \
  --out-csv results/extracted/file_payload_lengths.csv \
  --summary results/extracted/file_summary.json
```

## Current Outputs

The `results/extracted/` directory contains extracted payload-length CSV files
and summary JSON files generated from the available HIKARI PCAPs.

Raw PCAP files are intentionally excluded from Git because they are dataset
artifacts and can be large.
