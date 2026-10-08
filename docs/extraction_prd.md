# AdaptAES Extraction PRD

## Goal

Extract packet-level metadata from the available HIKARI anonymized PCAP files so
the AdaptAES benchmark can run on realistic packet-size distributions.

This stage does not perform AES encryption. It prepares the benchmark input.

## Input

Raw PCAP files:

```text
data/raw/*.pcap
```

Current available files include:

```text
Monday_2021-03-29.anonymized.pcap
Tuesday_2021-03-30.anonymized.pcap
Wednesday_2021-04-07.anonymized.pcap
Saturday_2021-04-10_1628.anonymized.pcap
Saturday_2021-05-01_0520.anonymized.pcap
Sunday_2021-03-28.anonymized.pcap
```

## Important Dataset Constraint

The anonymized HIKARI PCAPs preserve headers, timestamps, original frame lengths,
and protocol metadata, but the actual payload bytes may not be present.

Therefore, the extraction stage must calculate original payload length from
packet headers instead of using captured byte length.

## Required Extracted Fields

Each output CSV row represents one TCP/UDP packet with a nonzero payload length.

```text
packet_index
timestamp_seconds
captured_length
original_frame_length
protocol
src_ip
dst_ip
src_port
dst_port
ip_total_length
payload_length
adaptaes_rounds
```

## Payload Length Rules

For TCP:

```text
payload_length = IP total length - IP header length - TCP header length
```

For UDP:

```text
payload_length = UDP length - 8
```

These formulas recover the original transport-layer payload length from headers.

## AdaptAES Round Bucket

The extraction stage also assigns the round count that AdaptAES would use:

```text
1-128 bytes      -> 4 rounds
129-512 bytes    -> 6 rounds
513-1024 bytes   -> 8 rounds
>1024 bytes      -> 10 rounds
```

## Output

For each PCAP:

```text
results/extracted/<pcap_name>_payload_lengths.csv
results/extracted/<pcap_name>_summary.json
```

The CSV is the benchmark input. The JSON summary is used in the report.

## Usability Checks

A PCAP is usable if:

```text
parsed_tcp_udp_ipv4_packets > 0
packets_with_payload > 0
payload_bins has at least two nonempty size buckets
adaptaes_round_counts has at least two nonempty round choices
```

Best case:

```text
all four payload bins are represented
```

## Exact Command

Run extraction on all current PCAPs:

```bash
python3 scripts/batch_extract_payload_lengths.py \
  --pcap-dir "/home/ayati/Documents/Github Repos/AdaptAES/data/raw" \
  --out-dir results/extracted
```

Run extraction on one PCAP:

```bash
python3 scripts/extract_payload_lengths.py \
  --pcap "/home/ayati/Documents/Github Repos/AdaptAES/data/raw/Monday_2021-03-29.anonymized.pcap" \
  --out-csv results/extracted/monday_payload_lengths.csv \
  --summary results/extracted/monday_summary.json
```

## Next Stage After Extraction

The benchmark stage will read `payload_length` values from the CSV files and
generate synthetic plaintext payloads of the same lengths:

```text
plaintext = random bytes of payload_length
```

This preserves the real traffic size distribution while avoiding reliance on
payload contents that are not present in the anonymized PCAP.
