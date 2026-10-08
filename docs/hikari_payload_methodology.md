# AdaptAES HIKARI PCAP Methodology

## Dataset Use

The HIKARI PCAP files used here are anonymized packet captures. They preserve
packet headers, packet timing, original frame lengths, and enough TCP/UDP header
metadata to recover original payload lengths. The actual payload bytes are not
preserved in the example anonymized capture.

Because AdaptAES selects AES rounds from packet payload size, the benchmark uses
the original TCP/UDP payload lengths extracted from packet headers and generates
synthetic plaintext payloads of the same lengths.

## Payload Length Extraction

For TCP packets:

```text
payload_length = IP total length - IP header length - TCP header length
```

For UDP packets:

```text
payload_length = UDP length - 8
```

This is more accurate than using the captured packet length because the capture
may be truncated after headers.

## AdaptAES Round Policy

```text
1-128 bytes      -> 4 rounds
129-512 bytes    -> 6 rounds
513-1024 bytes   -> 8 rounds
>1024 bytes      -> 10 rounds
```

## Benchmark Pipeline

```text
HIKARI PCAP
  -> extract TCP/UDP payload lengths
  -> generate synthetic plaintext payloads with matching lengths
  -> run AES-10, fixed reduced-round AES, and AdaptAES
  -> measure encryption time, throughput, entropy, and avalanche effect
  -> generate CSV results and graphs
```

## Claim Boundary

Correct claim:

```text
AdaptAES is evaluated using real packet-size distributions extracted from
anonymized HIKARI-2021 PCAP traffic.
```

Avoid this claim:

```text
AdaptAES encrypts the original HIKARI packet payload contents.
```
