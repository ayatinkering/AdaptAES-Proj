# AdaptAES-Proj

**AdaptAES** is an Information Security lab project that evaluates packet-size-adaptive AES round reduction on PCAP-derived network payload sizes.

The project compares three encryption approaches:

| Method | Round Policy |
|---|---|
| Standard AES | 10 rounds for every payload |
| Reduced AES | fixed 4 rounds for every payload |
| AdaptAES | 4/6/8/10 rounds selected by payload size |

The main objective is to measure the performance impact of adaptive AES round selection on realistic network traffic sizes, then compare selected ciphertext statistical indicators against Standard AES.

> Important: this project measures timing and statistical indicators such as avalanche effect, entropy, chi-square, and correlation. It does not claim to prove full cryptanalytic security equivalence between reduced-round AES and standard AES-128.

## Project Summary

Standard AES-128 uses a fixed 10-round structure for every block of input. This project tests a lightweight adaptive idea: smaller network payloads are encrypted with fewer rounds, while larger payloads receive more rounds, and very large payloads use the full 10 rounds.

AdaptAES policy:

| Payload Length | AdaptAES Rounds |
|---:|---:|
| 1-128 bytes | 4 |
| 129-512 bytes | 6 |
| 513-1024 bytes | 8 |
| >1024 bytes | 10 |

The workflow is:

1. Extract payload lengths from anonymized PCAP files.
2. Generate deterministic synthetic plaintext payloads with matching lengths.
3. Encrypt/decrypt payloads using Standard AES, Reduced AES, and AdaptAES.
4. Measure timing, throughput, speedup, and time reduction.
5. Compute selected statistical security indicators.
6. Generate research tables and graphs.

## Repository Structure

```text
.
├── docs/
│   ├── AdaptAES_full_project_report.md
│   ├── benchmarking_prd.md
│   ├── extraction_prd.md
│   ├── hikari_payload_methodology.md
│   ├── payload_generation_prd.md
│   ├── security_performance_analysis.md
│   └── timing_benchmark_usage.md
├── scripts/
│   ├── aes_core.py
│   ├── aes_reduced.py
│   ├── aes_adaptive.py
│   ├── extract_payload_lengths.py
│   ├── batch_extract_payload_lengths.py
│   ├── generate_plaintext_payloads.py
│   ├── validate_generated_payloads.py
│   ├── benchmark_dataset_timings.py
│   ├── security_evaluation.py
│   ├── security_performance_analysis.py
│   ├── print_research_results.py
│   ├── print_analysis_results.py
│   └── generate_graphs.py
└── results/
    ├── extracted/
    ├── payloads/
    ├── timings/
    ├── security/
    ├── analysis/
    └── plots/
```

Raw PCAP files are intentionally excluded from Git because they are large dataset artifacts.

## Important Files

| File | Purpose |
|---|---|
| `scripts/aes_core.py` | Configurable-round AES implementation |
| `scripts/aes_reduced.py` | Fixed 4-round AES wrapper |
| `scripts/aes_adaptive.py` | AdaptAES policy and encrypt/decrypt wrapper |
| `scripts/extract_payload_lengths.py` | Extracts TCP/UDP payload lengths from one PCAP |
| `scripts/batch_extract_payload_lengths.py` | Extracts payload lengths from all PCAPs in a folder |
| `scripts/generate_plaintext_payloads.py` | Generates deterministic payload bytes matching extracted lengths |
| `scripts/benchmark_dataset_timings.py` | Runs encryption/decryption timing benchmarks |
| `scripts/security_performance_analysis.py` | Computes combined timing and statistical indicator summaries |
| `scripts/generate_graphs.py` | Builds final research graphs from structured result CSVs |
| `docs/AdaptAES_full_project_report.md` | Full project report with methodology and results |

## Dataset Notes

The project uses anonymized PCAP files. Because anonymized captures may preserve packet lengths but not usable original payload bytes, this project extracts payload sizes and then generates synthetic plaintext payloads with the same lengths.

This preserves the key experimental variable for AdaptAES:

```text
payload_length -> selected AES round count -> timing/security-indicator measurement
```

Payload length formulas:

```text
TCP payload length = IP total length - IP header length - TCP header length
UDP payload length = UDP length - 8
```

## Current Results Snapshot

Extracted dataset totals:

| Metric | Value |
|---|---:|
| Total packets | 4,587,976 |
| Payload packets | 2,355,051 |
| Payload packet share | 51.33% |
| TCP packets | 4,362,642 |
| UDP packets | 223,030 |

Payload distribution:

| Payload Range | Packet Count | Dataset Share | AdaptAES Rounds |
|---|---:|---:|---:|
| 1-128 B | 502,232 | 21.33% | 4 |
| 129-512 B | 213,169 | 9.05% | 6 |
| 513-1024 B | 93,739 | 3.98% | 8 |
| >1024 B | 1,545,911 | 65.64% | 10 |

Overall timing summary:

| Method | Rounds | Payloads Tested | Avg Enc Time | Avg Dec Time | Enc Time Reduction |
|---|---:|---:|---:|---:|---:|
| Standard AES | 10 | 300 | 48.34 ms | 86.06 ms | 0.00% |
| Reduced AES | 4 | 300 | 19.10 ms | 31.68 ms | 60.50% |
| AdaptAES | 4/6/8/10 | 300 | 47.91 ms | 85.29 ms | 0.88% |

AdaptAES timing by payload range:

| Payload Range | AdaptAES Rounds | Enc Reduction vs AES-10 | Dec Reduction vs AES-10 |
|---|---:|---:|---:|
| 1-128 B | 4 | 61.11% | 63.38% |
| 129-512 B | 6 | 40.44% | 42.24% |
| 513-1024 B | 8 | 20.42% | 21.82% |
| >1024 B | 10 | -0.31% | -0.36% |

Statistical indicator summary by round count:

| Rounds | Avalanche % | Key Avalanche % | Entropy | Correlation |
|---:|---:|---:|---:|---:|
| 4 | 50.011 | 50.010 | 3.941 | 0.001 |
| 6 | 49.916 | 49.989 | 3.942 | -0.003 |
| 8 | 50.227 | 49.923 | 3.941 | 0.001 |
| 10 | 50.012 | 50.009 | 3.942 | 0.000 |

## Final Graphs

Generated plots are stored in:

```text
results/plots/
```

| Graph | File |
|---|---|
| Payload distribution and AdaptAES round selection | `results/plots/graph1_payload_round_selection.png` |
| Encryption time comparison | `results/plots/graph2_encryption_time.png` |
| Decryption time comparison | `results/plots/graph3_decryption_time.png` |
| AdaptAES vs Standard AES encryption time | `results/plots/graph4_encryption_reduction.png` |
| Statistical security characteristics across methods | `results/plots/graph5_security_metrics_vs_rounds.png` |

## Setup

Use Python 3.10+.

Most scripts use the Python standard library. Graph generation requires Matplotlib.

Create a local virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install matplotlib
```

The repository ignores `.venv/`, raw PCAPs, and generated payload binaries.

## Reproduction Instructions

### Step 1: Place PCAP Files

Create a local raw-data directory and place `.pcap` files inside it:

```bash
mkdir -p data/raw
```

Example:

```text
data/raw/Monday_2021-03-29.anonymized.pcap
data/raw/Tuesday_2021-03-30.anonymized.pcap
```

### Step 2: Extract Payload Lengths

```bash
python3 scripts/batch_extract_payload_lengths.py \
  --pcap-dir data/raw \
  --out-dir results/extracted
```

Outputs:

```text
results/extracted/*_payload_lengths.csv
results/extracted/*_summary.json
```

### Step 3: Generate Plaintext Payloads

Default: generate 5,000 payloads per extracted CSV.

```bash
python3 scripts/generate_plaintext_payloads.py \
  --input-dir results/extracted \
  --out-dir results/payloads \
  --sample-size 5000 \
  --seed 42
```

Outputs:

```text
results/payloads/*_payloads.bin
results/payloads/*_payload_manifest.csv
results/payloads/*_payload_summary.json
results/payloads/combined_payload_summary.json
```

### Step 4: Validate Generated Payloads

```bash
python3 scripts/validate_generated_payloads.py \
  --payload-dir results/payloads
```

### Step 5: Run Timing Benchmarks

The pure-Python AES implementation is intentionally educational and can be slow, so the benchmark uses a limit per dataset.

```bash
python3 scripts/benchmark_dataset_timings.py \
  --payload-dir results/payloads \
  --out-dir results/timings \
  --limit 50
```

Outputs:

```text
results/timings/*_timings.csv
results/timings/*_timing_summary.json
results/timings/bucket_timing_summary.csv
results/timings/combined_timing_summary.json
```

### Step 6: Run Combined Statistical Analysis

```bash
python3 scripts/security_performance_analysis.py \
  --payload-dir results/payloads \
  --timing-dir results/timings \
  --out-dir results/analysis
```

Outputs:

```text
results/analysis/roundwise_security_summary.csv
results/analysis/bucket_security_performance_summary.csv
results/analysis/security_per_payload.csv
results/analysis/byte_frequency_by_round.csv
results/analysis/security_performance_summary.json
```

### Step 7: Print Result Tables

Dataset and timing tables:

```bash
python3 scripts/print_research_results.py
```

Combined timing and statistical-indicator tables:

```bash
python3 scripts/print_analysis_results.py
```

### Step 8: Generate Graphs

```bash
.venv/bin/python scripts/generate_graphs.py
```

Outputs:

```text
results/plots/graph1_payload_round_selection.png
results/plots/graph2_encryption_time.png
results/plots/graph3_decryption_time.png
results/plots/graph4_encryption_reduction.png
results/plots/graph5_security_metrics_vs_rounds.png
```

## Quick Demo Commands

If the result files already exist, use these commands for a quick project demo:

```bash
python3 scripts/print_research_results.py
python3 scripts/print_analysis_results.py
.venv/bin/python scripts/generate_graphs.py
```

Then open:

```text
docs/AdaptAES_full_project_report.md
results/plots/
```

## Interpreting the Results

Reduced AES is the fastest because every payload uses only 4 rounds.

Standard AES is the baseline because every payload uses 10 rounds.

AdaptAES changes behavior by payload size:

- small packets use 4 rounds and show the highest speed improvement
- medium packets use 6 rounds and show moderate speed improvement
- large packets use 8 rounds and show smaller speed improvement
- very large packets use 10 rounds and behave like Standard AES

The statistical-indicator results show avalanche values near 50%, entropy values close across methods, and correlation values near zero. These results support statistical comparability under the selected tests, not full cryptanalytic equivalence.

## Limitations

- The AES implementation is educational pure Python, not optimized production AES.
- Payload bytes are synthetic, but payload lengths come from PCAP-derived traffic.
- Statistical indicators are not a substitute for cryptanalysis.
- Raw PCAP files and generated payload binaries are intentionally not tracked in Git.

## Recommended Evaluation Files

For a teacher/project evaluation, show:

```text
docs/AdaptAES_full_project_report.md
README.md
scripts/aes_adaptive.py
scripts/benchmark_dataset_timings.py
scripts/security_performance_analysis.py
scripts/generate_graphs.py
results/analysis/bucket_security_performance_summary.csv
results/plots/
```

