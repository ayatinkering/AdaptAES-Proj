# AdaptAES Benchmarking PRD

## Goal

Build the benchmarking stage for AdaptAES using the extracted payload-length CSV
files produced from HIKARI PCAPs.

This stage compares three encryption modes:

```text
1. AES-10 baseline
2. Fixed reduced-round AES
3. AdaptAES packet-size-adaptive AES
```

The output must be quantitative CSV results and graphs suitable for the final
lab report and resume.

## Scope

This stage starts after extraction is complete.

Input:

```text
results/extracted/*_payload_lengths.csv
```

Output:

```text
results/benchmarks/*.csv
results/benchmarks/*.json
results/graphs/*.png
```

Raw PCAP files are not required for this stage.

## Dataset Assumption

The HIKARI anonymized PCAPs preserve original payload lengths but do not preserve
actual payload bytes. Therefore, the benchmark generates synthetic plaintext
payloads with the same length as each extracted packet payload.

For each row:

```text
payload_length -> generate payload_length random bytes
```

This preserves the real packet-size distribution while allowing encryption tests
to run consistently.

## Encryption Modes

### Mode 1: AES-10 Baseline

Purpose:

```text
Represents standard AES-128 behavior.
```

Configuration:

```text
rounds = 10
```

### Mode 2: Fixed Reduced-Round AES

Purpose:

```text
Represents prior lightweight AES approaches that use one reduced round count for
all inputs.
```

Configuration:

```text
rounds = 4
```

or, if the report wants a less aggressive comparison:

```text
rounds = 6
```

Recommended default:

```text
rounds = 4
```

### Mode 3: AdaptAES

Purpose:

```text
Select AES rounds dynamically from packet payload size.
```

Policy:

```text
1-128 bytes      -> 4 rounds
129-512 bytes    -> 6 rounds
513-1024 bytes   -> 8 rounds
>1024 bytes      -> 10 rounds
```

## Required Implementation Files

```text
src/adaptaes/__init__.py
src/adaptaes/policy.py
src/adaptaes/payloads.py
src/adaptaes/aes_variable_rounds.py
src/adaptaes/metrics.py
src/adaptaes/benchmark.py
src/adaptaes/plots.py
```

Optional CLI:

```text
src/adaptaes/cli.py
```

## AES Implementation Requirement

Most standard crypto libraries only expose full AES and do not allow custom
round counts. Therefore, implement an educational AES-128 encryption core with a
configurable round count.

Important report warning:

```text
Reduced-round AES is implemented only for controlled academic benchmarking and
is not intended for secure deployment.
```

## Benchmark Sampling

Do not benchmark every row by default. The extracted files contain millions of
payload lengths.

Default sample size:

```text
50,000 payloads per CSV
```

For quick testing:

```text
5,000 payloads per CSV
```

For final results:

```text
50,000 to 100,000 payloads per CSV
```

Sampling should be deterministic:

```text
random_seed = 42
```

## Payload Generation

For each selected payload length:

```text
plaintext = deterministic pseudorandom bytes of payload_length
```

Use a seeded generator so results can be reproduced.

Do not store generated plaintext payloads in Git.

## Required Metrics

For each encryption mode:

```text
dataset_name
sample_id
payload_length
mode
rounds_used
encryption_time_ns
decryption_time_ns
throughput_mb_s
ciphertext_entropy
```

For avalanche testing:

```text
dataset_name
payload_length
rounds_used
bit_difference_ratio
```

## Metric Definitions

### Encryption Time

Time required to encrypt one generated payload.

Use:

```text
time.perf_counter_ns()
```

### Decryption Time

Time required to decrypt one ciphertext.

Use:

```text
time.perf_counter_ns()
```

### Throughput

```text
throughput_mb_s = payload_size_mb / encryption_time_seconds
```

### Ciphertext Entropy

Use Shannon entropy over ciphertext bytes.

Expected range:

```text
0 to 8 bits per byte
```

Higher is generally better.

### Avalanche Effect

For selected samples:

```text
1. Generate plaintext P
2. Flip one bit to produce P'
3. Encrypt P and P'
4. Compare ciphertext bit differences
5. avalanche = changed_bits / total_bits
```

Ideal AES-like behavior is close to:

```text
0.5
```

## Required Output Files

Per dataset benchmark:

```text
results/benchmarks/<dataset>_benchmark.csv
results/benchmarks/<dataset>_benchmark_summary.json
results/benchmarks/<dataset>_avalanche.csv
```

Combined outputs:

```text
results/benchmarks/combined_benchmark.csv
results/benchmarks/combined_summary.json
```

Graphs:

```text
results/graphs/payload_size_distribution.png
results/graphs/round_distribution.png
results/graphs/encryption_time_by_mode.png
results/graphs/throughput_by_mode.png
results/graphs/entropy_by_mode.png
results/graphs/avalanche_by_rounds.png
results/graphs/security_performance_tradeoff.png
```

## Implementation Steps

### Step 1: Create Project Package

Create:

```text
src/adaptaes/
```

Add reusable modules for policy, payload generation, AES, metrics, benchmark,
and plotting.

### Step 2: Implement AdaptAES Policy

Function:

```text
select_rounds(payload_length) -> int
```

Expected behavior:

```text
1-128      -> 4
129-512    -> 6
513-1024   -> 8
>1024      -> 10
```

### Step 3: Implement Deterministic Payload Generator

Function:

```text
generate_payload(length, rng) -> bytes
```

Output must be exactly `length` bytes.

### Step 4: Implement Variable-Round AES

Functions:

```text
encrypt(payload, key, rounds) -> bytes
decrypt(ciphertext, key, rounds) -> bytes
```

Requirements:

```text
AES block size = 16 bytes
AES-128 key size = 16 bytes
PKCS#7 padding for arbitrary payload lengths
rounds must support 4, 6, 8, 10
decryption must recover original plaintext
```

### Step 5: Implement Metrics

Functions:

```text
shannon_entropy(data) -> float
throughput_mb_s(payload_length, encryption_time_ns) -> float
avalanche_score(payload, key, rounds) -> float
```

### Step 6: Implement Benchmark Runner

Inputs:

```text
payload-length CSV path
sample size
random seed
fixed reduced round count
output directory
```

For each sampled payload length:

```text
run AES-10
run fixed reduced AES
run AdaptAES
record metrics
```

### Step 7: Implement Summary Generator

For each mode, calculate:

```text
mean encryption time
median encryption time
mean decryption time
mean throughput
mean entropy
mean rounds used
sample count
```

### Step 8: Implement Graph Generator

Use benchmark CSVs to generate the required graphs.

Graphs must include titles, axes labels, legends, and readable units.

### Step 9: Verification

Run a small benchmark first:

```text
sample_size = 1,000
```

Check:

```text
all modes produce output
decryption returns original plaintext
no negative timings
round counts match policy
CSV files are created
graphs are created
```

Then run the final benchmark:

```text
sample_size = 50,000 per dataset
```

## Success Criteria

The benchmarking stage is complete when:

```text
AES-10, fixed reduced AES, and AdaptAES all run on extracted HIKARI payload sizes
benchmark CSVs are generated
summary JSON files are generated
all required graphs are generated
decryption correctness is verified
avalanche scores are produced
results are reproducible using seed 42
```

## Report Claim

Use this wording:

```text
AdaptAES was benchmarked using real packet payload-length distributions
extracted from anonymized HIKARI-2021 PCAP files. Synthetic plaintext payloads
with matching lengths were generated for encryption, enabling controlled
comparison of standard AES-128, fixed reduced-round AES, and adaptive-round AES.
```
