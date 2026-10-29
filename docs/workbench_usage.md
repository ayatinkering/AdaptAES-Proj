# AdaptAES cipher workbench

The interface uses the final teammate archive preserved byte-for-byte in
`research/hybrid_final/`. `SOURCE_MANIFEST.json` records every original file's
SHA-256. Original experiments, figures, and CSVs can still be run/read separately.
The UI's source viewer shows those exact files, not the API adapters.

## Start locally

Requirements: Python 3.10+, Node.js 22+, npm. The server has no Python dependencies.

```bash
cd web
npm install
npm run build
cd ..
python3 -m api.server
```

Open http://127.0.0.1:8000 . Change the port with `--port 8001`.
For frontend edits, run `npm run dev` inside `web` to watch/rebuild, keep the Python
server running, then refresh the browser. No separate development origin is used.

The planned FastAPI/Vite stack was simplified to React + esbuild and Python's
standard-library HTTP server because package network access was unavailable during
implementation. It has no database, account, external API, or model dependency.
Frontend packages are pinned; the Departure Mono font is self-hosted with its license.
This is a loopback-only local classroom app, not a production hosting configuration.

## Screens

- **Workbench:** arbitrary UTF-8 text or binary files up to 64 KiB, exact boundary
  samples, original/adaptive hybrid/fixed cipher selection, encryption/decryption,
  raw downloads, verified selected-block state trace, ARX word view, and bit-flip
  diffusion. Matched comparison is limited to 4 KiB and five repeats after warm-up.
- **Analysis:** supplied recorded integral/differential/linear/block-substitution
  evidence and bounded local experiments (one to three trials). Local jobs run in
  a separate process, can be cancelled, and have a 180-second polling timeout.
- **Research:** separate padded and raw-block timing collections, original CSVs,
  full exact source viewer, evidence index, and original study context/report.

The new adaptive hybrid adapter applies the exact fixed hybrid only to 1–128 byte
payloads, retaining original AES-6/8/10 above that. This wiring is new; the archive's
`aes_hybrid.py` itself always runs four rounds plus ARX.

## Measurement and interpretation

Input/key bytes and payload contents are not logged or persisted. Job results live
in memory until process shutdown or eviction; explicit user exports create files.
Single-run Python timings exclude trace and diffusion collection; trace state
outputs are checked against the exact supplied cipher output. Comparisons include
padding and key expansion consistently. These are educational implementation times,
not optimized AES-library or end-to-end network measurements.

The integral live adapter compiles only `square_attack` and `original_key` from
`evaluate_hybrid.py`, avoiding the script's import-time plotting/benchmark loops.
It performs actual AES-4 master-key verification. Other designs report candidate
filtering, not hardcoded key-recovery failures. The differential and linear quick
adapters use the supplied formulas with 256 samples per key (recorded runs use
2,048); they are explicitly separate observations. They do not invent a null
reference or security rating for a live run.

Block substitution succeeds in the supplied unauthenticated wrappers, including
AES-10. The UI reports this accurately. Meet-in-the-middle and related-key attacks
are Not run. Failure of one integral equation is not universal attack resistance.
The original report's 61.11% category saving and 0.88% aggregate saving are historical
values, not hybrid measurements; old raw timing artifacts need reconciliation.

## Tests

```bash
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
```

Tests cover archive integrity, AES known vectors, adaptive thresholds, hybrid
inversion, binary round trips, actual cipher/trace equivalence, integral key recovery,
block substitution, and source provenance. Long full research runs are not needed
for each regression check. Supplied standalone plotting/probe scripts additionally
require matplotlib and, for the supplied linear script, numpy.

## Demo sequence

1. Encrypt a short message and inspect the actual ARX state.
2. Choose the 128/129-byte presets to explain round selection.
3. Flip an input bit and inspect the changed output bits.
4. Run one integral trial; inspect exact recovery versus candidate elimination.
5. Compare recorded differential and linear observations with random references.
6. Show block substitution as a wrapper-level issue.
7. Open Research and compare hybrid with AES-5 and AES-10 within one timing method.

## Interactive lab upgrade

Home now runs the real cipher for a selected generated payload and displays
archived highlights directly from their CSV datasets. Workbench includes a payload
slider, backend-verified transformation replay, per-operation bit diffusion, and
packet-stream comparison. Analysis groups attack runs, payload-size measurements,
and session history. Research adds architecture, policy and measurement definitions.

`POST /api/stream` accepts `sizes` (1–12 integer byte counts, each 1–4096) and a
32-bit unsigned integer `seed`. It generates deterministic byte payloads and a
shared key. Each packet runs AdaptAES–ARX and AES-10 with alternating order, one
warm-up and three measured encryptions; every decryption is checked outside the
timer. Aggregate latency sums packet medians; aggregate throughput divides total
payload bytes by that sum. This is a synthetic workload, not captured traffic or
an end-to-end network benchmark. API timing measures the server, not the browser.

The encryption API also returns `diffusion.stages`: changed bits at each actual
intermediate state after one plaintext-bit flip, checked against the final count.

Up to 40 completed run summaries are saved in browser `sessionStorage` for the
current tab. No plaintext, ciphertext, raw attack details or keys are retained in
history. CSV exports include the displayed measurements; session CSV includes run
conditions. Clear history removes those summaries. The previous statement that no
results are stored refers to server persistence, not this new tab-local history.

## Vercel deployment

Deploy the repository root, not only `web/`: `vercel.json` builds the React app
and one Python function containing the exact archived research modules. The
Vercel adapter returns bounded experiments in the initiating request; it never
relies on in-memory job polling across function instances. Local jobs retain
process isolation and cancellation. Hosted bounded runs display a running state
and return on completion. Timings always refer to the machine running the API.

## Two-screen presentation

The primary interface now has only two destinations:

1. **Encryption & comparison:** enter text or a file (up to 4 KiB), select an
   exact payload-size preset, and run all eight configurations together. The
   table includes rounds, ARX allocation, median encryption/decryption time,
   throughput, speedup and exact recovery. Statistical comparison uses eight
   plaintext-bit and eight key-bit flips on the first padded block; entropy is
   averaged independently over 16-byte ciphertext blocks. Inspect any row to see
   that cipher's actual first-block transformations and slowed visual replay.
2. **Attack lab:** integral, differential, linear and block substitution run
   against AES-4, AES-4 + ARX, AES-5, AES-6, AES-8 and AES-10. The integral slider
   replays the actual four-set candidate counts from the completed experiment.
   Evidence includes chosen-message samples and per-byte surviving guesses. A
   verified recovered AES-4 master key is used to decrypt a generated AES-10
   challenge encrypted with the same key, demonstrating key-reuse compromise,
   not an attack against full-round AES. Substitution shows the original target,
   attacker replacement and delivered plaintext block.

The two screens retain state when switching. Original traffic-study tables are
available in a disclosure beneath the comparison. Their exact repository
aggregate CSVs are copied to `research/report_reference/`, outside the unchanged
teammate archive. They are separate from live runs and from the fixed hybrid's
recorded measurements. The archived round-wise sample counts sum to 90,000.

Restart the Python server after updating backend files. A frontend version guard
reports an old comparison API instead of rendering incomplete timing/statistics.

## Expanded performance measures

The comparison API accepts 3–15 timed repetitions (UI: 5 or 15), always excluding
one warm-up. It now reports thread CPU encryption time, mean/min/max encryption
latency, sample standard deviation, coefficient of variation, paired round-trip
median, microseconds per padded block and per payload byte, reciprocal-median
message rate, and padding/ciphertext size. Raw encryption samples are included in
CSV exports. Min/max and variation describe the collected samples only; no tail
latency, energy consumption, CPU utilisation or memory-efficiency claims are made.

The frontend can derive per-block cost, throughput and message rate from existing
API fields. It disables missing CPU/variation views until the server is restarted,
and explicitly labels the sum-of-medians fallback for round-trip time.
