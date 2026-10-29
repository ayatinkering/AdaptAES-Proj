# AdaptAES frontend implementation plan

Status: implementation completed following subsequent user authorization. See `workbench_usage.md` for the implemented stack and run instructions. This document preserves the original plan.

## 1. Authoritative inputs

1. Final teammate archive: `AdaptAES_hybrid_research (1).zip`, supplied with this request.
   Archive SHA-256: `45654d304decdae8fd0730606691d974802f3e8580192fd44e5565ce0257337c`.
   This archive supersedes the earlier ZIP for hybrid algorithms, probes and recorded results.
2. Research report: `IS_Project_Report (1).pdf`, nine pages, supplied earlier.
   This is authoritative for the original study, dataset, thresholds and historical report results.
3. Visual reference: https://departuremono.com/ . Inspected in the browser.
4. User direction: clean cryptography interface, black background, white/beige text,
   minimal motion, no eyebrows, gradient boxes, generic dashboard decoration or marketing filler.

The PDF predates ARX. Its original results must not be relabeled as hybrid results.
The final archive is evidence of code and supplied measurements, not an instruction
to execute every script or accept every summary label uncritically.

Existing local integration files are useful scaffolding, not a higher authority than
the final archive. Compare them before reuse. At inspection, `aes_core.py` and
`aes_hybrid.py` matched the final archive byte-for-byte; `aes_adaptive.py` differed
and needs a semantic comparison before integration. Preserve current uncommitted work.

## 2. What the final archive actually implements

| Source | Implemented behavior | UI treatment |
|---|---|---|
| `aes_core.py` | Configurable AES-128 rounds; padding; independent message-block processing | Fixed-round reference and operation trace |
| `aes_adaptive.py` | Original 4/6/8/10 policy based on original payload length | Original AdaptAES mode |
| `aes_hybrid.py` | Fixed AES-4 with two keyed ARX iterations after round 2; inverse and message helpers | Hybrid block mode, distinctly named AES-4 + ARX |
| `evaluate_hybrid.py` | Four-set integral candidate filtering, AES-4 master-key recovery, seven-repeat padded timings | Integral experiment and recorded padded performance |
| `compare_hybrid_five.py` | Forty-repeat raw-block timing and 1,500 matched diffusion pairs | Separate raw-block performance and diffusion experiment |
| `probe_arx.py` | All active-byte positions and internal balance diagnostics | Expanded integral experiment and white-box explanation |
| `probe_differential_linear.py` | Sampled output-difference counts, chi-square and bit-change bias; includes AES-10 | Differential probe, not a full differential key-recovery attack |
| `probe_linear.py` | Selected input/output bit correlations; includes AES-10 | Linear-correlation probe, not general linear cryptanalysis |
| `probe_active_attacker.py` | Block substitution and repeated-block visibility in independent-block wrappers | Wrapper-integrity experiment |
| `security_comparison_table.csv` | Cross-experiment summary, including untested attacks | Source index; link to underlying CSVs rather than treating it as sufficient proof |

The archive does not implement an adaptive ARX policy, a frontend, an API, a
network stack, authentication, a meet-in-the-middle attack, or a related-key attack.
Do not add any of these to the implemented-feature list.

### Findings that must be represented faithfully

- Supplied integral results: AES-4 master-key recovery in 20/20 trials; the unchanged
  candidate equation has zero final survivors for hybrid and AES-5/6/10.
- Non-AES-4 recovery counts in that script are explicitly set to false. Display
  candidate filtering as the primary result; do not imply adapted attacks ran.
- `probe_arx.py`'s `master_key_candidate_trials` counts singleton candidate sets,
  not independently verified master-key recovery.
- Active block substitution succeeds in 100/100 supplied trials in every tested
  independent-block wrapper, including hybrid and AES-10. Repeated blocks are
  visible in 100/100 trials. This concerns message framing/integrity, not an AES-10 key break.
- Differential and linear probe values are observations with finite samples;
  show the random reference and tested scope alongside them.
- Meet-in-the-middle and related-key attacks are marked Not tested.
- The historical PDF's 61.11% small-category reduction and 0.88% aggregate reduction
  belong to the original benchmark, not the hybrid. Its saved raw timing mismatch
  identified in the earlier audit must be reconciled before presenting it as reproducible.

## 3. Design direction

Departure Mono's identity comes from its pixel monospace, technical documents,
tabular alignment and fine structural rules. It is predominantly light on the
reference site. Use a dark counterpart to honor the user's existing black/beige
direction; preserve the typography and document geometry rather than copying the
site's flight content, collage imagery, scrolling scenes or letter-scramble effects.

No hero slogans, decorative upper labels, feature-card rows, neon security motifs,
shields, fake terminal output, gradient fills, glows, glass or constant animation.
The one distinctive visual object is the actual 16-byte AES state matrix.

### Proposed tokens

| Role | Value |
|---|---|
| Page | `#080808` |
| Working surface | `#121212` |
| Primary text | `#E9E5DC` |
| Secondary text | `#B6B1A7` |
| Structural rule | `#393732` |
| Selection/action fill | `#D6C5A6`, with dark text |

These are proposed implementation values, not colors claimed to have been copied
from the reference. Use text and symbols, not color alone, for outcomes.

- Self-host the official Departure Mono font and retain its SIL OFL license.
- Pixel typography at deliberate readable sizes: roughly 44px wordmark, 22px
  page title, 16.5px body, 13–14px secondary data. Confirm actual rendering in QA.
- Provide a system fallback for unsupported Unicode; text input accepts arbitrary UTF-8.
- Equal outer margins, 32px desktop / 16px mobile; working width around 1280px.
- Square controls, quiet 1px separators where they structure actual forms/tables.
- Minimal top navigation, no permanent oversized sidebar.
- State changes are immediate; optional 100–150ms control feedback only.
- No autoplay trace. Previous/Next and keyboard controls drive inspection.
- At 1440px, input, selected algorithm, primary action and initial output region
  should all be visible. Below about 900px, stack input before output. Contain
  horizontal scrolling inside byte tables, never across the whole page.

The requested reference and minimal-motion direction override generic skill
defaults about fonts, thin rules, stock image counts, palettes or animation.

## 4. Information architecture

Top navigation: AdaptAES / Encrypt / Analyze / Results / Paper.
The homepage is Encrypt itself, not a separate promotional landing page.

### Encrypt: first-screen composition

| Region | Contents |
|---|---|
| Header | AdaptAES wordmark, plain navigation, unobtrusive backend availability |
| Intro | One sentence: Explore adaptive AES and its ARX extension. |
| Left working column (~45%) | Text / File / Sample payloads, byte count, size presets, variant, key controls, Encrypt |
| Right working column (~55%) | Selected algorithm, original/padded sizes, ciphertext preview, timing and verified decryption |
| Lower inspection region | Block selector, operation list, before/after matrices, optional ARX word view |

Defaults: a short explicit sample and AdaptAES–ARX selected. Never auto-run a
benchmark or claim results before the user acts. Empty output says Enter a message
and choose Encrypt. Backend failures stay inside the affected output region.

#### Inputs and selection

- Text is encoded once as UTF-8. Show bytes separately from characters.
- Files are arbitrary bytes; do not reinterpret binary files as text. Initially cap
  live encryption at 64 KiB, with a visible reason: educational Python runtime.
- File picker, clear action, filename, exact byte size and bounded hex preview.
- Sample payloads: explicit sizes and patterns. Threshold presets: 128, 129, 512,
  513, 1024 and 1025 bytes. ASCII presets must generate exact byte counts.
- Network-derived sizes are an optional sample collection from existing local CSVs,
  labeled synthetic contents / capture-derived lengths. Do not claim live traffic capture.
- Explain selection in one sentence: 84 bytes selects AES-4 + ARX.
- Original AdaptAES: 4/6/8/10 using the report thresholds.
- Proposed integrated AdaptAES–ARX: hybrid only for 1–128 bytes, original 6/8/10
  above that. This is new integration, not behavior supplied by `aes_hybrid.py` alone.
- Advanced fixed configurations support fair block-level comparisons and are named
  explicitly, especially fixed AES-4 + ARX versus adaptive AdaptAES–ARX.
- Reject empty adaptive inputs as the authoritative policy does. Keep that distinct
  from whether standalone padded-message helpers accept empty data.
- Expose a fresh demo key and an optional validated 32-hex-character key field.
  Reuse the same key for matched comparisons. Do not persist keys or inputs in logs.

#### Outputs

Ciphertext as hex with bounded preview, copy/download actions; decrypted bytes
with UTF-8 text only when decodable; exact byte equality confirmation. Include
original byte length, padding bytes, encrypted blocks, selected AES rounds and
whether ARX runs. A changed input invalidates earlier results visibly.

Measure encryption/decryption inside Python; report API round-trip separately if
needed. A single execution is labeled Single run, not a benchmark. Timings exclude
UI rendering and trace collection. File download must preserve exact byte content.

#### State inspection

Collect a real selected-block trace through callbacks in a derived adapter without
altering the cipher transformations. Verify traced and untraced outputs match.
Render state as AES columns (`state[4*c+r]`), with row/column labels and hex bytes.
Expose AddRoundKey, SubBytes, ShiftRows and MixColumns according to actual rounds;
the final round has no MixColumns. ARX after round 2 gets its own selected stage.
Show four little-endian 32-bit words, rotation amounts and iteration index in an
expandable ARX detail view. Do not describe these as four extra AES rounds.

Bit-flip inspection changes one selected plaintext bit under the same key and
configuration. Compare one block with one block. Label the result Diffusion
inspection; do not use the full multi-block ciphertext as a 128-bit denominator.

### Analyze

Tab names: Integral / Differential / Linear / Block substitution.
One experiment form, one results region. Controls depend on the real experiment.
Toggle Run locally versus Recorded experiment; switching never relabels old values.

| Experiment | Primary visualization | Scope text |
|---|---|---|
| Integral | Survivors versus queries; per-byte candidate grid; verified recovery where supported | Structured chosen plaintexts generated by the experiment |
| Differential | Output-byte difference frequency and maximum bit-change bias, with random reference | Sampled difference probe |
| Linear | Maximum absolute tested bit correlation, with random reference | Selected single-bit masks, not an exhaustive mask search |
| Internal balance | Balanced byte positions before/after ARX | White-box diagnostic, not attacker-observable state |
| Block substitution | Source A / target B block strips; modified reconstruction and repeated-block equality | Local wrapper experiment, no authentication or network stack |

Never pretend integral analysis attacks the user's arbitrary paragraph. A link from
Encrypt transfers algorithm selection, not an assertion that text is a delta set.
Block substitution may use two user-editable messages padded/constructed to the
supported demonstration size; show exact block boundaries and same-key condition.

Outcomes: Exact key recovered / Candidates remain / No candidates satisfy equation /
Modified message accepted / Not tested. No Secure, Unbreakable, Attack blocked,
overall security percentage, or universal equivalence badge.

Source constraints: capture actual verification before labeling key recovery; do
not propagate the original forced-false recovery field as proof for non-AES-4.
Any improvements to verification are labeled a new local evaluator version, not
silently attributed to the supplied recorded data.

Live quick experiments use bounded parameters and small trial counts. Full
supplied datasets remain selectable as recorded evidence. CPU work runs in a
worker process with a timeout and genuine progress (completed sets/trials).
No fabricated percentage progress. Queue one live job at a time for this laptop.

### Results

Three evidence collections remain separate:

1. Original report: HIKARI extraction and original adaptive-round evaluation.
2. Final hybrid archive: supplied fixed-design attack/probe and timing measurements.
3. New local runs: integrated adaptive-hybrid tests and measurements.

Every figure/table includes source filename, experiment, units, trial count,
configuration and Live or Recorded. Include seed/environment when available;
missing recorded environment is Unknown, not guessed. Never interpolate missing
AES-10 results into experiments where that baseline was not run.

Raw-block `direct_timing.csv` and padded-message `speed_results.csv` are separate
experiments; do not put their values on one comparative axis. Throughput derives
from bytes and time with explicit MiB/s units. Use zero-based bars and fixed,
meaningful comparison axes; reference distributions need uncertainty, not invented
pass thresholds. The final ZIP stores aggregate values for many probes, not raw
trial distributions, so richer interactive plots require new measurements.

### Paper

Readable original-study summary, source report link, method, references, original
threshold table and a clearly separated Hybrid extension section. Do not rewrite
or replace the user's PDF as part of frontend work. Link original and new findings
to their respective experiments. Display authors from the authoritative report:
Ayati Rauthan and Ireshi Rawat. Confirm before changing attribution for the extension.

## 5. Technical architecture

Local React + TypeScript + Vite frontend in `web/`; FastAPI backend in `api/`.
Plain CSS tokens and purpose-built SVG charts; no large component kit or animation
dependency. Python remains the only cipher/attack implementation. Bind local API
to loopback, use an explicit local origin or same-origin proxy. No database or
external API is needed for the classroom demo. Do not use browser WebCrypto as a
substitute: it cannot reproduce this custom reduced-round cipher.

Preserve an immutable copy of final supplied sources and results with hashes in a
versioned research directory during implementation. Run behavior-preserving
refactors in derived modules. Do not import the supplied probe scripts directly
inside API handlers: they execute expensive loops and write files at import time.
Extract pure functions with explicit RNG/config/output arguments and main guards.
Preserve parameter defaults and provenance of supplied measurements.

Proposed API contracts:

| Endpoint | Contract |
|---|---|
| `GET /api/config` | Actual available modes, thresholds, experiment capabilities and limits |
| `POST /api/encrypt` | Bytes/base64, mode, key; ciphertext, verified recovery, selection and single-run times |
| `POST /api/trace` | Mode, key, selected block; actual stage states, validated final ciphertext |
| `POST /api/diffusion` | Block and bit selection; matched output differences |
| `POST /api/experiments` | Allowlisted experiment/config; job ID |
| `GET /api/experiments/{id}` | State, completed work, result or explicit failure |
| `DELETE /api/experiments/{id}` | Cancel queued/running job |
| `GET /api/results` | Recorded evidence with source and experiment metadata |

Job result schema: source archive digest, evaluator version, mode, seed, parameters,
units, per-trial observations where collected, elapsed processing, verified outcome,
and interpretation scope. Preserve partial results on cancellation distinctly.
Reject arbitrary Python, arbitrary paths, or shell commands as job inputs.

Do not change the original block cipher, add MAC/GCM, optimize just one comparison
arm, or substitute the friend's batching PR within this frontend project. Those
would be separate algorithm/experiment changes needing their own evaluation.

## 6. Build sequence and acceptance checks

| Phase | Deliverable | Acceptance checkpoint |
|---|---|---|
| 1. Evidence preparation | Final ZIP snapshot/hash manifest, result catalog, semantic diff | Every displayed recorded number traces to its actual CSV; original/hybrid separated |
| 2. Research adapters | Pure cipher/probe functions and adaptive wrapper | Known AES vector, hybrid reversibility, policy boundaries, unchanged outputs |
| 3. API | Encrypt/trace/diffusion and bounded experiment jobs | Binary round trips; no import-time jobs; cancellation, limits and errors work |
| 4. Visual shell | Reference-derived font/tokens/nav/workspace states | First screenshot matches the agreed typography, palette and restrained composition |
| 5. Encryption workspace | Text/file inputs, selection, outputs and state trace | UTF-8 sizing; threshold presets; selected-block output agrees with cipher |
| 6. Analysis | Integral and block substitution first, differential/linear next | Actual job outcomes; recorded/live distinction; truthful unsupported states |
| 7. Results and paper | Source-backed charts/tables, exports and original-study context | No mixing padding conventions or attributing original speedups to ARX |
| 8. Demo verification | End-to-end classroom sequence and production frontend build | Browser QA at 1440/768/390; keyboard/focus/contrast; no horizontal page overflow |

Meaningful tests include matching archive cipher outputs on seeded inputs,
traced/untraced equivalence, deterministic experiment configuration, actual AES-4
recovery verification, controlled block substitution, metadata consistency and
binary upload/download identity. Long research runs are not part of every test run.
Archive timings remain supplied results until rerun; don't assert identical timing
on another host. Use source correctness, not visually persuasive invented values.

## 7. Classroom demonstration

1. Enter short text; explain UTF-8 length and hybrid selection.
2. Inspect round 2, ARX words and the final state for one block.
3. Switch 128 to 129 bytes; show the actual policy transition.
4. Flip one bit; inspect matched ciphertext differences.
5. Run one quick integral comparison, then inspect the supplied larger experiment.
6. Show differential/linear observations with their reference samples.
7. Demonstrate block substitution accurately as a shared wrapper limitation.
8. Open performance and paper evidence, naming which experiment each belongs to.

## 8. Skill setup status

Requested `npx skills add anthropics/skills --skill frontend-design` and
`npx skills add Leonxlnx/taste-skill` were attempted with noninteractive Codex flags.
Both failed with npm registry DNS resolution (`EAI_AGAIN`). Neither is installed.
Upstream frontend-design and taste-skill guidance was retrieved and consulted;
it does not override the user's reference, palette or minimal-motion preference.
Retry installation when network/permissions allow, rather than claiming success.

No frontend/API code or deployment was produced during this planning task.
