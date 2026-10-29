# Running and presenting AdaptAES

## Start after closing your terminals

In a fresh Ubuntu terminal:

```bash
cd "/home/ayati/Documents/SEM 5/IS Proj/AdaptAES"
npm run build --prefix web
bash scripts/restart_workbench.sh
```

Keep that terminal open. Open http://127.0.0.1:8000/#home in your browser.
Stop with Ctrl+C. Closing the terminal stops the local API; the page needs that
API for encryption and attack runs. On another laptop, first run `npm ci --prefix
web` to install the pinned frontend packages. Python's API uses the standard library.

## A five-minute demonstration

1. **Explain the idea.** “Original AdaptAES allocates 4, 6, 8 or 10 AES rounds by
   payload size. Our hybrid adds two reversible ARX mixing iterations after
   round 2 on the small-payload path.”
2. **Encrypt one message.** Keep the default text, choose 5 timed repetitions,
   and click Encrypt & compare all. Show encryption/decryption times, throughput,
   speedup and verified recovery for all configurations. These are measured
   server timings, with one warm-up excluded.
3. **Show the policy.** Compare the 128 B and 129 B presets. The adaptive hybrid
   switches from four rounds + ARX to six AES rounds. Click Encrypt & compare all
   after changing size. Larger sizes do not use ARX in the adaptive integration;
   the fixed hybrid reference always uses ARX.
4. **Inspect the real state.** In the comparison table choose Inspect for AES-4
   + ARX. Scroll to Inside AES-4 + ARX, click ARX or Replay steps, and explain the
   4×4 before/after matrices. Yellow cells changed. Replay is slowed for reading,
   not included in timing.
5. **Compare statistics.** Show plaintext avalanche, key avalanche and block
   entropy. “These measure sampled diffusion, so we also evaluated actual attacks.”
6. **Run integral key recovery.** Open Attack lab, keep seed 20261029 and click
   Run experiment. Move the candidate-filtering slider through 256/512/768/1024
   queries. Show AES-4's recovered key and byte guesses; compare the hybrid and
   other round counts. In AES-4 evidence show the verified AES-10 challenge:
   the recovered key decrypts it because the same key was reused, not because
   the experiment attacks full-round AES directly.
7. **Show tampering separately.** Select Block substitution, then Intercept &
   replace a block. Compare the original encrypted block, replacement, and
   delivered plaintext. All current unauthenticated wrappers accept the change,
   including AES-10. More rounds do not add message authentication.
8. **Conclude with evidence.** “The hybrid disrupted the unchanged integral
   equation in the tested runs, while retaining a timing advantage in the
   displayed measurements. We report sampled diffusion and attack-specific
   results; they do not prove equivalence to AES-10 security.”

Optional: use 15 repetitions for more timing samples, export CSV, and open Timing
consistency and processing cost to show CPU time, variation and per-block cost.
Differential and linear tabs include actual samples and strongest tested masks;
these probes do not recover keys. Recorded results and the original report are
labelled separately from live runs.

## Push the prepared changes

```bash
cd "/home/ayati/Documents/SEM 5/IS Proj/AdaptAES"
bash scripts/push_workbench.sh
```

This imports the prepared commits from the local bundle and pushes the feature
branch used by PR #3, without checking out a branch, staging unrelated files,
changing the working tree or force-pushing. It needs working GitHub credentials
and network access in your normal terminal. Review and merge PR #3 to put the
changes on main: https://github.com/ayatinkering/AdaptAES-Proj/pull/3 .

## Hosted demonstration

A working Vercel deployment needs the repository root and `vercel.json`, not just
`web/`, because the experiments run in Python. Once deployed and verified, its
public URL works without your laptop's terminals. No verified hosted URL exists
at the time this guide was prepared; Vercel team access must be authorized first.
