AdaptAES hybrid research prototype

Contents: original AES core and adaptive wrapper from supplied ZIP; new aes_hybrid.py; evaluate_hybrid.py; saved figures and CSV files.
Run from this folder: python evaluate_hybrid.py (requires matplotlib).

Design: original 4 AES rounds, with a keyed reversible ARX transformation after round 2. The same 128-bit master key drives both AES and ARX; no independent-key security claim is made. Decryption reverses every operation. This is a block-cipher research prototype, not a secure packet-encryption protocol.

Experiment: 20 seeded random-key trials per configuration. The integral attack makes four groups of 256 chosen-block encryption queries per trial. It recovers the master key in all AES-4 trials. It produces zero surviving last-round-byte guesses for AES-4+ARX, AES-5, AES-6 and AES-10. Zero survivors means the original attack equation no longer applies. It does not prove those variants resist other attacks.

Timing: pure Python, seven repeats per payload size, median. All configurations use the same core and environment. Results are approximate and depend on computer load. For actual packet security, the independently encrypted blocks here also need a secure authenticated mode; ECB-style block processing is unsafe.

Next research: analyze possible new attacks on the hybrid, evaluate diffusion across rounds, assess key schedule and chosen-plaintext attacks, and compare against well-studied full-round authenticated encryption on the target hardware. Do not claim 10-round-AES-equivalent security from these results.

Additional active-attacker experiment: run python probe_active_attacker.py. It simulates an interceptor substituting a ciphertext block from another message under the same key. All four block-by-block modes accepted 100/100 changed messages and revealed repeated blocks in 100/100 trials. This is a wrapper/protocol integrity weakness, not a break of the AES round function. It is not a real network capture or a meet-in-the-middle key recovery attack.
