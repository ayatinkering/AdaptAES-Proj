"""Matched-key integral candidate filtering; failure is specific to this attack.

Unlike the supplied prototype, verify candidate round keys for every design.
Do not interpret zero survivors as generic cryptanalytic security.
"""

import argparse
import json
import random
import time
from pathlib import Path

import aes_core as aes
import aes_hybrid


def candidates(encrypt, blocks):
    survivors = [set(range(256)) for _ in range(16)]
    counts = []
    for structure in blocks:
        ciphertexts = [encrypt(block) for block in structure]
        for position in range(16):
            keep = set()
            for guess in survivors[position]:
                balance = 0
                for ct in ciphertexts:
                    balance ^= aes.INV_S_BOX[ct[position] ^ guess]
                if balance == 0:
                    keep.add(guess)
            survivors[position] = keep
        counts.append(sum(map(len, survivors)))
    return survivors, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--sets", type=int, default=4)
    parser.add_argument("--active-byte", type=int, default=0, choices=range(16))
    parser.add_argument("--seed", type=int, default=20261029)
    parser.add_argument("--out", type=Path, default=Path("results/adaptive_arx/integral.json"))
    args = parser.parse_args()
    if min(args.trials, args.sets) < 1:
        parser.error("trials and sets must be positive")
    rng, rows = random.Random(args.seed), []
    for trial in range(args.trials):
        key = rng.randbytes(16)
        structures = []
        for _ in range(args.sets):
            base = bytearray(rng.randbytes(16))
            structure = []
            for value in range(256):
                base[args.active_byte] = value
                structure.append(bytes(base))
            structures.append(structure)
        for name, rounds in (("aes4", 4), ("aes4_arx", 4), ("aes5", 5), ("aes10", 10)):
            encrypt = (lambda block: aes_hybrid.encrypt_block(block, key)) if name == "aes4_arx" else (lambda block: aes.encrypt_block(block, key, rounds))
            start = time.perf_counter()
            survivors, counts = candidates(encrypt, structures)
            elapsed = time.perf_counter() - start
            expected = aes.expand_key(key)[rounds]  # Evaluator only, not passed into attack.
            correct = sum(expected[j] in survivors[j] for j in range(16))
            exact = all(survivors[j] == {expected[j]} for j in range(16))
            rows.append(dict(trial=trial, design=name, queries=args.sets * 256,
                             surviving_guesses_per_set=counts, correct_key_bytes_retained=correct,
                             exact_final_round_key_recovered=exact, attack_seconds=elapsed))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(dict(seed=args.seed, active_byte=args.active_byte,
                                       scope="Unmodified four-round integral equation; not general attack resistance or master-key recovery", rows=rows), indent=2) + "\n")
    for name in ("aes4", "aes4_arx", "aes5", "aes10"):
        entries = [r for r in rows if r["design"] == name]
        print(name, "exact round-key recoveries:", sum(r["exact_final_round_key_recovered"] for r in entries), "/", args.trials)
    print(f"Saved {args.out}")


if __name__ == "__main__":
    main()
