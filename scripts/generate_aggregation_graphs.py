"""Explain recorded aggregation results without rerunning timing measurements."""

import argparse
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

MODES = ("immediate", "fixed", "adaptive")
LABELS = ("Per message", "Fixed batching", "Adaptive batching")
COLORS = ("#2667a8", "#ca7745", "#39836d")


def save(fig, path):
    handles, labels = fig.axes[0].get_legend_handles_labels()
    for ax in fig.axes:
        if ax.get_legend():
            ax.get_legend().remove()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(.5, .91), ncol=3, frameon=False)
    fig.tight_layout(rect=(0, .08, 1, .83))
    fig.savefig(path, dpi=160, bbox_inches="tight")
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("results/aggregation"))
    args = parser.parse_args()
    with (args.results_dir / "summary.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    out = args.results_dir / "plots"
    out.mkdir(parents=True, exist_ok=True)
    captures = [r for r in rows if r["workload"] == "capture"]
    names = list(dict.fromkeys(r["dataset"] for r in captures))
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.7))
    for i, mode in enumerate(MODES):
        selected = [next(r for r in captures if r["dataset"] == name and r["mode"] == mode) for name in names]
        x = [n + (i - 1) * .24 for n in range(len(names))]
        axes[0].bar(x, [float(r["processing_cpu_us_per_message"]) for r in selected], .24, label=LABELS[i], color=COLORS[i])
        axes[1].bar(x, [100 * int(r["overhead_bytes"]) / int(r["payload_bytes"]) for r in selected], .24, label=LABELS[i], color=COLORS[i])
    short_names = [name.split("_")[0][:3] + " " + name.split("_")[1][5:] for name in names]
    for ax in axes:
        ax.set_xticks(range(len(names)), short_names, rotation=35, ha="right")
        ax.legend(fontsize=8)
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=.2)
    axes[0].set(title="Measured processing cost", ylabel="Measured CPU time per message (us)")
    axes[1].set(title="Header, framing, nonce and tag", ylabel="Record overhead / payload bytes (%)")
    fig.suptitle("Capture-derived workloads: identical full-round AES-GCM in every policy")
    fig.text(.5, .01, "Lower is better. Queueing delay is modeled separately; these are not network throughput measurements.", ha="center", fontsize=9)
    save(fig, out / "capture_tradeoffs.png")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.7))
    for i, mode in enumerate(MODES):
        selected = [next(r for r in captures if r["dataset"] == name and r["mode"] == mode) for name in names]
        x = [n + (i - 1) * .24 for n in range(len(names))]
        axes[0].bar(x, [float(r["queue_p95_us"]) for r in selected], .24, label=LABELS[i], color=COLORS[i])
        axes[1].bar(x, [float(r["mean_messages_per_record"]) for r in selected], .24, label=LABELS[i], color=COLORS[i])
    for ax in axes:
        ax.set_xticks(range(len(names)), short_names, rotation=35, ha="right")
        ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=.2)
    axes[0].set(title="Waiting for an aggregation opportunity", ylabel="Modeled p95 queueing delay (us)")
    axes[1].set(title="Aggregation achieved on each capture", ylabel="Messages per authenticated record")
    fig.suptitle("Batching saves record overhead by introducing buffering")
    fig.text(.5, .01, "Queueing budget is a flush deadline, not an end-to-end latency guarantee. A lost record affects every message it contains.", ha="center", fontsize=8)
    save(fig, out / "capture_queueing.png")

    fig, axes = plt.subplots(1, 3, figsize=(12, 4.3))
    examples = ("controlled_burst", "controlled_sparse")
    for ax, column, title, ylabel in zip(axes,
        ("overhead_bytes", "queue_p95_us", "processing_cpu_us_per_message"),
        ("Record overhead", "Modeled queueing", "Measured processing cost"),
        ("Bytes", "p95 waiting time (us)", "CPU time per message (us)")):
        for i, mode in enumerate(MODES):
            selected = [next(r for r in rows if r["dataset"] == name and r["mode"] == mode) for name in examples]
            ax.bar([n + (i - 1) * .24 for n in range(2)], [float(r[column]) for r in selected], .24, label=LABELS[i], color=COLORS[i])
        ax.set_xticks(range(2), ["Burst", "Sparse"])
        ax.set(title=title, ylabel=ylabel)
        ax.legend(fontsize=7)
        ax.grid(axis="y", alpha=.2)
    fig.suptitle("Controlled synthetic examples: when buffering helps and when it hurts")
    fig.text(.5, .01, "Each example has 1024 64-byte messages in one flow. These are illustrations, not capture-derived traffic.", ha="center", fontsize=9)
    save(fig, out / "controlled_examples.png")
    print(f"Saved three aggregation figures to {out}")


if __name__ == "__main__":
    main()
