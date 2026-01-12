#!/usr/bin/env python3
"""
Plot a latency histogram from bench_latency.py CSV.

Usage:
  python3 scripts/plot_latency.py bench.csv --out latency.png
"""

from __future__ import annotations

import argparse
import csv
from typing import List

import matplotlib.pyplot as plt


def percentiles(xs: List[float], ps: List[float]) -> List[float]:
    if not xs:
        return [float("nan") for _ in ps]
    ys = sorted(xs)
    out = []
    for p in ps:
        k = int(round((p / 100.0) * (len(ys) - 1)))
        k = max(0, min(k, len(ys) - 1))
        out.append(ys[k])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("--out", default="", help="if set, save image to this path")
    ap.add_argument("--bins", type=int, default=60)
    args = ap.parse_args()

    latencies: List[float] = []
    with open(args.csv_path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            latencies.append(float(row["latency_ms"]))

    if not latencies:
        raise SystemExit("no latency samples found")

    p50, p95, p99 = percentiles(latencies, [50, 95, 99])
    mean = sum(latencies) / len(latencies)

    print(f"samples: {len(latencies)}")
    print(f"latency ms: p50={p50:.3f}  p95={p95:.3f}  p99={p99:.3f}  mean={mean:.3f}")

    plt.figure()
    plt.hist(latencies, bins=args.bins)
    plt.xlabel("Latency (ms)")
    plt.ylabel("Count")
    plt.title("Request latency distribution")

    # vertical markers
    for x, label in [(p50, "p50"), (p95, "p95"), (p99, "p99"), (mean, "mean")]:
        plt.axvline(x, linestyle="--", label=f"{label}={x:.2f}ms")

    plt.legend()

    if args.out:
        plt.savefig(args.out, dpi=160, bbox_inches="tight")
        print(f"saved plot to {args.out}")
    else:
        plt.show()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
