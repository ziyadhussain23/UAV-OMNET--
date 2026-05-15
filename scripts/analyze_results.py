#!/usr/bin/env python3
"""Analyze OMNeT++ results and print delay/compute summaries."""

import glob
import os
from collections import defaultdict
import csv

try:
    import pandas as pd  # type: ignore
except ModuleNotFoundError:
    pd = None


def csv_mean(path, column):
    values = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                values.append(float(row[column]))
            except (KeyError, ValueError, TypeError):
                continue
    return sum(values) / len(values) if values else 0.0


def csv_count(path):
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return sum(1 for _ in reader)


def csv_unique_count(path, column):
    values = set()
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if column in row:
                values.add(row[column])
    return len(values)


def parse_scalar_file(path):
    values = defaultdict(list)
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.startswith("scalar "):
                continue

            # Scalar format: scalar <module> <name> <value>
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            metric_name = parts[2]
            value = parts[3]

            try:
                values[metric_name].append(float(value))
            except ValueError:
                continue

    return values


def summarize(values, key):
    data = values.get(key, [])
    if not data:
        return None
    return sum(data) / len(data)


def main():
    summary_csv = os.path.join("simulations", "results", "omnet_summary.csv")
    phase2_csv = os.path.join("simulations", "results", "omnet_phase2_results.csv")
    phase3_csv = os.path.join("simulations", "results", "omnet_phase3_results.csv")

    if os.path.exists(summary_csv) and os.path.exists(phase2_csv) and os.path.exists(phase3_csv):
        print("=== OMNeT++ Exported CSV Summary ===")

        if pd is not None:
            summary = pd.read_csv(summary_csv)
            phase2 = pd.read_csv(phase2_csv)
            phase3 = pd.read_csv(phase3_csv)

            print(f"Configs analyzed: {len(summary)}")
            print(f"Phase 2 rows: {len(phase2)}")
            print(f"Phase 3 rows: {len(phase3)}")

            print(f"Average Phase 2 latency: {phase2['latency_ms'].mean():.3f} ms")
            print(f"Average Phase 2 compute: {phase2['compute_ms'].mean():.3f} ms")
            print(f"Average Phase 2 overhead: {phase2['overhead_bytes'].mean():.3f} bytes")

            print(f"Average Phase 3 latency: {phase3['latency_ms'].mean():.3f} ms")
            print(f"Average Phase 3 compute: {phase3['compute_ms'].mean():.3f} ms")
            print(f"Average Phase 3 overhead: {phase3['overhead_bytes'].mean():.3f} bytes")

            success_rate = phase2['success'].mean() * 100.0 if len(phase2) else 0.0
        else:
            print(f"Configs analyzed: {csv_unique_count(summary_csv, 'config')}")
            print(f"Phase 2 rows: {csv_count(phase2_csv)}")
            print(f"Phase 3 rows: {csv_count(phase3_csv)}")

            print(f"Average Phase 2 latency: {csv_mean(phase2_csv, 'latency_ms'):.3f} ms")
            print(f"Average Phase 2 compute: {csv_mean(phase2_csv, 'compute_ms'):.3f} ms")
            print(f"Average Phase 2 overhead: {csv_mean(phase2_csv, 'overhead_bytes'):.3f} bytes")

            print(f"Average Phase 3 latency: {csv_mean(phase3_csv, 'latency_ms'):.3f} ms")
            print(f"Average Phase 3 compute: {csv_mean(phase3_csv, 'compute_ms'):.3f} ms")
            print(f"Average Phase 3 overhead: {csv_mean(phase3_csv, 'overhead_bytes'):.3f} bytes")

            success_rate = csv_mean(phase2_csv, 'success') * 100.0

        print(f"Authentication success rate (Phase 2 rows): {success_rate:.2f}%")
        return

    files = glob.glob(os.path.join("simulations", "results", "*.sca"))
    if not files:
        print("No .sca files found in simulations/results")
        return

    merged = defaultdict(list)
    for path in files:
        parsed = parse_scalar_file(path)
        for metric, vals in parsed.items():
            merged[metric].extend(vals)

    latency = summarize(merged, "phase2LatencyMs")
    peer_latency = summarize(merged, "phase3LatencyMs")
    overhead = summarize(merged, "phase2OverheadBytes")
    success = summarize(merged, "authSuccessRate")

    print("=== OMNeT++ Scalar Summary ===")
    print(f"Files analyzed: {len(files)}")

    if latency is not None:
        print(f"Average Phase 2 auth latency: {latency:.3f} ms")
    else:
        print("Average Phase 2 auth latency: unavailable")

    if peer_latency is not None:
        print(f"Average Phase 3 peer auth latency: {peer_latency:.3f} ms")
    else:
        print("Average Phase 3 peer auth latency: unavailable")

    if overhead is not None:
        print(f"Average communication overhead: {overhead:.3f} bytes")
    else:
        print("Average communication overhead: unavailable")

    if success is not None:
        print(f"Authentication success rate: {success * 100.0:.2f}%")
    else:
        print("Authentication success rate: unavailable")


if __name__ == "__main__":
    main()
