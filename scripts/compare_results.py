#!/usr/bin/env python3
"""Compare Python baseline CSV against OMNeT++ CSV exports."""

import argparse
import csv

try:
    import pandas as pd  # type: ignore
except ModuleNotFoundError:
    pd = None


def resolve_col(df, *candidates):
    for col in candidates:
        if col in df.columns:
            return col
    return None


def resolve_col_names(header, *candidates):
    for col in candidates:
        if col in header:
            return col
    return None


def read_csv_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        header = reader.fieldnames or []
    return rows, header


def col_mean_from_rows(rows, col):
    vals = []
    for row in rows:
        try:
            vals.append(float(row[col]))
        except (KeyError, ValueError, TypeError):
            continue
    return (sum(vals) / len(vals)) if vals else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--python", required=True, help="Path to python_results.csv")
    parser.add_argument("--omnet", required=True, help="Path to omnet_results.csv")
    args = parser.parse_args()

    if pd is not None:
        py = pd.read_csv(args.python)
        om = pd.read_csv(args.omnet)

        print("Python results:\n", py.describe(include="all"))
        print("\nOMNeT++ results:\n", om.describe(include="all"))

        py_latency = resolve_col(py, "latency_ms", "Latency_ms")
        py_compute = resolve_col(py, "compute_ms", "Compute_ms")
        py_overhead = resolve_col(py, "overhead_bytes", "Overhead_bytes")

        om_latency = resolve_col(om, "latency_ms", "Latency_ms")
        om_compute = resolve_col(om, "compute_ms", "Compute_ms")
        om_overhead = resolve_col(om, "overhead_bytes", "Overhead_bytes")

        print("\nDifferences (OMNeT++ - Python):")

        if py_latency and om_latency:
            latency_diff = om[om_latency].mean() - py[py_latency].mean()
            print(f"Latency difference: {latency_diff:.3f} ms")
        else:
            print("Latency difference: unavailable (missing latency column)")

        if py_compute and om_compute:
            compute_diff = om[om_compute].mean() - py[py_compute].mean()
            print(f"Compute difference: {compute_diff:.3f} ms")
        else:
            print("Compute difference: unavailable (missing compute column)")

        if py_overhead and om_overhead:
            overhead_diff = om[om_overhead].mean() - py[py_overhead].mean()
            print(f"Overhead difference: {overhead_diff:.3f} bytes")
        else:
            print("Overhead difference: unavailable (missing overhead column)")

        return

    py_rows, py_header = read_csv_rows(args.python)
    om_rows, om_header = read_csv_rows(args.omnet)

    py_latency = resolve_col_names(py_header, "latency_ms", "Latency_ms")
    py_compute = resolve_col_names(py_header, "compute_ms", "Compute_ms")
    py_overhead = resolve_col_names(py_header, "overhead_bytes", "Overhead_bytes")

    om_latency = resolve_col_names(om_header, "latency_ms", "Latency_ms")
    om_compute = resolve_col_names(om_header, "compute_ms", "Compute_ms")
    om_overhead = resolve_col_names(om_header, "overhead_bytes", "Overhead_bytes")

    print(f"Python rows: {len(py_rows)}")
    print(f"OMNeT++ rows: {len(om_rows)}")
    print("\nDifferences (OMNeT++ - Python):")

    py_lat_mean = col_mean_from_rows(py_rows, py_latency) if py_latency else None
    om_lat_mean = col_mean_from_rows(om_rows, om_latency) if om_latency else None
    if py_lat_mean is not None and om_lat_mean is not None:
        print(f"Latency difference: {om_lat_mean - py_lat_mean:.3f} ms")
    else:
        print("Latency difference: unavailable (missing latency column)")

    py_cmp_mean = col_mean_from_rows(py_rows, py_compute) if py_compute else None
    om_cmp_mean = col_mean_from_rows(om_rows, om_compute) if om_compute else None
    if py_cmp_mean is not None and om_cmp_mean is not None:
        print(f"Compute difference: {om_cmp_mean - py_cmp_mean:.3f} ms")
    else:
        print("Compute difference: unavailable (missing compute column)")

    py_ovh_mean = col_mean_from_rows(py_rows, py_overhead) if py_overhead else None
    om_ovh_mean = col_mean_from_rows(om_rows, om_overhead) if om_overhead else None
    if py_ovh_mean is not None and om_ovh_mean is not None:
        print(f"Overhead difference: {om_ovh_mean - py_ovh_mean:.3f} bytes")
    else:
        print("Overhead difference: unavailable (missing overhead column)")


if __name__ == "__main__":
    main()
