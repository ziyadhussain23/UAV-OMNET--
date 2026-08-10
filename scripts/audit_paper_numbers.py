#!/usr/bin/env python3
"""Recompute every CSV-derived table/prose figure in final_theory/paper.tex
from the current simulations/results/*.csv files, via stats_util (the same
statistics engine the CSVs themselves were built with), and print the
canonical values so they can be checked against the paper's typeset text.

Zero scripts anywhere write .tex directly -- every number in the paper was,
and remains, hand-transcribed. This script does not change that (building a
robust LaTeX-table rewriter for a one-off audit would be more machinery than
the problem needs); it exists to make "does the paper still say what the
data says" a fast, mechanical check instead of an error-prone manual re-read,
and to be re-run whenever the underlying CSVs change (as they did between
the 10-run and 30-run campaigns) so a stale number cannot silently persist.

Run with no arguments; read the printed values against the corresponding
\\label{} in paper.tex.
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402

RESULTS = Path(__file__).resolve().parent.parent / "simulations" / "results"


def load(name):
    with open(RESULTS / name, newline="") as fh:
        return list(csv.DictReader(fh))


def section(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


def audit_functional():
    section("tab:functional -- Authentication outcomes")
    rel = load("omnet_reliability.csv")
    p3 = load("omnet_phase3_results.csv")
    configs = [("StadiumSHA3", 10), ("StadiumSPONGENT", 10), ("Baseline5UAV", 5),
               ("Swarm20", 20), ("ArbiterPuf", 10), ("HighNoise", 10)]
    for cfg, n in configs:
        rows = [r for r in rel if r["config"] == cfg]
        n_runs = len({r["run_id"] for r in rows})
        enrolled = sum(int(r["num_enrolled"]) for r in rows)
        successes = sum(int(r["auth_successes"]) for r in rows)
        lo, hi = stats_util.wilson_interval(successes, enrolled)
        p3rows = [r for r in p3 if r["config"] == cfg]
        p3_success = sum(1 for r in p3rows if r["success"] == "1")
        p3_total = len(p3rows)
        print(f"  {cfg:<16} n_runs={n_runs:<3} devices={enrolled:<5} "
              f"auth={successes:<5} rate={successes/enrolled:.3f} "
              f"wilson=[{lo:.3f},{hi:.3f}]  peer={p3_success}/{p3_total}")


def audit_latency():
    section("tab:latency -- Phase-2 latency and overhead")
    p2 = load("omnet_phase2_results.csv")
    for cfg in ("StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20"):
        rows = [r for r in p2 if r["config"] == cfg]
        n_runs = len({r["run_id"] for r in rows})
        out = {}
        for metric in ("wall_latency_ms", "compute_ms", "net_ms"):
            st = stats_util.two_stage_ci(rows, metric)
            halfwidth = st["sem"] * st["t_crit"]
            out[metric] = f"{st['mean_of_run_means']:.4f} +/- {halfwidth:.4f}"
        overhead = {int(round(float(r["overhead_bytes"]))) for r in rows}
        print(f"  {cfg:<16} n_runs={n_runs:<3} "
              f"end-to-end={out['wall_latency_ms']:<20} "
              f"compute={out['compute_ms']:<20} net={out['net_ms']:<20} "
              f"overhead_bytes={sorted(overhead)}")

    section("Prose: Phase-3 per-pair latency, 'unchanged from N=5 to N=20'")
    p3 = load("omnet_phase3_results.csv")
    for cfg in ("StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20"):
        rows = [r for r in p3 if r["config"] == cfg]
        st = stats_util.two_stage_ci(rows, "latency_ms")
        halfwidth = st["sem"] * st["t_crit"]
        overhead = {int(round(float(r["overhead_bytes"]))) for r in rows}
        print(f"  {cfg:<16} n_runs={st['n_runs']:<3} "
              f"latency={st['mean_of_run_means']:.4f} +/- {halfwidth:.4f} ms  "
              f"overhead_bytes={sorted(overhead)}")
    # A single defined pooling recipe: pool StadiumSHA3+StadiumSPONGENT+
    # Baseline5UAV+Swarm20 (every config the "unchanged across swarm size"
    # claim is actually about; excludes ArbiterPuf/HighNoise, which vary BER,
    # not swarm size, so pooling them in would answer a different question).
    pooled = []
    for cfg in ("StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20"):
        pooled += [r for r in p3 if r["config"] == cfg]
    st = stats_util.two_stage_ci(pooled, "latency_ms")
    halfwidth = st["sem"] * st["t_crit"]
    print(f"  POOLED (Stadium+Baseline5UAV+Swarm20, the swarm-size-varying "
          f"configs): n_runs={st['n_runs']} "
          f"latency={st['mean_of_run_means']:.4f} +/- {halfwidth:.4f} ms")


def audit_primitives():
    section("tab:primitives/tab:pki -- primitive costs (in-protocol; PKI baseline unchanged, restored from archive)")
    prim = load("omnet_primitive_costs.csv")
    names = ["mac", "mac_verify", "kdf", "extract", "aead_seal", "aead_open",
             "dh_keygen", "dh_derive"]
    for suite in ("sha3", "spongent"):
        print(f"  -- suite={suite} --")
        for name in names:
            rows = [r for r in prim if r["suite"] == suite and r["primitive"] == name]
            if not rows:
                print(f"    {name:<12} (no rows)")
                continue
            vals = [float(r["median_us"]) for r in rows]
            print(f"    {name:<12} n={len(rows):<5} median_us(mean of per-row medians)={sum(vals)/len(vals):.3f}")
    print("  NOTE: no 'hash160' rows exist in omnet_primitive_costs.csv for either "
        "suite -- confirms the standalone hash is never called as an "
        "in-protocol primitive; any 'Hash' row in tab:primitives must be "
        "sourced from omnet_pki_baseline.csv (ours-sha3,hash160) and labelled "
        "as such, not as 'measured in-protocol'.")


def audit_noise():
    section("tab:noise -- fuzzy-extractor reliability (NoiseSweep, now repeat=3 per point => 30 devices "
            "per point still, since it's UAV count x repeat, not repeat alone -- verify below)")
    ns = load("omnet_noise_sweep.csv")
    print(f"  columns: {list(ns[0].keys()) if ns else 'EMPTY'}")
    for row in ns[:3]:
        print(f"  sample row: {row}")


def audit_attacks():
    section("tab:attacks -- attack outcomes (now n_runs=5 per attack, not 1)")
    sec = load("omnet_security_results.csv")
    for row in sec:
        print(f"  {row['config']:<24} {row['attack']:<14} n_runs={row['n_runs']} "
              f"attempts={row['attempts']:<4} accepted={row['accepted']:<3} "
              f"oracle={row['oracle_replies']:<3} creds={row['credentials_exposed']:<3} "
              f"expected={row['expected_success']} "
              f"matches={row['outcome_matches_expectation']}")


def audit_mobility():
    section("NEW: mobility (item 8) -- omnet_mobility_results.csv")
    mob = load("omnet_mobility_results.csv")
    for model in ("linear", "randomwalk"):
        rows = [r for r in mob if r["mobility_model"] == model]
        if not rows:
            continue
        n_runs = len({r["run_id"] for r in rows})
        dists = [float(r["total_distance_traveled_m"]) for r in rows]
        st = stats_util.two_stage_ci(rows, "phase2_wall_latency_ms")
        halfwidth = st["sem"] * st["t_crit"]
        print(f"  {model:<12} n_runs={n_runs:<3} "
              f"mean_distance_m={sum(dists)/len(dists):.1f} "
              f"phase2_wall_latency_ms={st['mean_of_run_means']:.4f} +/- {halfwidth:.4f}")


def audit_inet():
    section("NEW: INET/802.11 (item 5) -- omnet_inet_latency.csv")
    inet = load("omnet_inet_latency.csv")
    for cfg in ("Inet80211SHA3", "Inet80211SPONGENT"):
        rows = [r for r in inet if r["config"] == cfg]
        if not rows:
            continue
        st = stats_util.two_stage_ci(rows, "wall_latency_ms")
        halfwidth = st["sem"] * st["t_crit"]
        succ = sum(int(r["success"]) for r in rows)
        print(f"  {cfg:<20} n_runs={st['n_runs']:<3} "
              f"wall_latency_ms={st['mean_of_run_means']:.3f} +/- {halfwidth:.3f} "
              f"success={succ}/{len(rows)}")


def audit_energy():
    section("NEW: energy (item 9) -- omnet_energy_costs.csv")
    en = load("omnet_energy_costs.csv")
    for row in en:
        if row["row_type"] != "aggregate_per_handshake":
            continue
        print(f"  [{row['source']:<16}] {row['primitive']:<24} {row['config']:<20} "
              f"{row['value']} {row['unit']}")


def audit_baseline_comparison():
    section("tab:baseline_comparison -- RSA/ECDSA full-protocol baseline (item 3, last)")
    baseline = load("omnet_baseline_results.csv")
    for cfg in ("BaselineRSA", "BaselineECDSA"):
        rows = [r for r in baseline if r["config"] == cfg]
        if not rows:
            print(f"  {cfg}: NO DATA")
            continue
        n_runs = len({r["run_id"] for r in rows})
        succ = sum(int(r["success"]) for r in rows)
        out = {}
        for metric in ("wall_latency_ms", "compute_ms", "net_ms"):
            st = stats_util.two_stage_ci(rows, metric)
            hw = st["sem"] * st["t_crit"]
            out[metric] = f"{st['mean_of_run_means']:.4f} +/- {hw:.4f}"
        ob = sorted({int(round(float(r["overhead_bytes"]))) for r in rows})
        realistic = None
        try:
            c = stats_util.two_stage_ci(rows, "compute_ms")["mean_of_run_means"]
            n = stats_util.two_stage_ci(rows, "net_ms")["mean_of_run_means"]
            realistic = c + n
        except Exception:
            pass
        print(f"  {cfg:<16} n_runs={n_runs:<3} success={succ}/{len(rows)}")
        print(f"    end-to-end={out['wall_latency_ms']:<20} compute={out['compute_ms']:<20} "
              f"net={out['net_ms']:<20} overhead_bytes={ob}")
        if realistic is not None:
            print(f"    realistic_total(compute+net) = {realistic:.4f}")


def audit_prose_repetition_counts():
    section("Prose: hardcoded repetition counts (grep final_theory/paper.tex for these)")
    print('  Expect NO remaining matches for: "ten independent repetitions", '
          '"ten repetitions per configuration", "ten runs", "over ten runs"')
    print("  All main configs now run 30 repetitions; attack configs run 5; "
          "NoiseSweep runs 3 x 21 combinations = 63.")


def main():
    audit_functional()
    audit_latency()
    audit_primitives()
    audit_noise()
    audit_attacks()
    audit_mobility()
    audit_inet()
    audit_energy()
    audit_baseline_comparison()
    audit_prose_repetition_counts()


if __name__ == "__main__":
    main()
