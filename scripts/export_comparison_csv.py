#!/usr/bin/env python3
"""Build omnet_comparison.csv: one row per configuration, every family together.

Why this file exists
--------------------
Each per-topic CSV answers one question, and that separation is deliberate. But a
reader also wants the one table that puts them side by side, and building it by
hand from five files is how transcription errors get into a paper. This script
does the join once, from the per-topic CSVs, so the comparison table and the
detail tables cannot disagree.

The two-clock problem
---------------------
The families do NOT share a clock model, and presenting them as if they did is
the single easiest way to publish a wrong comparison:

  two-clock families (idealised medium, noise, baselines)
      compute is host wall-clock (real CPU time); network is the simulator's own
      delay model. The simulated clock does not advance while compute runs, so
      "simulated elapsed" is close to network time and NOT compute+network.
      The honest total is compute + network, which is what reported_latency_ms
      carries for these rows.

  one-clock families (INET 802.11)
      everything runs on the simulation clock, so the measured end-to-end
      wall time already includes the crypto work inline. The honest total is
      wall_latency_ms, and net_ms is derived as wall - compute.

Both cases report compute and network separately (the reason this CSV exists),
and clock_model + reported_latency_ms state which total is the meaningful one,
so no reader has to guess.
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402

# config -> (family, clock_model, what it isolates)
FAMILIES = {
    "StadiumSHA3": ("latency", "two", "reference: N=10, software suite"),
    "StadiumSPONGENT": ("latency", "two", "suite swapped to constrained-hardware"),
    "Baseline5UAV": ("latency", "two", "swarm size N=5"),
    "Swarm20": ("latency", "two", "swarm size N=20"),
    "ArbiterPuf": ("noise", "two", "realistic PUF model, 3% BER"),
    "HighNoise": ("noise", "two", "PUF BER forced to 5%"),
    "NoiseSweep": ("noise", "two", "BER swept x three FE profiles"),
    "BaselineRSA": ("baseline", "two", "RSA-2048-signed ephemeral DH"),
    "BaselineECDSA": ("baseline", "two", "ECDSA-P256-signed ephemeral DH"),
    "Inet80211SHA3": ("inet", "one", "real 802.11 CSMA/CA, static"),
    "InetMobilityLinearSHA3": ("inet", "one", "real 802.11 CSMA/CA, moving linearly"),
    "InetMobilityRandomWalkSHA3": ("inet", "one", "real 802.11 CSMA/CA, random waypoints"),
}

COLS = ["config", "family", "clock_model", "scheme", "n_runs",
        "success_rate", "n_records",
        "compute_ms", "compute_ci95",
        "net_ms", "net_ci95",
        "wall_ms", "wall_ci95",
        "reported_latency_ms", "reported_ci95",
        "notes"]


def load(path):
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def ci(rows, col):
    """Two-stage CI over run means; returns (mean, halfwidth) or (None, None)."""
    if not rows or not any(r.get(col) not in ("", None) for r in rows):
        return None, None
    stats = stats_util.two_stage_ci(rows, col)
    if stats is None:
        return None, None
    return stats["mean_of_run_means"], stats["sem"] * stats["t_crit"]


def scheme_of(rows):
    for r in rows:
        if r.get("suite"):
            return r["suite"]
        if r.get("sig_suite"):
            return r["sig_suite"]
    return ""


def rnd(v):
    return "" if v is None else round(v, 4)


def build(results_dir):
    # Phase-2 rows per config, from whichever per-topic file owns that config.
    src = {
        "latency": load(results_dir / "omnet_phase2_results.csv"),
        "noise": load(results_dir / "omnet_noise_results.csv"),
        "baseline": load(results_dir / "omnet_baseline_results.csv"),
        "inet": load(results_dir / "omnet_inet_latency.csv"),
    }

    # The baseline file names its latency column wall_latency_ms and carries
    # compute/net itself; the INET file now does too. Normalise to compute_ms /
    # net_ms / wall_ms so the join is uniform.
    by_cfg = defaultdict(list)
    for rows in src.values():
        for r in rows:
            if r.get("phase", "phase2") != "phase2":
                continue          # peer rows have no wall time on the INET track
            by_cfg[r["config"]].append(r)

    out = []
    for cfg, (family, clock, note) in sorted(FAMILIES.items()):
        rows = by_cfg.get(cfg)
        if not rows:
            continue

        comp, comp_hw = ci(rows, "compute_ms")
        wall, wall_hw = ci(rows, "wall_latency_ms")
        net, net_hw = ci(rows, "net_ms")

        # Two-clock tracks never recorded a net_ms column; take it from the
        # idealised schema's own net_ms field, which build_phase2 emits.
        if net is None:
            net, net_hw = ci(rows, "net_ms")

        if clock == "two":
            reported = None if comp is None or net is None else comp + net
            rep_hw = None if reported is None or (comp_hw is None or net_hw is None) \
                else comp_hw + net_hw
        else:
            reported, rep_hw = wall, wall_hw

        succ = [float(r["success"]) for r in rows if r.get("success") not in ("", None)]
        out.append({
            "config": cfg,
            "family": family,
            "clock_model": clock,
            "scheme": scheme_of(rows),
            "n_runs": len({r["run_id"] for r in rows}),
            "n_records": len(rows),
            "success_rate": round(sum(succ) / len(succ), 6) if succ else "",
            "compute_ms": rnd(comp),
            "compute_ci95": rnd(comp_hw),
            "net_ms": rnd(net),
            "net_ci95": rnd(net_hw),
            "wall_ms": rnd(wall),
            "wall_ci95": rnd(wall_hw),
            "reported_latency_ms": rnd(reported),
            "reported_ci95": rnd(rep_hw),
            "notes": note,
        })
    return out


def export(results_dir):
    results_dir = Path(results_dir).resolve()
    rows = build(results_dir)
    if not rows:
        raise RuntimeError("no comparison rows: per-topic CSVs missing?")
    out_path = results_dir / "omnet_comparison.csv"
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"wrote {len(rows)} rows to {out_path}")
    print(f"  {'config':26s} {'clock':5s} {'compute':>9s} {'net':>9s} "
          f"{'wall':>9s} {'reported':>9s}")
    for r in rows:
        def f(v):
            return "  n/a  " if v in ("", None) else f"{v:9.3f}"
        print(f"  {r['config']:26s} {r['clock_model']:5s} {f(r['compute_ms'])} "
              f"{f(r['net_ms'])} {f(r['wall_ms'])} {f(r['reported_latency_ms'])}")
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    args = ap.parse_args()
    export(args.results_dir)


if __name__ == "__main__":
    main()
