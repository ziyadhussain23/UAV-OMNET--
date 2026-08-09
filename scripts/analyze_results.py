#!/usr/bin/env python3
"""Summarise the exported CSVs.

Reports mean +/- 95% CI with the run as the unit of replication, and refuses to
print an interval when fewer than three runs exist rather than emitting a
zero-width one. Success rates carry a Wilson interval, and when there are no
observed failures the rule-of-three upper bound is shown -- so "10 of 10
succeeded" reads as "failure probability at most ~26%", not "100% reliable".
"""

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402


def load(path):
    if not path.exists():
        return []
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def fmt_ci(stats, unit="", digits=4):
    if stats is None:
        return "n/a"
    m = stats["mean_of_run_means"]
    if stats.get("ci95_lo", "") == "":
        return "%.*f %s  (%s)" % (digits, m, unit, stats["ci_method"])
    half = (stats["ci95_hi"] - stats["ci95_lo"]) / 2.0
    return "%.*f +/- %.*f %s  (n=%d runs, df=%d)" % (
        digits, m, digits, half, unit, stats["n_runs"], stats["df"])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    args = ap.parse_args()
    d = Path(args.results_dir)

    p1 = load(d / "omnet_phase1_results.csv")
    p2 = load(d / "omnet_phase2_results.csv")
    p3 = load(d / "omnet_phase3_results.csv")
    rel = load(d / "omnet_reliability.csv")
    prim = load(d / "omnet_primitive_costs.csv")

    if not p2 and not p3:
        print("no exported results found in %s" % d)
        print("run: python3 scripts/run_experiments.py")
        return 1

    configs = sorted({r["config"] for r in p2} | {r["config"] for r in p3})
    print("=" * 78)
    print("UAV authentication protocol - results summary")
    print("=" * 78)
    print("configs: %d    phase1 rows: %d    phase2 rows: %d    phase3 rows: %d"
          % (len(configs), len(p1), len(p2), len(p3)))

    for config in configs:
        c2 = [r for r in p2 if r["config"] == config]
        c3 = [r for r in p3 if r["config"] == config]
        crel = [r for r in rel if r["config"] == config]
        runs = sorted({r["run_id"] for r in c2} | {r["run_id"] for r in c3})
        suite = c2[0]["suite"] if c2 else (c3[0]["suite"] if c3 else "?")

        print("\n" + "-" * 78)
        print("%s   [suite=%s, runs=%d]" % (config, suite, len(runs)))
        print("-" * 78)

        if c2:
            print("  Phase 2 (UAV<->GS)")
            for metric, unit in (("wall_latency_ms", "ms"), ("latency_ms", "ms"),
                                 ("compute_ms", "ms"), ("net_ms", "ms"),
                                 ("overhead_bytes", "B")):
                print("    %-18s %s" % (metric, fmt_ci(stats_util.two_stage_ci(c2, metric), unit)))
            print("    %-18s %s" % ("puf_eval_ms",
                                    fmt_ci(stats_util.two_stage_ci(c2, "puf_eval_ms"), "ms")))
            print("    %-18s %s" % ("fe_rep_ms",
                                    fmt_ci(stats_util.two_stage_ci(c2, "fe_rep_ms"), "ms")))

        if c3:
            print("  Phase 3 (UAV<->UAV, per pair-view)")
            for metric, unit in (("latency_ms", "ms"), ("compute_ms", "ms"),
                                 ("net_ms", "ms"), ("overhead_bytes", "B")):
                print("    %-18s %s" % (metric, fmt_ci(stats_util.two_stage_ci(c3, metric), unit)))

        # Reliability, reported honestly at the device level.
        if crel:
            enrolled = sum(int(r["num_enrolled"]) for r in crel)
            ok = sum(int(r["auth_successes"]) for r in crel)
            fefail = sum(int(r["fe_reproduction_failures"]) for r in crel)
            lo, hi = stats_util.wilson_interval(ok, enrolled)
            print("  Reliability")
            print("    device auth success  %d/%d = %.4f   Wilson95 [%.4f, %.4f]"
                  % (ok, enrolled, ok / enrolled if enrolled else 0.0, lo, hi))
            if fefail:
                print("    key-reproduction failures: %d (device never started the handshake)"
                      % fefail)
            if enrolled and ok == enrolled:
                print("    no failures observed => failure probability <= %.4f (rule of three)"
                      % stats_util.rule_of_three_upper(enrolled))

        # Phase-3 success over pair-views.
        if c3:
            ok3 = sum(1 for r in c3 if r["success"] == "1")
            lo, hi = stats_util.wilson_interval(ok3, len(c3))
            print("    peer auth success    %d/%d = %.4f   Wilson95 [%.4f, %.4f]"
                  % (ok3, len(c3), ok3 / len(c3), lo, hi))

    # Per-primitive cost, with the implementation named so a vendored primitive
    # is never silently compared against an optimised one.
    if prim:
        print("\n" + "=" * 78)
        print("Per-primitive cost (median us per call, aggregated over runs)")
        print("=" * 78)
        agg = {}
        for r in prim:
            key = (r["suite"], r["primitive"])
            agg.setdefault(key, []).append(float(r["median_us"] or 0.0))
        for (suite, name) in sorted(agg):
            vals = [v for v in agg[(suite, name)] if v > 0]
            if vals:
                print("  %-9s %-14s %8.2f us" % (suite, name, sum(vals) / len(vals)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
