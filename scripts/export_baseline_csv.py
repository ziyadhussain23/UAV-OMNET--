#!/usr/bin/env python3
"""Export the RSA/ECDSA baseline's .sca files to omnet_baseline_results.csv.

Separate from export_omnet_csv.py deliberately, same reasoning as
export_inet_csv.py: this track's scalars (baselineSuccess,
baselineWallLatencyMs, ...) are a different schema from the PUF protocol's,
so a dedicated exporter is clearer than retrofitting the existing one.

Per-primitive costs (prim_sign_*, prim_verify_*, prim_mac_*, ...) need NO
dedicated exporter at all -- they use the exact "prim_<name>_<field>" naming
scripts/export_omnet_csv.py's build_primitives() already parses generically,
so they flow into omnet_primitive_costs.csv automatically. Run that script
too (or use --also-primitives) to pick them up.
"""

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402


def parse_sca(path):
    run = {
        "file": str(path), "run_id": "", "config": "unknown", "runnumber": "",
        "repetition": "", "seedset": "", "modules": {},
    }
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("run "):
                run["run_id"] = line.split(maxsplit=1)[1]
            elif line.startswith("attr configname "):
                run["config"] = line.split(maxsplit=2)[2]
            elif line.startswith("attr runnumber "):
                run["runnumber"] = line.split(maxsplit=2)[2]
            elif line.startswith("attr repetition "):
                run["repetition"] = line.split(maxsplit=2)[2]
            elif line.startswith("attr seedset "):
                run["seedset"] = line.split(maxsplit=2)[2]
            elif line.startswith("scalar "):
                parts = line.split()
                if len(parts) < 4:
                    continue
                module, metric = parts[1], parts[2]
                try:
                    value = float(parts[3])
                except ValueError:
                    continue
                run["modules"].setdefault(module, {})[metric] = value
    return run


def gs_metrics(run):
    for name, metrics in run["modules"].items():
        if name.endswith(".groundStation"):
            return metrics
    return {}


def build_rows(run):
    rid = {
        "run_id": run["run_id"] or Path(run["file"]).stem,
        "config": run["config"],
        "runnumber": run["runnumber"],
        "repetition": run["repetition"],
        "seedset": run["seedset"],
    }
    gs = gs_metrics(run)
    suite = "ecdsa-p256" if gs.get("baselineSuite", 0.0) >= 0.5 else "rsa2048"

    rows = []
    for module, m in run["modules"].items():
        if "baselineSuccess" not in m:
            continue
        row = dict(rid)
        row.update({
            "uav_id": int(round(m.get("uavId", -1))),
            "sig_suite": suite,
            "success": int(round(m.get("baselineSuccess", 0.0))),
            "wall_latency_ms": round(m.get("baselineWallLatencyMs", 0.0), 6),
            "compute_ms": round(m.get("baselineComputeMs", 0.0), 6),
            "net_ms": round(m.get("baselineNetMs", 0.0), 6),
            "sign_ms": round(m.get("baseline_sign_ms", 0.0), 6),
            "verify_ms": round(m.get("baseline_verify_ms", 0.0), 6),
            "mac_ms": round(m.get("baseline_mac_ms", 0.0), 6),
            "kdf_ms": round(m.get("baseline_kdf_ms", 0.0), 6),
            "dh_ms": round(m.get("baseline_dh_ms", 0.0), 6),
            "overhead_bytes": int(round(m.get("baselineOverheadBytes", 0.0))),
            "bytes_b1": int(round(m.get("bytes_b1", 0.0))),
            "bytes_b2": int(round(m.get("bytes_b2", 0.0))),
            "bytes_b3": int(round(m.get("bytes_b3", 0.0))),
            "bytes_b4": int(round(m.get("bytes_b4", 0.0))),
        })
        rows.append(row)
    return rows


COLS = ["idx", "run_id", "config", "runnumber", "repetition", "seedset",
        "uav_id", "sig_suite", "success", "wall_latency_ms", "compute_ms", "net_ms",
        "sign_ms", "verify_ms", "mac_ms", "kdf_ms", "dh_ms", "overhead_bytes",
        "bytes_b1", "bytes_b2", "bytes_b3", "bytes_b4"]

DEFAULT_CONFIGS = ("BaselineRSA", "BaselineECDSA")


def export(results_dir, configs=DEFAULT_CONFIGS):
    results_dir = Path(results_dir).resolve()
    rows = []
    for cfg in configs:
        for path in sorted(results_dir.glob(f"{cfg}-*.sca")):
            rows.extend(build_rows(parse_sca(path)))
    if not rows:
        raise RuntimeError("no baseline rows found for configs=%s" % (configs,))

    for i, row in enumerate(rows):
        row["idx"] = i

    out_path = results_dir / "omnet_baseline_results.csv"
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"wrote {len(rows)} rows to {out_path}")
    for cfg in configs:
        cfg_rows = [r for r in rows if r["config"] == cfg]
        if not cfg_rows:
            continue
        succ = sum(r["success"] for r in cfg_rows)
        n_runs = len({r["run_id"] for r in cfg_rows})
        if n_runs < 3:
            print(f"  {cfg}: only {n_runs} run(s) so far (need >=3 for a CI) -- "
                  f"success={succ}/{len(cfg_rows)}")
            continue
        st = stats_util.two_stage_ci(cfg_rows, "wall_latency_ms")
        halfwidth = st["sem"] * st["t_crit"]
        print(f"  {cfg}: n_runs={st['n_runs']} "
              f"wall_latency_ms={st['mean_of_run_means']:.4f}+/-{halfwidth:.4f} "
              f"success={succ}/{len(cfg_rows)}")
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    ap.add_argument("--configs", nargs="*", default=list(DEFAULT_CONFIGS))
    args = ap.parse_args()
    export(args.results_dir, tuple(args.configs))


if __name__ == "__main__":
    main()
