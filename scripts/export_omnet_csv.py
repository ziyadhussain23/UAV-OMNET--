#!/usr/bin/env python3
"""Export OMNeT++ scalar files to CSV.

Schema-driven: each output file is one entry in SCHEMAS with an ordered column
list and a builder. Adding a metric means touching one place, not three.

Backward compatibility is deliberate. omnet_phase2_results.csv and
omnet_phase3_results.csv keep their original leading columns in their original
order, so existing figure and comparison scripts keep working; new columns are
appended. `idx` is assigned once, globally, before the per-suite split files are
written, so it is a stable join key across all of them (it was not before).
"""

import argparse
import csv
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402

UAV_MODULE_RE = re.compile(r"\.uav\[(\d+)\]$")
PEER_METRIC_RE = re.compile(r"^phase3_peer_(\d+)_(.+)$")


# ---------------------------------------------------------------------------
# .sca parsing
# ---------------------------------------------------------------------------

def parse_sca(path):
    """Read one scalar file into {run metadata, modules -> {metric: value}}."""
    run = {
        "file": str(path), "run_id": "", "config": "unknown", "runnumber": "",
        "repetition": "", "seedset": "", "itervars": {}, "modules": {},
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
            elif line.startswith("itervar "):
                parts = line.split(maxsplit=2)
                if len(parts) == 3:
                    run["itervars"][parts[1]] = parts[2].strip('"').replace('\\"', "")
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


def uav_modules(run):
    found = []
    for name, metrics in run["modules"].items():
        m = UAV_MODULE_RE.search(name)
        if m:
            found.append((int(m.group(1)), name, metrics))
    return sorted(found, key=lambda t: t[0])


def run_identity(run):
    """Fields repeated on every row so any table can be filtered or joined."""
    gs = gs_metrics(run)
    suite = "spongent" if gs.get("suite", gs.get("hashMode", 0.0)) >= 0.5 else "sha3"
    iv = run["itervars"]
    return {
        "run_id": run["run_id"] or Path(run["file"]).stem,
        "config": run["config"],
        "runnumber": run["runnumber"],
        "repetition": run["repetition"],
        "seedset": run["seedset"],
        "suite": suite,
        "hash_mode": suite,          # legacy column name, same value
        "num_uavs": int(gs.get("numUAVs", 0)),
        "puf_ber": iv.get("ber", ""),
        "fe_profile": iv.get("profile", ""),
        "attack_mode": iv.get("attack", ""),
    }


RID_COLS = ["run_id", "config", "runnumber", "repetition", "seedset", "suite",
            "num_uavs", "puf_ber", "fe_profile", "attack_mode"]


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

def build_phase1(run):
    rid = run_identity(run)
    gs = gs_metrics(run)
    rows = []
    for uav_id in range(rid["num_uavs"]):
        p = "phase1_uav_%d_" % uav_id
        if (p + "success") not in gs:
            continue
        row = dict(rid)
        row.update({
            "uav_id": uav_id,
            "success": int(round(gs.get(p + "success", 0.0))),
            "puf_eval_ms": round(gs.get(p + "puf_eval_ms", 0.0), 6),
            "fe_gen_ms": round(gs.get(p + "fe_gen_ms", 0.0), 6),
            "total_ms": round(gs.get(p + "total_ms", 0.0), 6),
            "helper_bytes": int(round(gs.get(p + "helper_bytes", 0.0))),
            "challenge_bytes": int(round(gs.get(p + "challenge_bytes", 0.0))),
            "details": "enrollment; config=%s" % rid["config"],
        })
        rows.append(row)
    return rows


PHASE1_COLS = (["idx"] + RID_COLS + [
    "uav_id", "success", "puf_eval_ms", "fe_gen_ms", "total_ms",
    "helper_bytes", "challenge_bytes", "details"])


def build_phase2(run):
    rid = run_identity(run)
    gs = gs_metrics(run)
    rows = []
    for uav_id, module, m in uav_modules(run):
        g = "phase2Gs_uav_%d_" % uav_id
        compute = m.get("phase2ComputeMs", 0.0)
        net = m.get("phase2NetMs", 0.0)
        row = {
            # --- original leading columns, unchanged order ---
            "success": int(round(m.get("phase2Success", 0.0))),
            "latency_ms": round(m.get("phase2LatencyMs", compute + net), 6),
            "compute_ms": round(compute, 6),
            "net_ms": round(net, 6),
            "overhead_bytes": int(round(m.get("phase2OverheadBytes", 0.0))),
            "hash_mode": rid["hash_mode"],
            "details": "OMNeT++; module=%s; config=%s" % (module, rid["config"]),
            "m1_uav_compute_ms": round(m.get("m1_uav_compute_ms", 0.0), 6),
            "m1_gs_compute_ms": round(gs.get(g + "m1_gs_compute_ms", 0.0), 6),
            "m1_net_ms": round(gs.get(g + "m1_net_ms", 0.0), 6),
            "m2_uav_verify_ms": round(m.get("m2_uav_verify_ms", 0.0), 6),
            "m2_net_ms": round(m.get("m2_net_ms", 0.0), 6),
            "puf_eval_ms": round(m.get("puf_eval_ms", 0.0), 6),
            "bch_ms": round(m.get("bch_ms", 0.0), 6),
            "m3_uav_compute_ms": round(m.get("m3_uav_compute_ms", 0.0), 6),
            "m3_gs_compute_ms": round(gs.get(g + "m3_gs_compute_ms", 0.0), 6),
            "m3_net_ms": round(gs.get(g + "m3_net_ms", 0.0), 6),
            "m4_uav_compute_ms": round(m.get("m4_uav_compute_ms", 0.0), 6),
            "m4_net_ms": round(m.get("m4_net_ms", 0.0), 6),
            "uav_id": uav_id,
            # --- appended ---
            "wall_latency_ms": round(m.get("phase2_wall_latency_ms", 0.0), 6),
            "fe_rep_ms": round(m.get("fe_rep_ms", 0.0), 6),
            "mac_ms": round(m.get("mac_ms", 0.0), 6),
            "kdf_ms": round(m.get("kdf_ms", 0.0), 6),
            "dh_ms": round(m.get("dh_ms", 0.0), 6),
            "aead_ms": round(m.get("aead_ms", 0.0), 6),
            "gs_mac_ms": round(gs.get(g + "mac_ms", 0.0), 6),
            "gs_kdf_ms": round(gs.get(g + "kdf_ms", 0.0), 6),
            "gs_dh_ms": round(gs.get(g + "dh_ms", 0.0), 6),
            "gs_aead_ms": round(gs.get(g + "aead_ms", 0.0), 6),
            "bytes_m1": int(round(m.get("bytes_m1", 0.0))),
            "bytes_m2": int(round(m.get("bytes_m2", 0.0))),
            "bytes_m3": int(round(m.get("bytes_m3", 0.0))),
            "bytes_m4": int(round(m.get("bytes_m4", 0.0))),
            "ephemeral_erased": int(round(m.get("ephemeral_erased", 0.0))),
            "replay_cache_hits": int(round(m.get("replay_cache_hits", 0.0))),
        }
        row.update(rid)
        row["row_uid"] = "%s|phase2|%d" % (row["run_id"], uav_id)
        rows.append(row)
    return rows


PHASE2_COLS = (["idx", "success", "latency_ms", "compute_ms", "net_ms",
                "overhead_bytes", "hash_mode", "details",
                "m1_uav_compute_ms", "m1_gs_compute_ms", "m1_net_ms",
                "m2_uav_verify_ms", "m2_net_ms", "puf_eval_ms", "bch_ms",
                "m3_uav_compute_ms", "m3_gs_compute_ms", "m3_net_ms",
                "m4_uav_compute_ms", "m4_net_ms", "config", "run_id", "uav_id"]
               + ["row_uid", "runnumber", "repetition", "seedset", "suite",
                  "num_uavs", "puf_ber", "fe_profile", "attack_mode",
                  "wall_latency_ms", "fe_rep_ms", "mac_ms", "kdf_ms", "dh_ms",
                  "aead_ms", "gs_mac_ms", "gs_kdf_ms", "gs_dh_ms", "gs_aead_ms",
                  "bytes_m1", "bytes_m2", "bytes_m3", "bytes_m4",
                  "ephemeral_erased", "replay_cache_hits"])


def build_phase3(run):
    rid = run_identity(run)
    rows = []
    for uav_id, module, m in uav_modules(run):
        peers = {}
        for metric, value in m.items():
            pm = PEER_METRIC_RE.match(metric)
            if pm:
                peers.setdefault(int(pm.group(1)), {})[pm.group(2)] = value
        for peer_id, pm in sorted(peers.items()):
            # One row per ordered (initiator, responder) view. Both sides record
            # their own timings, so keep both and mark which is which.
            row = {
                "success": int(round(pm.get("success", 0.0))),
                "latency_ms": round(pm.get("latency_ms", 0.0), 6),
                "compute_ms": round(pm.get("compute_ms", 0.0), 6),
                "net_ms": round(pm.get("net_ms", 0.0), 6),
                "overhead_bytes": int(round(pm.get("overhead_bytes", 0.0))),
                "hash_mode": rid["hash_mode"],
                "details": "pair=UAV%d<->UAV%d; config=%s" % (uav_id, peer_id, rid["config"]),
                "p1_i_compute_ms": round(pm.get("p1_i_compute_ms", 0.0), 6),
                "p1_p2_j_compute_ms": round(pm.get("p1_p2_j_compute_ms", 0.0), 6),
                "p1_net_ms": round(pm.get("p1_net_ms", 0.0), 6),
                "p2_p3_i_compute_ms": round(pm.get("p2_p3_i_compute_ms", 0.0), 6),
                "p2_net_ms": round(pm.get("p2_net_ms", 0.0), 6),
                "p3_net_ms": round(pm.get("p3_net_ms", 0.0), 6),
                "uav_id": uav_id,
                "peer_uav_id": peer_id,
                "initiator": int(round(pm.get("initiator", 0.0))),
                "mac_ms": round(pm.get("mac_ms", 0.0), 6),
                "kdf_ms": round(pm.get("kdf_ms", 0.0), 6),
                "dh_ms": round(pm.get("dh_ms", 0.0), 6),
                "pair_id": "%d-%d" % (min(uav_id, peer_id), max(uav_id, peer_id)),
            }
            row.update(rid)
            row["row_uid"] = "%s|phase3|%d|%d" % (row["run_id"], uav_id, peer_id)
            rows.append(row)
    return rows


PHASE3_COLS = (["idx", "success", "latency_ms", "compute_ms", "net_ms",
                "overhead_bytes", "hash_mode", "details",
                "p1_i_compute_ms", "p1_p2_j_compute_ms", "p1_net_ms",
                "p2_p3_i_compute_ms", "p2_net_ms", "p3_net_ms",
                "config", "run_id", "uav_id", "peer_uav_id"]
               + ["row_uid", "runnumber", "repetition", "seedset", "suite",
                  "num_uavs", "puf_ber", "fe_profile", "attack_mode",
                  "initiator", "pair_id", "mac_ms", "kdf_ms", "dh_ms"])


def build_primitives(run):
    """Per-primitive cost, with the implementation named."""
    rid = run_identity(run)
    rows = []
    for module, metrics in sorted(run["modules"].items()):
        prims = {}
        for metric, value in metrics.items():
            if metric.startswith("prim_"):
                body = metric[len("prim_"):]
                for field in ("_calls", "_total_ms", "_mean_us", "_median_us", "_p95_us"):
                    if body.endswith(field):
                        name = body[: -len(field)]
                        if name.startswith("gs_"):
                            name = name[3:]
                        prims.setdefault(name, {})[field.strip("_")] = value
                        break
        role = "groundStation" if module.endswith(".groundStation") else "uav"
        for name, vals in sorted(prims.items()):
            row = dict(rid)
            row.update({
                "module": module, "role": role, "primitive": name,
                "calls": int(round(vals.get("calls", 0.0))),
                "total_ms": round(vals.get("total_ms", 0.0), 6),
                "mean_us": round(vals.get("mean_us", 0.0), 6),
                "median_us": round(vals.get("median_us", 0.0), 6),
                "p95_us": round(vals.get("p95_us", 0.0), 6),
            })
            rows.append(row)
    return rows


PRIMITIVE_COLS = (["idx"] + RID_COLS + ["module", "role", "primitive", "calls",
                                        "total_ms", "mean_us", "median_us", "p95_us"])


def build_reliability(run):
    """Fuzzy-extractor reliability: the honest device-level success rate."""
    rid = run_identity(run)
    gs = gs_metrics(run)
    if "numEnrolled" not in gs:
        return []
    row = dict(rid)
    enrolled = int(round(gs.get("numEnrolled", 0.0)))
    attempts = int(round(gs.get("totalAuthAttempts", 0.0)))
    successes = int(round(gs.get("totalAuthSuccess", 0.0)))
    row.update({
        "num_enrolled": enrolled,
        "auth_attempts": attempts,
        "auth_successes": successes,
        # Of devices that managed to send M1.
        "auth_success_rate": round(gs.get("authSuccessRate", 0.0), 9),
        # Of ALL enrolled devices: lower when a device cannot reproduce its key
        # and therefore never starts the handshake at all.
        "device_auth_success_rate": round(gs.get("deviceAuthSuccessRate", 0.0), 9),
        "fe_reproduction_failures": int(round(gs.get("feReproductionFailures", 0.0))),
    })
    row.update(stats_util.proportion_summary(successes, enrolled))
    return [row]


RELIABILITY_COLS = (["idx"] + RID_COLS + [
    "num_enrolled", "auth_attempts", "auth_successes", "auth_success_rate",
    "device_auth_success_rate", "fe_reproduction_failures",
    "successes", "trials", "rate", "wilson_lo", "wilson_hi",
    "rule_of_three_upper_failure"])


# ---------------------------------------------------------------------------
# Summary with confidence intervals
# ---------------------------------------------------------------------------

SUMMARY_METRICS = [
    ("phase2", "latency_ms", "ms"), ("phase2", "compute_ms", "ms"),
    ("phase2", "net_ms", "ms"), ("phase2", "wall_latency_ms", "ms"),
    ("phase2", "overhead_bytes", "B"), ("phase2", "puf_eval_ms", "ms"),
    ("phase2", "fe_rep_ms", "ms"), ("phase2", "mac_ms", "ms"),
    ("phase2", "kdf_ms", "ms"), ("phase2", "dh_ms", "ms"),
    ("phase3", "latency_ms", "ms"), ("phase3", "compute_ms", "ms"),
    ("phase3", "net_ms", "ms"), ("phase3", "overhead_bytes", "B"),
]

SUMMARY_CI_COLS = ["config", "suite", "num_uavs", "puf_ber", "fe_profile",
                   "attack_mode", "phase", "metric", "unit",
                   "n_runs", "n_obs_total", "obs_per_run_mean",
                   "mean_of_run_means", "sd_of_run_means", "sem", "df", "t_crit",
                   "ci95_lo", "ci95_hi", "pooled_mean", "pooled_sd", "median",
                   "p05", "p95", "min", "max", "ci_method"]


def build_summary_ci(phase_rows):
    """Long-format summary: one row per (config, phase, metric)."""
    out = []
    groups = {}
    for phase, rows in phase_rows.items():
        for row in rows:
            key = (row.get("config", ""), row.get("suite", ""), row.get("num_uavs", ""),
                   row.get("puf_ber", ""), row.get("fe_profile", ""),
                   row.get("attack_mode", ""), phase)
            groups.setdefault(key, []).append(row)

    for (config, suite, n, ber, profile, attack, phase), rows in sorted(
            groups.items(), key=lambda kv: [str(x) for x in kv[0]]):
        for mphase, metric, unit in SUMMARY_METRICS:
            if mphase != phase:
                continue
            stats = stats_util.two_stage_ci(rows, metric)
            if stats is None:
                continue
            entry = {"config": config, "suite": suite, "num_uavs": n, "puf_ber": ber,
                     "fe_profile": profile, "attack_mode": attack,
                     "phase": phase, "metric": metric, "unit": unit}
            entry.update(stats)
            out.append(entry)
    return out


# Legacy wide summary, kept so existing scripts keep working.
LEGACY_SUMMARY_COLS = ["config", "hash_mode", "num_runs",
                       "phase2_mean_latency_ms", "phase2_mean_compute_ms",
                       "phase2_mean_net_ms", "phase2_mean_overhead_bytes",
                       "phase3_mean_latency_ms", "phase3_mean_compute_ms",
                       "phase3_mean_net_ms", "phase3_mean_overhead_bytes",
                       "auth_success_rate", "device_auth_success_rate",
                       "phase2_latency_ci95_lo", "phase2_latency_ci95_hi", "n_runs"]


def build_legacy_summary(p2, p3, rel):
    by_config = {}
    for row in p2:
        by_config.setdefault(row["config"], {"p2": [], "p3": [], "rel": []})["p2"].append(row)
    for row in p3:
        by_config.setdefault(row["config"], {"p2": [], "p3": [], "rel": []})["p3"].append(row)
    for row in rel:
        by_config.setdefault(row["config"], {"p2": [], "p3": [], "rel": []})["rel"].append(row)

    out = []
    for config in sorted(by_config):
        g = by_config[config]
        p2rows, p3rows, relrows = g["p2"], g["p3"], g["rel"]
        runs = {r["run_id"] for r in p2rows} or {r["run_id"] for r in p3rows}
        ci = stats_util.two_stage_ci(p2rows, "latency_ms") if p2rows else None

        def avg(rows, key):
            vals = [float(r[key]) for r in rows if r.get(key) not in ("", None)]
            return round(sum(vals) / len(vals), 6) if vals else 0.0

        out.append({
            "config": config,
            "hash_mode": p2rows[0]["hash_mode"] if p2rows else "",
            "num_runs": len(runs),
            "n_runs": len(runs),
            "phase2_mean_latency_ms": avg(p2rows, "latency_ms"),
            "phase2_mean_compute_ms": avg(p2rows, "compute_ms"),
            "phase2_mean_net_ms": avg(p2rows, "net_ms"),
            "phase2_mean_overhead_bytes": avg(p2rows, "overhead_bytes"),
            "phase3_mean_latency_ms": avg(p3rows, "latency_ms"),
            "phase3_mean_compute_ms": avg(p3rows, "compute_ms"),
            "phase3_mean_net_ms": avg(p3rows, "net_ms"),
            "phase3_mean_overhead_bytes": avg(p3rows, "overhead_bytes"),
            "auth_success_rate": avg(relrows, "auth_success_rate"),
            "device_auth_success_rate": avg(relrows, "device_auth_success_rate"),
            "phase2_latency_ci95_lo": ci.get("ci95_lo", "") if ci else "",
            "phase2_latency_ci95_hi": ci.get("ci95_hi", "") if ci else "",
        })
    return out


def write_csv(path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return len(rows)


def assign_indices(rows):
    for i, row in enumerate(rows):
        row["idx"] = i


def export(results_dir, include_configs=None):
    results_dir = Path(results_dir).resolve()
    sca_files = sorted(results_dir.glob("*.sca"))
    if not sca_files:
        raise FileNotFoundError("no .sca files in %s" % results_dir)

    p1, p2, p3, prim, rel = [], [], [], [], []
    for path in sca_files:
        run = parse_sca(path)
        if include_configs and run["config"] not in include_configs:
            continue
        p1 += build_phase1(run)
        p2 += build_phase2(run)
        p3 += build_phase3(run)
        prim += build_primitives(run)
        rel += build_reliability(run)

    if not p2 and not p3:
        raise RuntimeError("no matching runs found (configs=%s)" % include_configs)

    # Assign idx once, globally, before any split file is written, so it stays a
    # stable join key everywhere.
    for rows in (p1, p2, p3, prim, rel):
        assign_indices(rows)

    written = {}
    written["phase1"] = write_csv(results_dir / "omnet_phase1_results.csv", PHASE1_COLS, p1)
    written["phase2"] = write_csv(results_dir / "omnet_phase2_results.csv", PHASE2_COLS, p2)
    written["phase3"] = write_csv(results_dir / "omnet_phase3_results.csv", PHASE3_COLS, p3)
    written["primitives"] = write_csv(results_dir / "omnet_primitive_costs.csv",
                                      PRIMITIVE_COLS, prim)
    written["reliability"] = write_csv(results_dir / "omnet_reliability.csv",
                                      RELIABILITY_COLS, rel)

    summary_ci = build_summary_ci({"phase2": p2, "phase3": p3})
    written["summary_ci"] = write_csv(results_dir / "omnet_summary_ci.csv",
                                      SUMMARY_CI_COLS, summary_ci)
    written["summary"] = write_csv(results_dir / "omnet_summary.csv",
                                   LEGACY_SUMMARY_COLS,
                                   build_legacy_summary(p2, p3, rel))

    # Per-suite splits reuse the global idx rather than renumbering.
    for suite in ("sha3", "spongent"):
        s2 = [r for r in p2 if r["suite"] == suite]
        s3 = [r for r in p3 if r["suite"] == suite]
        if s2 or s3:
            write_csv(results_dir / ("omnet_phase2_%s.csv" % suite), PHASE2_COLS, s2)
            write_csv(results_dir / ("omnet_phase3_%s.csv" % suite), PHASE3_COLS, s3)
            written["phase2_" + suite] = len(s2)
            written["phase3_" + suite] = len(s3)

    return written


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    ap.add_argument("--configs", nargs="*", default=None)
    args = ap.parse_args()

    written = export(args.results_dir, set(args.configs) if args.configs else None)
    print("OMNeT++ CSV export complete:")
    for key in sorted(written):
        print("  %-18s %d rows" % (key, written[key]))


if __name__ == "__main__":
    main()
