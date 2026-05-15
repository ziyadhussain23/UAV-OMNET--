#!/usr/bin/env python3
"""Export OMNeT++ .sca results into Python-style CSV files for delay comparison."""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

UAV_MODULE_RE = re.compile(r"\.uav\[(\d+)\]$")


def parse_sca_file(path: Path) -> Dict:
    run_data = {
        "file": str(path),
        "run_id": "",
        "config": "",
        "runnumber": "",
        "modules": defaultdict(dict),
    }

    with path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("run "):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    run_data["run_id"] = parts[1]
                continue

            if line.startswith("attr configname "):
                run_data["config"] = line.split(maxsplit=2)[2]
                continue

            if line.startswith("attr runnumber "):
                run_data["runnumber"] = line.split(maxsplit=2)[2]
                continue

            if not line.startswith("scalar "):
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            module = parts[1]
            metric = parts[2]
            value = parts[3]

            try:
                run_data["modules"][module][metric] = float(value)
            except ValueError:
                continue

    return run_data


def sorted_uav_modules(module_map: Dict[str, Dict[str, float]]) -> List[Tuple[int, str, Dict[str, float]]]:
    rows = []
    for module, metrics in module_map.items():
        m = UAV_MODULE_RE.search(module)
        if m is None:
            continue
        rows.append((int(m.group(1)), module, metrics))
    rows.sort(key=lambda x: x[0])
    return rows


def find_ground_station_metrics(module_map: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    for module, metrics in module_map.items():
        if module.endswith(".groundStation"):
            return metrics
    return {}


def build_phase_rows(run_data: Dict) -> Tuple[List[Dict], List[Dict], Dict]:
    config = run_data["config"] or "unknown"
    run_id = run_data["run_id"] or Path(run_data["file"]).stem
    modules = run_data["modules"]

    gs = find_ground_station_metrics(modules)
    auth_success_rate = gs.get("authSuccessRate", 0.0)

    # Detect hash mode from GS scalars (1.0 = spongent, 0.0 = sha3).
    hash_mode_val = gs.get("hashMode", 0.0)
    hash_mode = "spongent" if hash_mode_val >= 0.5 else "sha3"

    phase2_rows: List[Dict] = []
    phase3_rows: List[Dict] = []

    uav_rows = sorted_uav_modules(modules)
    uav_metrics_by_id: Dict[int, Dict[str, float]] = {uav_id: metrics for uav_id, _, metrics in uav_rows}

    for uav_id, module, metrics in uav_rows:
        gs_prefix = f"phase2Gs_uav_{uav_id}_"

        phase2_success = int(
            round(
                metrics.get(
                    "phase2Success",
                    gs.get(gs_prefix + "success", metrics.get("isPhase2Authenticated", 0.0)),
                )
            )
        )

        m1_uav_compute = metrics.get("m1_uav_compute_ms", metrics.get("phase2M1UavComputeMs", 0.0))
        m1_gs_compute = metrics.get("m1_gs_compute_ms", gs.get(gs_prefix + "m1_gs_compute_ms", 0.0))
        m1_net = metrics.get("m1_net_ms", gs.get(gs_prefix + "m1_net_ms", 0.0))

        m2_uav_verify = metrics.get("m2_uav_verify_ms", metrics.get("phase2M2UavVerifyMs", 0.0))
        m2_net = metrics.get("m2_net_ms", metrics.get("phase2M2NetMs", 0.0))

        puf_eval = metrics.get("puf_eval_ms", metrics.get("phase2PufEvalMs", 0.0))
        bch_ms = metrics.get("bch_ms", gs.get(gs_prefix + "bch_ms", 0.0))

        m3_crypto = metrics.get("m3_crypto_ms", metrics.get("phase2M3CryptoMs", 0.0))
        m3_uav_compute = metrics.get("m3_uav_compute_ms", m3_crypto)
        m3_gs_compute = metrics.get("m3_gs_compute_ms", gs.get(gs_prefix + "m3_gs_compute_ms", 0.0))
        m3_net = metrics.get("m3_net_ms", gs.get(gs_prefix + "m3_net_ms", 0.0))

        m4_uav_compute = metrics.get("m4_uav_compute_ms", metrics.get("phase2M4UavComputeMs", 0.0))
        m4_net = metrics.get("m4_net_ms", metrics.get("phase2M4NetMs", 0.0))

        # Dual-mode hash timing.
        phase2_sha3_ms = metrics.get("phase2Sha3ComputeMs", 0.0) + gs.get(gs_prefix + "sha3_ms", 0.0)
        phase2_spongent_ms = metrics.get("phase2SpongentComputeMs", 0.0) + gs.get(gs_prefix + "spongent_ms", 0.0)
        m1_uav_sha3_ms = metrics.get("m1_uav_sha3_ms", 0.0)
        m1_uav_spongent_ms = metrics.get("m1_uav_spongent_ms", 0.0)
        m3_crypto_sha3_ms = metrics.get("m3_crypto_sha3_ms", 0.0)
        m3_crypto_spongent_ms = metrics.get("m3_crypto_spongent_ms", 0.0)

        phase2_compute_sum = (
            m1_uav_compute
            + m1_gs_compute
            + m2_uav_verify
            + puf_eval
            + bch_ms
            + m3_uav_compute
            + m3_gs_compute
            + m4_uav_compute
        )
        phase2_net_sum = m1_net + m2_net + m3_net + m4_net
        phase2_latency_sum = phase2_compute_sum + phase2_net_sum
        phase2_compute = metrics.get("phase2ComputeMs", phase2_compute_sum)
        phase2_net = metrics.get("phase2NetMs", phase2_net_sum)
        phase2_latency = metrics.get("phase2LatencyMs", phase2_latency_sum)
        phase2_overhead = int(round(metrics.get("phase2OverheadBytes", 0.0)))

        phase2_rows.append(
            {
                "idx": 0,
                "success": phase2_success,
                "latency_ms": round(phase2_latency, 6),
                "compute_ms": round(phase2_compute, 6),
                "net_ms": round(phase2_net, 6),
                "overhead_bytes": phase2_overhead,
                "hash_mode": hash_mode,
                "sha3_compute_ms": round(phase2_sha3_ms, 6),
                "spongent_compute_ms": round(phase2_spongent_ms, 6),
                "details": f"OMNeT++; module={module}; config={config}",
                "m1_uav_compute_ms": round(m1_uav_compute, 6),
                "m1_gs_compute_ms": round(m1_gs_compute, 6),
                "m1_net_ms": round(m1_net, 6),
                "m1_uav_sha3_ms": round(m1_uav_sha3_ms, 6),
                "m1_uav_spongent_ms": round(m1_uav_spongent_ms, 6),
                "m2_uav_verify_ms": round(m2_uav_verify, 6),
                "m2_net_ms": round(m2_net, 6),
                "puf_eval_ms": round(puf_eval, 6),
                "bch_ms": round(bch_ms, 6),
                "m3_crypto_ms": round(m3_crypto, 6),
                "m3_crypto_sha3_ms": round(m3_crypto_sha3_ms, 6),
                "m3_crypto_spongent_ms": round(m3_crypto_spongent_ms, 6),
                "m3_uav_compute_ms": round(m3_uav_compute, 6),
                "m3_gs_compute_ms": round(m3_gs_compute, 6),
                "m3_net_ms": round(m3_net, 6),
                "m4_uav_compute_ms": round(m4_uav_compute, 6),
                "m4_net_ms": round(m4_net, 6),
                "config": config,
                "run_id": run_id,
                "uav_id": uav_id,
            }
        )

    # Phase 3: Collect per-peer metrics from full-mesh scalars (phase3_peer_X_*).
    # Also fall back to the old single-peer format for backward compatibility.
    PEER_METRIC_RE = re.compile(r"^phase3_peer_(\d+)_(.+)$")
    RESP_METRIC_RE = re.compile(r"^phase3_resp_(\d+)_(.+)$")

    # Build responder data from per-peer responder scalars and old single-peer scalars.
    responder_by_pair: Dict[Tuple[int, int], Dict[str, float]] = {}

    for responder_id, responder_metrics in uav_metrics_by_id.items():
        # Per-peer responder scalars (phase3_resp_X_*)
        for key, value in responder_metrics.items():
            rm = RESP_METRIC_RE.match(key)
            if rm:
                requester_id = int(rm.group(1))
                metric_name = rm.group(2)
                pair_key = (requester_id, responder_id)
                if pair_key not in responder_by_pair:
                    responder_by_pair[pair_key] = {}
                responder_by_pair[pair_key][metric_name] = value

        # Old single-peer responder scalars (backward compat)
        requester_id = int(round(responder_metrics.get("phase3ResponderPeerId", -1.0)))
        if requester_id < 0:
            continue
        pair_key = (requester_id, responder_id)
        if pair_key not in responder_by_pair:
            responder_by_pair[pair_key] = {}
        old_data = responder_by_pair[pair_key]
        old_data.setdefault("p1_p2_j_compute_ms", responder_metrics.get("responder_p1_p2_j_compute_ms", 0.0))
        old_data.setdefault("p3_j_compute_ms", responder_metrics.get("responder_p3_j_compute_ms", 0.0))
        old_data.setdefault("p3_net_ms", responder_metrics.get("responder_p3_net_ms", 0.0))
        old_data.setdefault("sha3_ms", responder_metrics.get("responder_sha3_ms", 0.0))
        old_data.setdefault("spongent_ms", responder_metrics.get("responder_spongent_ms", 0.0))

    for i, init_metrics in sorted(uav_metrics_by_id.items()):
        # Discover all peers this UAV initiated with (full-mesh per-peer scalars).
        peer_metrics_by_j: Dict[int, Dict[str, float]] = {}
        for key, value in init_metrics.items():
            m = PEER_METRIC_RE.match(key)
            if m:
                j = int(m.group(1))
                metric_name = m.group(2)
                if j not in peer_metrics_by_j:
                    peer_metrics_by_j[j] = {}
                peer_metrics_by_j[j][metric_name] = value

        # If no per-peer scalars found, fall back to old single-peer format.
        if not peer_metrics_by_j:
            j = int(round(init_metrics.get("phase3PeerId", -1.0)))
            if j < 0:
                continue
            peer_metrics_by_j[j] = {
                "success": init_metrics.get("phase3Success", 0.0),
                "compute_ms": init_metrics.get("phase3ComputeMs", 0.0),
                "net_ms": init_metrics.get("phase3NetMs", 0.0),
                "latency_ms": init_metrics.get("phase3LatencyMs", 0.0),
                "overhead_bytes": init_metrics.get("phase3OverheadBytes", 0.0),
                "p1_i_compute_ms": init_metrics.get("p1_i_compute_ms", 0.0),
                "p1_p2_j_compute_ms": init_metrics.get("p1_p2_j_compute_ms", 0.0),
                "p1_net_ms": init_metrics.get("p1_net_ms", 0.0),
                "p2_p3_i_compute_ms": init_metrics.get("p2_p3_i_compute_ms", 0.0),
                "p2_net_ms": init_metrics.get("p2_net_ms", 0.0),
                "p3_j_compute_ms": init_metrics.get("p3_j_compute_ms", 0.0),
                "p3_net_ms": init_metrics.get("p3_net_ms", 0.0),
            }

        for j, pm in sorted(peer_metrics_by_j.items()):
            pair_key = (i, j)
            resp_data = responder_by_pair.get(pair_key, {})

            p1_i_compute = pm.get("p1_i_compute_ms", 0.0)
            p1_p2_j_compute = pm.get("p1_p2_j_compute_ms", 0.0)
            if p1_p2_j_compute == 0.0:
                p1_p2_j_compute = resp_data.get("p1_p2_j_compute_ms", 0.0)

            p1_net = pm.get("p1_net_ms", 0.0)

            p2_p3_i_compute = pm.get("p2_p3_i_compute_ms", 0.0)
            p2_net = pm.get("p2_net_ms", 0.0)

            p3_j_compute = pm.get("p3_j_compute_ms", 0.0)
            if p3_j_compute == 0.0:
                p3_j_compute = resp_data.get("p3_j_compute_ms", 0.0)

            p3_net = pm.get("p3_net_ms", 0.0)
            if p3_net == 0.0:
                p3_net = resp_data.get("p3_net_ms", 0.0)

            phase3_compute = p1_i_compute + p1_p2_j_compute + p2_p3_i_compute + p3_j_compute
            phase3_net = p1_net + p2_net + p3_net
            phase3_latency = phase3_compute + phase3_net
            phase3_overhead = int(round(pm.get("overhead_bytes", 0.0)))
            phase3_success = int(round(pm.get("success", 0.0)))

            # Initiator-side hash timing for this pair.
            init_sha3 = pm.get("sha3_ms", 0.0)
            init_spongent = pm.get("spongent_ms", 0.0)
            # Responder-side hash timing for this pair.
            resp_sha3 = resp_data.get("sha3_ms", 0.0)
            resp_spongent = resp_data.get("spongent_ms", 0.0)
            pair_sha3 = init_sha3 + resp_sha3
            pair_spongent = init_spongent + resp_spongent

            phase3_rows.append(
                {
                    "idx": 0,
                    "success": phase3_success,
                    "latency_ms": round(phase3_latency, 6),
                    "compute_ms": round(phase3_compute, 6),
                    "net_ms": round(phase3_net, 6),
                    "overhead_bytes": phase3_overhead,
                    "hash_mode": hash_mode,
                    "sha3_compute_ms": round(pair_sha3, 6),
                    "spongent_compute_ms": round(pair_spongent, 6),
                    "details": f"pair=UAV{i}<->UAV{j}; config={config}",
                    "p1_i_compute_ms": round(p1_i_compute, 6),
                    "p1_p2_j_compute_ms": round(p1_p2_j_compute, 6),
                    "p1_net_ms": round(p1_net, 6),
                    "p2_p3_i_compute_ms": round(p2_p3_i_compute, 6),
                    "p2_net_ms": round(p2_net, 6),
                    "p3_j_compute_ms": round(p3_j_compute, 6),
                    "p3_net_ms": round(p3_net, 6),
                    "config": config,
                    "run_id": run_id,
                    "uav_id": i,
                    "peer_uav_id": j,
                }
            )

    summary = {
        "config": config,
        "run_id": run_id,
        "num_phase2_rows": len(phase2_rows),
        "num_phase3_rows": len(phase3_rows),
        "auth_success_rate": auth_success_rate,
        "hash_mode": hash_mode,
    }
    return phase2_rows, phase3_rows, summary


def mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def assign_indices(rows: List[Dict]) -> None:
    for i, row in enumerate(rows):
        row["idx"] = i


def write_csv(path: Path, rows: List[Dict], columns: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in columns})


def export_from_sca(results_dir: Path, include_configs: Optional[Set[str]] = None) -> Dict[str, Path]:
    sca_files = sorted(results_dir.glob("*.sca"))
    if not sca_files:
        raise FileNotFoundError(f"No .sca files found in {results_dir}")

    all_phase2: List[Dict] = []
    all_phase3: List[Dict] = []
    summaries: List[Dict] = []

    for sca in sca_files:
        run_data = parse_sca_file(sca)
        config = run_data["config"] or "unknown"
        if include_configs is not None and config not in include_configs:
            continue

        phase2_rows, phase3_rows, summary = build_phase_rows(run_data)
        all_phase2.extend(phase2_rows)
        all_phase3.extend(phase3_rows)
        summaries.append(summary)

    if not all_phase2 and not all_phase3:
        if include_configs:
            raise FileNotFoundError(
                f"No matching .sca rows found for configs: {', '.join(sorted(include_configs))}"
            )
        raise FileNotFoundError(f"No usable scalar rows found in {results_dir}")

    assign_indices(all_phase2)
    assign_indices(all_phase3)

    summary_by_config: Dict[str, Dict] = {}
    for cfg in {s["config"] for s in summaries}:
        phase2_cfg = [r for r in all_phase2 if r["config"] == cfg]
        phase3_cfg = [r for r in all_phase3 if r["config"] == cfg]
        cfg_summaries = [s for s in summaries if s["config"] == cfg]

        # Determine hash mode from the first matching summary.
        hash_mode = cfg_summaries[0]["hash_mode"] if cfg_summaries else "sha3"

        summary_by_config[cfg] = {
            "config": cfg,
            "hash_mode": hash_mode,
            "num_runs": len(cfg_summaries),
            "phase2_mean_latency_ms": round(mean([r["latency_ms"] for r in phase2_cfg]), 6),
            "phase2_mean_compute_ms": round(mean([r["compute_ms"] for r in phase2_cfg]), 6),
            "phase2_mean_sha3_ms": round(mean([r["sha3_compute_ms"] for r in phase2_cfg]), 6),
            "phase2_mean_spongent_ms": round(mean([r["spongent_compute_ms"] for r in phase2_cfg]), 6),
            "phase2_mean_net_ms": round(mean([r["net_ms"] for r in phase2_cfg]), 6),
            "phase2_mean_overhead_bytes": round(mean([r["overhead_bytes"] for r in phase2_cfg]), 6),
            "phase3_mean_latency_ms": round(mean([r["latency_ms"] for r in phase3_cfg]), 6),
            "phase3_mean_compute_ms": round(mean([r["compute_ms"] for r in phase3_cfg]), 6),
            "phase3_mean_sha3_ms": round(mean([r["sha3_compute_ms"] for r in phase3_cfg]), 6),
            "phase3_mean_spongent_ms": round(mean([r["spongent_compute_ms"] for r in phase3_cfg]), 6),
            "phase3_mean_net_ms": round(mean([r["net_ms"] for r in phase3_cfg]), 6),
            "phase3_mean_overhead_bytes": round(mean([r["overhead_bytes"] for r in phase3_cfg]), 6),
            "auth_success_rate": round(mean([s["auth_success_rate"] for s in cfg_summaries]), 6),
        }

    out_phase2 = results_dir / "omnet_phase2_results.csv"
    out_phase3 = results_dir / "omnet_phase3_results.csv"
    out_summary = results_dir / "omnet_summary.csv"

    phase2_columns = [
        "idx",
        "success",
        "latency_ms",
        "compute_ms",
        "net_ms",
        "overhead_bytes",
        "hash_mode",
        "sha3_compute_ms",
        "spongent_compute_ms",
        "details",
        "m1_uav_compute_ms",
        "m1_gs_compute_ms",
        "m1_net_ms",
        "m1_uav_sha3_ms",
        "m1_uav_spongent_ms",
        "m2_uav_verify_ms",
        "m2_net_ms",
        "puf_eval_ms",
        "bch_ms",
        "m3_crypto_ms",
        "m3_crypto_sha3_ms",
        "m3_crypto_spongent_ms",
        "m3_uav_compute_ms",
        "m3_gs_compute_ms",
        "m3_net_ms",
        "m4_uav_compute_ms",
        "m4_net_ms",
        "config",
        "run_id",
        "uav_id",
    ]
    phase3_columns = [
        "idx",
        "success",
        "latency_ms",
        "compute_ms",
        "net_ms",
        "overhead_bytes",
        "hash_mode",
        "sha3_compute_ms",
        "spongent_compute_ms",
        "details",
        "p1_i_compute_ms",
        "p1_p2_j_compute_ms",
        "p1_net_ms",
        "p2_p3_i_compute_ms",
        "p2_net_ms",
        "p3_j_compute_ms",
        "p3_net_ms",
        "config",
        "run_id",
        "uav_id",
        "peer_uav_id",
    ]
    summary_columns = [
        "config",
        "hash_mode",
        "num_runs",
        "phase2_mean_latency_ms",
        "phase2_mean_compute_ms",
        "phase2_mean_sha3_ms",
        "phase2_mean_spongent_ms",
        "phase2_mean_net_ms",
        "phase2_mean_overhead_bytes",
        "phase3_mean_latency_ms",
        "phase3_mean_compute_ms",
        "phase3_mean_sha3_ms",
        "phase3_mean_spongent_ms",
        "phase3_mean_net_ms",
        "phase3_mean_overhead_bytes",
        "auth_success_rate",
    ]

    write_csv(out_phase2, all_phase2, phase2_columns)
    write_csv(out_phase3, all_phase3, phase3_columns)
    summary_rows = [summary_by_config[cfg] for cfg in sorted(summary_by_config.keys())]
    write_csv(out_summary, summary_rows, summary_columns)

    # Also produce per-hash-mode CSV files for convenience.
    outputs: Dict[str, Path] = {
        "phase2": out_phase2,
        "phase3": out_phase3,
        "summary": out_summary,
    }

    for hash_mode in ("sha3", "spongent"):
        ph2 = [r for r in all_phase2 if r["hash_mode"] == hash_mode]
        ph3 = [r for r in all_phase3 if r["hash_mode"] == hash_mode]
        if not ph2 and not ph3:
            continue

        # Drop columns for the inactive hash mode to avoid all-zero columns.
        if hash_mode == "sha3":
            drop_cols = {"spongent_compute_ms", "m1_uav_spongent_ms", "m3_crypto_spongent_ms"}
        else:
            drop_cols = {"sha3_compute_ms", "m1_uav_sha3_ms", "m3_crypto_sha3_ms"}

        mode_ph2_cols = [c for c in phase2_columns if c not in drop_cols]
        mode_ph3_cols = [c for c in phase3_columns if c not in drop_cols]
        assign_indices(ph2)
        assign_indices(ph3)
        mode_ph2 = results_dir / f"omnet_phase2_{hash_mode}.csv"
        mode_ph3 = results_dir / f"omnet_phase3_{hash_mode}.csv"
        write_csv(mode_ph2, ph2, mode_ph2_cols)
        write_csv(mode_ph3, ph3, mode_ph3_cols)
        outputs[f"phase2_{hash_mode}"] = mode_ph2
        outputs[f"phase3_{hash_mode}"] = mode_ph3

    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Export OMNeT++ .sca data into CSV files.")
    parser.add_argument(
        "--results-dir",
        default="simulations/results",
        help="Directory containing OMNeT++ .sca files (default: simulations/results)",
    )
    parser.add_argument(
        "--configs",
        nargs="*",
        default=None,
        help="Optional list of config names to include in export",
    )
    args = parser.parse_args()

    results_dir = Path(args.results_dir).resolve()
    include_configs = set(args.configs) if args.configs else None
    outputs = export_from_sca(results_dir, include_configs=include_configs)

    print("OMNeT++ CSV export complete:")
    for key, path in sorted(outputs.items()):
        print(f"  {key}: {path}")


if __name__ == "__main__":
    main()
