#!/usr/bin/env python3
"""Export the INET/802.11 track's .sca files to omnet_inet_latency.csv.

Separate from export_omnet_csv.py deliberately: the INET track's scalars
(inetPhase2Success, inetPhase2WallLatencyMs, ...) are a different, smaller
schema than the idealised-medium track's, and its results are not meant to
replace that track's numbers -- they're the other side of a disclosed lower
bound (see omnetpp_inet.ini's header comment), so they get their own CSV
rather than being merged into the existing one.

Compute/network decomposition
-----------------------------
On this track everything runs on ONE clock (the simulation clock), unlike the
idealised medium, where compute is host wall-clock and network is simulated and
the two never meet. Here:

  wall_latency_ms  measured: end-to-end simulated time for the handshake,
                   including CSMA/CA backoff, queueing and propagation
  compute_ms       measured: the protocol's own host-clock timers, summed
  net_ms           DERIVED: wall - compute, i.e. everything that is not the
                   app's own computation. It is flagged as derived
                   (net_ms_derived = 1) so it is never mistaken for an
                   independent measurement.

Peer rows carry the same three, from inetP3Peer_<id>_* scalars.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402

UAV_APP_RE = re.compile(r"\.uav\[(\d+)\]\.app\[0\]$")
PEER_RE = re.compile(r"^inetP3Peer_(\d+)_(.+)$")

DEFAULT_CONFIGS = ("Inet80211SHA3", "InetMobilityLinearSHA3",
                   "InetMobilityRandomWalkSHA3")


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
        if name.endswith(".groundStation.app[0]"):
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
    m1_attempts = gs.get("inetM1Attempts", 0.0)
    m4_successes = gs.get("inetM4Successes", 0.0)

    rows = []
    for module, m in run["modules"].items():
        match = UAV_APP_RE.search(module)
        if not match or "inetPhase2Success" not in m:
            continue
        wall = round(m.get("inetPhase2WallLatencyMs", 0.0), 6)
        comp = round(m.get("inetPhase2ComputeMs", 0.0), 6)
        row = dict(rid)
        row.update({
            "uav_id": int(match.group(1)),
            "phase": "phase2",
            "peer_uav_id": "",
            "success": int(round(m.get("inetPhase2Success", 0.0))),
            "wall_latency_ms": wall,
            "compute_ms": comp,
            # Derived, never measured: disclosed as such in the column name's
            # companion flag so a reader cannot mistake it for a reading.
            "net_ms": round(max(0.0, wall - comp), 6),
            "net_ms_derived": 1,
            "bytes_sent": int(round(m.get("inetBytesSent", 0.0))),
            "bytes_received": int(round(m.get("inetBytesReceived", 0.0))),
            "gs_m1_attempts": int(round(m1_attempts)),
            "gs_m4_successes": int(round(m4_successes)),
        })
        rows.append(row)

        # One row per peer this UAV holds a session with. Wall time for a peer
        # exchange is not recorded per peer on this track (the protocol keeps no
        # such timestamp), so wall/net are left empty rather than fabricated;
        # the peer row's compute is real and is what the comparison needs.
        peers = {}
        for metric, value in m.items():
            pm = PEER_RE.match(metric)
            if pm:
                peers.setdefault(int(pm.group(1)), {})[pm.group(2)] = value
        for peer_id, pm in sorted(peers.items()):
            prow = dict(rid)
            prow.update({
                "uav_id": int(match.group(1)),
                "phase": "phase3",
                "peer_uav_id": peer_id,
                "success": int(round(pm.get("success", 0.0))),
                "wall_latency_ms": "",
                "compute_ms": round(pm.get("computeMs", 0.0), 6),
                "net_ms": "",
                "net_ms_derived": 0,
                "bytes_sent": "",
                "bytes_received": "",
                "gs_m1_attempts": "",
                "gs_m4_successes": "",
            })
            rows.append(prow)
    return rows


COLS = ["idx", "run_id", "config", "runnumber", "repetition", "seedset",
        "uav_id", "phase", "peer_uav_id", "success",
        "wall_latency_ms", "compute_ms", "net_ms", "net_ms_derived",
        "bytes_sent", "bytes_received", "gs_m1_attempts", "gs_m4_successes"]


def export(results_dir, configs=DEFAULT_CONFIGS):
    results_dir = Path(results_dir).resolve()
    rows = []
    for cfg in configs:
        for path in sorted(results_dir.glob(f"{cfg}-*.sca")):
            rows.extend(build_rows(parse_sca(path)))
    if not rows:
        raise RuntimeError("no INET-track rows found for configs=%s" % (configs,))

    for i, row in enumerate(rows):
        row["idx"] = i

    out_path = results_dir / "omnet_inet_latency.csv"
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"wrote {len(rows)} rows to {out_path}")
    for cfg in configs:
        # Phase 2 rows only for the latency summary: peer rows carry no wall
        # time on this track, so including them would average blanks.
        cfg_rows = [r for r in rows if r["config"] == cfg and r["phase"] == "phase2"]
        if not cfg_rows:
            continue
        succ = sum(r["success"] for r in cfg_rows)
        n_runs = len({r["run_id"] for r in cfg_rows})
        if n_runs < 3:
            print(f"  {cfg}: only {n_runs} run(s) so far (need >=3 for a CI) -- "
                  f"success={succ}/{len(cfg_rows)}")
            continue
        stats = stats_util.two_stage_ci(cfg_rows, "wall_latency_ms")
        halfwidth = stats["sem"] * stats["t_crit"]
        cs = stats_util.two_stage_ci(cfg_rows, "compute_ms")
        cwidth = cs["sem"] * cs["t_crit"]
        peers = [r for r in rows if r["config"] == cfg and r["phase"] == "phase3"]
        pok = sum(r["success"] for r in peers)
        print(f"  {cfg}: n_runs={stats['n_runs']} "
              f"wall={stats['mean_of_run_means']:.3f}+/-{halfwidth:.3f} "
              f"compute={cs['mean_of_run_means']:.3f}+/-{cwidth:.3f} "
              f"success={succ}/{len(cfg_rows)} "
              f"peers={pok}/{len(peers)}")
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    ap.add_argument("--configs", nargs="*", default=list(DEFAULT_CONFIGS))
    args = ap.parse_args()
    export(args.results_dir, tuple(args.configs))


if __name__ == "__main__":
    main()
