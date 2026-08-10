#!/usr/bin/env python3
"""Export the Atk* attack scalars into omnet_security_results.csv.

Previously this file had no generating script at all: it was hand-assembled
from raw .sca scalars / the Cmdenv summary printout, and had no run-count or
confidence-interval logic, unlike every other results CSV in this project.

Joins on (config, attack_mode), NOT config alone: AttackerNode::observe()
unconditionally runs attemptCredentialRecovery() on every observed M4
regardless of the configured attackMode, so a single .sca file (e.g.
AtkReplayM1) can carry more than one atk_<mode>_* scalar group. Grouping by
mode keeps those groups from being merged into one misleading row.
"""

import argparse
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stats_util  # noqa: E402

ATK_SCALAR_RE = re.compile(
    r"^atk_([a-z0-9]+)_(attempts|accepted|rejected|replies_elicited|"
    r"credentials_exposed|responses_leaked|success_rate|expected_success|"
    r"outcome_matches_expectation)$"
)


def parse_sca(path):
    run = {
        "file": str(path), "run_id": "", "config": "unknown",
        "protocol_variant": "hardened", "modules": {},
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
            elif "protocolVariant" in line and "legacy" in line:
                # .sca escapes the NED string value's own quotes, so the raw
                # line ends with `legacy\""` (backslash + two quotes), not a
                # plain `"legacy"` -- substring match instead of endswith().
                run["protocol_variant"] = "legacy"
    return run


def attacker_metrics(run):
    for name, metrics in run["modules"].items():
        if ".attacker[" in name:
            return metrics
    return {}


def any_uav_metrics(run):
    for name, metrics in run["modules"].items():
        if re.search(r"\.uav\[\d+\]$", name):
            return metrics
    return {}


def per_run_modes(run, m):
    """Every distinct attack mode this run's attacker scalars mention."""
    modes = set()
    for metric in m:
        match = ATK_SCALAR_RE.match(metric)
        if match:
            modes.add(match.group(1))
    return modes


def collect(results_dir, configs):
    # (config, mode) -> list of per-run dicts
    groups = {}
    for cfg in configs:
        for path in sorted(results_dir.glob(f"{cfg}-*.sca")):
            run = parse_sca(path)
            m = attacker_metrics(run)
            if not m:
                continue
            uav = any_uav_metrics(run)
            for mode in per_run_modes(run, m):
                p = f"atk_{mode}_"
                # `accepted` IS the generic cross-mode success counter --
                # AttackerNode.cc increments it in the same statement as
                # repliesElicited (gsimpersonate's oracle hit) or
                # credentialsExposed (credsniff's plaintext read), never
                # independently. Summing accepted+replies+creds would double
                # count the identical event; `accepted` alone already matches
                # exactly what AttackerNode's own finish() uses for
                # success_rate = accepted/attempts.
                accepted = m.get(p + "accepted", 0.0)
                replies = m.get(p + "replies_elicited", 0.0)
                creds = m.get(p + "credentials_exposed", 0.0)
                succeeded = 1.0 if accepted > 0 else 0.0
                groups.setdefault((cfg, mode), []).append({
                    "run_id": run["run_id"] or path.stem,
                    "protocol_variant": run["protocol_variant"],
                    "attempts": m.get(p + "attempts", 0.0),
                    "accepted": accepted,
                    "oracle_replies": replies,
                    "credentials_exposed": creds,
                    "run_succeeded": succeeded,
                    "expected_success": m.get(p + "expected_success", 0.0),
                    "observed_messages": m.get("attack_observed_messages", 0.0),
                    "devices_authenticated": uav.get("phase2Success", 0.0),
                })
    return groups


def build_rows(groups):
    rows = []
    for (config, mode), runs in sorted(groups.items()):
        attempts = sum(r["attempts"] for r in runs)
        accepted = sum(r["accepted"] for r in runs)
        oracle = sum(r["oracle_replies"] for r in runs)
        creds = sum(r["credentials_exposed"] for r in runs)
        run_successes = sum(r["run_succeeded"] for r in runs)
        n_runs = len(runs)
        expected = runs[0]["expected_success"] if runs else 0.0

        # Pooled Wilson interval over ATTEMPTS (the finer-grained trial count,
        # matching what AttackerNode itself reports as success_rate =
        # accepted/attempts per run) -- and a second one over RUNS (did this
        # independent seed show the attack succeed at all), since a single
        # run's attempts share one seed/attacker instance and are therefore
        # correlated in exactly the sense scripts/stats_util.py's own
        # docstring warns about; reporting both avoids re-making that mistake
        # here while still surfacing the finer-grained count.
        attempt_wilson = stats_util.proportion_summary(int(round(accepted)), int(round(attempts)))
        run_wilson = stats_util.proportion_summary(int(round(run_successes)), n_runs)

        rows.append({
            "config": config,
            "protocol_variant": runs[0]["protocol_variant"] if runs else "hardened",
            "attack": mode,
            "n_runs": n_runs,
            "attempts": int(round(attempts)),
            "accepted": int(round(accepted)),
            "oracle_replies": int(round(oracle)),
            "credentials_exposed": int(round(creds)),
            "success_rate": attempt_wilson["rate"],
            "success_wilson_lo": attempt_wilson["wilson_lo"],
            "success_wilson_hi": attempt_wilson["wilson_hi"],
            "runs_with_success": int(round(run_successes)),
            "run_success_rate": run_wilson["rate"],
            "run_success_wilson_lo": run_wilson["wilson_lo"],
            "run_success_wilson_hi": run_wilson["wilson_hi"],
            "expected_success": int(round(expected)),
            "outcome_matches_expectation":
                int((accepted > 0) == bool(expected)) if n_runs else "",
            "observed_messages": int(round(sum(r["observed_messages"] for r in runs))),
            "devices_authenticated": int(round(sum(r["devices_authenticated"] for r in runs))),
        })
    return rows


COLS = ["config", "protocol_variant", "attack", "n_runs", "attempts", "accepted",
        "oracle_replies", "credentials_exposed", "success_rate", "success_wilson_lo",
        "success_wilson_hi", "runs_with_success", "run_success_rate",
        "run_success_wilson_lo", "run_success_wilson_hi", "expected_success",
        "outcome_matches_expectation", "observed_messages", "devices_authenticated"]

DEFAULT_CONFIGS = ["AtkGsImpersonate", "AtkLegacyGsImpersonate", "AtkReplayM1",
                    "AtkCredentialSniff"]


def export(results_dir, configs=DEFAULT_CONFIGS):
    results_dir = Path(results_dir).resolve()
    groups = collect(results_dir, configs)
    if not groups:
        raise RuntimeError("no attack scalars found for configs=%s" % (configs,))
    rows = build_rows(groups)

    out_path = results_dir / "omnet_security_results.csv"
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"wrote {len(rows)} rows to {out_path}")
    for row in rows:
        flag = "OK" if row["outcome_matches_expectation"] in (1, "") else "MISMATCH"
        print(f"  [{flag}] {row['config']:<24} {row['attack']:<14} "
              f"n_runs={row['n_runs']} attempts={row['attempts']} "
              f"success_rate={row['success_rate']:.3f} "
              f"expected={row['expected_success']}")
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    ap.add_argument("--configs", nargs="*", default=DEFAULT_CONFIGS)
    args = ap.parse_args()
    export(args.results_dir, args.configs)


if __name__ == "__main__":
    main()
