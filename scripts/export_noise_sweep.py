#!/usr/bin/env python3
"""Aggregate the PUF noise sweep into a reliability curve.

Reports the measured key-reproduction failure rate at each bit-error rate beside
the analytic binomial prediction. Agreement between the two is the end-to-end
evidence that error correction genuinely happens: an inert decoder -- the defect
the audit found in the previous implementation -- would show a flat curve that
tracked nothing.

The default profile is chosen precisely because its failure rate is measurable. A
1e-15 rate cannot be observed in any feasible Monte Carlo, so a sweep against it
would be vacuous.
"""

import argparse
import csv
import glob
import math
import os
import re
from collections import defaultdict

# profile -> (bch t, number of blocks L, repetition factor)
PROFILES = {
    "bch255-131-18": (18, 4, 1),
    "bch255-91-25": (25, 5, 1),
    "rep3-bch255-131-18": (18, 5, 3),
}


def binomial_tail_above(n, p, t):
    """P(Binomial(n, p) > t), computed in log space."""
    if p <= 0.0:
        return 0.0
    if p >= 1.0:
        return 1.0
    log_coeff = 0.0
    tail = 0.0
    for k in range(n + 1):
        if k > 0:
            log_coeff += math.log(n - k + 1) - math.log(k)
        term = log_coeff + k * math.log(p) + (n - k) * math.log1p(-p)
        if k > t:
            tail += math.exp(term)
    return tail


def wilson(successes, trials, z=1.96):
    if trials == 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1.0 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def parse(path):
    """Return (itervars, scalars) for one .sca file."""
    scalars = {}
    itervars = {}
    with open(path, errors="replace") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "scalar":
                try:
                    scalars[parts[2]] = float(parts[3])
                except ValueError:
                    pass
            elif len(parts) >= 2 and parts[0] == "attr" and parts[1] == "iterationvarsd":
                # e.g. ber=0.01/profile=bch255-91-25 -- already unquoted, which is
                # why this is preferred over the escaped `itervar` lines.
                for chunk in line.split(None, 2)[2].strip().split("/"):
                    if "=" in chunk:
                        k, v = chunk.split("=", 1)
                        itervars[k.strip()] = v.strip()
    return itervars, scalars


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    ap.add_argument("--pattern", default="NoiseSweep-*.sca")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.results_dir, args.pattern)))
    if not files:
        print("no sweep results found; run: -c NoiseSweep")
        return 1

    agg = defaultdict(lambda: {"runs": 0, "devices": 0, "attempts": 0,
                               "ok": 0, "fefail": 0})
    for path in files:
        iv, sc = parse(path)
        if "numEnrolled" not in sc:
            continue
        try:
            ber = float(iv.get("ber", "0"))
        except ValueError:
            ber = 0.0
        key = (ber, iv.get("profile", "unknown"))
        a = agg[key]
        a["runs"] += 1
        a["devices"] += int(sc.get("numEnrolled", 0.0))
        a["attempts"] += int(sc.get("totalAuthAttempts", 0.0))
        a["ok"] += int(sc.get("totalAuthSuccess", 0.0))
        a["fefail"] += int(sc.get("feReproductionFailures", 0.0))

    rows = []
    for (ber, profile), a in sorted(agg.items()):
        t, blocks, rep = PROFILES.get(profile, (18, 4, 1))
        # With a [3,1,3] inner code a bit is wrong only if 2 of 3 copies flip.
        effective = ber if rep == 1 else 3 * ber * ber * (1 - ber) + ber ** 3
        per_block = binomial_tail_above(255, effective, t)
        predicted = 1.0 - (1.0 - per_block) ** blocks

        devices = a["devices"]
        measured = a["fefail"] / devices if devices else 0.0
        lo, hi = wilson(a["fefail"], devices)
        rows.append({
            "puf_ber": ber, "fe_profile": profile, "bch_t": t,
            "num_blocks_L": blocks, "rep_factor": rep,
            "runs": a["runs"], "devices": devices,
            "fe_failures": a["fefail"],
            "measured_frr": round(measured, 6),
            "frr_ci95_lo": round(lo, 6), "frr_ci95_hi": round(hi, 6),
            "predicted_frr_binomial": round(predicted, 12),
            "per_block_failure_pred": round(per_block, 12),
            "prediction_within_ci": int(lo <= predicted <= hi),
            "device_auth_success_rate": round(a["ok"] / devices, 6) if devices else 0.0,
        })

    out = os.path.join(args.results_dir, "omnet_noise_sweep.csv")
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print("%d sweep points -> %s\n" % (len(rows), out))
    hdr = ("%6s %-22s%6s%6s%10s%17s%12s%8s" %
           ("BER", "profile", "dev", "fail", "measFRR", "CI95", "predFRR", "inCI"))
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        ci = "[%.3f,%.3f]" % (r["frr_ci95_lo"], r["frr_ci95_hi"])
        print("%6.2f %-22s%6d%6d%10.4f%17s%12.2e%8s" %
              (r["puf_ber"], r["fe_profile"], r["devices"], r["fe_failures"],
               r["measured_frr"], ci, r["predicted_frr_binomial"],
               "yes" if r["prediction_within_ci"] else "NO"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
