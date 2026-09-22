"""One-off checker: recompute every headline number the papers quote, straight from the CSVs.

Standard library only, so it runs without a virtualenv.
"""
import csv
import math
import statistics as st
from collections import defaultdict
from pathlib import Path

R = Path(__file__).resolve().parent.parent / "final results"

# t critical values at 95%, two-sided, indexed by degrees of freedom
TCRIT = {2: 4.3027, 3: 3.1824, 4: 2.7764, 5: 2.5706, 6: 2.4469, 7: 2.3646,
         8: 2.3060, 9: 2.2622, 10: 2.2281, 14: 2.1448, 19: 2.0930,
         29: 2.0452, 62: 1.9990}


def tcrit(df):
    if df in TCRIT:
        return TCRIT[df]
    ks = sorted(TCRIT)
    lo = max([k for k in ks if k <= df], default=ks[0])
    return TCRIT[lo]


def load(name):
    with open(R / name, newline="") as f:
        return list(csv.DictReader(f))


def num(row, key):
    v = row.get(key, "")
    return float(v) if v not in ("", None) else float("nan")


def runmeans(rows, col, key="run_id"):
    g = defaultdict(list)
    for r in rows:
        v = num(r, col)
        if not math.isnan(v):
            g[r[key]].append(v)
    return [st.fmean(v) for v in g.values() if v]


def ci(vals):
    n = len(vals)
    if n == 0:
        return float("nan"), float("nan"), 0
    if n < 3:
        return st.fmean(vals), float("nan"), n
    hw = tcrit(n - 1) * st.stdev(vals) / math.sqrt(n)
    return st.fmean(vals), hw, n


def avg(rows, col):
    v = [num(r, col) for r in rows]
    v = [x for x in v if not math.isnan(x)]
    return st.fmean(v) if v else float("nan")


def sel(rows, **kw):
    return [r for r in rows if all(r.get(k) == v for k, v in kw.items())]


def hdr(t):
    print("\n" + "=" * 76 + f"\n{t}\n" + "=" * 76)


p2 = load("omnet_phase2_results.csv")
p3 = load("omnet_phase3_results.csv")
p1 = load("omnet_phase1_results.csv")
noise = load("omnet_noise_results.csv")

hdr("PHASE 2 per-config (two-stage CI over run means)")
for cfg in ["StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20"]:
    d = sel(p2, config=cfg)
    if not d:
        print(f"{cfg:20s} MISSING")
        continue
    e, eh, n = ci(runmeans(d, "wall_latency_ms"))
    c, ch, _ = ci(runmeans(d, "compute_ms"))
    w, wh, _ = ci(runmeans(d, "net_ms"))
    print(f"{cfg:20s} runs={n:3d} rec={len(d):5d} elapsed={e:7.4f}+-{eh:.4f} "
          f"compute={c:7.4f}+-{ch:.4f} net={w:7.4f}+-{wh:.4f} "
          f"bytes={avg(d,'overhead_bytes'):7.1f}  C+N={c+w:.4f}")

hdr("NOISE family (arbiter-model reliability configs, from omnet_noise_results.csv)")
for cfg in ["ArbiterPuf", "HighNoise"]:
    d = sel(noise, config=cfg)
    if not d:
        print(f"{cfg:20s} MISSING")
        continue
    e, eh, n = ci(runmeans(d, "wall_latency_ms"))
    c, ch, _ = ci(runmeans(d, "compute_ms"))
    ok = sum(int(float(r["success"])) for r in d)
    print(f"{cfg:20s} runs={n:3d} rec={len(d):5d} ok={ok:4d} elapsed={e:7.4f}+-{eh:.4f} "
          f"compute={c:7.4f}+-{ch:.4f}")

hdr("PHASE 3 pooled over the four size-varying configs")
sz = {"StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20"}
d = [r for r in p3 if r["config"] in sz]
m, h, n = ci(runmeans(d, "latency_ms"))
print(f"pooled  lat={m:.4f}+-{h:.4f} (runs={n}) bytes={avg(d,'overhead_bytes'):.2f} pairviews={len(d)}")
for cfg in sorted(sz):
    dd = sel(p3, config=cfg)
    a, ah, an = ci(runmeans(dd, "latency_ms"))
    c, _, _ = ci(runmeans(dd, "compute_ms"))
    w, _, _ = ci(runmeans(dd, "net_ms"))
    print(f"  {cfg:18s} lat={a:.4f}+-{ah:.4f} compute={c:.4f} net={w:.4f} "
          f"C+N={c+w:.4f} n={len(dd)}")

hdr("FUNCTIONAL: device counts and successes")
for cfg in ["StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20"]:
    d2, d3 = sel(p2, config=cfg), sel(p3, config=cfg)
    e1 = sel(p1, config=cfg)
    nrun = len({r["run_id"] for r in d2})
    N = int(float(d2[0]["num_uavs"])) if d2 else 0
    ok2 = sum(int(float(r["success"])) for r in d2)
    ok3 = sum(int(float(r["success"])) for r in d3)
    print(f"{cfg:18s} runs={nrun:2d} N={N:2d} enrolled={len(e1):4d} devices={nrun*N:4d} "
          f"p2rows={len(d2):4d} p2ok={ok2:4d}  p3rows={len(d3):6d} p3ok={ok3:6d}")
for cfg in ["ArbiterPuf", "HighNoise"]:
    d2 = sel(noise, config=cfg)
    nrun = len({r["run_id"] for r in d2})
    N = int(float(d2[0]["num_uavs"])) if d2 else 0
    ok2 = sum(int(float(r["success"])) for r in d2)
    print(f"{cfg:18s} runs={nrun:2d} N={N:2d} (noise file)      devices={nrun*N:4d} "
          f"p2rows={len(d2):4d} p2ok={ok2:4d}")

hdr("PHASE 2 MESSAGE BREAKDOWN")
cols = ["m1_uav_compute_ms", "puf_eval_ms", "bch_ms", "m1_gs_compute_ms",
        "m2_uav_verify_ms", "m3_uav_compute_ms", "m3_gs_compute_ms",
        "m4_uav_compute_ms", "m1_net_ms", "m2_net_ms", "m3_net_ms", "m4_net_ms",
        "bytes_m1", "bytes_m2", "bytes_m3", "bytes_m4",
        "compute_ms", "net_ms", "overhead_bytes",
        "mac_ms", "kdf_ms", "dh_ms", "aead_ms", "fe_rep_ms",
        "gs_mac_ms", "gs_kdf_ms", "gs_dh_ms", "gs_aead_ms"]
a = sel(p2, config="StadiumSHA3")
b = sel(p2, config="StadiumSPONGENT")
print(f"{'field':24s} {'sha3':>10s} {'spongent':>10s}   n={len(a)}/{len(b)}")
for c in cols:
    print(f"{c:24s} {avg(a,c):10.4f} {avg(b,c):10.4f}")

hdr("PHASE 3 MESSAGE BREAKDOWN")
a3 = sel(p3, config="StadiumSHA3")
b3 = sel(p3, config="StadiumSPONGENT")
print(f"{'field':24s} {'sha3':>10s} {'spongent':>10s}   n={len(a3)}/{len(b3)}")
for c in ["p1_i_compute_ms", "p1_p2_j_compute_ms", "p2_p3_i_compute_ms",
          "p1_net_ms", "p2_net_ms", "p3_net_ms", "compute_ms", "net_ms",
          "latency_ms", "overhead_bytes", "mac_ms", "kdf_ms", "dh_ms"]:
    print(f"{c:24s} {avg(a3,c):10.4f} {avg(b3,c):10.4f}")

hdr("BASELINES RSA / ECDSA")
bl = load("omnet_baseline_results.csv")
for cfg in sorted({r["config"] for r in bl}):
    d = sel(bl, config=cfg)
    e, eh, n = ci(runmeans(d, "wall_latency_ms"))
    c, ch, _ = ci(runmeans(d, "compute_ms"))
    w, wh, _ = ci(runmeans(d, "net_ms"))
    ob = sorted({int(float(r["overhead_bytes"])) for r in d})
    print(f"{cfg:16s} suite={d[0]['sig_suite']:9s} runs={n} rec={len(d)}")
    print(f"    elapsed={e:.4f}+-{eh:.4f} compute={c:.4f}+-{ch:.4f} net={w:.4f}+-{wh:.4f} "
          f"C+N={c+w:.4f}")
    print(f"    sign={avg(d,'sign_ms'):.4f} verify={avg(d,'verify_ms'):.4f} "
          f"dh={avg(d,'dh_ms'):.4f} mac={avg(d,'mac_ms'):.4f} kdf={avg(d,'kdf_ms'):.4f} "
          f"bytes={ob[0]}-{ob[-1]} ok={avg(d,'success'):.4f}")

hdr("PKI TIGHT-LOOP BENCH")
for r in load("omnet_pki_baseline.csv"):
    print(f"{r['scheme']:12s} {r['operation']:8s} it={r['iterations']:>5s} "
          f"mean_us={r['mean_us']:>10s} med_us={r['median_us']:>10s} "
          f"p05={r['p05_us']:>9s} p95={r['p95_us']:>9s}")

hdr("PRIMITIVE COSTS in-protocol (Stadium configs)")
pc = load("omnet_primitive_costs.csv")
for suite, cfg in [("sha3", "StadiumSHA3"), ("spongent", "StadiumSPONGENT")]:
    d = sel(pc, config=cfg)
    g = defaultdict(list)
    calls = defaultdict(int)
    for r in d:
        g[r["primitive"]].append(num(r, "median_us"))
        calls[r["primitive"]] += int(float(r["calls"]))
    print(f"-- {suite} ({cfg})")
    for k in sorted(g):
        print(f"     {k:22s} calls={calls[k]:7d} median_of_medians={st.median(g[k]):10.3f} us")

hdr("INET 802.11 (one clock: compute measured, net = wall - compute derived)")
inet = load("omnet_inet_latency.csv")
for cfg in sorted({r["config"] for r in inet}):
    d = sel(inet, config=cfg, phase="phase2")
    ok = [r for r in d if r["success"] == "1"]
    e, eh, n = ci(runmeans(ok, "wall_latency_ms"))
    c, ch, _ = ci(runmeans(ok, "compute_ms"))
    w, wh, _ = ci(runmeans(ok, "net_ms"))
    peers = sel(inet, config=cfg, phase="phase3")
    pok = sum(1 for r in peers if r["success"] == "1")
    print(f"{cfg:26s} runs={n} ok={len(ok)}/{len(d)} peers={pok}/{len(peers)} "
          f"wall={e:7.3f}+-{eh:.3f} compute={c:6.3f}+-{ch:.3f} net={w:7.3f}+-{wh:.3f}")

hdr("COMPARISON (one row per config; reported = C+N two-clock, wall one-clock)")
cmp_rows = load("omnet_comparison.csv")
for r in sorted(cmp_rows, key=lambda x: (x["family"], x["config"])):
    def g(k):
        v = r.get(k, "")
        return "  n/a " if v in ("", None) else f"{float(v):7.3f}"
    print(f"  {r['config']:26s} {r['family']:9s} {r['clock_model']:4s} "
          f"compute={g('compute_ms')} net={g('net_ms')} wall={g('wall_ms')} "
          f"reported={g('reported_latency_ms')}")

hdr("NOISE SWEEP")
ns = load("omnet_noise_sweep.csv")
print(f"{'ber%':>5s} {'profile':22s} {'t':>3s} {'L':>2s} {'dev':>4s} {'fail':>5s} "
      f"{'meas':>7s} {'pred':>12s} {'inCI':>5s}")
for r in ns:
    print(f"{float(r['puf_ber'])*100:5.0f} {r['fe_profile']:22s} {r['bch_t']:>3s} "
          f"{r['num_blocks_L']:>2s} {r['devices']:>4s} {r['fe_failures']:>5s} "
          f"{float(r['measured_frr']):7.4f} {float(r['predicted_frr_binomial']):12.4e} "
          f"{r['prediction_within_ci']:>5s}")

hdr("SECURITY / ATTACKS")
for r in load("omnet_security_results.csv"):
    print({k: v for k, v in r.items() if v not in ("", None)})

hdr("PHASE 1 ENROLLMENT")
for cfg in sorted({r["config"] for r in p1}):
    d = sel(p1, config=cfg)
    print(f"{cfg:20s} n={len(d):5d} puf={avg(d,'puf_eval_ms'):.4f} gen={avg(d,'fe_gen_ms'):.4f} "
          f"tot={avg(d,'total_ms'):.4f} helper={avg(d,'helper_bytes'):.0f} "
          f"chal={avg(d,'challenge_bytes'):.0f} ok={avg(d,'success'):.4f}")

hdr("RELIABILITY FILE")
rel = load("omnet_reliability.csv")
agg = defaultdict(lambda: [0, 0, 0, 0])
for r in rel:
    a2 = agg[r["config"]]
    a2[0] += int(float(r["num_enrolled"]))
    a2[1] += int(float(r["auth_attempts"]))
    a2[2] += int(float(r["auth_successes"]))
    a2[3] += int(float(r["fe_reproduction_failures"]))
for k in sorted(agg):
    e, at, su, fe = agg[k]
    print(f"{k:24s} enrolled={e:5d} attempts={at:5d} successes={su:5d} "
          f"fe_fail={fe:4d} devrate={su/e if e else 0:.4f}")

hdr("ENERGY")
for r in load("omnet_energy_costs.csv"):
    print(f"{r['row_type']:16s} {r['primitive'][:44]:44s} {r['config'][:16]:16s} "
          f"{r['value']:>10s} {r['unit']:12s} {r['confidence']}")
