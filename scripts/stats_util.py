"""Statistics helpers for the results pipeline.

The unit of replication is the RUN (one seed set), not the CSV row. Rows inside
one run share a PRNG stream, one host process and one OS scheduling epoch, so
they are strongly correlated. Pooling the 300 rows of a 30-run x 10-UAV campaign
and dividing by sqrt(300) would inflate the degrees of freedom from 29 to 299 and
shrink the interval by roughly sqrt(10) ~ 3.2x. Every interval here is therefore
computed two-stage: per-run means first, then a t-interval across runs.

Stdlib only, so the scripts run without a virtualenv.
"""

import math

# Two-sided 97.5% quantiles of Student's t, indexed by degrees of freedom.
_T_TABLE = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
    15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
    27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042, 40: 2.021, 50: 2.009,
    60: 2.000, 80: 1.990, 100: 1.984, 120: 1.980,
}


class InsufficientRuns(Exception):
    """Raised when too few runs exist to form an interval.

    Deliberately an exception rather than a silent zero-width interval: the
    previous results set reported single-run point estimates to four significant
    figures, which is precisely the failure this guard prevents.
    """


def t_critical(df):
    """Two-sided 97.5% t quantile for `df` degrees of freedom."""
    if df <= 0:
        raise InsufficientRuns("t_critical: df must be positive")
    if df in _T_TABLE:
        return _T_TABLE[df]
    known = sorted(_T_TABLE)
    if df > known[-1]:
        return 1.960  # normal approximation
    lo = max(k for k in known if k < df)
    hi = min(k for k in known if k > df)
    frac = (df - lo) / (hi - lo)
    return _T_TABLE[lo] + frac * (_T_TABLE[hi] - _T_TABLE[lo])


def mean(values):
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def stdev(values):
    values = list(values)
    if len(values) < 2:
        return 0.0
    m = mean(values)
    return math.sqrt(sum((v - m) ** 2 for v in values) / (len(values) - 1))


def percentile(values, q):
    values = sorted(values)
    if not values:
        return 0.0
    if q <= 0:
        return values[0]
    if q >= 1:
        return values[-1]
    pos = q * (len(values) - 1)
    lo = int(pos)
    hi = min(lo + 1, len(values) - 1)
    return values[lo] + (pos - lo) * (values[hi] - values[lo])


def two_stage_ci(rows, value_key, run_key="run_id", min_runs=3):
    """Mean +/- 95% CI with the run as the unit of replication.

    `rows` is an iterable of dicts. Returns a dict of summary fields; raises
    InsufficientRuns when fewer than `min_runs` runs are present.
    """
    per_run = {}
    for row in rows:
        raw = row.get(value_key, "")
        if raw == "" or raw is None:
            continue
        try:
            v = float(raw)
        except (TypeError, ValueError):
            continue
        per_run.setdefault(row.get(run_key, ""), []).append(v)

    if not per_run:
        return None

    run_means = [mean(v) for v in per_run.values()]
    n_runs = len(run_means)
    all_obs = [v for vals in per_run.values() for v in vals]

    out = {
        "n_runs": n_runs,
        "n_obs_total": len(all_obs),
        "obs_per_run_mean": round(len(all_obs) / n_runs, 4),
        "mean_of_run_means": round(mean(run_means), 9),
        "sd_of_run_means": round(stdev(run_means), 9),
        "pooled_mean": round(mean(all_obs), 9),
        "pooled_sd": round(stdev(all_obs), 9),
        "median": round(percentile(all_obs, 0.5), 9),
        "p05": round(percentile(all_obs, 0.05), 9),
        "p95": round(percentile(all_obs, 0.95), 9),
        "min": round(min(all_obs), 9),
        "max": round(max(all_obs), 9),
    }

    if n_runs < min_runs:
        # Report the descriptive statistics but no interval, and say why.
        out.update({
            "df": n_runs - 1, "t_crit": "", "sem": "", "ci95_lo": "", "ci95_hi": "",
            "ci_method": "none: %d run(s) < %d required" % (n_runs, min_runs),
        })
        return out

    df = n_runs - 1
    sem = out["sd_of_run_means"] / math.sqrt(n_runs)
    tc = t_critical(df)
    out.update({
        "df": df,
        "t_crit": round(tc, 4),
        "sem": round(sem, 9),
        "ci95_lo": round(out["mean_of_run_means"] - tc * sem, 9),
        "ci95_hi": round(out["mean_of_run_means"] + tc * sem, 9),
        "ci_method": "two-stage t; unit=run; df=R-1",
    })
    return out


def wilson_interval(successes, trials, z=1.96):
    """Wilson score interval for a proportion.

    Preferred over the normal approximation near 0 and 1, which is exactly where
    authentication success rates and false-accept rates live.
    """
    if trials == 0:
        return (0.0, 0.0)
    p = successes / trials
    z2 = z * z
    denom = 1.0 + z2 / trials
    centre = (p + z2 / (2 * trials)) / denom
    half = (z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rule_of_three_upper(trials):
    """95% upper bound on an event probability after observing zero events.

    With 10 trials and no failures the honest statement is "at most ~26%", not
    "100% reliable" -- the claim the previous results made from exactly that
    sample size.
    """
    return 3.0 / trials if trials > 0 else 1.0


def proportion_summary(successes, trials):
    out = {
        "successes": successes,
        "trials": trials,
        "rate": round(successes / trials, 9) if trials else 0.0,
    }
    lo, hi = wilson_interval(successes, trials)
    out["wilson_lo"] = round(lo, 9)
    out["wilson_hi"] = round(hi, 9)
    if trials and successes == trials:
        out["rule_of_three_upper_failure"] = round(rule_of_three_upper(trials), 9)
    else:
        out["rule_of_three_upper_failure"] = ""
    return out
