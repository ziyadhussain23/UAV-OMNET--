#!/usr/bin/env python3
"""Run simulation configurations and export the CSVs.

Differences from the previous runner, all deliberate:
  * every configuration runs by default, not just the first one;
  * --clean archives existing results instead of deleting them;
  * a failing configuration does not abort the remaining ones;
  * host, CPU, OpenSSL, OMNeT++ and git provenance are recorded per run, so a
    reader can tell what produced a number.
"""

import argparse
import csv
import datetime
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from export_omnet_csv import export  # noqa: E402

ALL_CONFIGS = [
    "StadiumSHA3", "StadiumSPONGENT", "Baseline5UAV", "Swarm20",
    "ArbiterPuf", "HighNoise",
    "AtkEavesdrop", "AtkCredSniff", "AtkTamper",
]


def provenance():
    def sh(cmd):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                                  timeout=10).stdout.strip()
        except Exception:
            return ""
    cpu = ""
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "host": platform.node(),
        "cpu_model": cpu,
        "openssl_version": sh("openssl version").replace(",", " "),
        "omnetpp_version": sh("opp_run -v 2>/dev/null | head -1").replace(",", " "),
        "git_commit": sh("git rev-parse --short HEAD"),
        "dirty": "1" if sh("git status --porcelain") else "0",
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", default=".")
    ap.add_argument("--configs", nargs="*", default=ALL_CONFIGS)
    ap.add_argument("--runs", type=int, default=None,
                    help="limit to the first N repetitions of each config")
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--clean", action="store_true",
                    help="archive existing results before running")
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    root = Path(args.workspace).resolve()
    exe = root / "src" / "uavauthsim"
    ini = root / "simulations" / "omnetpp.ini"
    results = root / "simulations" / "results"
    logs = results / "logs"
    logs.mkdir(parents=True, exist_ok=True)

    if not args.skip_build:
        print("building...")
        rc = subprocess.run(["bash", str(root / "scripts" / "build_omnet_project.sh")],
                            cwd=str(root)).returncode
        if rc != 0:
            print("build failed", file=sys.stderr)
            return 1
    if not exe.exists():
        print("executable not found: %s" % exe, file=sys.stderr)
        return 1

    if args.clean:
        stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
        archive = results / "archive" / stamp
        moved = 0
        for pattern in ("*.sca", "*.vec", "*.vci", "*.csv"):
            for path in results.glob(pattern):
                archive.mkdir(parents=True, exist_ok=True)
                shutil.move(str(path), str(archive / path.name))
                moved += 1
        if moved:
            print("archived %d files to %s" % (moved, archive))

    prov = provenance()
    rows = []
    failures = []

    for config in args.configs:
        run_spec = ["-c", config]
        if args.runs is not None:
            run_spec += ["-r", ",".join(str(i) for i in range(args.runs))]

        cmd = [str(exe), "-u", "Cmdenv", "-n", "%s;%s" % (root / "src", root / "simulations"),
               "-f", str(ini)] + run_spec
        started = datetime.datetime.now().isoformat(timespec="seconds")
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(cmd, cwd=str(root / "simulations"), capture_output=True,
                                  text=True, timeout=args.timeout)
            rc = proc.returncode
            out = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
        except subprocess.TimeoutExpired:
            rc, out = -1, "TIMEOUT after %ds" % args.timeout
        elapsed = (time.perf_counter() - t0) * 1000.0

        (logs / ("%s.log" % config)).write_text(out)
        status = "ok" if rc == 0 else "failed"
        if rc != 0:
            failures.append(config)
        print("  %-16s %-7s %9.1f ms" % (config, status, elapsed))

        row = {"config": config, "status": status,
               "run_wallclock_ms": round(elapsed, 3),
               "log_file": str(logs / ("%s.log" % config)),
               "error": "" if rc == 0 else "exit=%d" % rc,
               "cmd": " ".join(cmd).replace(",", " "),
               "started_at_iso": started,
               "finished_at_iso": datetime.datetime.now().isoformat(timespec="seconds")}
        row.update(prov)
        rows.append(row)

    cols = ["config", "status", "run_wallclock_ms", "log_file", "error", "cmd",
            "started_at_iso", "finished_at_iso", "host", "cpu_model",
            "openssl_version", "omnetpp_version", "git_commit", "dirty"]
    with open(results / "omnet_run_times.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    # Export whatever succeeded; a failure in one configuration must not discard
    # the results of the others.
    try:
        written = export(results, {r["config"] for r in rows if r["status"] == "ok"})
        print("\nexported:")
        for key in sorted(written):
            print("  %-18s %d rows" % (key, written[key]))
    except Exception as exc:  # noqa: BLE001
        print("export failed: %s" % exc, file=sys.stderr)
        return 1

    if failures:
        print("\nFAILED configurations: %s" % ", ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
