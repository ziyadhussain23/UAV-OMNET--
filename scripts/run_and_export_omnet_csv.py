#!/usr/bin/env python3
"""Run OMNeT++ configurations and export Python-style CSV results."""

from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import time
from pathlib import Path

from export_omnet_csv import export_from_sca

DEFAULT_CONFIGS = ["StadiumSHA3"]


def run_command(cmd: list[str], cwd: Path) -> str:
    result = subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OMNeT++ and export CSV results")
    parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace root containing src/ and simulations/ (default: current directory)",
    )
    parser.add_argument(
        "--configs",
        nargs="*",
        default=DEFAULT_CONFIGS,
        help=f"Configurations to run (default: {' '.join(DEFAULT_CONFIGS)})",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip build step and run existing executable",
    )
    parser.add_argument(
        "--no-clean-results",
        action="store_true",
        help="Do not remove old UAVAuth-*.sca/.vec files before running",
    )
    args = parser.parse_args()

    root = Path(args.workspace).resolve()
    exe = root / "src" / "uavauthsim"
    ini = root / "simulations" / "omnetpp.ini"
    results_dir = root / "simulations" / "results"
    logs_dir = results_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    if not args.no_clean_results:
        for pattern in ("UAVAuth-*.sca", "UAVAuth-*.vec", "UAVAuth-*.vci"):
            for path in results_dir.glob(pattern):
                path.unlink(missing_ok=True)

    if not args.skip_build:
        print("Building OMNeT++ project...")
        run_command([str(root / "scripts" / "build_omnet_project.sh")], root)

    if not exe.exists():
        raise FileNotFoundError(f"Executable not found: {exe}")

    run_rows = []
    ned_path = f"{root / 'src'};{root / 'simulations'}"

    for cfg in args.configs:
        print(f"Running config: {cfg}")
        t0 = time.perf_counter()
        cmd = [
            str(exe),
            "-u",
            "Cmdenv",
            "-n",
            ned_path,
            "-f",
            str(ini),
            "-c",
            cfg,
        ]

        try:
            out = run_command(cmd, root)
            status = "ok"
            error = ""
        except subprocess.CalledProcessError as exc:
            out = (exc.stdout or "") + "\n" + (exc.stderr or "")
            status = "failed"
            error = f"exit={exc.returncode}"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        log_file = logs_dir / f"{cfg}.log"
        log_file.write_text(out, encoding="utf-8")

        run_rows.append(
            {
                "config": cfg,
                "status": status,
                "run_wallclock_ms": round(elapsed_ms, 6),
                "log_file": str(log_file),
                "error": error,
            }
        )

        if status != "ok":
            print(f"Config {cfg} failed. See {log_file}")
            break

    run_csv = results_dir / "omnet_run_times.csv"
    with run_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["config", "status", "run_wallclock_ms", "log_file", "error"],
        )
        writer.writeheader()
        for row in run_rows:
            writer.writerow(row)

    if all(r["status"] == "ok" for r in run_rows):
        outputs = export_from_sca(results_dir, include_configs=set(args.configs))
        print("\nCSV exports generated:")
        print(f"  {outputs['phase2']}")
        print(f"  {outputs['phase3']}")
        print(f"  {outputs['summary']}")
        print(f"  {run_csv}")
    else:
        print("\nSome runs failed; CSV export skipped.")
        print(f"Run status CSV: {run_csv}")
        sys.exit(1)


if __name__ == "__main__":
    main()
