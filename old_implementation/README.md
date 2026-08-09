# Archived implementation (frozen)

This directory holds the **previous** OMNeT++ implementation of the UAV authentication protocol,
kept for reference and for reproducing the older result set. It mirrors the `old_theory/`
convention used for the earlier manuscript.

**It is excluded from the build.** `opp_makemake --deep` runs from `src/`, so nothing here is
compiled by `scripts/build_omnet_project.sh`.

Contents:

- `src/` — the previous crypto, protocol, and node sources.
- `tests/` — the previous standalone `test_puf.cc`.
- `build_omnet_project.sh.orig` — the build script as it stood before the rewrite.

Do not modify these files. The audit of this code is in `REPORT.md` (Parts B and C); the
replacement is specified in `revised_theory/paper.tex` and implemented in the top-level `src/`.

To build the archived version, copy it into a scratch checkout and run the original script there.
