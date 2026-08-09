# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A PUF-based UAV authentication protocol (4-phase: enrollment, GS↔UAV authentication, UAV↔UAV peer authentication, session-key derivation), implemented two ways:

- **`src/`** — the primary OMNeT++ 6.3 (C++) discrete-event simulation. This is where active work happens.
- **`UAV-Authentication/`** — an earlier Python reference implementation (`uav_puf_auth/` package) used for protocol validation and as a cross-check baseline (`scripts/compare_results.py` diffs its output against the OMNeT++ output). Not the primary target for new work unless asked.

## Environment activation (required every new terminal)

OMNeT++ bundles its own Python venv via `setenv`, which conflicts with this project's `.venv`. Always activate in this order:

```bash
cd ~/UAV-OMNET++
deactivate 2>/dev/null
source ~/omnetpp-6.3.0/setenv > /dev/null
deactivate 2>/dev/null
source .venv/bin/activate
export PATH="$HOME/omnetpp-6.3.0/bin:$PATH"
```

Verify with `which opp_makemake` (should resolve under `omnetpp-6.3.0/bin`) and `which python` (should resolve under `.venv/bin`).

## Build & run commands

```bash
# Build (produces src/uavauthsim)
chmod +x scripts/build_omnet_project.sh
scripts/build_omnet_project.sh

# Optional build flags for non-default backends:
USE_LIBCORRECT=1 scripts/build_omnet_project.sh   # real BCH via libcorrect instead of the stub
USE_SODIUM=1     scripts/build_omnet_project.sh   # libsodium ECDH instead of the stub session-key derivation

# Run the default baseline config
scripts/run_baseline.sh

# Run a specific config (see simulations/omnetpp.ini for the full list)
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c StadiumSHA3
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c StadiumSPONGENT
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c Swarm20
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c HighNoise

# Export/analyze results (venv must be active)
python scripts/run_and_export_omnet_csv.py            # run all configs + export CSVs
python scripts/run_and_export_omnet_csv.py --skip-build --configs StadiumSHA3 StadiumSPONGENT
python scripts/export_omnet_csv.py                     # re-export from existing .sca files only
python scripts/analyze_results.py                      # summary statistics
python scripts/compare_results.py --python UAV-Authentication/results/phase2_results.csv --omnet results2/omnet_phase2_results.csv
```

`build_omnet_project.sh` links `-lcrypto` unconditionally (`SHA3Hash.cc` uses OpenSSL EVP) — if the linker complains about missing `EVP_*` symbols, install `libssl-dev`.

Build artifacts land in `src/out/clang-release/`; `opp_makemake` regenerates `src/Makefile`, so re-run the build script (not raw `make`) after adding/removing source files.

### Tests

`tests/test_puf.cc` is a standalone PUF-uniqueness/reliability sanity check, not wired into the OMNeT++ Makefile or any CI script. Compile and run it manually when touching `PUFSimulator`:

```bash
g++ -std=c++17 -I src tests/test_puf.cc src/crypto/PUFSimulator.cc -o /tmp/test_puf && /tmp/test_puf
```

There is no automated test suite beyond this file — validate protocol changes by running the simulation configs and checking `scripts/analyze_results.py` output (particularly `Authentication success rate`) against expectations.

## Architecture (`src/`)

Four-phase protocol, split across three OMNeT++ simple modules (`src/nodes/`) that exchange typed `ProtocolMessage`s (`src/protocols/ProtocolMessages.h`) via `sendDirect` (no MAC-layer contention modeled — reported network delay is a lower bound, link bitrate + propagation delay only):

- **`GroundStation`** — enrolls UAVs (Phase 1: generates CRPs from a per-UAV `PUFSimulator`), and answers Phase 2 authentication (issues a challenge + nonce, verifies the PUF response against BCH-corrected helper data, confirms).
- **`UAVNode`** — holds its own `PUFSimulator` instance, runs Phase 2 (authenticate against `GroundStation`) then, once authenticated, Phase 3 (peer-to-peer mutual authentication with `peerTargetId`) and Phase 4 (session-key derivation from the peer exchange).
- **`NetworkController`** — coordinates/observes network-level behavior (see `src/nodes/NetworkController.cc`).

Protocol logic itself lives in `src/protocols/Phase{1Enrollment,2Authentication,3PeerAuth,4SessionKey}.{h,cc}` — these are plain classes invoked by the node modules, not simple modules themselves. When changing protocol behavior, edit the `Phase*` class; when changing simulation wiring/timing/metrics, edit the node `.cc`/`.ned` files.

Crypto primitives live in `src/crypto/`:
- `PUFSimulator` — simulates a strong PUF (seed + noise level → challenge/response), with static Hamming-distance helpers for uniqueness/reliability checks (see `tests/test_puf.cc`).
- `BCHCodec` — fuzzy extractor / helper-data error correction (stub by default; real BCH via `libcorrect` behind `USE_LIBCORRECT`).
- `HashWrapper` — dispatches to `SHA3Hash` or `SPONGENT` (`SPONGENT-160`) based on the `hashMode` NED parameter (`"sha3"` / `"spongent"`). **Never use the `*Dual()` hash methods in normal runs** — they compute both hashes (~15× overhead) and exist only for explicit dual-mode benchmark configs (`StadiumBoth`).
- `CryptoUtils` — shared byte/nonce/random utilities.

`ProtocolMessage` (`src/protocols/ProtocolMessages.h`) is a single generic `cMessage` subclass reused across all message types (`MessageType` enum: `AUTH_REQUEST`, `CHALLENGE_ISSUANCE`, `PUF_RESPONSE`, `AUTH_CONFIRMATION`, `PEER_AUTH_REQUEST`, `PEER_AUTH_RESPONSE`, `PEER_AUTH_COMPLETE`), with generic `field1/field2/field3` byte-vector payload slots and `metricA..D` timing fields instrumented per-step for latency/overhead measurement — check the `MessageType` before reading which fields are populated.

Metrics (per-phase compute/network latency, communication overhead in bytes, auth success) are recorded via `simsignal_t` (`authLatencySignal`, `commOverheadSignal`, `peerAuthLatencySignal`) declared with `result-recording-modes = all` in `simulations/omnetpp.ini`, and written to `simulations/results/UAVAuth-<config>-<run>.{sca,vec}`. `UAVNode` tracks a large number of granular per-step timing fields (`m1UavComputeMs`, `m2UavVerifyMs`, `pufEvalMs`, `bchMs`, etc., plus per-peer maps for Phase 3) — when adding a new protocol step, follow the existing naming convention (`m<msgNum><role><ComputeMs|NetMs>`) so `scripts/export_omnet_csv.py` / `analyze_results.py` continue to parse consistently.

`simulations/omnetpp.ini` defines a "Stadium" scenario as the base config (10 UAVs in a fixed perimeter layout around a 500×300m field, GS at center) with `hashMode` as a parametrized dimension (`StadiumSHA3`, `StadiumSPONGENT`, `StadiumBoth`), plus `Baseline5UAV`, `Swarm20` (scalability), and `HighNoise` (elevated PUF error rate) variants.

## Python reference (`UAV-Authentication/`)

Standalone package (`uav_puf_auth/`) simulating the same 4-phase protocol for cross-validation. Notable substitutions vs. the paper/OMNeT++ implementation:
- PUF: `pypuf.simulation.ArbiterPUF`, 128-bit challenge/response (128 single-bit evaluations from sub-challenges derived from the seed).
- BCH: `bchlib`, polynomial 8219, t=18.
- Hash: SHA3-256 truncated to 160 bits (in place of SPONGENT-160).
- MAC/Enc: hash-derived (`mac160` = `hash160(key||msg)`; `stream_xor` via SHAKE256) — simulation-only, not production crypto.
- Network: in-process simulated delay by default; real TCP sockets for two-machine demos (`ground_station_server.py` + `uav_client.py`).

Run via `python provision.py` (one-time CRP enrollment) then `python ground_station_server.py &` and `python uav_client.py 1`. Full details in `UAV-Authentication/README.md` and `UAV-Authentication/docs/IMPLEMENTATION_GUIDE.md`.

## Output/artifact locations

- `simulations/results/` — raw `.sca`/`.vec` from OMNeT++ runs.
- `results2/` (referenced by README, generated by `run_and_export_omnet_csv.py`) — `omnet_summary.csv`, `omnet_phase2_results.csv`/`omnet_phase3_results.csv`, split-by-hash-mode CSVs.
- `ppt/`, `research paper/`, `paper.pdf`, `docs/` — presentation/paper sources, not code; only touch when asked.
