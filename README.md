# UAVAuthProtocol — OMNeT++ Implementation

PUF-based UAV authentication protocol simulated in OMNeT++ 6.3, with a Python reference under [UAV-Authentication/](UAV-Authentication/) and analysis scripts under [scripts/](scripts/).

---

## Quick start (one command)

From the project root, in any new terminal:

```bash
cd ~/UAV-OMNET++ && \
deactivate 2>/dev/null; \
source ~/omnetpp-6.3.0/setenv > /dev/null && \
deactivate 2>/dev/null; \
source .venv/bin/activate && \
export PATH="$HOME/omnetpp-6.3.0/bin:$PATH" && \
chmod +x scripts/build_omnet_project.sh && \
scripts/build_omnet_project.sh && \
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c StadiumSHA3     && \
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c StadiumSPONGENT && \
python scripts/run_and_export_omnet_csv.py --skip-build --configs StadiumSHA3 StadiumSPONGENT 
```

This activates OMNeT++ + Python venv → builds → runs both stadium configs (SHA3 + SPONGENT) → exports CSVs to `simulations/results/` → prints summary.

**Verified output (last run):**
```
Configs analyzed: 2
Phase 2 rows: 20    avg latency 4.203 ms,  compute 3.538 ms,  overhead 175 B
Phase 3 rows: 90    avg latency 7.869 ms,  compute 7.402 ms,  overhead 104 B
Authentication success rate: 100.00%
```

> **Notes**
> - `setenv` auto-activates OMNeT++'s bundled Python venv, which conflicts with this project's `.venv`. The two `deactivate` calls + explicit `PATH` export above resolve that.
> - `SHA3Hash.cc` uses OpenSSL EVP, so the build script links `-lcrypto`. If linker complains about missing `EVP_*` symbols, install OpenSSL dev headers: `sudo apt install libssl-dev`.
> - Use `--skip-build` on `run_and_export_omnet_csv.py` after the first build (its internal subprocess build call can fail under captured output).

---

## 0. One-time setup

Prerequisites already installed on the lab machine:

- OMNeT++ 6.3 at `~/omnetpp-6.3.0/`
- Python 3 venv at `.venv/` (created with `python3 -m venv .venv`)

If the venv is missing, recreate it:

```bash
cd ~/UAV-OMNET++
python3 -m venv .venv
source .venv/bin/activate
pip install -r UAV-Authentication/requirements.txt
```

---

## 1. Activate the environment (do this in EVERY new terminal)

```bash
cd ~/UAV-OMNET++
deactivate 2>/dev/null                          # exit any active venv first
source ~/omnetpp-6.3.0/setenv                   # OMNeT++ tools
deactivate 2>/dev/null                          # exit OMNeT++'s bundled venv
source .venv/bin/activate                       # this project's venv
export PATH="$HOME/omnetpp-6.3.0/bin:$PATH"     # ensure opp_makemake stays on PATH
```

Verify:

```bash
which opp_makemake     # -> ~/omnetpp-6.3.0/bin/opp_makemake
which python           # -> ~/UAV-OMNET++/.venv/bin/python
```

---

## 2. Build the OMNeT++ simulation

```bash
chmod +x scripts/build_omnet_project.sh scripts/run_baseline.sh
scripts/build_omnet_project.sh
```

Optional flags (real BCH backend / libsodium ECDH):

```bash
USE_LIBCORRECT=1 scripts/build_omnet_project.sh
USE_SODIUM=1     scripts/build_omnet_project.sh
USE_LIBCORRECT=1 USE_SODIUM=1 scripts/build_omnet_project.sh
```

Produces `src/uavauthsim`.

---

## 3. Run simulations

### Default baseline

```bash
scripts/run_baseline.sh
```

### Specific configurations (see [simulations/omnetpp.ini](simulations/omnetpp.ini))

```bash
cd simulations
../src/uavauthsim -u Cmdenv -n ../src:../simulations -c StadiumSHA3      omnetpp.ini
../src/uavauthsim -u Cmdenv -n ../src:../simulations -c StadiumSPONGENT  omnetpp.ini
../src/uavauthsim -u Cmdenv -n ../src:../simulations -c Swarm20          omnetpp.ini
../src/uavauthsim -u Cmdenv -n ../src:../simulations -c HighNoise        omnetpp.ini
```

Scalar / vector results are written to `simulations/results/UAVAuth-<config>-<run>.{sca,vec}`.

---

## 4. Export & analyze results

All commands below assume the venv is active (`source .venv/bin/activate`).

```bash
# Run all configs and export per-phase CSVs into results2/
python scripts/run_and_export_omnet_csv.py

# Or just re-export from existing .sca files:
python scripts/export_omnet_csv.py

# Summary statistics
python scripts/analyze_results.py

# Compare OMNeT++ vs Python reference
python scripts/compare_results.py \
    --python UAV-Authentication/results/phase2_results.csv \
    --omnet  results2/omnet_phase2_results.csv
```

Key output files in [results2/](results2/):

- `omnet_summary.csv` — per-config means (latency, compute, network, overhead, success).
- `omnet_phase2_results.csv` / `omnet_phase3_results.csv` — per-UAV per-run rows.
- `omnet_phase2_sha3.csv` / `omnet_phase2_spongent.csv` — split by hash mode.

---

## 5. Run the Python reference implementation (optional)

```bash
source .venv/bin/activate
cd UAV-Authentication
python provision.py            # one-time CRP enrollment
python ground_station_server.py &
python uav_client.py 1
```

Detailed Python-side instructions: [UAV-Authentication/README.md](UAV-Authentication/README.md).

---

## Directory layout

- [src/crypto/](src/crypto/) — PUF, SPONGENT-160, SHA3-256, BCH wrapper, byte utilities.
- [src/protocols/](src/protocols/) — Phase 1–4 protocol logic and typed messages.
- [src/nodes/](src/nodes/) — `UAVNode`, `GroundStation`, `NetworkController` modules + NED.
- [simulations/](simulations/) — `UAVNetwork.ned`, `omnetpp.ini`, scalar/vector outputs.
- [scripts/](scripts/) — build / run / export / analyze helpers.
- [UAV-Authentication/](UAV-Authentication/) — Python reference implementation (provision + GS + UAV client).
- [results2/](results2/) — final exported CSVs used by the paper / slides.
- [ppt/](ppt/) — end-semester presentation (`endsem.tex` → `endsem.pdf`).
- [docs/](docs/), [research paper/](research%20paper/) — paper sources.

---

## Notes

- This baseline uses direct message delivery (`sendDirect`) for deterministic protocol validation; it models link bitrate + propagation delay only — **no MAC-layer contention** is simulated, so reported network delay is a lower bound.
- For publication-grade BCH behavior, build with `USE_LIBCORRECT=1`.
- For real ECDH-based session keys, build with `USE_SODIUM=1`.
- Never use the `*Dual()` hash methods in normal runs — they compute both SHA3 and SPONGENT (~15× overhead). Dual is only for explicit benchmark configs.

