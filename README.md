# PUF-Based UAV Swarm Authentication

A four-phase authentication protocol for drone swarms, rooted in a hardware
fingerprint (a Physical Unclonable Function) rather than a stored key, with a full
OMNeT++ 6.3 implementation and evaluation.

Specification: [`final_theory/paper.tex`](final_theory/paper.tex).
Implementation: [`src/`](src/). Results: [`final results/`](final%20results/).
What changed and why: [`report.md`](report.md).

**Contents**

1. [How to run it](#1-how-to-run-it)
2. [The protocol explained](#2-the-protocol-explained)
3. [How it is implemented](#3-how-it-is-implemented)
4. [Results and where to find them](#4-results-and-where-to-find-them)

---

## 1. How to run it

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| OMNeT++ | 6.3.0 | expected at `~/omnetpp-6.3.0` |
| C++ compiler | C++17 | OMNeT++ supplies clang |
| OpenSSL headers | 3.5.5 | `libssl-dev` — SHA3, HMAC, HKDF, ChaCha20-Poly1305, X25519 |
| Python | 3.8+ | analysis scripts are **standard-library only**; no virtualenv |
| INET | 4.5 (release) | only for the 802.11 track; expected at `~/oment-workspace2/inet4.5` |

SPONGENT-160 and Ascon-128a are in the source tree. Nothing else to install.

### Environment (every new terminal)

```bash
cd ~/UAV-OMNET++
source ~/omnetpp-6.3.0/setenv > /dev/null
export PATH="$HOME/omnetpp-6.3.0/bin:$PATH"
which opp_makemake     # -> ~/omnetpp-6.3.0/bin/opp_makemake
```

### Build

```bash
scripts/build_omnet_project.sh          # -> src/uavauthsim
BUILD_MODE=debug scripts/build_omnet_project.sh
```

Always use this script, never bare `make`: `opp_makemake` generates a Makefile with a
fixed object list, so a new source file is only picked up when the script re-runs.
Extra compiler flags go in `src/makefrag`.

### Tests

```bash
bash tests/run_tests.sh          # 12 suites, ~2 minutes
bash tests/run_tests.sh bch      # one suite by name substring
```

Expected: `=== 12 passed, 0 failed ===`. These do not link the simulation kernel, so
each takes seconds. A test declares its own dependencies in a `// DEPS:` comment, so
adding one needs no runner edit.

### Run the simulation

One configuration, one repetition:

```bash
cd simulations
../src/uavauthsim -u Cmdenv -n ../src:../simulations -f omnetpp.ini -c StadiumSHA3 -r 0
```

The full campaign. Omit `--runs` so every configuration uses its configured `repeat`
(30), which is what the confidence intervals need:

```bash
python3 scripts/run_experiments.py --configs StadiumSHA3 StadiumSPONGENT \
        Baseline5UAV Swarm20 ArbiterPuf HighNoise NoiseSweep \
        AtkGsImpersonate AtkLegacyGsImpersonate AtkReplayM1 AtkCredentialSniff \
        BaselineRSA BaselineECDSA
```

`--clean` archives previous results to `simulations/results/archive/<timestamp>/`
instead of deleting them. `--skip-build` skips the rebuild. The runner exports the
CSVs itself.

### Configurations

| Configuration | What it isolates |
|---|---|
| `StadiumSHA3` | reference: N=10, software crypto profile |
| `StadiumSPONGENT` | crypto profile swapped to constrained hardware |
| `Baseline5UAV` | swarm size N=5 |
| `Swarm20` | swarm size N=20 — 190 peer pairs |
| `ArbiterPuf` | realistic delay-based PUF model, 3% error |
| `HighNoise` | PUF error forced to 5% |
| `NoiseSweep` | error rate 0–10% x three error-correction profiles |
| `AtkGsImpersonate` | forged ground-station messages |
| `AtkLegacyGsImpersonate` | control arm: one check disabled, to prove the adversary works |
| `AtkReplayM1` | replay of a captured message |
| `AtkCredentialSniff` | passive read of the credential package |
| `BaselineRSA` / `BaselineECDSA` | same-platform public-key handshake comparisons |

Mobility and 802.11 contention live on the INET track (`Inet80211SHA3`,
`InetMobilityLinearSHA3`, `InetMobilityRandomWalkSHA3`):

```bash
scripts/build_omnet_project_inet.sh
export LD_LIBRARY_PATH="$HOME/oment-workspace2/inet4.5/out/clang-release/src"
cd simulations
for c in Inet80211SHA3 InetMobilityLinearSHA3 InetMobilityRandomWalkSHA3; do
    ../src_inet/out/clang-release/uavauthsim_inet -u Cmdenv \
        -n "../src:../src_inet:.:$HOME/oment-workspace2/inet4.5/src" \
        -f omnetpp_inet.ini -c "$c"
done
cd ..
python3 scripts/export_inet_csv.py
```

### Other exporters

```bash
python3 scripts/export_omnet_csv.py           # re-derive from existing .sca files
python3 scripts/export_baseline_csv.py        # RSA/ECDSA baselines
python3 scripts/export_noise_sweep.py         # reliability sweep
python3 scripts/export_security_results.py    # attack outcomes
python3 scripts/export_energy_csv.py          # literature energy table
python3 scripts/export_comparison_csv.py      # unified per-config table
python3 scripts/validate_for_papers.py        # recompute every headline number
```

---

## 2. The protocol explained

### The idea

A drone that stores a key can be captured and the key read out. A **PUF** avoids
storing anything: microscopic manufacturing variation makes each chip answer a
*challenge* `C` with a *response* `R = PUF(C)` that no other chip reproduces and
nobody can predict. The silicon is the key, so there is nothing to steal.

Responses drift slightly with temperature, voltage and ageing, so a raw response
cannot be a key directly. A **fuzzy extractor** fixes that: enrollment stores public
*helper data*, and later the same device reconstructs the identical key from a noisy
response plus that helper data.

### Notation

| Symbol | Meaning |
|---|---|
| `UAV_i`, `GS` | drone *i*; ground station |
| `mk_i` | drone *i*'s master key — **never stored** |
| `P_i` | public helper data |
| `Cred_ij` | credential for pair *(i,j)* only |
| `SK_i`, `SK_ij` | session keys |
| `TID_i` | rotating temporary identity |
| `N_x`, `T_x` | 128-bit nonce; timestamp |
| `g^a`, `g^ab` | ephemeral share; shared Diffie–Hellman secret |
| `MAC_K`, `KDF`, `AE` | keyed authenticator; key derivation; authenticated encryption |

### Phase 1 — Enrollment (once, in a trusted facility)

The ground station challenges the drone's PUF, runs the fuzzy extractor, and stores
`{ID, TID, challenge, helper data, mk}`. The drone is given only
`{TID, challenge, helper data}` — **all public**. No secret is written to the drone.

### Phase 2 — Drone ↔ ground station (4 messages)

Both sides derive a key from `mk_i`: the GS from its database, the drone by
regenerating `mk_i` from its PUF.

1. `M1` — drone sends TID, nonce, timestamp, ephemeral share, MAC.
2. `M2` — GS verifies, replies with its nonce, share and MAC.
3. `M3` — drone **verifies M2 first**, then confirms. If M2 fails, nothing is sent.
4. `M4` — GS delivers per-pair credentials under authenticated encryption.

Both sides derive `SK_i = KDF(mk_i ‖ g^ab ‖ transcript)` and erase their ephemeral
scalars, so the session is forward-secret.

### Phase 3 — Drone ↔ drone (3 messages, no ground station)

Peers authenticate directly using their per-pair `Cred_ij`, so it works with the
ground link down. Three messages, each a MAC over the transcript, with distinct type
tags so a token from one step cannot be replayed as another. Then
`SK_ij = KDF(Cred_ij ‖ g^a'b' ‖ transcript)`.

### Phase 4 — Session keys

Both interactive phases end here. Every session key mixes two independent secrets: the
long-term one (`mk_i` or `Cred_ij`) and a fresh ephemeral Diffie–Hellman secret. The
exchange is mandatory — there is no path that omits it — so a session either gets
forward secrecy or fails.

### Security properties

| Property | Rests on |
|---|---|
| Mutual authentication | keyed MACs both directions, under a PUF-derived key |
| No interrogation oracle | verify-before-respond; response never transmitted |
| Replay resistance | nonce cache + timestamp window + per-message type tags |
| Peer authentication | per-pair credential delivered under authenticated encryption |
| Capture resistance | no stored secret; damage bounded to *N−1* links |
| Forward secrecy | mandatory ephemeral exchange, scalars erased |

---

## 3. How it is implemented

### Layout

```
src/
  core/       Bytes, Encoding        byte/bit utilities; canonical message encoder
  crypto/     CryptoSuite            interface both profiles implement
              Sha3Suite              SHA3 / HMAC / HKDF / ChaCha20-Poly1305
              SpongentSuite          SPONGENT / keyed sponge / Ascon-128a
              X25519, Drbg, OsslCommon, PrimitiveCounters
  puf/        PufModel               interface + sub-challenge derivation
              IdealPrfPuf            idealised model (keyed PRF) — used in sims
              ArbiterPuf            128-stage additive-delay model
              XorArbiterPuf         XOR of k chains (tests only)
              MinEntropy            NIST SP 800-90B estimators
  fe/         BchCodec, FuzzyExtractor   BCH(255,131,18); three profiles
  protocol/   Wire, Protocol          message format; all four phases
  nodes/      UavNode, GroundStationNode, WirelessMedium, AttackerNode
src_inet/apps/  the same protocol over a real INET 802.11 stack
tests/          12 standalone suites, no simulation kernel
scripts/        build, run, export, validate
simulations/    network, scenarios, results
```

### Key decisions

**One encoder, three jobs.** A single function serialises each message; its output is
simultaneously the wire bytes, the MAC input, and the byte count used for delay. Each
field is `tag ‖ length ‖ value` with ascending tags, which makes the encoding
*injective* and *canonical*. Reading an absent field raises an error rather than
returning empty bytes.

**Two interoperable crypto profiles**, selected by one parameter:

| | `sha3` | `spongent` |
|---|---|---|
| Hash | SHA3-256 truncated to 160 bits | SPONGENT-160/160/16 |
| MAC | HMAC-SHA3-256, 128-bit tag | prefix keyed sponge |
| KDF | HKDF | one-pass sponge |
| AEAD | ChaCha20-Poly1305 | Ascon-128a |
| Key exchange | X25519 | X25519 |

**Everything is domain-separated.** Separate leading bytes for hash, MAC and KDF, and
every derived key carries a unique label, so a key minted for one purpose cannot be
mistaken for another.

**The PUF is one keyed call, not a per-bit loop.** The idealised model returns the
whole response from a counter-mode HMAC-SHA3-256 stream:

```
block_n = HMAC-SHA3-256(deviceKey, label ‖ challenge ‖ n)
```

Four calls cover a 1020-bit response. The arbiter model takes its sub-challenges from
one SHA3-256 counter-mode stream rather than one hash per bit, and reads the delay sum
directly from that stream. Noise uses a 16-bit threshold on two DRBG bytes instead of
a floating-point draw per bit — same distribution, far cheaper.

**The challenge is fixed at enrollment and held locally**, so regenerating `mk_i`
before M1 is possible and does not weaken verify-before-respond: a fraudulent ground
station cannot choose the challenge, and the drone still emits nothing until the GS
authenticator verifies. See [`docs/spec-deviations.md`](docs/spec-deviations.md).

**The two tracks use different clocks, and results say which.** On the idealised
medium, compute is host wall-clock and network is the simulator's delay model, and the
simulated clock does not advance during crypto — so "simulated elapsed" is not a
total, and compute + network is. On INET and the signature baselines everything runs on
the simulation clock, so measured wall time is the total and network is derived as
`wall − compute` (flagged as derived).

### Verification

Every primitive is checked against published reference values where they exist: SHA3
(FIPS 202/CAVP), HMAC-SHA3, HKDF (RFC 5869), ChaCha20-Poly1305 (RFC 8439), X25519
(RFC 7748, low-order points rejected), Ascon-128a (all 1089 official vectors),
SPONGENT-160 (designers' reference digest — no official KAT file exists), and
BCH(255,131,18) (degree 124, exact recovery across 18,000 trials, failure correctly
reported beyond the radius).

---

## 4. Results and where to find them

### Files

Every file answers one question. `omnet_comparison.csv` is the overview.

| File | Contents |
|---|---|
| `omnet_comparison.csv` | one row per configuration, every family side by side |
| `omnet_phase1/2/3_results.csv` | enrollment, Phase 2, Phase 3 for the latency family |
| `omnet_phase2_sha3.csv`, `omnet_phase2_spongent.csv` | the same split by crypto profile |
| `omnet_noise_results.csv` | the reliability family (ArbiterPuf, HighNoise, NoiseSweep) |
| `omnet_noise_sweep.csv` | measured key-reproduction failure rate vs the binomial prediction |
| `omnet_security_results.csv` | attack outcomes, expectations, and whether they matched |
| `omnet_baseline_results.csv` | RSA-2048 and ECDSA-P256 signed-DH handshakes |
| `omnet_inet_latency.csv` | the 802.11 track: Phase 2 and Phase 3, static and moving |
| `omnet_primitive_costs.csv` | per-primitive cost, named by implementation |
| `omnet_pki_baseline.csv` | tight-loop RSA/ECDSA/ECDH/X25519 benchmark |
| `omnet_energy_costs.csv` | literature-sourced energy, with a confidence label per row |
| `omnet_summary.csv`, `omnet_summary_ci.csv` | per-config rollups with confidence intervals |
| `omnet_run_times.csv` | wall-clock per configuration, with host and version provenance |

### Statistics

Thirty independent repetitions per configuration, each with its own seed. The unit of
replication is the **run**, not the row: rows inside one run share a PRNG stream and a
scheduling epoch, so pooling them would understate every interval by roughly √N.
Intervals are therefore two-stage — a per-run mean, then a *t* interval across run
means with *R−1* degrees of freedom. Proportions use Wilson intervals, and where no
failure is observed the rule-of-three bound is quoted rather than "100%".

Compute times are host wall-clock; network delays are simulated. These are different
clocks and are never summed without qualification.

### Headline numbers

Configurations side by side, compute and network separate (`omnet_comparison.csv`):

| config | clock | compute (ms) | network (ms) | reported (ms) |
|---|---|---|---|---|
| StadiumSHA3 | two | 0.569 | 1.074 | **1.643** |
| StadiumSPONGENT | two | 3.456 | 1.079 | 4.535 |
| Baseline5UAV | two | 0.458 | 0.714 | 1.172 |
| Swarm20 | two | 0.487 | 1.790 | 2.277 |
| BaselineRSA | two | 1.069 | 0.699 | 1.767 |
| BaselineECDSA | two | 0.341 | 0.452 | 0.793 |
| Inet80211SHA3 | one | 0.417 | 11.455 | **11.871** |
| InetMobilityLinearSHA3 | one | 0.425 | 11.716 | 12.141 |
| InetMobilityRandomWalkSHA3 | one | 0.408 | 11.483 | 11.891 |
| ArbiterPuf | two | 1.274 | 1.074 | 2.348 |
| HighNoise | two | 1.057 | 0.856 | 1.913 |
| NoiseSweep | two | 2.069 | 0.917 | 2.986 |

`two` = two clocks, so reported is compute + network. `one` = one clock, so reported is
measured wall time and network is derived.

Two readings worth noting. **Compute is flat** (0.34–0.57 ms, apart from the
hardware-oriented spongent profile) across swarm size, motion, and even the real MAC.
**Network dominates wherever the channel is real.** Optimising crypto cannot improve
the 802.11 number, because that number is the channel, not the protocol.

Phase 3 costs 0.417 ms per pair with 197 bytes of traffic, pooled across swarm sizes
(per-pair cost does not grow with N; only the pair count does). Over real 802.11 all
45 pairs of a ten-drone swarm complete.

### Reliability and security

| Check | Result |
|---|---|
| Phase 2, idealised, both profiles | 300/300 |
| Phase 3, idealised, N=20 | 11,362/11,382 views |
| Phase 2 over real 802.11 | 300/300 |
| Phase 3 over real 802.11 | 2700/2700 peer views |
| ArbiterPuf at 3% PUF error | 300/300 devices |
| HighNoise at 5% PUF error | 239/300 devices |
| Reliability sweep | all 21 points within the binomial prediction |
| Forged GS, full protocol | 0 replies from 40 attempts |
| Forged GS, control arm | 5/40 succeed, as designed |
| Replay, credential sniffing | 0 accepted |
| Unit tests | 12 suites pass |

A device that cannot reproduce its key does not authenticate *incorrectly* — it never
transmits at all, so noise degrades availability, not security.

### Reproducing a number

```bash
python3 scripts/validate_for_papers.py
```

Recomputes every headline figure straight from the CSVs and prints it with its
interval.
