# REPORT4.md — Full Status: Theory, Implementation, Results, and What Genuinely Remains

This supersedes `REPORT3.md`. That report tracked six future-work items as
outstanding; **all six are now built, measured, and folded into
`final_theory/paper.tex`.** This document restates the full picture in one
place: what was already fixed before this round, what got added this round,
the real numbers behind each addition, and the honest list of what's left.

For the plain-language version, see `WHAT_I_DID.md`. For the full theory +
implementation + results reference, see `COMPLETE_ANALYSIS.md`. This report
is the status/tracking layer between them.

---

## Part A — Everything from `REPORT.md` / `report2.md`. Still all fixed.

No regressions from the prior audits. Carried forward unchanged from
`REPORT3.md`:

| Flaw | Status |
|---|---|
| Unkeyed GS→UAV auth (fake signing) | ✅ Fixed — every message is a keyed MAC |
| PUF read-out oracle via fake GS | ✅ Fixed — verify-before-respond, no oracle |
| Swarm-wide plaintext credential | ✅ Fixed — per-pair `Cred_ij`, AEAD-wrapped |
| No forward secrecy / silent no-DH path | ✅ Fixed — mandatory X25519, fails closed |
| Wrong helper-data entropy claim | ✅ Fixed — correct min-entropy bound + proof |
| CRP exhaustion / unauthenticated M1 | ✅ Fixed — stable regenerable key, no CRP pool |
| Phase-3 reflection/key-confusion | ✅ Fixed — type tags, nonces, separate KDF labels |
| Informal/false security proofs | ✅ Fixed — 9 theorems/lemmas via standard reductions |
| BCH decode broken (identity function) | ✅ Fixed — real BCH, 18,000/18,000 trials pass |
| "Arbiter PUF" was actually a PRNG | ✅ Fixed — real additive-delay model, actually used |
| SPONGENT non-spec | ✅ Fixed — byte-exact vs. reference implementation |
| ECDH dead code, no PFS | ✅ Fixed — X25519 mandatory, `erase()` called |
| Circular GS token check | ✅ Fixed — real MAC verify, not self-referential |
| n=1, no statistics | ✅ Fixed — now **30 seeds**, two-stage CI, Wilson intervals |
| Cross-platform speedup claims | ✅ Fixed — same-platform RSA/ECC re-measured |
| "100% success" statistically vacuous | ✅ Fixed — Wilson score intervals everywhere |

---

## Part B — The six items this round closed out

`REPORT3.md`'s "what is left" list had 10 items. The user selected six to
build, in a deliberately chosen order (mobility → INET → energy → 30-seed
re-run → number audit → RSA/ECC baseline, so the expensive full campaign ran
exactly once against the complete, final set of configs). All six are done.

### B.1 Re-run the campaign at 30 seeds

**Before:** `omnetpp.ini` said `repeat = 30`; every CSV backing the paper had
only 10 runs — an export script had silently limited every config to
`--runs 10`.

**Now:** every main config (`StadiumSHA3`, `StadiumSPONGENT`, `Baseline5UAV`,
`Swarm20`, `ArbiterPuf`, `HighNoise`, plus the new `MobilityLinear`,
`MobilityRandomWalk`, `BaselineRSA`, `BaselineECDSA`) has a real 30 `.sca`
files on disk; the four attack configs have their full 5 reps each. Verified
directly: `ls simulations/results/StadiumSHA3-*.sca | wc -l` → 30, same for
every other main/mobility/baseline config; attack configs → 5 each.

### B.2 Systematic number audit

`scripts/audit_paper_numbers.py` recomputes every CSV-derived table and prose
figure in `final_theory/paper.tex` straight from the current CSVs via the
same statistics engine (`stats_util.py`) that built them, and prints
canonical values to check against the typeset text. It now covers every
table including the three new ones (mobility, INET, energy) and the new
baseline-comparison table. Re-running it (see the raw output block below)
shows no `"ten independent repetitions"` / `"ten runs"` text remaining
anywhere in `final_theory/paper.tex` — every repetition-count reference in
the paper now says 30 (main configs) or 5 (attacks).

### B.3 Real full RSA/ECDSA protocol baseline (not just bare primitives)

**Before:** the RSA/ECC comparison pitted this protocol's full 4-message
simulated handshake (nonces, network delay, replay cache, mandatory PFS)
against RSA/ECDSA's *isolated* `sign()`/`verify()`/`derive()` calls — not a
fair fight, and `REPORT3.md` flagged this explicitly as "only half-fair."

**Now:** a real competing protocol, `BaselineSigAuth` (RSA-signed and
ECDSA-signed ephemeral X25519), built with its own `Sign`/`Verify` primitive
counters, run through the identical `WirelessMedium`, same instrumentation,
same 30 seeds, as `[Config BaselineRSA]` / `[Config BaselineECDSA]`:

| Protocol | End-to-end | Realistic (compute+net) | Overhead | Success |
|---|---|---|---|---|
| This work (sha3) | 1.5028 ± 0.0023 ms | 2.60 ms | 777 B | 300/300 |
| RSA-signed baseline | 1.4042 ± 0.0023 ms | 2.05 ms | 703 B | 300/300 |
| ECDSA-signed baseline | 0.9109 ± 0.0023 ms | 0.83 ms | 330–335 B | 300/300 |

Read honestly, this protocol is **~3× slower end-to-end than same-platform
ECDSA** — the PUF-reading step is a real cost ECDSA never pays. The paper's
selling point is correctly framed as the *property* (no stored secret to
steal on capture), not raw speed.

### B.4 Real 802.11/INET MAC contention

**Before:** `WirelessMedium` modeled one shared delay path with zero
collisions or retransmissions — an admitted lower bound, not a realistic
figure.

**Now:** a separate build (`src_inet/`, own executable, own
`omnetpp_inet.ini`, deliberately isolated from the trusted plain build per
the original plan's build-isolation rule) runs the identical Phase-2
handshake over INET's real ad-hoc 802.11 stack — genuine CSMA/CA, retries,
collisions:

| Config | Handshake latency | Success |
|---|---|---|
| Inet80211SHA3 | 11.722 ± 0.408 ms | 298/300 (99.3%) |
| Inet80211SPONGENT | 11.744 ± 0.409 ms | 298/300 (99.3%) |

That's roughly **8× the idealized-delay figure** (1.503/1.508 ms), and 2 of
300 attempts genuinely fail from MAC-layer contention rather than protocol
logic. Scoped deliberately to Phase-2 latency/throughput only — static
positions, no attacker track on this track, exactly as the original plan
required (porting the attacker's `sendDirect`-based interception model onto
INET's real gate/channel topology was explicitly out of scope).

### B.5 UAV mobility model

**Before:** drones were static perimeter points; no waypoint/mobility
evaluation.

**Now:** `MobilityLinear` (constant velocity, boundary bounce) and
`MobilityRandomWalk` (new random heading every tick), both at 30 seeds:

| Model | Mean distance travelled | Phase-2 latency |
|---|---|---|
| Linear | 2,398.7 m | 1.5026 ± 0.0023 ms |
| Random walk | 2,396.2 m | 1.5028 ± 0.0023 ms |

Latency is unchanged from the static case, because `WirelessMedium` reads
each drone's position fresh on every call — motion doesn't break anything
structurally. This does not model Doppler, fading, or range-based dropout;
that's stated as scope, not hidden.

### B.6 Energy/power model

**Before:** no energy/power/nJ figures anywhere — only two qualitative,
literature-cited gate-equivalent sentences.

**Now:** `scripts/energy_model.py` + `scripts/export_energy_csv.py` produce
`omnet_energy_costs.csv`, converting measured primitive timings to energy via
cited literature constants, with every row explicitly tagged
`measured-derived` or `estimate:lit` so provenance is never ambiguous:

| Cost | Value | Source |
|---|---|---|
| X25519 keygen+derive (one side) | 10.28 mJ / handshake | estimate:lit |
| Radio TX+RX, one UAV, N=10 (StadiumSHA3) | 214.03 µJ / handshake | measured-derived |
| Radio TX+RX, one UAV, N=5 | 147.50 µJ / handshake | measured-derived |
| Radio TX+RX, one UAV, N=20 | 347.09 µJ / handshake | measured-derived |

The finding that matters: **X25519, not the PUF read or the radio, dominates
energy cost** — by roughly 50× over the radio figure at N=10. That directly
informs where a real embedded deployment should focus power-optimization
effort.

---

## Part C — Raw audit output (grounding for every number above)

Captured from `python3 scripts/audit_paper_numbers.py`, run against the final
30-seed CSVs, immediately before this report was written:

```
tab:functional -- Authentication outcomes
  StadiumSHA3      n_runs=30  devices=300   auth=300   rate=1.000
  StadiumSPONGENT  n_runs=30  devices=300   auth=300   rate=1.000
  Baseline5UAV     n_runs=30  devices=150   auth=150   rate=1.000
  Swarm20          n_runs=30  devices=600   auth=600   rate=1.000
  ArbiterPuf       n_runs=30  devices=300   auth=298   rate=0.993
  HighNoise        n_runs=30  devices=300   auth=247   rate=0.823

tab:latency -- Phase-2 latency and overhead
  StadiumSHA3      end-to-end=1.5028 +/- 0.0023  overhead=777 B
  StadiumSPONGENT  end-to-end=1.5082 +/- 0.0023  overhead=781 B
  Baseline5UAV     end-to-end=1.1442 +/- 0.0039  overhead=507 B
  Swarm20          end-to-end=2.2221 +/- 0.0023  overhead=1317 B

Phase-3 per-pair latency, pooled (N=120 runs): 0.4167 +/- 0.0006 ms

tab:attacks
  AtkGsImpersonate         accepted=0/40   expected=No   matched
  AtkLegacyGsImpersonate   accepted=5/40   expected=Yes  matched (the ablation control)
  AtkReplayM1              accepted=0/5    expected=No   matched
  AtkCredentialSniff       accepted=0/50   expected=No   matched

mobility
  linear      distance=2398.7 m  latency=1.5026 +/- 0.0023 ms
  randomwalk  distance=2396.2 m  latency=1.5028 +/- 0.0023 ms

INET/802.11
  Inet80211SHA3       latency=11.722 +/- 0.408 ms  success=298/300
  Inet80211SPONGENT   latency=11.744 +/- 0.409 ms  success=298/300

baseline comparison
  BaselineRSA     end-to-end=1.4042 +/- 0.0023  success=300/300
  BaselineECDSA   end-to-end=0.9109 +/- 0.0023  success=300/300

Prose repetition-count check: no remaining "ten runs"/"ten repetitions" text.
```

Re-run this script (no arguments) any time the CSVs change — it's the fast,
mechanical way to check "does the paper still say what the data says"
without a manual re-read.

---

## Part D — What genuinely remains

Everything security-critical was closed out before this round. Everything
future-work-shaped that was scoped for this round is now done. What's left
is the four `REPORT3.md` items the user explicitly deferred:

| # | What's left | Why it matters | Effort |
|---|---|---|---|
| 1 | **Run the Tamarin proof for real** | The six symbolic properties (injective agreement, no-replay, capture-isolation, key-secrecy, forward-secrecy) are described in the paper as a model; no `.spthy` file exists, nothing has actually been machine-verified | High |
| 2 | **Dedicated DoS/flooding evaluation** | Only replay and impersonation were attack-tested; no message-flooding, rate-limiting, or nonce-cache-exhaustion study | Medium |
| 3 | **ML-modeling-attack curve for the PUF** | No plot of modeling-attack accuracy vs. number of CRPs to bound how learnable the Arbiter-PUF model is | Medium |
| 4 | **Reproducibility artifact** | No Dockerfile, no DOI, no one-command "build+run+regenerate everything" packaging | Medium |

Plus, unchanged from before: no FPGA/real-hardware prototype, and no
timing/power side-channel analysis of the two hand-written primitives (both
stated as scope limitations in the paper, not hidden gaps).

---

## Bottom line

- **All theory and implementation flaws (`REPORT.md`, `report2.md`) remain
  fixed.** No regressions.
- **All six items this round's plan targeted are done and measured**: 30-seed
  campaign, systematic number audit, real RSA/ECDSA full-protocol baseline,
  real 802.11/INET contention, UAV mobility, and a derived energy model — all
  folded into `final_theory/paper.tex`, which compiles clean (31 pages, no
  LaTeX errors, only pre-existing cosmetic underfull-hbox warnings).
- **Four items remain, all explicitly deferred by the user, none
  security-critical:** Tamarin proof execution, DoS/flooding study, ML-
  modeling-attack curve, reproducibility artifact.
- The headline honest story is unchanged in spirit but now backed by more
  evidence: this is not the fastest protocol on the table (~3× slower than
  same-platform ECDSA, ~8× slower again under real MAC contention) — its
  case is that no secret is ever stored on the drone, and that's a property
  speed comparisons can't capture.
