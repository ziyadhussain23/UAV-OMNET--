# Report: What Changed and Why

Everything done to this project, in order, in plain language. Read top to bottom:
what was wrong, what was fixed, what was added, and what the numbers say now.

Companion documents: `README.md` (how to run it, how it works), `CLAUDE.md` (notes
for AI assistants), `docs/spec-deviations.md` (where the code and the paper differ).

---

## Part 1 — Fixing the broken protocol

### 1.1 The problem

The original paper described a good idea: drones that prove who they are without
storing a secret, by using a **PUF** (a chip whose manufacturing imperfections make
it a unique fingerprint in silicon). The implementation did not do what the paper
claimed. Three faults made the security story false:

| Fault | What it meant |
|---|---|
| Messages were "signed" by hashing public values | Anyone could compute the same value. The locks had no keys in them. |
| A drone never checked the ground station was real | An attacker could pose as the GS and make a drone run its PUF repeatedly, harvesting answers until they could clone the fingerprint. |
| The error-correcting code did nothing | It returned the noisy input unchanged while reporting success. The system "worked" only because a loose check let it through. |

Also: results came from one simulation run each (no error bars), and the speed
comparison put laptop timings against numbers from much slower hardware.

### 1.2 What was done

The old tree was archived to `old_implementation/` and a fresh implementation was
written against the corrected specification. Work was staged, and **each stage had
to pass its test before the next began**, which is why faults surfaced early rather
than inside a published number.

**Fixes, in the order they were made:**

1. **Real keyed authentication.** Every message now carries a MAC computed with a
   key only the real device (via its PUF) or the ground station has. Forging one is
   a cryptographic break, not a copy-paste.

2. **Verify-before-respond.** The drone checks the ground station's authenticator
   *before* doing any PUF work. A forged message gets no reply at all, so there is
   no oracle to harvest. Confirmed by running the attack: 0 replies from 40 forged
   messages, while the same attacker succeeds 5/40 when the check is removed.

3. **Real error correction.** BCH(255,131,18) built from the conjugate closure of
   its roots, so the generator really has degree 124. It corrects up to 18 flipped
   bits and fails loudly beyond that instead of miscorrecting.

4. **Per-pair credentials.** Instead of one secret shared by the whole swarm, each
   drone pair gets its own, delivered inside authenticated encryption. Capturing a
   drone now exposes only that drone's own links.

5. **Mandatory forward secrecy.** Every session mixes in an ephemeral X25519
   exchange, and the scalars are erased afterwards. There is no code path that
   skips it. A later key compromise cannot unlock past sessions.

6. **Proper statistics.** Thirty independent repetitions per configuration, each
   with its own seed, and two-stage confidence intervals (per-run mean first, then
   across run means). One run cannot show a one-in-a-thousand failure.

7. **Honest comparisons.** RSA and ECDSA baselines were implemented and run through
   the same simulator, same host, same OpenSSL, instead of quoting other papers'
   numbers from different hardware.

---

## Part 2 — Making the PUF fast

### 2.1 The problem

The simulated PUF was the slowest thing in the protocol: **1.15 ms** per handshake,
about 72% of all Phase-2 compute time. That is backwards. A real PUF answers in
nanoseconds; the simulation was reporting an artefact of its own loop.

The loop was doing this, for each of 1020 response bits:

1. a full SHA3-256 to build a question,
2. a full HMAC-SHA3-256 to get an answer,
3. keep **one bit** of that answer and discard the rest.

Two thousand hash calls to produce 128 bytes.

### 2.2 What was done

**One keyed call instead of 2040.** The whole response is now a counter-mode
HMAC-SHA3-256 stream:

```
block_n = HMAC-SHA3-256(deviceKey, label ‖ challenge ‖ n)   for n = 0, 1, 2, ...
response = block_0 ‖ block_1 ‖ ...   truncated to the bit count
```

Four calls cover a 1020-bit response. Same security (it is still a keyed PRF per
device, with independent uniform output bits), a fraction of the work.

**Noise without a draw per bit.** The Bernoulli coin flip now comes from two DRBG
bytes compared against a 16-bit threshold, instead of a floating-point draw per
bit. Same distribution, ~5x cheaper.

**The arbiter model got the same treatment.** All sub-challenges now come from one
SHA3-256 counter-mode stream instead of one hash per bit, and the delay sum reads
from that stream directly.

### 2.3 Result

| | Before | After |
|---|---|---|
| PUF evaluation per handshake | 1.153 ms | **0.043 ms** (27x faster) |
| Phase-2 compute | 1.602 ms | **0.569 ms** |
| Phase-2 realistic total (compute + network) | 2.68 ms | **1.643 ms** |
| vs RSA-2048 handshake (1.767 ms) | slower | **faster** |
| vs ECDSA handshake (0.793 ms) | 3.2x slower | 2.1x slower |

The RSA comparison **flipped in this project's favour**. The remaining gap to
ECDSA is almost entirely the mandatory X25519 exchange, which is the deliberate
price of forward secrecy, and the paper already discloses it.

---

## Part 3 — One CSV per question

### 3.1 The problem

Every CSV contained every configuration. `omnet_phase2_results.csv` mixed the
reference runs, the reliability runs, the mobility runs, and the attack runs, so
"average latency" silently depended on which rows you happened to filter. Attack
timings sat beside normal timings; mobility positions appeared in the latency file.
Reading a table meant filtering by hand, which is how transcription errors get into
a paper.

### 3.2 What was done

Each file now answers exactly one question, and the routing lives in one place in
`scripts/export_omnet_csv.py`:

| File | Contains only |
|---|---|
| `omnet_phase1/2/3_results.csv`, `omnet_summary*.csv` | StadiumSHA3, StadiumSPONGENT, Baseline5UAV, Swarm20 |
| `omnet_noise_results.csv` | ArbiterPuf, HighNoise, NoiseSweep |
| `omnet_security_results.csv` | the four `Atk*` configs, outcomes only, no timings |
| `omnet_baseline_results.csv` | BaselineRSA, BaselineECDSA |
| `omnet_inet_latency.csv` | the three INET configurations |
| `omnet_comparison.csv` | one row per config, every family side by side |

### 3.3 Benefit

A number can no longer be accidentally averaged with a row it does not belong with.
`scripts/validate_for_papers.py` recomputes every headline figure from these files
and reports nothing missing.

---

## Part 4 — Making mobility meaningful

### 4.1 The problem

Mobility was measured on the idealised medium, where the only thing motion changes
is propagation delay. Over a 500 m field that is nanoseconds, and a handshake
finishes in 1.5 ms during which an 8 m/s drone moves about 1.2 cm. The measurement
was a null result **by construction** — it could not have shown anything else.

### 4.2 What was done

Mobility was moved to the INET track, where a real IEEE 802.11 stack computes
received power and SNIR from live positions. Motion there changes the actual
channel: range, contention, and backoff all respond to distance. The idealized
track's mobility code and configurations were deleted rather than kept as a
non-finding.

### 4.3 What it cost the paper

Table `tab:mobility` in `final_theory/paper.tex` reported the old null result. That
section now needs to point at the INET mobility numbers instead.

---

## Part 5 — Peer authentication over a real radio

### 5.1 The problem

Phase 3 (drone-to-drone authentication) had only ever run over the idealised
medium. Its selling point is that it is light — three short MAC messages, no PUF —
but it had never met real contention.

### 5.2 What was done

Phase 3 was ported to the INET track, running over the same UDP/802.11 stack as
Phase 2. Two bugs had to be fixed first, both silent:

1. **Identity loss.** Phase 3's second and third messages carry no identity field
   on the wire; they rely on the transport saying who sent them. The in-process
   transport did this for free; INET does not. Recovering the sender from its L3
   address does not work either, because a host has several addresses and the
   routed source is not the one the resolver returns. Fixed by giving each drone
   its own port (`peerBasePort + uavId`), so a datagram's source port names its
   sender exactly. This is what a real peer-to-peer service does.

2. **A bind-order race.** Each drone's port was assigned in `initialize()`, but
   INET can call `handleStartOperation()` before that runs. All ten drones bound
   port 9300; nine binds failed and every peer packet drew ICMP
   destination-unreachable. Fixed by computing the port at bind time.

   Related: `*.uav[*].app[0].uavId = index` in the ini silently gave every app `0`,
   because with two wildcards `index` binds to the innermost one. The device id now
   comes from its own index in `uav[]`.

### 5.3 Result

All 45 pairs in a ten-drone swarm now complete over real 802.11: 2700/2700 peer
views, 300/300 Phase-2 handshakes.

---

## Part 6 — Separate compute from network

### 6.1 Why this matters

Compute is what you can improve. Network is the environment. Reporting one number
hides which you are paying for.

The subtlety is that the two tracks use **different clocks**:

* **Idealised medium — two clocks.** Compute is host wall-clock; network is the
  simulator's delay model. The simulated clock does not advance while crypto runs,
  so "simulated elapsed" is close to network time and is *not* a total. The honest
  total is compute + network.
* **INET and the signature baselines — one clock.** Everything runs on the
  simulation clock, so measured end-to-end wall time already contains the crypto
  inline. The honest total is wall time, and network is derived as `wall − compute`.

Adding the two families together without saying which clock is in use is the
easiest way to publish a wrong comparison.

### 6.2 What was done

INET now records compute from the protocol's own timers and derives network as
`wall − compute`, flagged `net_ms_derived = 1` so a derived value is never mistaken
for a measurement. `omnet_comparison.csv` reports `reported_latency_ms` as
compute + network for two-clock rows and wall for one-clock rows, with a
`clock_model` column stating which.

### 6.3 What it shows

| config | family | clock | compute | net | reported |
|---|---|---|---|---|---|
| StadiumSHA3 | latency | two | 0.569 | 1.074 | **1.643** |
| Baseline5UAV | latency | two | 0.458 | 0.714 | 1.172 |
| Swarm20 | latency | two | 0.487 | 1.790 | 2.277 |
| BaselineRSA | baseline | two | 1.069 | 0.699 | 1.767 |
| BaselineECDSA | baseline | two | 0.341 | 0.452 | 0.793 |
| Inet80211SHA3 | inet | one | 0.417 | 11.455 | **11.871** |
| InetMobilityLinearSHA3 | inet | one | 0.425 | 11.716 | 12.141 |
| InetMobilityRandomWalkSHA3 | inet | one | 0.408 | 11.483 | 11.891 |
| ArbiterPuf / HighNoise / NoiseSweep | noise | two | — | — | 2.348 / 1.913 / 2.986 |

The pattern is the point: **compute stays flat** (0.34–0.57 ms) across suite
choice, swarm size, motion, and even the real MAC. **Network swings from 0.45 ms
to 11.7 ms.** Optimising crypto cannot help the INET number, because the INET
number is the channel.

Motion now shows a measurable effect for the first time: linear motion costs
12.141 ms against 11.871 ms static, a real 0.27 ms of channel cost that the
idealised medium could not have revealed.

---

## Part 7 — Where things stand

### Verified

| Check | Result |
|---|---|
| Unit tests | 12 suites, all pass |
| Phase 2, idealised, sha3 | 300/300 |
| Phase 2, idealised, spongent | 300/300 |
| Phase 3, idealised (N=20) | 11,362/11,382 views |
| Phase 2 over real 802.11 | 300/300 |
| Phase 3 over real 802.11 | 2700/2700 peer views |
| Reliability sweep | all 21 points within the binomial prediction |
| Attacks | all outcomes match expectation, control arm succeeds as designed |
| Headline-figure check | `scripts/validate_for_papers.py` clean |

### Known limits, stated honestly

* **Reliability at 5% PUF error.** 239/300 devices authenticate. A device that
  cannot reproduce its key does not authenticate *incorrectly* — it never
  transmits at all. Availability degrades; security does not.
* **Default fuzzy-extractor profile.** Fails about once in a thousand at 3% PUF
  error. A stronger profile reaches far lower but costs three times the PUF bits.
* **Entropy rate.** The default assumes a 0.95 min-entropy rate; measurements at
  1000 devices support about 0.854. Either cite a larger measurement or use the
  stronger profile.
* **Peer rows on INET** carry compute but no wall time, because the protocol keeps
  no per-peer timestamp. Per-peer wall latency would need a small timer added.
* **No attacker track on INET.** The adversary model relies on a single
  interception point, which a real gate/channel topology does not have.

### Open, from the analysis

1. The enrollment challenge is fixed, so one observed PUF response compromises a
   device permanently. A small challenge pool per device would bound this.
2. Phase 3 uses permanent numeric ids on the wire, so the rotating identities
   delivered in Phase 4 go unused. Using them is close to free.
3. Per-pair credentials never expire. Making them epoch-bound would bound a
   capture's future damage and give a revocation mechanism.
4. The replay cache records a nonce before verifying its MAC, so it can be flooded
   and poisoned. Moving one line fixes it.
5. The master key stays in RAM for the whole session instead of being wiped after
   use, which a cold-boot attack can read.

### Documentation

The paper's tables were computed from the earlier mixed CSVs. They need re-reading
from the per-topic files. The analysis behind the open items above was recorded in
a prior document that has since been folded into this one.
