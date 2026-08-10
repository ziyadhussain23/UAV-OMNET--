# Paper Summary — Fast Authentication Between UAVs

One-stop, honest summary of `final_theory/paper.tex` plus the implementation and
results behind it. Nothing important skipped, nothing padded.

## The one-paragraph idea

Drones normally prove their identity with a stored private key — steal the drone,
steal the key. This protocol instead derives the key from a PUF (a chip's own
manufacturing fingerprint) every time it's needed, so nothing secret ever sits in
the drone's memory. Four phases: enroll once, authenticate to the ground station,
authenticate peer-to-peer without the ground station, derive session keys with
forward secrecy.

## The protocol, phase by phase

1. **Enrollment (once, offline).** GS reads the PUF at L challenge points, runs a
   fuzzy extractor (BCH(255,131,18) code-offset construction) to turn the noisy
   reading into a stable master key `mk_i`. GS keeps `mk_i`; the drone keeps only
   public stuff — its challenge, helper data, temporary ID. Nothing secret on the
   drone.
2. **UAV↔GS mutual auth, 4 messages (M1–M4).** Every message is a keyed MAC under
   a key derived from `mk_i`. The drone verifies the GS's MAC (M2) *before* doing
   anything else — this one rule is what stops a fake GS from using the drone as
   an oracle to harvest PUF responses. M4 delivers each drone's peer credentials,
   encrypted, plus a rotated ID.
3. **UAV↔UAV peer auth, 3 messages (P1–P3), no GS needed.** Uses a per-pair
   credential `Cred_ij` (not one swarm-wide secret), so capturing one drone only
   burns that drone's own N−1 links, not the whole swarm.
4. **Session keys + forward secrecy.** Both phases end in the same KDF shape:
   `KDF(long-term-key || ephemeral-DH-secret || transcript)`. The DH exchange
   (X25519) is mandatory and scalars are erased after use — that's what gives
   forward secrecy: a later key leak can't unlock past sessions.

## Security proof

Nine design goals stated up front (mutual auth, anonymity, replay/MITM
resistance, no stored secret, GS-free peer auth, mandatory PFS, lightweight ops,
scalability, noise tolerance). Backed by **six theorems + one lemma + one
corollary**, each a reduction to a standard assumption (EUF-CMA MAC, IND-CCA/
INT-CTXT AEAD, gap-CDH, PUF unpredictability):

- Helper-data privacy (how much the fuzzy extractor's public data can leak)
- Phase-2 mutual authentication
- No PUF read-out oracle (the corollary that makes verify-before-respond matter)
- Replay resistance
- Phase-3 peer mutual authentication
- MITM resistance
- Session-key secrecy
- Perfect forward secrecy
- Physical capture resistance (blast radius = N−1 links, not the whole swarm)

The paper also describes a Tamarin symbolic model mirroring these six properties
— **this model is described but not actually built or run** in this codebase.
Flagged honestly in the paper's own limitations, but it's the one claim that
needs fixing before submission (see `PUBLICATION_REVIEW.md`).

## Implementation

Clean split: `src/protocol/` has zero dependency on the OMNeT++ simulator — it's
plain C++ that could run on real hardware unchanged. `src/nodes/` is the
simulation wiring around it.

- **`core/`** — one canonical byte encoder used for wire format, MAC input, and
  byte-counting simultaneously, so those three can never disagree.
- **`crypto/`** — two interoperable suites behind one interface: `sha3`
  (SHA3-256/HMAC/HKDF/ChaCha20-Poly1305, software-oriented) and `spongent`
  (SPONGENT-160/keyed-sponge/Ascon-128a, hardware-oriented). Both use X25519 for
  the ephemeral exchange. HMAC doesn't work with SPONGENT's 2-byte rate, so the
  sponge suite uses a keyed-sponge MAC instead — stated as an explicit 80-bit
  profile, not silently downgraded.
- **`fe/`** — the BCH decoder and fuzzy extractor. The entropy budget
  (`L(ρn − (n−k)) ≥ ℓ + 2log(1/ε)`) is a runtime assertion, not just a paper
  formula — it refuses to start if under-provisioned. Fails closed: no key
  returned if decoding fails, never a partial/uncorrected one.
- **`puf/`** — three PUF models: an idealized PRF stand-in, a 128-stage arbiter
  model with noise applied to the actual timing race (not by flipping bits
  randomly — this reproduces the real reliability profile of silicon), and an
  XOR-arbiter variant.
- **`nodes/`** — `UavNode`, `GroundStationNode`, `WirelessMedium` (the one shared
  link-delay model, and the attacker's interception point), `AttackerNode`.

**Verification:** 12 test suites (grew from the paper's stated "nine" — a stale
count worth fixing), ~430k assertions. Every primitive checked against published
reference values: FIPS 202, RFC 5869, RFC 8439, RFC 7748, all 1,089 official
Ascon-128a KAT vectors, and SPONGENT byte-exact against the designers' own
reference code (no official KAT exists for SPONGENT — stated openly, not
glossed over).

## The 17 evaluation scenarios — what each one actually tests

Every scenario changes exactly one variable off the `StadiumSHA3` reference
point, so results are attributable, not confounded:

| Family | Scenarios | What it isolates |
|---|---|---|
| Reference + suite | StadiumSHA3, StadiumSPONGENT | default cost, cost of the hardware-oriented suite |
| Scaling | Baseline5UAV (N=5), StadiumSHA3 (N=10), Swarm20 (N=20) | does per-pair cost stay flat as N grows |
| Reliability | ArbiterPuf (realistic PUF model), HighNoise (5% BER), NoiseSweep (1–10% BER × 3 FE profiles) | does the BCH decoder genuinely correct errors |
| Deployment realism | MobilityLinear/RandomWalk, Inet80211SHA3/SPONGENT | does motion or real 802.11 contention break anything |
| Baselines | BaselineRSA, BaselineECDSA | fair full-protocol speed comparison |
| Security | AtkGsImpersonate, AtkLegacyGsImpersonate (ablation control), AtkReplayM1, AtkCredentialSniff | do attacks fail, and is the attacker code itself proven to work |

## Results — the numbers that matter

All at **30 repetitions** per config (5 for attacks), two-stage confidence
intervals (run-level, not record-level), Wilson intervals for proportions.

**Functional correctness.** Idealized PUF model: 100% authentication in every
config, including all 11,400 peer pairs at N=20. Realistic arbiter model at 3%
BER: 99.3%. Forced 5% BER: 82.3% — a real, disclosed reliability limit, not
hidden behind "100% success."

**Phase-2 handshake (message-by-message):**

| Message | What happens | sha3 (ms) | spongent (ms) | Net (ms) | Size (B) |
|---|---|---|---|---|---|
| M1 | UAV: PUF eval + Rep + MAC σ1 | 1.433 | 1.989 | 0.255 | 104 |
| M2 | UAV verifies GS's MAC (the oracle-blocking gate) | 0.080 | 1.168 | 0.230 | 85 |
| M3 | UAV: MAC σ3 | 0.080 | 1.168 | 0.174 | 43 |
| M4 | GS: AEAD-seal credential package | 0.010 | 0.128 | 0.843 | 545/549 |

M1 dominates because the PUF read (69–71% of its own compute time) has to
happen before M1 can even be sent — the paper's own spec implies it happens
later, at M3, but that's not realizable since M1's MAC needs the key already.
Network delay is suite-independent; the suite gap is almost entirely a compute
cost, concentrated in M2/M3 where one MAC call runs in isolation.

**Phase-3 peer handshake:** 0.417 ms (sha3) pooled across all swarm sizes,
genuinely flat with N — the O(N²) total cost comes from pair count, not
per-pair cost. No PUF touch at all in Phase 3, which is why it's ~3× cheaper
than Phase 2.

**Primitive-level cost, same host, same OpenSSL:**

| Op | sha3 (ours) | spongent (ours) | RSA-2048 | ECDSA-P256 |
|---|---|---|---|---|
| MAC | 2.2 µs | 228.3 µs | — | — |
| Sign/verify | — | — | 1048.6 / 32.0 µs | 43.6 / 109.0 µs |
| X25519 keygen+derive | ~190 µs | ~190 µs | — | — |

Own symmetric primitives are cheaper than every RSA/ECC operation, by an order
of magnitude. The mandatory X25519 exchange is *comparable* to ECDH/ECDSA, not
faster — that's the honest cost of forward secrecy being non-optional.

**Full-protocol baseline comparison (the fair fight, not primitive vs.
primitive):**

| Protocol | Compute+Net total | Success |
|---|---|---|
| ECDSA-signed baseline | 0.83 ms | 300/300 |
| RSA-signed baseline | 2.05 ms | 300/300 |
| This work (sha3) | 2.68 ms | 300/300 |
| This work (spongent) | 5.53 ms | 300/300 |

**~3.2× slower than ECDSA, close to RSA.** The paper states this plainly in the
abstract rather than hiding it — the sell is "no stored secret," not speed.

**Reliability sweep:** 20 of 21 measured failure-rate points across 1–10% BER
land inside the binomial prediction's 95% CI, across four orders of magnitude —
the strongest evidence in the paper that the BCH decoder is actually correcting
errors and not just passing input through. The paper's own claimed "<10⁻¹⁵
failure rate" isn't reachable with the default single-layer code (measured
~1.2×10⁻³ at 3% BER); a triple-redundant profile reaches it at 3× PUF cost.

**Real 802.11 contention (INET track):** 11.7 ms vs 1.5 ms idealized — a 7.8×
gap, disclosed as the honest cost of MAC-layer contention the primary model
can't show. Scoped to Phase-2 only, static positions, no attacker (structurally
can't port the attacker's interception model onto INET's real topology).

**Mobility:** constant-velocity and random-walk motion both leave latency
unchanged (~1.5 ms) — a single handshake is too fast for ~1 cm of travel to
matter against a 500×300 m field. Confirms motion doesn't break anything
structurally; doesn't claim more than that.

**Energy:** X25519 costs ~10.3 mJ per handshake side vs ~214 µJ of radio energy
— the ephemeral DH exchange dominates energy cost by ~50×, not the PUF or the
radio. Every figure tagged `measured-derived` or `estimate:lit` so provenance
is never ambiguous.

**Attacks (with a negative control):** 0/40 forged GS messages accepted, 0/5
replays accepted, 0/50 credential reads succeeded — against the real protocol.
Against a deliberately weakened ablation (verify-before-respond disabled), the
*same* attacker code succeeds 5/40 times. That's the falsifiability check: the
zeros above are evidence the attacker works, not evidence of a broken
adversary.

## What's genuinely good

Falsifiable security evaluation (the ablation control), correct two-stage
statistics, honest "we're slower, here's why" framing instead of a dressed-up
speed claim, a reliability curve that actually validates the decoder, primitives
checked against real test vectors, and 8 explicitly documented deviations from
the paper's literal spec (`docs/spec-deviations.md`) rather than silent patches.

## What's still open

No Tamarin `.spthy` file exists — the symbolic-verification claim in the paper
needs either a real model or a reworded sentence before submission. No ML
modeling-attack curve for the PUF. No revocation mechanism for a captured
drone's credentials. No hardware PUF validation — everything rests on simulated
models. Full detail and a submission roadmap are in `PUBLICATION_REVIEW.md`.
