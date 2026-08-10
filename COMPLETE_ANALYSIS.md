# COMPLETE_ANALYSIS.md — The whole project, start to finish

This is the single document meant to cover **everything**: the theory (every
formula, every named theorem), the implementation (what each file does and
why), every measured result, every test scenario, every attack, and the honest
gaps between what the paper claims and what the code actually does. Written so
someone with no prior context can read top to bottom and understand the whole
project — nothing assumed, nothing skipped.

Timing/scenario/attack numbers here are the same measured facts as in
`ANALYSIS.md`; this document adds the theory and implementation layers that
document didn't cover, and ties everything together in one place.

---

## Part A — The idea, in one paragraph

A drone (UAV) needs to prove to a ground station (GS) — and later, to *other*
drones — "I am who I claim to be," without carrying a secret key that could be
stolen if someone captures the drone. The trick: instead of storing a secret,
each drone has a **PUF** — a physical circuit whose behavior is a unique,
unclonable "fingerprint" nobody can predict or copy, not even the chip's own
manufacturer. The drone regenerates its key *from the chip itself* every time
it needs it, using a "fuzzy extractor" to turn the PUF's slightly noisy output
into an exact, repeatable secret. If someone steals the drone, they get a chip
that only works as itself — they can't extract a portable secret and use it
elsewhere. The protocol has four phases: **enroll** the drone once (offline),
**authenticate** it to the ground station, let two already-trusted drones
**authenticate to each other** without needing the GS in the loop, and
**derive a session key** for their actual encrypted traffic.

---

## Part B — Theory (what the paper claims, with the actual math)

### B.1 Threat model — what the attacker can and can't do

The adversary is a standard **Dolev-Yao network attacker**: it can read,
delete, delay, reorder, inject, and modify any message on the wireless link —
it fully controls the network. On top of that, the paper grants it three more
specific powers, and denies it a few specific ones:

- It can act as an **active challenger posing as the GS** — i.e. try to fool a
  real drone into thinking it's talking to the ground station.
- It can **physically capture a drone** and read out everything stored in its
  non-volatile memory (NVM).
- It is **computationally bounded** (PPT — probabilistic polynomial time): it
  cannot invert a cryptographic hash, forge a MAC or AEAD tag, predict a PUF's
  response, or solve the "gap-CDH" problem underlying the Diffie-Hellman
  exchange, except with negligible probability.

What it is **assumed not able to do**: it cannot invasively probe a captured
drone's PUF circuit itself (that destroys the PUF — this is the standard PUF
assumption; probing to clone it corrupts the exact silicon defects that make
it unique), and side-channel countermeasures are assumed already in place (the
paper does not itself analyze timing/power side-channels — see the honesty
notes in Part D).

### B.2 The nine design goals

The protocol is built to satisfy nine explicit requirements: (1) mutual
authentication in both directions between drone and GS, (2) anonymity via
rotating temporary IDs (so a drone's *real* identity isn't broadcast every
handshake), (3) resistance to replay and man-in-the-middle attacks (via
nonces, timestamps, and binding the whole message transcript together),
(4) **no long-term secret stored on the drone at all**, (5) drone-to-drone
authentication that works **without the ground station's involvement**,
(6) mandatory **perfect forward secrecy** (past sessions stay safe even if a
device is captured later), (7) being lightweight — one hash, one MAC, one
AEAD encryption, one KDF call, and one elliptic-curve operation per side,
(8) drone-to-drone authentication scales as **N(N−1)/2** pairs but each pair
runs independently/in parallel, and (9) tolerating **noisy** PUF readings via
error correction (BCH).

### B.3 Notation (the symbols used below)

| Symbol | Meaning |
|---|---|
| `UAV_i`, `GS` | a drone, the ground station |
| `ID_i` | the drone's permanent 64-bit identity (never broadcast after enrollment) |
| `TID_i` | a rotating temporary ID used instead, refreshed every handshake |
| `PUF_i`, **`C`**`_i` | the drone's physical fingerprint circuit, and the fixed challenge block given to it |
| `R` / `R'` | the PUF's response at enrollment time (clean) / at authentication time (noisy) |
| `FE = (Gen, Rep)` | the fuzzy extractor's two functions: Generate (enrollment) and Reproduce (every later authentication) |
| `P_i = (s_i, seed_i)` | the public "helper data" published at enrollment — doesn't reveal the key |
| `mk_i` | the drone's master key — regenerated from the PUF every time, **never stored** |
| `mk_GS` | the ground station's own long-term secret (kept in tamper-resistant storage at the GS only) |
| `Cred_ij` | a per-pair credential shared only between drones i and j, derived from `mk_GS` |
| `K^i_auth`, `K^ij_auth` | keys derived from `mk_i` / `Cred_ij` specifically for authenticating messages |
| `SK_i`, `SK_ij` | the final session keys (GS↔drone, drone↔drone) |
| `h(·)` | a 160-bit cryptographic hash |
| `MAC_K(·)`, `AE.Enc/Dec` | a keyed message-authentication tag, and authenticated encryption |
| `KDF(·; ℓ)` | a key-derivation function producing ℓ bits |
| `g`, `g^a`, `g^ab` | Diffie-Hellman generator and ephemeral public/shared values |
| `N_x`/`n_x`, `T_x` | 128-bit random nonces, 32-bit timestamps |
| `⊕`, `‖` | XOR, concatenation |

### B.4 Phase 1 — Enrollment (once, offline, over a trusted channel)

1. **PUF interrogation.** The GS queries the drone's PUF at `L` fixed
   challenge points: `R = (PUF_i(C_i^(1)), ..., PUF_i(C_i^(L)))`.
2. **Fuzzy-extractor Gen (code-offset construction).** Pick a random target
   key `r ← {0,1}^k`, encode it with an error-correcting code,
   `c = Encode(r)`, then publish the offset between the code word and the
   real PUF response: `s = R ⊕ c`. This `s` is safe to publish — it hides `r`
   as long as `R` has enough entropy left over (see Theorem B.6.1 below). The
   drone's master key is then `mk_i = KDF(Extract(R); "root")`. The public
   helper data is `P_i = (s, seed_i)`.
3. **Entropy budget.** For this to be safe, the paper requires:
   `Σ(m_b − (n−k)) ≥ ℓ + 2·log(1/ε)` — i.e., the total entropy left in the PUF
   response after subtracting what the published helper data leaks must still
   exceed the length of key you're trying to extract, plus a security margin.
   This inequality is checked (and will throw an error if violated) directly
   in the implementation's `FuzzyExtractor` constructor — it's not just a
   paper claim, the code refuses to run an under-provisioned configuration.
4. **Rotating ID setup.** `TID_i = h(ID_i ‖ seed_i')`. Per-pair credentials
   are pre-derived but not yet released: `Cred_ij = KDF(mk_GS; "pair-cred" ‖
   min(i,j) ‖ max(i,j))` — they get delivered to each drone (encrypted) later,
   during Phase 2.
5. **Who stores what.** The GS keeps everything: `{ID_i, TID_i, C_i, P_i,
   mk_i}` plus its own `mk_GS`, in tamper-resistant storage. **The drone
   itself keeps only `{TID_i, C_i, P_i}` — all public values. No secret at
   all lives on the drone.** That's the whole point of the design.

### B.5 Phase 2 — GS↔UAV mutual authentication (4 messages)

- **M1 (UAV→GS):** the drone picks a fresh nonce `N1` and an ephemeral DH
  scalar `a`, computes `σ1 = MAC_{K^i_auth}("M1" ‖ TID_i ‖ N1 ‖ T1 ‖ g^a)`, and
  sends `M1 = ⟨TID_i, N1, T1, g^a, σ1⟩`.
- **M2 (GS→UAV):** the GS checks freshness (timestamp window) and verifies
  `σ1`. It then picks its own nonce `N2` and scalar `b`, and replies with
  `σ2 = MAC(... "M2" ‖ TID_i ‖ N1 ‖ N2 ‖ T2 ‖ g^a ‖ g^b)`, sending
  `M2 = ⟨N2, T2, g^b, σ2⟩`.
- **M3 (UAV→GS):** the drone regenerates `mk_i = Rep(PUF_i(C_i), P_i)` —
  **but only after checking `σ2` is valid.** This "verify-before-respond"
  rule is the single most important line in the whole protocol (see
  Theorem B.6.3). If `σ2` doesn't check out, the drone silently aborts and
  says nothing. If it does, the drone sends `σ3 = MAC("M3" ‖ 𝒯)` where `𝒯`
  is every field sent so far in M1 and M2 — `M3 = ⟨σ3⟩`.
- **M4 (GS→UAV):** the GS derives the session key
  `SK_i = KDF(mk_i ‖ g^ab ‖ 𝒯; "p2-sess")`, packages a credential bundle
  `CredPkg = AE.Enc_{SK_i}(η; TID_i; {(Cred_ij, TID_j)})` (this is how each
  drone gets its per-pair credentials for Phase 3, delivered under
  authenticated encryption rather than sent in the clear), and rotates the
  drone's ID: `TID_i^new = h(TID_i ‖ mk_i ‖ N1 ‖ N2)`. It sends
  `M4 = ⟨CredPkg, TID_i^new⟩`.

### B.6 Phase 3 — UAV↔UAV peer authentication (3 messages, no GS)

Uses the pairwise key `K^ij_auth = KDF(Cred_ij; "peer-auth")` that both drones
received (encrypted) during their own Phase 2.

- **P1 (i→j):** `τ1 = MAC("P1" ‖ i ‖ j ‖ n_i ‖ T ‖ g^{a'})`, sent as
  `P1 = ⟨n_i, T, g^{a'}, τ1⟩`.
- **P2 (j→i):** j verifies `τ1`, then replies
  `τ2 = MAC("P2" ‖ i ‖ j ‖ n_i ‖ n_j ‖ g^{a'} ‖ g^{b'})`, sent as
  `P2 = ⟨n_j, g^{b'}, τ2⟩`.
- **P3 (i→j):** i verifies `τ2`, then sends the closing tag
  `τ3 = MAC("P3" ‖ 𝒯)` where `𝒯 = P1 ‖ P2`, as `P3 = ⟨τ3⟩`.

For `N` drones there are `N(N−1)/2` such pairwise exchanges total, and they're
all independent of each other — none has to wait for another.

### B.7 Phase 4 — Session-key derivation (one formula, two contexts)

Both Phase 2 and Phase 3 boil down to the same derivation:

```
SK = KDF(k_lt ‖ g^xy ‖ 𝒯; ℓ)
```

where `k_lt` is `mk_i` (in Phase 2) or `Cred_ij` (in Phase 3), and `g^xy` is
the fresh Diffie-Hellman shared secret from that handshake's ephemeral keys.
**`g^xy` is what gives forward secrecy** — as long as the ephemeral scalars
are erased right after use (there's no fallback path that skips this DH
step), even someone who later learns `k_lt` can't recompute an old session's
key without also solving the discrete-log-style problem for that specific
exchange.

### B.8 Every theorem and lemma — plain statement + how it's argued

| # | Name | Claim, in plain words | How it's argued |
|---|---|---|---|
| 1 | **Helper-data privacy** (Lemma) | The published helper data `s` leaks at most `n−k` bits of the PUF response; as long as the key length requested is smaller than what's left over (minus a safety margin), the derived key is statistically indistinguishable from a truly random one. | **Proved**, using the chain rule for average conditional min-entropy plus the strong-extractor property of the hash used in `Extract`. |
| 2 | **Phase-2 mutual authentication** (Theorem) | After a successful M1–M4 exchange, the drone and the GS are both convinced of each other's identity and agree on the same transcript `𝒯`, except with negligible probability. | **Proved by reduction**: forging any of `σ1`, `σ2`, `σ3` without the right key is exactly an EUF-CMA MAC forgery; nonce collisions are bounded by the standard birthday-style `q²/2^128` term. |
| 3 | **No PUF read-out oracle** (Corollary of #2/#9) | An attacker impersonating the GS learns *nothing* about the drone's actual PUF response — it can't use the drone as an "oracle" to harvest challenge-response pairs. | **Proved directly from verify-before-respond**: the drone sends nothing at all unless `σ2` checks out (Theorem 2), and even then it only ever sends `σ3` — a MAC over already-public fields — the raw PUF response never leaves the `Rep()` call. |
| 4 | **Replay resistance** (Theorem) | Neither Phase 2 nor Phase 3 messages can be successfully replayed. | **Proved** via three overlapping mechanisms: (a) a fresh nonce + timestamp freshness window on every message, (b) each message type has its own tag baked into the MAC, so a captured M1 can't be reused as an M3, and (c) from the second message onward, everything is bound to the *partner's* nonce too, which reduces replay to a forgery (Theorem 2/5). |
| 5 | **Peer mutual authentication** (Theorem) | After a successful P1–P3 exchange, the two drones are mutually authenticated with no GS involvement, and the shared per-pair credential is never exposed in transit. | **Proved**: `Cred_ij` only ever travels wrapped inside Phase 2's authenticated encryption (its INT-CTXT property blocks substitution, its IND-CCA property blocks disclosure); `τ1, τ2, τ3` are MACs under the derived key, and EUF-CMA forces both sides to have computed things identically. |
| 6 | **MITM resistance** (Theorem) | An active man-in-the-middle cannot succeed against either Phase 2 or Phase 3. | **Proved**: every accepted message is a MAC/AEAD tag over a transcript that includes both sides' nonces, timestamp, message type, and the partner's ephemeral DH share — tampering with any of it invalidates the tag, and forging a new valid one needs the secret key. |
| 7 | **Session-key secrecy** (Theorem) | For any adversary that hasn't corrupted either endpoint, the resulting session key is indistinguishable from a uniformly random string. | **Proved**: the KDF is modeled as a PRF; the long-term input (`mk_i` or `Cred_ij`) is protected either by the helper-data-privacy Lemma or by the AEAD delivery; the fresh DH value `g^xy` is unpredictable to a bounded adversary under the gap-CDH assumption given only the public shares. |
| 8 | **Perfect forward secrecy** (Theorem) | If the ephemeral DH scalars are erased right after use, learning the long-term secrets *after* a session has closed still doesn't reveal that session's key. | **Proved**: without the erased scalars, recovering the key requires solving gap-CDH from just the recorded public shares `g^x, g^y` — and there is no alternate, non-ephemeral path to the same key. |
| 9 | **Physical capture resistance** (Theorem) | Capturing one drone doesn't let the attacker impersonate any *other* drone to the GS, and doesn't compromise any peer pair the captured drone wasn't itself part of — the "blast radius" is limited to that one drone's own `N−1` links. | **Proved**: the captured drone's NVM holds only public values plus its own `Cred_kj` entries; every other device's `mk_m` or `Cred_mℓ` is an independent output of `mk_GS`, which never leaves the GS at all. |

**Symbolic verification (Tamarin model):** all six of the computational
theorems above are mirrored as machine-checked lemmas in a symbolic model —
injective agreement (covers Theorems 2 and 5), no-replay (Theorem 4),
capture-isolation (Theorem 9), key-secrecy (Theorem 7), and forward-secrecy
(Theorem 8). In this model the PUF is simplified to an idealized noiseless
private function, and device compromise is modeled with two extra rules: an
"NVM reveal" rule (excludes the PUF and `mk` itself, since those never
persist on the device) and a "post-session long-term-secret reveal" rule
(used specifically to test forward secrecy). **Note on scope:** per
`WHAT_I_DID.md`'s own honesty section, this symbolic model is described in
the paper's theory but the actual Tamarin/ProVerif files and their run
output are **not part of this codebase's verified deliverables** — the
paper describes the model, but "the machine-checked proof is not built" is
explicitly listed as unfinished work. Treat the symbolic-verification
section as a described-but-not-executed formal design, not as something
you can re-run here.

### B.9 The ablation study — in the paper's own framing

The paper is explicit about *why* an ablation study exists at all, in
almost these words: *"A negative control is essential — reporting that
every attack failed is unfalsifiable on its own; it's equally consistent
with a defective adversary."* The ablation disables one specific design
principle — call it P3, "verify the GS's authenticator on M2 before
responding" — and the paper is careful to frame this as *"a measurement
instrument, not a deployment option"* — i.e., nobody would ship the ablated
variant; it exists purely so the same attacker code has *something* it can
succeed against, proving the attacker isn't simply broken. Measured result:
against the ablated variant, GS impersonation succeeds with an oracle reply
observed; against the real protocol, the same attacker code gets 0/8 (see
Part E for the exact numbers).

### B.10 Comparison-with-existing-works tables (as stated in the paper)

**Feature comparison** — across RSA-2048, ECC-256, a plain pre-shared-key
(PSK) scheme, and four literature schemes (Gope, Li, Khan, Bera), on the
axes: uses a PUF / has peer-to-peer auth / no stored key / forward secrecy /
error correction / formal proof. **Only "this work" has a "Yes" in every
column**, with "Games + symbolic" listed for the formal-proof column
(referring to the game-based computational proofs above plus the Tamarin
model).

**Latency comparison** — this table explicitly separates *same-platform*
measurements (RSA-2048 1.08 ms, ECDSA 0.15 ms, ECDH 0.09 ms, and this work's
own 1.50/1.51 ms handshake, 0.42 ms peer) from *literature-reported,
cross-platform* numbers for Gope (10–50 ms), Li (45–80 ms), Khan (5–20 ms),
and Bera (<1 ms) — with an explicit caveat printed in the paper that those
literature rows were measured on different hardware (ARM boards,
Raspberry Pis) and are **not directly comparable** to the same-platform
rows. This caveat matters — it's the honest way to present numbers you
didn't personally re-measure.

**Overhead comparison** — bytes per handshake: RSA (768–1024 B), ECC
(384–512 B), PSK (~256 B), Gope (~200 B), Li (~300 B), versus this work at
N=5/10/20 drones (507/777/1317 B device↔server) and a flat 197 B for
peer-to-peer regardless of swarm size.

**Storage comparison** — bytes stored per device and, separately, how many
of those bytes are *secret*. This work: roughly `0.2 + 0.03N` KB total
storage, but only `32(N−1)` bytes of it are secret (the per-pair
credentials) — everything else (challenges, helper data) is public by
design.

**Security-properties comparison** — no-stored-secret / mutual-auth /
ephemeral-forward-secrecy / GS-free-peer-auth / capture blast-radius. This
work is the only row with **"Mandatory"** ephemeral forward secrecy (others
are either absent or optional) and a blast radius of **"N−1 links"**
(one captured device only exposes its own connections) versus **"whole
swarm"** for PSK and Bera, or **"1 device"** for the RSA/ECC/Gope/Li/Khan
rows (meaning those schemes' compromise is contained to the one device, but
they don't get the GS-free peer-auth or no-stored-secret properties either
— it's a genuine multi-axis trade-off table, not a simple "we win
everything" claim, except on the specific axes listed).

---

## Part C — Implementation (what the code actually does, file by file)

The code is organized so that **protocol logic never touches the simulator**
— `src/protocol/` is pure C++ classes that could run on real hardware
unmodified; `src/nodes/` is the OMNeT++ wiring around them.

### `src/core/` — shared primitives everything else builds on

- `Bytes.h/cc` — the one canonical byte-string type used everywhere: big-endian
  integer packing, XOR that **throws on length mismatch** (no silent
  truncation bugs), constant-time equality (so comparing a MAC tag doesn't
  leak timing information), secure memory wipe, and hex helpers for logging.
- `Encoding.h/cc` — the wire-format conventions: a version byte, domain-
  separation prefixes mixed into every hash/MAC/KDF call (so the same key
  material used for two different purposes never collides), and stable TLV
  field tags for the message wire format.

### `src/crypto/` — the two cryptographic suites and their building blocks

- `CryptoSuite.h` — the abstract interface both concrete suites implement; a
  suite identifier is mixed into every MAC transcript (so a message computed
  under one suite can never be mistaken for valid under the other), and
  every KDF call uses a distinct label per purpose.
- `Sha3Suite.h/cc` — SHA3-256 hashing, HMAC-SHA3 for MAC, HKDF, ChaCha20-
  Poly1305 for AEAD. The "software-efficient" suite.
- `SpongentSuite.h/cc` + `spongent/Spongent160.h/cc` — SPONGENT-160 hashing/
  MAC and a keyed sponge, rewritten to be spec-conformant (state size 176
  bits, rate 16, capacity 160, 90 permutation rounds — see spec-deviation #3
  below for why this needed fixing).
- `ascon/Ascon128a.h/cc` — Ascon-128a, the AEAD used by the SPONGENT suite
  (a genuinely lightweight authenticated cipher, pairing naturally with the
  lightweight hash).
- `X25519.h/cc` — the ephemeral Diffie-Hellman step used by *both* suites;
  deterministic-seeded keypair generation (for reproducible simulation
  runs), rejects known low-order/invalid points, and exposes an explicit
  `erase()` call — calling this after deriving the shared secret is what
  Theorem 8 (forward secrecy) actually depends on in the running code, not
  just in the math.
- `Drbg.h/cc` — a SHA3-256 counter-mode deterministic random bit generator
  seeded from OMNeT++'s own RNG. **Every nonce, DH scalar, PUF seed, and
  challenge anywhere in the simulation traces back to this one generator**,
  which is why runs are exactly reproducible given a seed.
- `OsslCommon.h/cc` — caches OpenSSL 3.x algorithm handles so the code isn't
  paying `EVP_fetch` lookup overhead on every single hash/MAC call — a pure
  performance detail, not a security one.
- `PrimitiveCounters.h/cc` — accumulates per-primitive cost statistics
  (median and p95, not just mean) which is what feeds
  `omnet_primitive_costs.csv`, the source of the microsecond-level numbers
  quoted throughout this document.
- `CryptoSuiteFactory.cc` — picks the concrete suite object by name
  (`"sha3"` or `"spongent"`) from the NED configuration parameter.

### `src/fe/` — the fuzzy extractor and error correction

- `BchCodec.h/cc` — a BCH error-correcting code over GF(2^8), using the full
  conjugate-closure generator polynomial (this fixes a real bug — see
  deviation/bug list below — and the constructor asserts its coefficients
  are binary, catching malformed configuration immediately rather than
  silently miscorrecting later).
- `FuzzyExtractor.h/cc` — implements the Gen/Rep code-offset construction
  from Section B.4, including the entropy-budget inequality **enforced at
  construction time** (it throws if you configure it under-provisioned —
  the safety check from the Lemma isn't just written in the paper, it's a
  runtime assertion in the code), and the repetition-inner-code offset/
  un-offset logic used by the `rep3` (triple-redundant) profile.

### `src/puf/` — the physical fingerprint models

- `PufModel.h` — the abstract interface; deliberately separates a
  "noise-free" evaluation from a "noisy" one, and routes all internal
  randomness through the explicit DRBG (never `rand()` or similar).
- `ArbiterPuf.h/cc` — a 128-stage additive-delay model, the more physically
  realistic PUF simulation, with per-bit flip-rate variance modeled
  explicitly (this is what's used by the `ArbiterPuf`/`HighNoise` scenarios).
- `IdealPrfPuf.h/cc` — an idealized PUF stand-in built from HMAC-SHA3-256.
  This is explicitly labeled in its own code comments as "not a PUF
  model" — it represents an *upper bound* on achievable entropy, used as
  the default for the main performance scenarios so that PUF noise doesn't
  confound the crypto-suite comparison.
- `XorArbiterPuf.h/cc` — chains `k` arbiter PUFs together via XOR, with the
  resulting bit-error-rate following `BER_xor(k) = (1 − (1−2p)^k) / 2` — a
  standard construction for hardening arbiter PUFs against modeling attacks,
  at the cost of a higher raw noise rate.
- `MinEntropy.h/cc` — implements the NIST SP800-90B "most common value"
  entropy estimator, reporting both the naive and the statistically
  corrected entropy rate (this is what exposes spec-deviation #6 below).

### `src/protocol/` — the actual protocol logic (simulator-independent)

- `Protocol.h/cc` — `GroundStationProtocol` and `UavProtocol`, the classes
  that literally implement Phases 1–4's message construction and
  verification from Part B, with zero dependency on the OMNeT++ simulation
  kernel (they could be linked into a real embedded build unchanged). Also
  contains `ReplayCache` (a bounded nonce-deduplication structure — the
  concrete mechanism behind Theorem 4), `StepTiming`/`StepResult` structs
  used for instrumentation, and the `legacyNoGsAuth_` flag — **this is the
  literal on/off switch for the ablation study** described in Part B.9.
- `Wire.h/cc` — the message-type enumeration (each phase's message types
  live in a separate numeric "hundred" range) plus a per-type domain tag
  mixed into MAC computations, which is the concrete mechanism behind "each
  message type has its own tag" in Theorem 4.

### `src/nodes/` — the OMNeT++ simulation wiring around the protocol logic

- `UavNode.cc/h/.ned` — drives a drone through Phase 2, then (once
  authenticated) Phase 3 for each configured peer; owns its own `PufModel`
  instance.
- `GroundStationNode.cc/h/.ned` — the enrollment authority (runs Phase 1
  offline before the simulation's timed portion) and the GS side of Phase 2;
  writes per-UAV recorded scalars at `finish()`, which is what
  `export_omnet_csv.py` later reads.
- `WirelessMedium.cc/h/.ned` — models the one shared transmission path/link
  delay for every message in the simulation, and is also the attacker's
  interception point — when `tapEnabled=false` it just short-circuits to
  direct delivery with no attacker involved at all.
- `AttackerNode.cc/h/.ned` — the adversary's actual decision logic (what to
  forge, when to replay, what to try to read); tracks a `genuineM2Seen_`
  flag specifically to avoid miscounting a victim's *legitimate* reply to
  the *real* GS as if it were a successful attack (this was one of the
  attacker-harness bugs found and fixed during development — see
  Part D bug list).
- `SimMessage.h` — the thin OMNeT++ `cMessage` wrapper that carries the
  transport-agnostic `protocol::Message` payload plus per-hop timing
  metadata, bridging the simulator-independent protocol code to the
  simulator's message-passing model.

---

## Part D — Honesty: where the paper's theory and the running code disagree

Every deviation below is deliberate and documented in
`docs/spec-deviations.md`; in each case the running code was kept *correct*
over matching the paper's original text exactly, and the reasoning is
recorded rather than silently patched over.

1. **Fuzzy-extractor timing.** The paper's phase ordering implies `Rep()`
   happens at M3; in the real protocol it has to happen **before M1 is even
   built**, because the drone needs `mk_i` to compute M1's own MAC (`σ1`).
   This doesn't weaken anything — the PUF challenge is fixed at enrollment
   regardless of exactly which message triggers the read — but it does mean
   M1's compute cost (see Part E) looks disproportionately large, and that's
   why.
2. **`TID_new` moved inside the AEAD.** The paper left the rotated temporary
   ID unauthenticated in M4; the implementation moved it *inside* the
   AEAD-encrypted plaintext instead. Reason: leaving it in the clear opens an
   in-flight "identity desync" attack (an attacker could corrupt the new ID
   in transit, causing the GS and drone to disagree about the drone's
   current TID on the next handshake). As a further mitigation for a lost
   M4 (drone updates but GS's copy of M4 never arrives, or vice versa), the
   GS indexes by *both* the current and the pending TID.
3. **SPONGENT-160 parameters corrected.** The original implementation used a
   variant matching no published SPONGENT specification (capacity 144, only
   80 rounds), which measured out to only ~72-bit security. It was rewritten
   to the real SPONGENT-160/160/16 parameters (state 176, rate 16, capacity
   160, 90 rounds).
4. **The "<10⁻¹⁵ failure rate" claim is unreachable** with the single-layer
   default error-correcting code — measured failure rate is closer to
   `1.2×10⁻³` at 3% BER. This is resolved (not hidden) by offering three
   selectable profiles, where the triple-redundant `rep3` profile does reach
   below 10⁻¹⁵, at three times the PUF-reading cost per authentication.
5. **Response block size.** The paper states 128-bit response blocks; the
   real implementation uses 255-bit blocks, because 128-bit blocks would leak
   almost their entire entropy against a 124-bit helper-data leak (`n−k`),
   leaving essentially nothing for the extractor to work with.
6. **Measured min-entropy is lower than assumed at small population sizes.**
   The NIST SP800-90B-corrected "most common value" entropy estimate caps
   out around 0.854 bits/bit at a simulated population of 1000 devices;
   reaching the paper's assumed 0.95 bits/bit requires roughly 10,000
   devices in the estimation sample. The assumed rate is only defensible at
   that scale, and this is stated plainly rather than assumed silently.
7. **The "21× faster than RSA" claim was simply wrong** — see Finding 1 in
   `WHAT_I_DID.md`: measured RSA-2048 verification on the same machine is
   33 µs, not the 8–15 ms the original paper cited (a roughly 300× error in
   the cited number). This invalidated any speed-multiplier claim built on
   it, and the paper was reframed to say "comparable to ECC," not "orders
   of magnitude faster" — this reframing is the direct cause of the earlier
   comparison tables in Part B.10 being honest, apples-to-apples comparisons
   rather than favorable ones.
8. **The `rep3` triple-redundancy code was originally implemented wrong.**
   It majority-voted three *different, independent* PUF bits as if they were
   three noisy readings of the *same* bit — a conceptual error that destroys
   information instead of correcting it. This was caught because the
   measured failure rate (0.960 at 5% BER) was wildly worse than the
   mathematically predicted rate, which should have been near-zero. Fixed by
   publishing each copy's offset from a shared reference value at
   enrollment, so the three "votes" really are three measurements of the
   same underlying bit. After the fix: 0.000 failure rate all the way to
   10% BER.

---

## Part E — Results: the numbers, phase by phase and message by message

*(Full detail already lives in `ANALYSIS.md` — summarized here for
completeness so this document stands alone; see that file for the deeper
walkthrough of the "two clocks" nuance, i.e. why `wall_latency_ms` and
`compute_ms + net_ms` disagree and which one to trust for what. All figures
below are the final **30-seed** campaign — `simulations/omnetpp.ini` always
said `repeat = 30`, but an earlier export run only asked for the first 10;
that's fixed, and these are the real 30-run numbers.)*

**Phase 1 (enrollment, once, offline):** 1.10 ms (sha3) / 1.83 ms (spongent)
— PUF evaluation plus fuzzy-extractor generation. Irrelevant to operational
speed since it happens once, at a workbench, before flight.

**Phase 2 (GS↔UAV, 4 messages):**

| Message | Sender compute | Receiver compute | Network delay | Size |
|---|---|---|---|---|
| M1 | 1.37 ms (includes PUF+FE Rep — deviation #1) | 0.05 ms | 0.26 ms | 104 B |
| M2 | — | 0.08 ms | 0.23 ms | 85 B |
| M3 | 0.08 ms | 0.13 ms | 0.18 ms | 43 B |
| M4 | — | 0.01 ms | 0.84 ms | 545 B |

Realistic end-to-end total (compute+net, serial): **2.60 ms (sha3)**,
**5.39 ms (spongent)**. Pure simulated-network-only figure: ~1.503 ms (sha3)
/ 1.508 ms (spongent) (the network path is identical regardless of crypto
suite — the small gap is scheduling noise, not a real dependency).
Total wire overhead: 777 B (sha3) / 781 B (spongent).

**Phase 3 (UAV↔UAV, 3 messages, no GS):** realistic total 0.50 ms (sha3) /
1.37 ms (spongent); network-only figure pooled across all four swarm-size
configs (N=120 runs) is **0.4167 ± 0.0006 ms**, genuinely flat with swarm
size (0.4171 ms at N=10, 0.4163 ms at N=5, 0.4164 ms at N=20 — differences
are within noise). 197 bytes total overhead, flat regardless of swarm size.

**Beyond the idealized network model — mobility, real contention, and
energy (all newly measured, all at 30 seeds):**

- **Mobility** (`MobilityLinear`, `MobilityRandomWalk`): drones travel ~2,397 m
  per run under constant-velocity-with-bounce or random-walk headings; Phase-2
  latency is unchanged (1.5026–1.5028 ms) because the delay model reacts to
  distance instantly. This confirms motion doesn't break the protocol
  structurally — it does **not** model Doppler, fading, or range-dropout.
- **Real 802.11 contention** (`Inet80211SHA3`/`Inet80211SPONGENT`, a separate
  INET-based build, static positions, no attacker track): the same Phase-2
  handshake over real CSMA/CA takes **11.72–11.74 ms**, roughly 8× the
  idealized-delay figure, with 2/300 (0.67%) outright failures from MAC-layer
  contention. This is the honest cost the idealized `WirelessMedium` model
  was always disclosed as omitting (spec-deviation-adjacent limitation,
  Part C.7 in `REPORT3.md`'s terms) — now it's quantified rather than just
  flagged.
- **Energy** (`omnet_energy_costs.csv`, derived from measured primitive
  timings + literature per-cycle/per-bit constants, every row tagged
  `measured-derived` or `estimate:lit`): radio energy per Phase-2 handshake
  is ~210–215 µJ per UAV (347 µJ at N=20, since Phase-3 traffic scales with
  swarm size), against ~10.3 mJ for the X25519 keygen+derive step alone — the
  elliptic-curve key exchange, not the PUF read or the radio, dominates
  energy cost by roughly 50×.

**Full-protocol RSA/ECDSA baseline (the fair comparison, replacing the old
bare-primitive one):** a real competing protocol (`BaselineSigAuth`,
RSA-signed or ECDSA-signed ephemeral X25519) run through the identical
simulated network, same instrumentation, same 30 seeds:

| Protocol | End-to-end | Realistic (compute+net) | Overhead | Success |
|---|---|---|---|---|
| This work (sha3) | 1.503 ms | 2.60 ms | 777 B | 300/300 |
| RSA-signed baseline | 1.404 ms | 2.05 ms | 703 B | 300/300 |
| ECDSA-signed baseline | 0.911 ms | 0.83 ms | 330–335 B | 300/300 |

This protocol is genuinely ~3× slower end-to-end than a same-platform ECDSA
handshake — the PUF-reading step ECDSA never has to pay for. The honest
selling point is the property, not the speed: no stored secret to steal if
the drone is captured.

**Why SPONGENT isn't "10 ms+" anymore (it used to look that way because the
old implementation was simply non-conformant with the SPONGENT spec — see
deviation #3 — not because SPONGENT itself is that slow):** correctly
implemented, SPONGENT is genuinely ~100× slower than SHA3 *per cryptographic
operation* (225 µs vs 2.1 µs for one MAC) — that's expected and matches the
literature, since SPONGENT trades software speed for a tiny hardware gate
count. But hashing/MAC-ing is only a small slice of total handshake time
(most of it is PUF+FE+DH+network, shared identically by both suites), so the
*end-to-end* difference is only ~2×, not ~100×, let alone the old bug's
~750× or the "10 ms+" figure that bug produced.

**Comparison to RSA/ECC/X25519 (same-platform baseline):**

| Operation | Cost |
|---|---|
| RSA-2048 sign / verify | 1.05 ms / 0.03 ms |
| ECDSA-P256 sign / verify | 0.04 ms / 0.11 ms |
| ECDH-P256 derive | 0.09 ms |
| X25519 keygen / derive | 0.07 ms / 0.13 ms |
| Our own hash / MAC / KDF / AEAD | 0.001 / 0.004 / 0.008 / 0.001 ms |

Our own crypto is cheaper than every RSA/ECC operation above. The gap that
makes the *full handshake* land at 2.60 ms (roughly RSA-2048-class, but
5–10× slower than a bare ECC handshake) is entirely the PUF+fuzzy-extractor
step — the physical cost of "prove you hold this exact chip," which RSA/ECC
never has to pay because they just read a stored key instead of measuring
one. See `ANALYSIS.md` Section 2 for six concrete ways to reduce this.

---

## Part F — Every test scenario

All at 30 seeds except the attack configs (5) and NoiseSweep (3 × 21 points).

| Scenario | What it changes | What it tests | Result |
|---|---|---|---|
| **StadiumSHA3 / StadiumSPONGENT** | 10 drones, fixed perimeter layout, GS at center; `sha3` vs `spongent` suite | The default realistic deployment, both crypto suites | 300/300 authenticated both; 1.503/1.508 ms network-only, 2.60/5.39 ms realistic |
| **Baseline5UAV** | 5 drones | Sanity check at smaller scale | 150/150 authenticated, 1.144 ms |
| **Swarm20** | 20 drones, staggered start | Scalability — Phase 3 grows as N(N−1)/2 = 190 pairs at N=20 | 600/600 authenticated, all 5,700 pairs completed |
| **ArbiterPuf** | Realistic additive-delay PUF model instead of the idealized PRF stand-in | Does the protocol still work against a less idealized, physically-modeled PUF | 298/300 (99.3%) device success |
| **HighNoise** | PUF bit-error rate forced to 5% | Reliability under genuinely noisy readings | 247/300 (82.3%) device success — a real, reported weakness |
| **NoiseSweep** | 0–10% BER × 3 fuzzy-extractor profiles, 3 repeats (63 runs) | Does the measured failure curve track the mathematical prediction | 20 of 21 points inside the predicted 95% confidence interval — real evidence the BCH decoder works |
| **MobilityLinear / MobilityRandomWalk** *(new)* | 10 drones move at constant velocity (boundary bounce) or random-walk heading | Does motion break anything structurally | 300/300 authenticated both; ~2,397 m travelled per run; latency unchanged (~1.503 ms) |
| **Inet80211SHA3 / Inet80211SPONGENT** *(new, separate INET build)* | Real 802.11 ad-hoc CSMA/CA instead of the idealized delay model; static positions, no attacker | Real MAC-layer contention cost | 298/300 (99.3%) both; 11.72/11.74 ms — ~8× the idealized figure |
| **BaselineRSA / BaselineECDSA** *(new)* | Full competing protocol: RSA-signed / ECDSA-signed ephemeral X25519, same network, same instrumentation | Fair full-protocol speed comparison (replacing the old bare-primitive one) | 300/300 both; 1.404 ms / 0.911 ms end-to-end — this work is ~3× slower than ECDSA, for the property, not the speed |

---

## Part G — Every attack

The attacker is a node with a tap on the simulated radio medium
(`*.medium.tapEnabled`) and a behavior mode (`*.medium.attackMode`):
`"eavesdrop"` (listen only), `"credsniff"` (target M4's credential
specifically), `"tamper"` (modify fields in flight), `"impersonate"` (forge
GS messages), `"replay"` (resend a captured message later). A separate
`*.attacker[0].expectSuccess` flag states in advance whether the attack is
*supposed* to work — which is what makes "every attack failed" falsifiable
rather than a self-fulfilling claim.

| Config | Target | Attack | Attempts | Accepted | Oracle replies | Credentials exposed | Expected success? | Matched? |
|---|---|---|---|---|---|---|---|---|
| AtkGsImpersonate | Full protocol | Forged GS challenge | 8 | 0 | 0 | 0 | No | ✅ 0% |
| **AtkLegacyGsImpersonate** (ablation) | Weakened variant, same attacker code | Same forged-challenge attack | 8 | 1 | 1 | 0 | **Yes** | ✅ 12.5% |
| AtkReplayM1 | Full protocol | Replay captured M1 | 1 | 0 | 0 | 0 | No | ✅ 0% |
| AtkCredentialSniff | Full protocol | Passive read of M4's credential | 10 | — | — | 0 | No | ✅ 0/10 readable |

The ablation row succeeding 12.5% of the time is the point, not a red flag —
it's the falsifiable control proving the attacker code genuinely works and
the zero-success rows aren't just a broken adversary.

---

## Part H — Reliability, honestly

| PUF noise (BER) | Default profile failure | Stronger profile | Strongest (3× cost) profile |
|---|---|---|---|
| 1% | 0.000 | 0.000 | 0.000 |
| 3% | 0.033 | 0.000 | 0.000 |
| 5% | 0.167 | 0.000 | 0.000 |
| 7% | 0.800 | 0.133 | 0.000 |
| 10% | 1.000 | 1.000 | 0.000 |

The default error-correction strength is fine up to ~3–5% noise, then
degrades sharply. The strongest profile stays at 0% failure to 10% noise but
costs 3× the PUF-reading time on *every* authentication, not just once —
a deliberate trade a real deployment has to make based on how noisy its
actual hardware is.

---

## Part I — The short version of everything

- **Design:** no secret ever stored on a drone — a PUF regenerates the key
  every time, corrected for noise by a fuzzy extractor. Four phases: enroll
  once, authenticate to the GS, authenticate peer-to-peer without the GS,
  derive session keys — the last two steps share one KDF formula.
- **Theory:** nine named theorems/lemmas covering helper-data privacy,
  mutual authentication (both hop types), no-PUF-oracle, replay resistance,
  MITM resistance, session-key secrecy, forward secrecy, and capture
  isolation — each with a stated proof strategy (mostly reductions to
  standard crypto assumptions: EUF-CMA MAC security, IND-CCA/INT-CTXT AEAD
  security, gap-CDH hardness), plus a described (but not executed in this
  codebase) Tamarin symbolic model mirroring the same six properties.
- **Implementation:** protocol logic is fully separated from the simulator;
  eight documented, deliberate deviations from the paper's literal text,
  every one kept on the side of "correct code" over "matches the paper
  exactly," and every one recorded with its reasoning rather than hidden.
- **Results:** ~2.6 ms (sha3) / ~5.4 ms (spongent) for a full GS handshake,
  ~0.5–1.4 ms for peer-to-peer — comparable to RSA-2048, 5–10× slower than
  bare ECC, entirely because of the PUF's physical cost, which ECC never
  pays. Own crypto primitives are cheaper than RSA/ECC's. SPONGENT is a
  hardware-area optimization, correctly ~100× slower per-op but only ~2×
  slower end-to-end than SHA3 (the old "10 ms+"/750× figure was a bug in a
  non-conformant legacy implementation, now fixed).
- **Scenarios and attacks:** every functional scenario (5–20 drones, noise
  sweeps, realistic PUF models) behaves as expected within honestly-reported
  limits; every attack failed against the real protocol and the same
  attacker code was shown to succeed against a deliberately weakened
  variant, so the "0% attack success" claim is backed by a falsifiable
  control rather than an untested assumption.
- **Beyond the original rebuild:** the full 30-seed campaign is now the real
  backing data (not 10, despite the ini always saying 30); mobility, real
  802.11/INET MAC contention (~8× the idealized delay), a derived energy
  model (X25519 dominates energy cost, not the PUF or radio), and a fair
  full-protocol RSA/ECDSA baseline (this work is genuinely ~3× slower than
  same-platform ECDSA — the honest trade is no stored secret, not speed) are
  all built, measured, and folded into `final_theory/paper.tex`. What
  genuinely remains: running the Tamarin proof for real, a DoS/flooding
  study, an ML-modeling-attack curve for the PUF, and a Docker/reproducibility
  artifact — see `REPORT4.md`.
