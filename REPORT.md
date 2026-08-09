# Publication-Readiness & Protocol-Security Report
### "Fast PUF-Based Four-Phase Authentication for UAV Swarms"

**Prepared:** 2026-08-09
**Scope:** Full audit of the journal manuscript (`research paper/uav_puf_journal.tex`), the conference manuscript (`research paper/uav_puf_conference.tex`), the OMNeT++/C++ reference implementation (`src/`), the Python reference (`UAV-Authentication/`), the simulation results (`simulations/results/`, `final results/`), and the stated 5-item future plan.
**Method:** Direct manual reading of the paper and code, cross-checked by a multi-agent audit (5 deep readers + 3 critique lenses + 10 adversarial verification passes + 2 future-plan analysts). Every "critical/high" claim below was independently re-checked against the actual files; **none of the ten verified findings were refuted.**

> ⚠️ **This report only analyzes. No code, paper, or result files were changed.**

---

## 0. Bottom line (read this first)

**Is it good enough to submit right now? No — not to either a conference or a journal, and not after cosmetic edits.**

The paper is a well-organized, honestly-caveated, engineering-rich manuscript sitting on top of **(a) a protocol that does not actually provide the security it claims, and (b) an implementation whose three central primitives (BCH, PUF, SPONGENT) are broken, faked, or non-conformant.** These are correctness problems, not presentation problems, so they cannot be revised away — they require a protocol redesign and a re-implementation before the results mean anything.

The encouraging part: **the skeleton is genuinely good** (clear four-phase structure, an honest Limitations section, a novel and interesting hardware gate-equivalent angle, a working simulation harness), and **almost every blocker is fixable.** Your own 5-item future plan already targets several of them — but you are mis-framing three of those items as "enhancements" when they are actually **mandatory fixes for current defects.**

| Dimension | Grade | One-line justification |
|---|---|---|
| Idea / motivation | **B+** | PUF-rooted, no-key-storage, GS-free peer auth is a reasonable and timely goal. |
| Protocol security (as specified) | **F** | 2 of 5 theorems provably false; 2 more unsound; core assumption mathematically wrong. |
| Novelty | **C−** | Incremental over Gope/Alladi/Li; the one fresh angle rests on a broken artifact. |
| Implementation fidelity | **D−** | BCH decode is inert; "Arbiter PUF" is a PRNG; SPONGENT is non-spec; ECDH is dead code. |
| Experimental rigor | **F** | n=1 single-seed runs; headline numbers irreproducible & self-contradictory; 4 of 6 configs never run. |
| Writing / structure | **B** | Clear, well-organized, honest limitations — the strongest part of the work. |

**Editorial prediction (candid):**
- **Mid-tier IEEE/Springer conference:** *Reject, resubmit after redesign.* The mutual-authentication claim is false by the paper's own equations — that is not a major-revision distance.
- **Q1/Q2 journal (target is IEEE TVT per the manuscript):** *Reject.* Compounds the unsound security with an invalid, irreproducible empirical basis. Acceptance would require what is effectively a new paper.

**The single most important sentence in this report:** *Three of your five "future work" items (full-spec SPONGENT, per-pair PUF Phase 3, formal verification) are not future enhancements — they are repairs of defects that currently invalidate your central claims. Treat them as prerequisites, not extensions.*

---

## Part A — Protocol security analysis (the theory)

This is the part you specifically asked about: *how good is the protocol, and what are its flaws?*

### A.0 Verdict on the protocol design

The protocol is a **standard fuzzy-extractor + challenge-response construction** dressed in four phases. Conceptually it is fine and familiar. **But as written, it does not achieve mutual authentication, does not root peer authentication in the PUF, has no forward secrecy in its base mode, and leaks its Phase-3 root secret in plaintext.** Four of the five "theorems" are unsound. The reason, in one line: **almost every "authenticating" value in the protocol is an *unkeyed* hash of data that is entirely public on the wire.** An unkeyed hash gives *integrity*, not *authentication* — anyone can recompute it.

### A.1 CRITICAL — Phase 2 GS→UAV authentication does not exist (Theorems 1 & 4 are false)

- **What the paper says:** M2 = ⟨C, N₂, β₁⟩ with β₁ = h(TID‖C‖N₂‖T₁), and Theorem 1's proof claims forging β₁ "requires knowledge of C known only to the GS."
- **The flaw:** The challenge `C` is transmitted *in cleartext inside the very same message M2* that β₁ supposedly protects. Every input to β₁ (TID, C, N₂, T₁) is public. β₁ is therefore an unkeyed checksum, not a MAC. **Any active adversary can synthesize a valid M2 with an arbitrary challenge C′.** The same defect makes α₁ = h(TID‖T₁‖N₁) in M1 non-authenticating.
- **Consequence:** The UAV never authenticates the GS. Genuine authentication happens only at M3 (where the PUF response enters), so the "four-message mutual handshake" is really one-directional. **Theorem 1 (Mutual Authentication) and Theorem 4 (MITM Resistance) are unsound in the GS→UAV direction.**
- **Evidence:** `uav_puf_journal.tex:520-527` (β₁, C in M2), `:1150-1168` (proof); `src/protocols/Phase2Authentication.cc:41-48` (unkeyed hash over public values). **Verified: CONFIRMED (critical).**

### A.2 CRITICAL — Chosen-challenge PUF read-out oracle → clone the PUF without capturing it (undermines Theorem 5)

- Because the GS is not authenticated (A.1), an attacker sends M2 with a chosen challenge `C′` and chosen nonce `N₂`. The UAV replies with R^masked = PUF(C′) ⊕ h(N₂). Since **`N₂` is public and attacker-chosen, `h(N₂)` is known**, so the attacker recovers **R^noisy = PUF(C′) for any challenge it wants.**
- This is a textbook **CRP-harvesting oracle.** A 128-stage Arbiter PUF — the exact primitive the paper names as its root of trust — is well known to be machine-learnable from a few thousand CRPs. The attacker builds a software clone offline and impersonates the UAV to the *real* GS.
- **Consequence:** This voids the unclonability/unpredictability assumptions (Assumptions 2–3) and **Theorem 5 (Physical Capture Resistance) in practice — with no physical capture at all.** The masking construction `R ⊕ h(N₂)` is itself a design error: a mask must use a value the querying party cannot control or predict.
- **Evidence:** `uav_puf_journal.tex:531-536`; `src/protocols/Phase2Authentication.cc:49-54` (`maskResponse`). **Verified: CONFIRMED (critical).**

### A.3 CRITICAL — The Phase-3 root secret (`Cred`) is a swarm-wide PSK sent in plaintext (Theorem 3 is false)

- The GS mints **one 20-byte `networkCredential` and issues the *same* `Cred` to every UAV.** M4 = ⟨success, Cred⟩ carries it **with no encryption and no MAC** (it is not wrapped under SK_i).
- **Three fatal consequences:**
  1. A **passive eavesdropper on any single enrollment** learns `Cred` — the *only* secret in all of Phase 3 — and can then derive every pair's session key SK_ij from on-wire nonces.
  2. Any swarm member (or anyone who learned `Cred`) can **impersonate any UAV to any other** simply by filling in the victim's identity integers; the identities i,j are unkeyed hash inputs bound to no per-device secret. Theorem 3's claim that an "identity swap is detectable" is **false** — the attacker doesn't swap to its own ID, it just writes the victim's ID.
  3. An **active adversary can inject a forged M4** with `success=true` and an attacker-chosen `Cred`, seizing control of the group key (KCI / group takeover).
- **This is the deepest conceptual problem:** Phase 3 is *group authentication mislabeled as per-device mutual authentication.* It is **not PUF-rooted at all.** It re-introduces exactly the "whole swarm compromised if any device is captured" weakness that your Introduction criticizes PSK for.
- **Evidence:** `src/nodes/GroundStation.cc:319-333` (`field1=networkCredential`, no MAC/encryption), `:71` (one Cred for whole swarm); `src/nodes/UAVNode.cc:539` (adopts blindly); `uav_puf_journal.tex:552-554,1187-1210`. **Verified: CONFIRMED (critical).**

### A.4 HIGH — No forward secrecy in the base scheme; optional ECDH is unauthenticated and silently degrades to zero-DH

- SK_i = h(R^noisy‖N₁‖N₂‖T₁) and SK_ij = h(i‖j‖n_i‖n_j‖Cred) are **deterministic functions of a long-term secret plus public nonces.** One later compromise of the PUF (via A.2) or of `Cred` (via A.3) lets an attacker recompute *every past session key* from recorded transcripts → **zero forward secrecy.**
- The "optional Curve25519" path has two defects: (i) the ephemeral public keys are never bound into any MAC, so it is unauthenticated (unknown-key-share possible for a `Cred`-holder); and (ii) **`Phase4SessionKey::deriveWithECDH` falls back to `hash(basicKey‖localPub‖remotePub)` with NO scalar multiplication when `USE_SODIUM` is undefined — which is the default build** — producing a "session key" with no secrecy while appearing to offer PFS.
- **Evidence:** `uav_puf_journal.tex:540-546,597-618,1250-1262`; `src/protocols/Phase4SessionKey.cc:19-36`. **Verified: CONFIRMED (high).**

### A.5 HIGH — Helper-data "negligible leakage" (Assumption 4) is mathematically wrong

- Assumption 4 / Phase 1.2 claim H = Encode(R) ⊕ R is "computationally independent of R." This **misapplies the code-offset secure-sketch theory:** such a sketch provably leaks up to **n−k bits** of min-entropy about R (the syndrome) — a *bounded loss*, not independence. For BCH(255,131,18), n−k = 124 redundancy bits against a 128-bit response, so residual min-entropy can collapse to a handful of bits.
- *Nuance (in your favor):* H is **not transmitted on the wire** in this design (GS reconstructs ecc = H ⊕ R^noisy locally), so this is an **assumption-soundness error**, not an on-wire leak. But the theorem statement is still wrong, and a reviewer with a crypto background will flag it immediately. Also note the GS DB stores raw R in plaintext, so DB confidentiality — not helper-data masking — is what actually protects responses.
- **Evidence:** `uav_puf_journal.tex:467-478,1136-1140`; `src/protocols/Phase1Enrollment.cc:40-45`. **Verified: CONFIRMED (medium–high).**

### A.6 HIGH — CRP budget of 12 per UAV is far too small; M1 enables CRP-exhaustion DoS

- The GS is provisioned with `numCRPsPerUAV = 12` and consumes one CRP per authentication. A UAV re-authenticates on every mission/reconnect/handover; **12 single-use CRPs is exhausted almost immediately** in real deployment, after which the UAV cannot authenticate without re-enrollment. The paper never analyzes CRP lifetime budgeting.
- Because M1 is unauthenticated (A.1) and the only replay defense is a ±5 s timestamp window, **an attacker can forge/replay M1 within the window to drive the GS to fetch/advance CRPs** — an active exhaustion + state-desync DoS.
- **Evidence:** `simulations/omnetpp.ini:17` (numCRPsPerUAV=12), `:GS timestampWindowMs=5000`; `src/nodes/GroundStation.cc` CRP fetch/advance path. **Verified: CONFIRMED.**

### A.7 MEDIUM — Phase 3 lacks domain separation and freshness → reflection / key-confusion

- τ₁ = h(i‖j‖n_i‖Cred) and τ₃ = h(i‖j‖n_j‖Cred) share an **identical input layout with no message-role tag**, so request and completion tokens are interchangeable (reflection/oracle-confusion). Phase 3 has **no timestamps** at all (even though Theorem 2 lists timestamps as a defense). And SK_ij differs from the authenticator τ₂ only by identity ordering (i‖j vs j‖i) over the same secret/nonces — a **key/authenticator domain-separation failure.**
- **Evidence:** `uav_puf_journal.tex:583-596`; `src/protocols/Phase3PeerAuth.cc:36-95`. **Verified: CONFIRMED (medium).**

### A.8 The "Security Analysis" section is informal, and its proofs rest on false premises

Even setting aside the specific flaws, the five "theorems" are **prose paragraphs with no formal adversary model, no security game, no reduction.** The headline "1 − 2⁻¹⁵⁹" is a hash-collision/guessing bound, not a proof of authentication — it says nothing about the real attack surface (that the authenticators contain no secret). A journal security proof needs a game-based reduction or a mechanized ProVerif/Tamarin model. **This is why your future item #5 is not optional.**

### A.9 Summary of the protocol's security posture

| Claimed property | Reality | Status |
|---|---|---|
| Phase-2 mutual auth (Thm 1) | Only UAV→GS holds; GS→UAV unauthenticated | ❌ False |
| Replay resistance (Thm 2) | Partial; Phase 3 has no timestamps; ±5s window replay + CRP desync | ⚠️ Weak |
| Phase-3 peer mutual auth (Thm 3) | Group PSK, not per-device; plaintext `Cred`; any member impersonates anyone | ❌ False |
| MITM resistance (Thm 4) | Fails wherever authenticators are unkeyed (M1, M2) | ❌ False |
| Physical-capture resistance (Thm 5) | Undermined: PUF cloned via chosen-challenge oracle without capture; `Cred` capture breaks whole mesh | ❌ Undermined |
| Helper-data secrecy (Assumption 4) | Wrong claim; correct statement is n−k entropy loss | ❌ Unsound |
| Forward secrecy | None in base mode; optional ECDH unauthenticated + silently no-DH | ❌ Absent |

**What a fixed protocol needs (this is the redesign, not a patch):**
1. **Key the GS direction.** Establish a per-device secret at enrollment (e.g. an enrollment MAC key, or derive the GS-direction MAC from the enrolled response R_ref so only a CRP-database holder can forge it). Replace every `h(...)` "MAC" with HMAC/PRF keyed by a value the adversary provably lacks. Authenticate the GS *before* any challenge is answered, so no PUF oracle exists.
2. **Never mask with an attacker-controlled value.** Bind the mask to the GS-shared secret.
3. **Deliver `Cred` under authenticated encryption** (wrap M4 under SK_i / AEAD), and **replace the swarm-wide `Cred` with per-pair, PUF-rooted credentials** (see future item #4).
4. **Add per-message-type domain tags and freshness to Phase 3;** separate key derivation from authenticator (KDF(K,"session",tr) vs MAC(K,"auth",tr)).
5. **Make an authenticated ephemeral key exchange mandatory for PFS;** remove the silent no-DH fallback (fail closed if libsodium absent).
6. **Re-prove all theorems in a formal model** (Tamarin — see A.8 and future item #5).

---

## Part B — Implementation audit (what the code actually does vs. what the paper claims)

Three of the four primitives whose costs and correctness the results claim to demonstrate **are not what the paper describes.** This means the evaluation validated a *different system* from the one specified.

### B.1 CRITICAL — The BCH fuzzy extractor is mathematically broken; decode never corrects anything

- The generator polynomial is built **only from cyclotomic-coset representatives** (conjugate roots are marked "used" but never multiplied in), producing **GF(256)-valued coefficients** that are then XORed into a 0/1 bit array. `eccBits` is set to m·t = 144 instead of the true deg(g) = 124, so **k = 111, not 131**, and only 111 of the 128 PUF-response bits ever enter the codeword.
- **Empirical test (standalone compile of `BCHCodec.cc`):** a zero-error round-trip *fails* the syndrome check; with 4 random bit-errors (the 3% scenario) **decode failed 200/200 trials**, always falling through to "decoding failed" and returning the noisy input unchanged. `decode()` is effectively an **identity function.**
- **Why the protocol still "works":** authentication succeeds *only* because `GroundStation.cc:308-311` accepts any response within Hamming distance 24 of the enrolled one, and both sides key from the same *uncorrected* noisy response.
- **Therefore false:** "BCH(255,131,18) absorbs 3% PUF noise with the 4.7× margin predicted by theory" (line 781), "corrects up to t=18 errors," the "<10⁻¹⁵ decode-failure probability," and the reported ~22 µs "BCH decode" cost (that's the cost of a *failed* decode).
- **Bonus:** the paper claims a `USE_LIBCORRECT` build substitution — **it exists nowhere in the repo** (grep returns zero hits). Fabricated capability claim.
- **Evidence:** `src/crypto/BCHCodec.cc:93-104,147,19-22`; test result `trials=200 recovered_original=0 decode_failed=200`; `uav_puf_journal.tex:781, ~674`. **Verified: CONFIRMED (critical).**

### B.2 HIGH — The "128-stage Arbiter PUF" is a seeded PRNG; the arbiter model is dead code

- `PUFSimulator::evaluate()` (the only path called, from `Phase1Enrollment.cc:38` and `UAVNode.cc:482`) hashes the challenge with FNV-1a mixed with the device seed and streams bits from a reseeded `std::mt19937`. It is a **keyed PRF, not a delay-additive arbiter model.** The genuine `evaluateArbiterBit()` / `evaluateROPUFBit()` functions and `delayWeights` **are never called** (grep: zero call sites).
- The contribution bullet and system model call it "a 128-stage Arbiter PUF simulator" (lines 180, 405); only the implementation section softens it to "Arbiter-style." **No PUF-realism property is actually simulated** — no challenge-response correlation, no environmental drift, and critically **no ML-modeling-attack behavior** (which matters precisely because of the A.2 oracle attack).
- Noise is not the claimed Bernoulli(p): `addNoise()` flips exactly round(128·0.03)=4 fixed positions. The project's own test reports **intra-chip HD = 5.73%**, exceeding the journal's "≤5%" and far from the conference paper's "3.0%."
- **Evidence:** `src/crypto/PUFSimulator.cc:36-57,59-83,85-103`; test output `Intra-chip Hamming distance: 5.72917%`. **Verified: CONFIRMED (high).**

### B.3 HIGH — SPONGENT-160 is non-spec and unverified; the headline gap is an implementation artifact

- The permutation keeps the correct S-box, rate/capacity (16/144), 80 rounds, and pLayer form, **but the round constants are ad-hoc** (`state[0]^=round`, `state[last]^=round*0x9E`) — the spec uses a 7-bit LFSR value and its bit-reverse. **Outputs cannot match any SPONGENT-160 test vector, and no SPONGENT test exists.**
- The software cost (~890 µs/call) is driven by a naive per-bit, fresh-`std::vector`-per-`pLayer` implementation vs OpenSSL's optimized SHA3. So the abstract's central quantitative claim — **the 20–30× software gap and the 2,225× per-call ratio — is largely an artifact of an unoptimized toy sponge, not a property of the algorithm.**
- The paper *does* footnote the deviation (to its credit), but the bold result tables and the entire hardware-crossover narrative present these numbers as intrinsic.
- **Evidence:** `src/crypto/SPONGENT.cc:75-77,89-112`; `uav_puf_journal.tex:87-95,689-695`. **Verified: partially-confirmed (medium) — the slowdown is real; the "lightweight" story survives only as an FPGA projection.**

### B.4 MEDIUM — ECDH / Phase-4 forward secrecy is unreachable dead code

- `Phase4SessionKey::deriveWithECDH()` is never called; `USE_SODIUM` is never defined in the Makefile; no ephemeral keypair generation exists anywhere. The "~2 ms on ARM Cortex-A72" PFS figure is **not from this implementation.** "Gated on a compile-time flag" implies it works when set — it does not. (See A.4 for the silent no-DH fallback.)
- **Evidence:** `src/protocols/Phase4SessionKey.cc:19-36`; Makefile has no `-DUSE_SODIUM`. **Verified: CONFIRMED (medium).**

### B.5 MEDIUM — GS token verification is circular

`GroundStation::onPufResponse` derives SK_i from the received (unmasked) response and then verifies the UAV's token h(maskedResponse‖SK_i) **against a token computed from the exact same received data.** `tokenOk` is therefore true for any well-formed message by construction; authentication rests *entirely* on the Hamming-distance-24 check. The proofs lean on γ₁ verification as a meaningful step; in the implementation it can never fail. **Evidence:** `src/nodes/GroundStation.cc:292-311`.

### B.6 LOW — Spec/implementation divergences

`Phase4SessionKey::deriveBasicKey` omits the timestamp T₁ that the spec's SK_i includes → two divergent session-key definitions coexist. The GS Hamming threshold is `responseDistanceThreshold=20` in code vs τ=24 in the paper (and 24 in `omnetpp.ini`). The "reference implementation" and the "analyzed protocol" are not the same object.

---

## Part C — Results & experimental-methodology audit

### C.1 CRITICAL — n = 1: every number is a single-seed point estimate

`omnet_summary.csv` shows `num_runs=1` for both configs; both `.sca` files carry `attr repetition 0` / `attr seedset 0`; `omnetpp.ini` has no `repeat=` key. **No confidence intervals, standard deviations, or error bars are possible,** yet the paper reports latencies to 3–4 significant figures and microsecond per-component breakdowns as stable statistics. Compute times are `std::chrono` wall-clock brackets on the host laptop, sensitive to OS scheduling, never averaged across trials. **Verified: CONFIRMED (critical).**

### C.2 CRITICAL — Headline numbers are irreproducible and internally contradictory

- The Evaluation/abstract/conclusion report **Phase-2 SPONGENT = 14.044 ms** and swarm total **794.52 ms**. But the **Comparison section (line 937/953) and the entire Hardware Projection section (lines 1100/1105) still use the pre-revision 7.37 ms / 727.8 ms.** SHA3 is likewise **0.699 ms** in Eval vs a stale **0.67 ms** in the comparison tables (lines 383, 936).
- Neither value matches the archived CSV (`simulations/results`: 7.456 ms; `final results`: 7.368 ms). So **one quantity appears as three different numbers** (14.044 / 7.37 / 7.456), and *Section VII flatly contradicts Section V.*
- The **conference version is internally consistent** (uses 14.044/794.5 everywhere) — so the journal specifically *regressed* by updating the abstract/eval but not the downstream tables. The speedup multipliers (21×/11×) are computed against the stale 0.67 ms baseline.
- **This alone is a reject-and-resubmit at any venue.** **Verified: CONFIRMED (the internal contradiction) + partially-confirmed (repo mismatch).**

### C.3 CRITICAL — The measured pipeline is not the claimed pipeline

Follows directly from B.1–B.3: the BCH decoder is inert, the "PUF" is a PRNG, and SPONGENT is non-spec. The results therefore characterize a Hamming-threshold check over a PRNG, timed against an unoptimized sponge — **not the protocol the paper describes.**

### C.4 HIGH — Four of six configs were never run; scalability is arithmetic, and HighNoise is broken by construction

- Only `StadiumSHA3` and `StadiumSPONGENT` have result files. **`StadiumBoth`, `Baseline5UAV`, `Swarm20`, `HighNoise` have zero backing data.** The "End-to-End Swarm Authentication Time" table is per-UAV-mean × 10 and per-pair-mean × 45 arithmetic from the single 10-UAV run — **not a scalability measurement.**
- **`HighNoise` is broken by construction:** `UAVNetwork.ned` *hard-assigns* `pufNoiseLevel = 0.03` (a non-`default()` assignment), so the ini's `*.uav[*].pufNoiseLevel = 0.05` is **silently ignored** — a run would test 3% noise while claiming 5%. The same NED pattern kills the `${hashMode}` itervar: both `.sca` files record `itervar hashMode "sha3"` including the SPONGENT run, so **result-file provenance metadata is wrong.**
- **Evidence:** `simulations/UAVNetwork.ned` (`pufNoiseLevel = 0.03;`), `.sca` itervar vs recorded scalar; `export_omnet_csv.py` infers mode from a scalar to work around it. **Verified: CONFIRMED (high).**

### C.5 HIGH — "100% success" is statistically vacuous, and partly guaranteed by construction

10 Phase-2 exchanges + 45 pairs, one seed, one fixed 3% noise point deep inside the margin (expected 3.84 bit-errors vs threshold 24). A 95% upper bound from 10 Bernoulli trials still permits **~26% per-auth failure.** Combined with the circular token check (B.5), success at this benign point was a foregone conclusion. No seed sweep, no noise sweep, no threshold sensitivity. **Verified: CONFIRMED.**

### C.6 HIGH — Speedup claims are cross-platform

"21× faster than RSA-2048, 11× faster than ECC-256" compares **this work on x86-64 laptop** against RSA/ECC on **ARM Cortex-A72** and PUF baselines on **Raspberry Pi 4B** (the platform column admits it). The Discussion itself concedes SHA3 degrades 2–20× on ARM — which erases most of the claimed gap. Also, RSA-2048 "8–15 ms verify" is implausibly high (RSA *verify* is tens of µs) and is mis-cited to a PUF paper. **Verified: CONFIRMED (high).**

### C.7 MEDIUM — Network delay is a deterministic two-constant artifact

`phase2_mean_net_ms=0.6646` and `phase3_mean_net_ms=0.466822` are **byte-identical across both hash modes** (same seedset → same jitter draw). The `sendDirect` model has no CSMA/CA, RTS/CTS, ACKs, or retransmissions. The "95% network-bound" characterization is a property of two hand-set constants (0.1 ms processing, 6 Mbps), not an emergent result — and says nothing about the 45 concurrent Phase-3 handshakes that would collide at swarm scale. The paper *does* honestly disclose this as a lower bound. **Verified: CONFIRMED (medium).**

---

## Part D — Paper-level / presentation issues (fast, high-visibility fixes)

| # | Issue | Location | Severity |
|---|---|---|---|
| D.1 | "No key storage" ✓ in the security table contradicts the stored `Cred` + session keys (Storage section counts them) | table line 1006 vs `:984-990` | High |
| D.2 | "No public-key cryptography" contradicts the advertised optional Curve25519 PFS in the same sentence | abstract `:82-83` vs `:604-610` | Medium |
| D.3 | Citation `puf_uav_cross_domain` is **B. Li et al.** in the bibliography but labeled **"Chatterjee"** in three tables | tables `:380,945,973` vs `:1402` | Medium |
| D.4 | "279 B/pair beats PSK 256 B" compares **two handshakes (P2+P3) to one** | `:913-915` vs table `:968-976` | Medium |
| D.5 | BCH arithmetic impossible: "144-bit parity from 128-bit data" under a BCH(255,131,18) heading (parity should be 124) | `:277,671-672` | Medium |
| D.6 | Storage formula "560+40N" ≠ its own component sum "552+40N" | `:984-987` | Low |
| D.7 | Python reference README claims overheads (210/196 B) that "match paper targets" but the paper publishes 175/104 B; a reviewer opening the repo finds 406 B | `UAV-Authentication/README.md` vs paper | Medium |

---

## Part E — How good is this, honestly?

**What is genuinely good and worth keeping:**
- The **four-phase structure** is a clean, defensible way to organize enrollment → GS auth → peer auth → keying.
- **GS-free peer authentication** is a legitimately attractive goal for latency-sensitive swarms.
- The **hardware gate-equivalent (GE) angle** (~8,390 GE for the SPONGENT stack, ~5× smaller than the SHA3 config) is the freshest idea in the paper and the best candidate to build a defensible contribution around.
- The **Limitations section is unusually honest** — it already names the SPONGENT non-conformance, the Phase-3 `Cred` coarseness, the missing formal verification, and the missing MAC layer. This is a real strength and a good sign about the authors.
- The **OMNeT++ harness itself is solid** engineering (composite link-delay model, per-message timing instrumentation, dual-mode benchmarking).

**Where it stands:** you have a strong *engineering scaffold and an interesting hardware story* wrapped around *security claims that collapse under inspection* and an *evaluation that measures the wrong system with no statistics.* The good news is that the honesty in the Limitations section shows you already sense where the soft spots are — this report is largely a sharper, evidence-backed version of instincts you already have. Nearly every blocker is fixable with focused work; none of them are "the idea is wrong."

**Novelty caveat:** PUF-based UAV/FANET authentication is crowded (Gope, Alladi, Li, Chatterjee). A four-phase fuzzy-extractor + challenge-response scheme is standard. Your two potentially-novel angles are (a) genuinely PUF-rooted GS-free peer auth and (b) the rigorous software/hardware crossover study — but **(a) currently degrades to a group PSK and (b) rests on a broken artifact.** Fix those two and you have a real contribution; leave them and the delta over prior work is packaging.

---

## Part F — Your 5-item future plan: how to implement, and an honest reframing

> **Reframing first:** Items **1, 4, and 5 are not enhancements — they repair current defects that invalidate central claims.** Item **2 will most likely *shrink* your headline speedup** (necessary honesty). Item **3 is a genuine enhancement.** Do them roughly in the order F.5 → F.4 → F.1/F.2 → F.3 (verification drives the redesign; redesign drives new measurements).

### F.1 — Full-spec SPONGENT-160, verified against test vectors  *(effort: medium · impact: high · this is a FIX)*
- **Fix the permutation** in `src/crypto/SPONGENT.cc`: state (rate 16 + capacity 144), 80 rounds, PRESENT S-box, and pLayer `(j·40) mod 159` already match SPONGENT-160/160/16. Replace the fake round constants with the spec **7-bit LFSR `lCounter`** (initial value + feedback polynomial from Bogdanov et al., CHES 2011, Table 3) XORed into the LSBs, with its bit-reverse XORed into the MSBs, stepped each round. Keep `SPONGENT.h`'s interface unchanged so `HashWrapper`/Phase2-4 need no edits.
- **Generate ground-truth vectors** by compiling the reference C (SUPERCOP / original spongent code) locally, hash a fixed set (empty, "abc", random 128-/512-bit), and hard-code the digests into a new `tests/test_spongent.cc`; add a `make check` target next to `test_puf.cc`.
- **Optimize while you're there:** replace the per-bit `std::vector`-allocating `pLayer` with a precomputed 160-entry permutation table + nibble S-box LUT, so the measured software cost reflects a *competent* implementation.
- **Then:** rebuild → re-run `StadiumSPONGENT` → re-export → **propagate the new number to *all* tables** (this is the natural moment to kill the 14.044-vs-7.37 contradiction, C.2).
- **Risk (be ready for it):** the optimized, spec-correct number could shrink the software gap from 20–30× to single digits, weakening the crossover narrative. Report whatever it is — the hardware-GE story can carry the contribution.

### F.2 — Same-platform RSA-2048 / ECC-256 baselines via OpenSSL  *(effort: low · impact: high)*
- OpenSSL is already linked (`-lcrypto`), so no new dependency. **Tier 1 (do first):** `tests/bench_pki_baselines.cc` using `EVP_PKEY` — RSA-2048 sign/verify, ECDSA P-256 sign/verify, ECDH P-256 + X25519 derive — timed with the same `std::chrono` pattern, 1000+ iters, median + stddev; cross-check against `openssl speed`. **Tier 2 (stronger):** `src/protocols/BaselineSigAuth.{h,cc}` implementing a signature challenge-response over the *same* simulated network, driven by a new `authMode` param and `[Config BaselineRSA]`/`[Config BaselineECC]`.
- **Best move:** run both the baselines *and* your protocol's compute path on a **Raspberry Pi 4B / Cortex-A72** to give one honest embedded-platform column.
- **Risk (important):** on the same platform, RSA *verify* is ~tens of µs and ECDSA verify ~100–200 µs on x86 — and since SHA3-mode latency is 95% network, a same-network ECDSA handshake may be nearly as fast end-to-end. **The "21× faster" headline will likely not survive.** Pivot the selling point to **hardware footprint (GE), no-certificate operation, and the PUF root of trust** — a narrative rewrite, but a defensible one.

### F.3 — INET 802.11 MAC integration (≥1 experiment)  *(effort: high · impact: high · genuine enhancement)*
- Install INET 4.5.x against `~/omnetpp-6.3.0` (`opp_env install inet-4.5`). **Do not rewrite the nodes** — the protocol logic is transport-agnostic. Add thin adapter apps in `src/inet_apps/` (`UAVAuthApp`, `GsAuthApp`) extending `inet::ApplicationBase` with a `UdpSocket`, sizing packets to the real 175 B / 104 B payloads. New `UAVNetworkInet.ned` (10 `AdhocHost` + GS, `Ieee80211Interface` ad-hoc, `StationaryMobility` at the existing stadium coords), new `[Config Inet80211SHA3/SPONGENT]` plus a contention variant with background traffic — **all with `repeat=30`, which fixes C.1 for this experiment simultaneously.**
- **Payoff:** converts your admitted "lower bound" into a quantified claim (report mean + 95th-percentile delay under CSMA/CA with ACKs/retransmissions). **Risk:** latency rises to sub-5-ms under contention — honest, but requires updating abstract/conclusion/tables. Scope to the 10-UAV scenario.

### F.4 — Per-pair PUF-rooted Phase-3 (high-security mode)  *(effort: medium · impact: high · this FIXES A.3)*
- **Design (Kerberos-style, GS-mediated):** after Phase 2, GS derives per-pair `Cred_ij = KDF(K_master, i, j)` and delivers to UAV_i the set `{Cred_ij ⊕ h(SK_i‖j‖"pairkey"), MAC}` — **each pair key wrapped under the PUF-derived SK_i**, so possession is genuinely PUF-gated. Apply the *same* wrap+MAC to the legacy `Cred` path to repair the plaintext-M4 flaw at the same time.
- **Code:** new `src/protocols/Phase3PeerAuthPUF.{h,cc}` keyed by `Cred_ij`, with **per-role domain tags** (fixes A.7) and an HMAC construction `h(k‖h(k‖m))` instead of unkeyed hash; add a `peerCredentials` map to `UAVNode.h`; extend GS to wrap the pair set in M4/M5. New `peerAuthMode` param + `[Config StadiumPUFPair]`.
- **Evaluate side-by-side:** latency delta (≈one extra hash), overhead growth (+20 B/peer), storage delta, and the **security delta quantified**: capture of UAV_k now compromises only (N−1)/C(N,2) of links vs 100%. Add `tests/test_capture.cc` (leak one NVM → forgery succeeds against legacy mode, fails cross-pair in the new mode).
- **Risk:** it is still *stored-wrapped-credential* based, not literally per-pair PUF evaluation (peers can't evaluate each other's PUFs) — **phrase carefully** or reviewers will call it "PSK with extra steps." O(N²) distribution hurts the 100-UAV story (mitigate with on-demand tickets).

### F.5 — Formal symbolic verification  *(effort: high · impact: high · this will EXPOSE that Thms 1/3/4 are false — start it FIRST)*
- **Use Tamarin, not ProVerif:** the protocol needs XOR (`R ⊕ h(N₂)`), which Tamarin supports natively (ProVerif doesn't), and stateful one-time CRP consumption, which Tamarin's multiset rewriting models directly.
- **`verification/uav_puf.spthy`:** model `h` as a free function, each PUF as a private per-device function `puf(~seed, c)`, all wire messages public, the GS CRP database as linear facts consumed per authentication. **Lemmas:** injective agreement both directions (Phase 2 & 3), secrecy of SK_i and SK_ij, plus **compromise scenarios** (reveal `Cred`, reveal one NVM).
- **Expected first run:** Tamarin **finds the known attacks** (forgeable β₁ GS-impersonation, M4 `Cred` interception, Phase-3 insider impersonation). Use the traces to drive the concrete repairs from Part A.9, patch spec+code together, and re-verify until all lemmas pass. Ship the `.spthy`, a `scripts/run_tamarin.sh`, and the proof output.
- **Payoff:** converts your *weakest* section into your *strongest* (a lemma/result table, "verified, Tamarin 1.10", cited artifact). **Risk:** XOR+hash reasoning can diverge (may need oracle heuristics or to abstract the mask as `senc(R, h(N₂))` — disclose the abstraction). Noisy PUF matching can't be modeled symbolically — model the noiseless idealization and say so.

---

## Part G — Additional work that would materially strengthen the paper

Ranked by impact-per-effort. The first three are effectively **mandatory** alongside your 5 items.

1. **[MANDATORY] Fix the internal-number contradictions and re-derive all speedups** *(low effort, high impact).* Script the LaTeX table rows from `omnet_summary.csv` so numbers can't diverge again; grep the `.tex` for every stale literal (7.37, 727.8, 0.67, 28.1) and regenerate; fix the storage formula and the "144-bit parity" error. This is the highest-leverage single fix in the whole project. *(See C.2, D.5, D.6.)*
2. **[MANDATORY] Repair the BCH extractor (or swap in `libcorrect`/`bchlib`) and prove it corrects errors** *(medium, high).* Add `tests/test_bch.cc` asserting: 0-error → errCount 0; ≤t errors → exact recovery; t+1 → detected failure. Re-key both sides from the *corrected* response and remove the distance-24 crutch. Actually wire the claimed `USE_LIBCORRECT` macro into the Makefile or delete the claim. *(Fixes B.1.)*
3. **[MANDATORY] Replace unkeyed hashes + plaintext `Cred` with real keyed primitives** (HMAC for α/β/γ/τ under PUF-rooted keys; AES-GCM/ChaCha20-Poly1305 for M4; bind ephemeral pubkeys into the transcript MAC; remove the silent no-DH fallback) *(high, high).* This is the code half of the Part-A redesign. Note it means the scheme is no longer "hash/XOR only" — update the contribution framing honestly. *(Fixes A.1, A.3, A.4.)*
4. **Statistical rigor: ≥30 seeds + 95% CIs, and a PUF+BCH reliability sweep** *(medium, high).* Add `repeat = 30` + seed sweep; make `analyze_results.py` emit mean ± CI; sweep `pufNoiseLevel` 0–10% and plot **FRR/FAR vs noise** with the t=18 threshold marked; report empirical decode-failure rate vs the analytic 10⁻¹⁵. Fix the NED hard-assignment first (C.4). *(Fixes C.1, C.5.)*
5. **Run an actual adversary simulation** *(medium, high).* An `AttackerNode` module that executes replay, GS-impersonation (the A.2 oracle), passive `Cred`-sniffing, and MITM — reporting attack success **before and after** the G.3 fixes. This operationalizes Theorems 1–5 and is far more convincing than pen-and-paper proofs. Pair it with G.3 so you publish the *defended* version.
6. **Real Arbiter-PUF model + ML-modeling-attack curve** *(medium, medium).* Wire up the existing delay model (or adopt `pypuf`), use true Bernoulli(p) noise, and plot modeling-attack accuracy vs #CRPs — directly bounding Assumption 2/3 and the A.2 oracle severity. This may push you toward an XOR-Arbiter/interpose-PUF; let the curve make that choice evidence-based. *(Fixes B.2.)*
7. **Reproducibility artifact ("make reproduce") + Zenodo DOI + artifact-evaluation badge** *(medium, high).* One command that builds, runs all six configs with the seed sweep, exports CSVs, and regenerates every table/figure from those CSVs; pin the toolchain in a Dockerfile; remove committed `__pycache__`; add `.gitignore`. Forces internal consistency and materially helps acceptance.
8. **Key revocation / re-enrollment for CRP depletion & post-capture recovery** *(high, medium).* Specify a CRP-replenishment sub-protocol and a `Cred`-rotation/revocation broadcast; simulate a capture event showing impersonation success drops to 0 after rotation. Closes the A.6 lifecycle gap.
9. **UAV mobility model** *(high, medium).* Replace static perimeter coordinates with waypoint/linear mobility + a range gate; report success and latency-vs-distance. Static positioning is a credibility gap for a UAV paper.
10. **Energy/power model** *(medium, medium).* Per-primitive nJ/byte (from the same synthesis sources as the GE counts) + radio TX/RX energy → mJ per authentication and "auths per charge." This substantiates the SPONGENT-on-hardware value proposition that the *software* timings actively undermine.
11. **DoS-resistance evaluation** *(medium, medium).* M1-flooding CRP-exhaustion, ±5 s window replay, Phase-3 flooding — plus mitigations (client puzzle before CRP fetch, per-TID rate-limit, nonce cache, Phase-3 timestamps). *(Addresses A.6.)*
12. **Refresh + correct the related-work comparison** *(low, medium).* Fix "Chatterjee"→"Li et al." in three tables; add 3–5 recent (2023–2025) PUF-UAV/FANET baselines with a platform column per row; re-check every "✓" in the security table (qualify "No key storage"). *(Fixes D.1, D.3.)*

---

## Part H — Recommended roadmap to a submittable paper

The dependencies matter: verification exposes the flaws, the redesign fixes them, and only then do new measurements mean anything.

**Phase 1 — Correctness foundation (do before writing anything new):**
1. G.1 (reconcile all numbers) — a few days, unblocks everything.
2. F.5 start (Tamarin model of the *current* protocol) — confirms which theorems fail and produces attack traces.
3. G.2 (repair/replace BCH + tests) and B.2 fix (real PUF or honest relabel).

**Phase 2 — Protocol redesign (the actual contribution):**
4. Part A.9 redesign, realized as G.3 (keyed MACs, AEAD M4) + F.4 (per-pair PUF-rooted Phase 3).
5. Re-verify in Tamarin (F.5 finish) until all lemmas prove; add the regression that re-introducing plaintext-M4 breaks the `Cred`-secrecy lemma.
6. G.5 adversary sim showing attacks succeed pre-fix, fail post-fix.

**Phase 3 — Honest measurement:**
7. F.1 (spec SPONGENT + vectors), F.2 (same-platform baselines), G.4 (30 seeds + CIs + noise sweep), C.4 fixes (run the four missing configs; fix the NED override).
8. F.3 (one INET 802.11 experiment) if time allows — high credibility payoff.

**Phase 4 — Package:**
9. G.7 (reproducibility artifact + DOI), D.1–D.7 presentation fixes, rewrite abstract/contributions to match the *fixed* claims, G.12 (refresh related work).

**Realistic scope guidance:** Phases 1–2 + the mandatory parts of Phase 3 (F.1, F.2, G.4) are the **minimum for a credible mid-tier conference resubmission.** Adding F.3, F.4's full evaluation, G.5, G.6, and G.7 gets you to **journal (TVT-class) quality.** Do **not** submit anywhere before Phase 2 is done — the mutual-authentication claim being false by your own equations is the one thing no reviewer will forgive.

---

## Appendix — Confidence & provenance

- Every "critical/high" finding was **independently re-verified against the actual repository files** by a dedicated adversarial-checker pass instructed to *refute* it. **Of ten high-severity claims checked, all came back CONFIRMED or PARTIALLY-CONFIRMED; none were refuted.**
- Two findings are *partially* confirmed with important nuance: (i) the SPONGENT slowdown is real, but its "lightweight" story survives *as a hardware projection* — don't overstate it as fully false; (ii) the "irreproducible numbers" claim is nuanced by the existence of two result directories — the *internal* 14.044-vs-7.37 contradiction is unambiguous, the repo mismatch depends on which directory is canonical.
- Line numbers reference `research paper/uav_puf_journal.tex` and files under `src/` as of this audit. If you renumber during edits, re-locate by the quoted tokens.
- Primitives were tested empirically where feasible: the BCH codec was compiled standalone and failed 200/200 decode trials; the PUF test reports intra-chip HD 5.73%.
