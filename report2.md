# Report 2 — Theory Readiness Check: Can We Start Implementation?

**Question:** Is the theory in `revised_theory/` now sound and complete enough to begin implementation?

**Verdict: YES — the theory is GREEN. You can proceed to implementation.**

Every theory-level flaw identified in `REPORT.md` **Part A (A.1–A.8)** is resolved in
`revised_theory/paper.tex` (and its siblings `uav_protocol_theory.tex`,
`uav_puf_protocol.tex`). The protocol is now cryptographically coherent: all six security
theorems are sound as stated, and none of the earlier "provably false" theorems remain.

The only caveats are **not theory flaws** — they are concrete engineering decisions you must
pin down *as you code* (Section 3). Handle those and the implementation will faithfully realize
the theory.

---

## 1. Flaw-by-flaw resolution (REPORT.md Part A → paper.tex)

| Ref | Original theory flaw | Status | How it is resolved in the theory |
|-----|----------------------|--------|----------------------------------|
| **A.1** | GS→UAV auth non-existent (unkeyed hashes) | ✅ **Resolved** | Every message is a **keyed MAC** under `K^i_auth = KDF(mk_i; "p2-auth")`; only the genuine PUF holder or the GS can produce it. |
| **A.2** | Chosen-challenge PUF read-out oracle | ✅ **Resolved** | **Verify-before-respond** (UAV aborts silently on bad `σ₂`) + the **raw PUF response never leaves the device** (consumed inside `Rep`). See Cor. "No PUF read-out oracle." |
| **A.3** | Swarm-wide `Cred` sent in plaintext | ✅ **Resolved** | **Per-pair** `Cred_ij = KDF(mk_GS; "pair-cred"‖i‖j)`, delivered under **AEAD** (`AE.Enc_{SK_i}`). Capture of one node exposes only its `N−1` links. |
| **A.4** | No forward secrecy / silent no-DH fallback | ✅ **Resolved** | **Mandatory** authenticated ephemeral X25519 folded into every session key; **fails closed** if absent. Thm. "Perfect forward secrecy." |
| **A.5** | Helper-data "independence" claim is wrong | ✅ **Resolved** | Restated correctly as a **min-entropy bound** `H̃∞(R\|P) ≥ m−(n−k)` (Lemma "Helper-data privacy") + the enrollment **entropy-budget inequality** Eq. (budget). |
| **A.6** | CRP exhaustion + unauthenticated M1 | ✅ **Resolved** | **Stable, reusable** `mk_i` (one enrollment → unlimited authentications, no CRP pool to drain); **M1 is now MAC-authenticated**. |
| **A.7** | Phase-3 reflection / key-confusion | ✅ **Resolved** | Per-message **type tags** (`P1/P2/P3`), **nonces + timestamp**, and **separate KDF labels** for the session key vs. the authenticator. |
| **A.8** | "Security analysis" was informal / false premises | ✅ **Resolved** | Six theorems reduced to standard assumptions (EUF-CMA MAC, IND-CCA/INT-CTXT AEAD, PUF unpredictability, gap-CDH) + a described **Tamarin** symbolic model. |

**Security posture now (compare to REPORT.md A.9):**

| Property | Before | Now |
|----------|--------|-----|
| Phase-2 mutual auth | ❌ False | ✅ Sound (keyed MAC both directions) |
| Replay / MITM | ⚠️ Weak | ✅ Sound (nonces + timestamps + type tags + transcript) |
| Phase-3 peer auth | ❌ False | ✅ Sound (per-pair credential, no group PSK) |
| Physical-capture resistance | ❌ Undermined | ✅ Sound (no stored key; `N−1` blast radius) |
| Helper-data assumption | ❌ Unsound | ✅ Correct min-entropy bound |
| Forward secrecy | ❌ Absent | ✅ Mandatory authenticated DH |

---

## 2. Is the theory "perfect"? — one honest note

The **protocol design** is complete and sound. Two things are *described but not yet produced*,
and one narrative point must stay consistent — none block starting implementation:

- **Tamarin model is written up, not yet run.** `paper.tex` describes the model and lemmas; the
  actual `.spthy` file and proof output do not exist yet. Not needed to start coding, but needed
  before the paper can claim "mechanically verified." (Build + run it in parallel with, or after,
  implementation.)
- **The protocol is no longer "symmetric-only."** Mandatory X25519 means it now uses one
  public-key primitive. `paper.tex` already says "…and one elliptic curve" consistently — just
  keep every future claim/table aligned with that (don't reintroduce a "no public-key crypto"
  line).

---

## 3. Pre-implementation checklist (pin these before/while you code)

These are the concrete specs the theory intentionally leaves open. They are the *implementation
work itself* — decide them explicitly so the code matches the proofs.

### 3.1 Concrete primitive suite (fixes REPORT B.1–B.4 at the code level)
- **Hash `h`:** SHA3-256 truncated to 160 bits (OpenSSL EVP) **and** a **spec-compliant**
  SPONGENT-160 verified against official test vectors (the previous SPONGENT was non-conformant).
- **MAC:** a real keyed MAC — **HMAC-SHA3** (or a keyed sponge). Never bare `h(...)`.
- **AEAD:** choose one concretely — **Ascon-128a** or ChaCha20-Poly1305 (libsodium). Used for M4
  credential delivery.
- **KDF:** **HKDF** (Extract-then-Expand) over the chosen hash; the strong extractor `Ext` = HKDF-Extract
  with the enrollment `seed` as the salt.
- **Curve:** **X25519** (libsodium). Generate a fresh ephemeral keypair per handshake; **erase the
  scalar after use** (required for the forward-secrecy proof to hold).

### 3.2 Fuzzy extractor — the one genuine theory→implementation gap
- Replace the broken from-scratch codec (REPORT B.1) with a **verified BCH(255,131,18)** (e.g.
  `libcorrect` or `bchlib`). Unit-test it: 0 errors → identical `mk`; ≤ t=18 errors → identical `mk`;
  > t → detected failure.
- **Choose `L`** (number of PUF response blocks) from the entropy budget
  `Σ(m_b − 124) ≥ ℓ + 2log(1/ε)`. This depends on the **measured per-block min-entropy `m_b`** of
  your PUF — a single 128-bit block cannot yield a 256-bit key after the 124-bit sketch leak, so
  `L ≥ 2–3` in practice. Measure `m_b`, then fix `L`.
- Define how the 128-bit response maps into the 131/255-bit codeword (pad/shorten) — document it.

### 3.3 Realistic PUF (fixes REPORT B.2)
- Replace the PRNG "PUF" with an actual **Arbiter/RO delay model** (or `pypuf`), driven by
  **Bernoulli(p) per-bit noise**, so the fuzzy extractor is exercised for real and modeling-attack
  behavior is meaningful.

### 3.4 State & robustness details (correctness, not new crypto)
- **Replay cache:** GS and UAVs keep a bounded nonce cache with timestamp-window eviction.
- **TID resync:** if M4 is lost, GS and UAV desynchronize on `TID_i^new`; implement a fallback
  (accept the old TID until the new one is confirmed, or index the record by `ID_i`).
- **Phase-3 precondition:** both peers must have completed Phase 2 and hold `Cred_ij` before their
  peer handshake — enforce this ordering.
- **GS DB:** store `mk_i` and `mk_GS` in the tamper-resistant store; never expose them.

---

## 4. Recommended implementation order

1. **Primitives first** (Section 3.1) with unit tests + SPONGENT/BCH test-vector checks.
2. **Fuzzy extractor + real PUF** (3.2, 3.3); prove round-trip + noise sweep before wiring the protocol.
3. **Phase 1 → 2 → 3 → 4** in order; assert `mk_i` regenerates identically on the UAV and matches the GS.
4. **Adversary tests** — replay, GS-impersonation, `Cred`-sniffing, MITM — expected to **fail** now
   (this operationalizes the theorems and is your strongest evidence).
5. In parallel: author + run the **Tamarin** `.spthy` so the "mechanically verified" claim is real.

---

## Bottom line

**Go.** The theory resolves every Part-A flaw and is internally consistent; there is no remaining
theoretical hole that would make implementation build on sand. Start implementing to the spec in
`revised_theory/paper.tex`, pin the primitive suite and the fuzzy-extractor parameters (`L`, block
mapping) early, and keep the code, the paper, and (eventually) the Tamarin model describing the
**same** protocol.
