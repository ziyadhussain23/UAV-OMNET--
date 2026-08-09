# Specification deviations

Points where the implementation departs from `revised_theory/paper.tex`, with the
reason. Each needs a corresponding edit to the `.tex` in the post-implementation
pass; the code is not bent to match a text bug.

## 1. The fuzzy extractor runs before M1, not at M3

**Paper:** Phase 2, step 4 — the UAV regenerates `mk_i` when it receives M2.

**Implementation:** the UAV regenerates `mk_i` before it sends M1.

**Why:** `σ1` in M1 is a MAC keyed by `K_auth = KDF(mk_i; "p2-auth")`. The UAV
cannot produce M1 at all without `mk_i`, so deriving it at step 4 is not
realisable. This is an internal inconsistency in the paper, not a design choice.

**Effect on the security argument:** none, and the verify-before-respond
corollary is if anything strengthened. The challenge is fixed at enrollment and
stored on the device, so a fraudulent ground station cannot choose it; and the
UAV still emits nothing until `σ2` verifies. Measured: 0/200 forged M2 messages
elicited any reply.

**Metric consequence:** `puf_eval_ms` and `fe_rep_ms` are attributed to M1 rather
than M3. The scalar names are unchanged.

## 2. `TID_new` moves inside the M4 AEAD

**Paper:** `M4 = ⟨AE.Enc_{SK_i}(CredPkg), TID_i^new⟩` — the rotated identity is
sent alongside the ciphertext, unauthenticated.

**Implementation:** `TID_new` is part of the AEAD plaintext.

**Why:** as written, an attacker can flip the identity in flight and permanently
desynchronise the UAV from the ground station. It costs nothing to authenticate.

**Mitigation also implemented:** the ground station indexes records by both the
current and the pending TID, so a lost M4 does not strand a device.

## 3. SPONGENT parameters

**Paper:** SPONGENT-160 with the implementation's original rate/capacity.

**Implementation:** SPONGENT-160/160/16 — state 176 bits, rate 16, capacity 160,
90 rounds.

**Why:** the previous code used capacity 144 with 80 rounds, which matches no
published SPONGENT variant (so no test vector could ever pass) and implies only
72-bit security. Capacity 160 gives the 80-bit level a 160-bit hash should have.
The paper should state the spongent profile as an explicit 80-bit
constrained-hardware profile, deliberately asymmetric with the 128-bit X25519 and
AEAD components.

## 4. Decode-failure probability

**Paper:** "decode-failure probability < 10⁻¹⁵" for BCH(255,131,18) at 3% BER.

**Measured:** with 255-bit blocks and L = 4, the per-block failure probability at
3% BER is ≈3×10⁻⁴ and the system FRR ≈1.2×10⁻³. The claim is unreachable with a
single-layer code.

**Resolution:** three selectable profiles are implemented, and the measured FRR
curve is reported rather than the analytic claim:

| profile | code | L | FRR @3% BER |
|---|---|---|---|
| `bch255-131-18` (default, paper parameters) | BCH(255,131,18) | 4 | ≈1.2e-3 |
| `bch255-91-25` | BCH(255,91,25) | 5 | ≈4e-7 |
| `rep3-bch255-131-18` | [3,1,3] ⊕ BCH(255,131,18) | 5 | <1e-15 |

This turns a wrong claim into a result: the paper's parameters give 1.2e-3, and a
repetition inner code at 3× PUF cost reaches the reliability originally claimed.
It also keeps the default FRR measurable — 1e-15 is unobservable in any feasible
Monte Carlo, so the noise sweep would otherwise be vacuous.

**Verified end to end:** at 5% BER the measured FRR is 0.193 against a binomial
prediction of 0.205, which is only possible if error correction is genuinely
happening.

## 5. Response block size

**Paper:** 128-bit PUF responses.

**Implementation:** 255-bit response blocks (matching the BCH block length).

**Why:** the code-offset sketch leaks up to n−k = 124 bits per block. A 128-bit
block therefore contributes at most ~4 bits of residual entropy — and none at all
at a realistic min-entropy rate — so the key budget cannot be met. With 255-bit
blocks each contributes ~118 bits at rate 0.95, and L = 4 gives 473 ≥ 384.

Consequently the paper's remark that "128 × 0.03 ≈ 3.84 expected flips, well
within t = 18" should read 255 × 0.03 ≈ 7.65.

## 6. Measured min-entropy vs the assumed rate

The PUF characterisation found that the NIST SP 800-90B MCV estimator's 99%
confidence correction alone caps the *corrected* min-entropy rate of any source —
including a perfect one — at about 0.854 bit/bit when measured over 1000 devices.
Reaching a corrected rate of 0.95 requires roughly 10⁴ devices.

The fuzzy extractor's default `assumedMinEntropyRate = 0.95` is therefore
justifiable only from a large-population measurement. Measured values:

| source | corrected MCV (D=1000) | uncorrected MCV (D=40000) |
|---|---|---|
| uniform reference | 0.8522 | 0.9939 |
| ideal PRF model | 0.8544 | 0.9924 |
| arbiter (128-stage) | 0.8562 | 0.9952 |

Both the corrected and uncorrected rates are exposed on `EntropyEstimate`. If the
paper wants to claim 0.95 it must cite a measurement at D ≈ 10⁴; otherwise the
assumed rate should be lowered, which costs one extra block (L = 5 rather than 4
at rate 0.854).

Separately: no bit-level entropy estimator can see an arbiter PUF's real
weakness, since each response bit is a linear function of 129 delay weights and
about 129 challenge–response pairs suffice to model the device. That is a
property of the challenges, not of the response bits, and it is the reason the
protocol never exposes a response.

## 7. The speed comparison does not survive same-platform measurement

`tests/bench_pki_baseline.cc` measures RSA, ECDSA, ECDH and X25519 with the same
OpenSSL build, on the same host, using the same clock as the protocol. Median
per-operation cost (OpenSSL 3.5.5, x86-64):

| operation | median |
|---|---|
| RSA-2048 verify | **33 us** |
| RSA-2048 sign | 1049 us |
| ECDSA P-256 sign | 44 us |
| ECDSA P-256 verify | 109 us |
| ECDH P-256 derive | 91 us |
| X25519 keygen | 66 us |
| X25519 derive | 126 us |
| our hash160 | 1.0 us |
| our MAC | 3.8 us |
| our KDF | 8.0 us |
| our AEAD seal | 1.2 us |

Two consequences, both of which contradict the earlier manuscript.

**The "8-15 ms for RSA-2048 verification" figure is wrong by two orders of
magnitude.** Verification with a small public exponent costs 33 us here. Any
speedup multiplier derived from that figure — the "21x faster than RSA" headline
among them — has to go.

**This protocol is not dramatically faster than ECC; it is comparable.** Each
handshake performs an X25519 keygen plus a derive, about 190 us of public-key
work, against roughly 91-155 us for an ECDH or ECDSA exchange. Once the mandatory
ephemeral exchange is included — and it is mandatory, because forward secrecy
depends on it — the protocol sits in the same performance class as the schemes it
was previously claimed to beat by an order of magnitude.

The defensible claims are therefore about properties, not speed:

- no long-term secret is stored on the device (the master key is regenerated from
  the PUF on demand), so a captured drone yields no key material;
- no certificate or PKI infrastructure is required;
- peer authentication needs no ground-station round trip;
- a captured node's exposure is bounded to its own N-1 links;
- the symmetric core is small (hash 1.0 us, MAC 3.8 us), which is what matters for
  a hardware target, and the gate-equivalent argument is unaffected.

The evaluation section should be rewritten around those, with the same-platform
table above replacing the cross-platform citations.

## 8. The repetition inner code was initially wrong, and the sweep caught it

Worth recording because it is the clearest example of the measurement finding a
bug rather than confirming a claim.

The first implementation of the `rep3` profile majority-voted three *consecutive
PUF bits*. That is not a repetition code: those are three independent physical
bits, not three noisy measurements of one bit, so voting them reduces no noise and
actively destroys reliability. Measured FRR at 5% BER was **0.960**, against a
prediction of essentially zero -- a discrepancy large enough that it could only be
a defect.

The correct construction fixes a reference at enrollment, publishes each copy's
offset against that reference as helper data, and in the field un-offsets the
copies before voting, so every copy really is a measurement of the same value. The
error rate then falls from p to about 3p^2. After the fix the same measurement gave
**0.000**.

Two lessons for the write-up. First, a concatenated fuzzy extractor needs the inner
code to act on repeated measurements, which costs `rep` PUF evaluations per outer
bit -- the 3x cost is intrinsic, not an implementation artefact. Second, the inner
offsets are additional public helper data, so the leak accounting has to include
them: `HelperData::leakBits()` charges `(rep-1)` bits per outer bit on top of the
outer code's `n-k`.
