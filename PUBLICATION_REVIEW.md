# Publication Review: Is This Paper Ready?

A deep, honest assessment of `final_theory/paper.tex` and the codebase behind it,
written after re-reading the full paper, re-running the test suite, re-running the
number audit, and checking every claimed artifact on disk. Old implementation and
old theory are ignored as requested.

**Short answer: yes, this is publishable material, but not tomorrow.** The core
work is genuinely strong, stronger than a typical student submission. There is
one integrity-level blocker you must fix before any submission, a handful of
things reviewers will definitely attack, and a clear path to a good venue.

---

## 1. What I verified myself (not taken on trust)

| Check | Result |
|---|---|
| Test suite (`tests/run_tests.sh`) | 12 suites, all pass, includes the 18,000-trial BCH sweep and 0/200 forged-M2 oracle check |
| Result files on disk | 30 `.sca` per main config (10 configs), 5 per attack config (4), 63 for NoiseSweep, 30 each for both INET configs. Matches the paper exactly |
| `scripts/audit_paper_numbers.py` | Every table number (functional, latency, phase-3, primitives, attacks, mobility, INET, baselines) matches the CSVs |
| Tamarin model file (`*.spthy`) | **Does not exist anywhere in the repo** |
| Paper builds | `paper.pdf` present, 31 pages, compiles clean |

So the measurement story is real and reproducible. The problem list below is
about presentation, one false claim, and venue fit, not about the data.

---

## 2. Why this paper is good (genuine strengths)

These are things most submissions in this space do NOT have, and they are your
selling points in a cover letter and rebuttal:

1. **A falsifiable security evaluation.** The ablation config
   (`AtkLegacyGsImpersonate`) proves the attacker code actually works, so the
   0/40 impersonation result is evidence rather than an untested assumption.
   Reviewers in security venues notice and reward this; almost nobody does it.

2. **Statistics done correctly.** Two-stage confidence intervals with the run as
   the replication unit, Wilson intervals for proportions, rule-of-three bounds
   instead of claiming "100% reliable". This is above the bar for most
   networking papers.

3. **Honest negative results, stated in the abstract itself.** The paper openly
   says it is 3.2x slower than ECDSA and that the win is the property (no stored
   secret), not speed. This reads as credible, and it preempts the most obvious
   reviewer attack. The retraction of the "21x faster than RSA" folklore figure
   (measured 33 us, not 8-15 ms) is itself a small contribution.

4. **The reliability sweep validates the implementation.** 20 of 21 measured
   FRR points inside the binomial prediction's CI across four orders of
   magnitude is strong evidence the BCH decoder genuinely corrects errors. A
   broken decoder cannot track that curve.

5. **Primitives verified against published vectors.** FIPS 202, RFC 5869, RFC
   8439, RFC 7748, all 1,089 Ascon KAT vectors, byte-exact SPONGENT vs the
   reference implementation, with the SPONGENT caveat stated honestly.

6. **Real baselines, same platform.** Full RSA-signed and ECDSA-signed
   ephemeral-DH protocols run through the same simulator, not cherry-picked
   cross-platform literature numbers. Plus a separate INET 802.11 track that
   quantifies the idealized-medium gap (7.8x) instead of hiding it.

7. **Clean layered implementation.** Protocol logic has zero simulator
   dependency, one canonical encoder feeds wire, MAC, and byte-count so those
   can never disagree, the entropy budget is a runtime assertion, and the fuzzy
   extractor fails closed. `docs/spec-deviations.md` documenting all 8
   deviations is exemplary research hygiene.

8. **The comparison table (Table 1) holds up.** Against Gope, Li, Khan, Bera,
   PSK, RSA, ECC, this really is the only design with PUF root + peer auth + no
   stored key + mandatory PFS + error correction + a games-plus-symbolic
   argument. The novelty claim is defensible.

---

## 3. The one blocker you MUST fix before submitting

### The Tamarin claim is currently false as written

The abstract says the theorems are "mirrored by a symbolic model in the Tamarin
prover" and Section 5.9 says "The prover discharges lemmas that correspond
one-to-one with the theorems above."

**No `.spthy` file exists in this repository. The prover has never been run.**
`REPORT4.md` itself lists "Run the Tamarin proof for real" as open work.

This is not a weakness, it is a false claim of machine-checked verification.
If a reviewer asks for the model (they routinely do), or the venue has artifact
evaluation, this becomes an integrity problem that kills the paper and worse.

You have exactly two honest options:

- **Option A (strongly recommended): actually write and run the model.** The
  protocol is a standard MAC-authenticated DH handshake with credential
  issuance; this is squarely inside Tamarin's comfort zone. Expect roughly
  300-500 lines of `.spthy`: rules for enrollment, M1-M4, P1-P3, an NVM-reveal
  rule, a post-session reveal rule, and 6 lemmas (injective agreement x2,
  no-replay, capture isolation, key secrecy, forward secrecy). This converts
  the paper's weakest sentence into one of its strongest sections and unlocks
  better venues.
- **Option B: reword everywhere.** Change "the prover discharges" to "we
  specify a symbolic model suitable for Tamarin; mechanised verification is
  future work", and delete "mirrored by ... Tamarin prover" from the abstract,
  contributions list, Table 1's "Games + symbolic" cell, and the conclusion.
  This is honest but visibly weakens the formal-proof column that
  differentiates you from Gope/Li/Khan/Bera ("Informal").

Do not submit with the current wording under any circumstances.

---

## 4. Things reviewers will attack (fix or pre-empt)

### 4.1 The bibliography needs a verification pass
Several entries look unverifiable or garbled and a desk editor may spot-check:

- `puf_ntu`: author given as "National Technological University" with venue
  "DR-NTU Technical Report Series". DR-NTU is Nanyang Technological
  University's repository, not a report series, and an institution is not an
  author. This one reads fabricated as written.
- Several entries have suspiciously generic titles and untraceable metadata
  (`securing_uav_fanet`, `lightweight_crypto_evaluation`, `arbiter_puf_iot`,
  `puf_key_exchange`). Check each against a real DOI.
- Delvaux et al. TIFS citation: verify the exact title/volume (his well-known
  paper is "Helper Data Algorithms for PUF-Based Key Generation").

Action: DOI-verify all 28 entries, replace anything you cannot trace with a
paper you have actually read. One fabricated reference can sink the submission
on its own. Also: 28 references is thin for a journal; 40-55 is typical. The
related-work section is only ~1 page and needs deepening for a journal.

### 4.2 No real PUF hardware
Everything rests on simulated PUFs (ideal PRF, arbiter model, XOR-arbiter).
The arbiter model is well built (delay-domain noise, 98x flip-rate variance,
measured inter-device HD 0.502), but a top security venue (CCS, S&P, USENIX,
NDSS, WiSec) will likely say "no silicon, no deal". This bounds your venue tier
rather than blocking publication. Say clearly in limitations that validation on
FPGA/SRAM PUF hardware is future work (the paper already does; keep it).

### 4.3 No ML modeling-attack evaluation
The paper's own threat model says PUF responses are unpredictable given
polynomially many CRPs, and arbiter PUFs are famously learnable from ~129 CRPs.
Your defence is architectural (responses never leave the device, no oracle),
which is correct, but a reviewer in this exact subfield will ask for the
modeling-attack curve anyway. This is cheap to add: `pypuf` is already in the
Python reference tree. Train logistic regression / LR-attacks on your own
arbiter model at increasing CRP counts, plot accuracy, then state that the
protocol exposes zero CRPs so the curve's x-axis is unreachable for a network
adversary. One figure, one paragraph, closes the topic.

### 4.4 No DoS / resource-exhaustion discussion
An adversary can spam M1s to make the GS do MAC verifications, or spam P1s at a
drone. The replay cache is bounded, good, but nothing rate-limits the crypto.
At minimum add a paragraph: cost asymmetry per forged message (one cheap MAC
verify at 2.2 us, no PUF read, no DH until sigma verifies), plus the
nonce-cache bound. Ideally add one measured flooding config.

### 4.5 Missing protocol pieces a careful reader will notice
- **Revocation.** Theorem 8 bounds capture damage to N-1 links, but there is no
  mechanism to revoke a captured drone's `Cred_kj` set. One subsection
  describing GS-driven revocation (push new credential lists in the next M4, or
  a blacklist in the credential package) would close this.
- **Clock synchronization.** Freshness uses 32-bit timestamps and a window
  Delta-T, but the paper never states the sync assumption between drones (who
  have no GS during Phase 3). One paragraph needed.
- **Phase-3 anonymity is under-specified.** Phase 2 gets rotating TIDs, but the
  Phase-3 description MACs identities i, j without saying what identity the
  wire actually carries. If permanent IDs, the anonymity goal fails on the
  horizontal plane. Say explicitly that peers address each other by the TIDs
  delivered in the credential package.
- **GS as single point of failure.** All `Cred_ij` derive from `mk_GS`; GS
  compromise breaks the whole swarm. This is a fair design choice (GS is
  tamper-resistant by assumption) but deserves one honest sentence in
  limitations.

### 4.6 Stale internal numbers
- Section 6.7 says "nine test programs"; the runner now reports **12 suites**
  (baseline-sig-auth, signature-suite, wire-roundtrip were added later).
  Recount the assertions figure too.
- Sanity-check every count like this before camera-ready; you already have the
  audit script, extend it to cover prose counts.

---

## 5. Formatting / venue-mechanics problems

1. **The paper is formatted as a thesis, not a submission.** Institute title
   page with logo, roll number, supervisor block, table of contents, 11pt
   single-column article at 31 pages. No venue accepts this layout. You need:
   - IEEE journal: `IEEEtran` journal mode, roughly 11-14 double-column pages.
   - Conference: `IEEEtran` conference mode, cut to 6-10 pages (hard: you would
     drop the energy section, compress implementation, move KAT table and some
     proofs to an appendix or tech report).
2. **Bibliography style**: switch `thebibliography` to BibTeX with the venue's
   style file once you pick the target.
3. **Anonymization**: most security venues are double-blind; strip the title
   page, acknowledgments, and any identifying paths before submission.

---

## 6. Where to submit (realistic tiers)

Given: solid simulation study, correct statistics, real baselines, no hardware,
and (if you do Option A) a mechanised proof.

**Journals, best fit first:**

| Venue | Fit | Notes |
|---|---|---|
| Elsevier Vehicular Communications | Very good | UAV security papers with simulation-only evaluation are normal here |
| Elsevier Ad Hoc Networks / Computer Networks | Good | Protocol + OMNeT++ evaluation is the house style |
| IEEE Internet of Things Journal | Good but ambitious | High volume, likes PUF papers; wants the Tamarin proof done and richer related work |
| IEEE Trans. Vehicular Technology | Plausible | Wants stronger networking realism; your INET track helps |
| IEEE TIFS / TDSC | Stretch | Would want hardware PUF data or a deeper formal treatment |
| IEEE Access | Fallback | Fast, indexed, lower prestige |

**Conferences:**

| Venue | Fit |
|---|---|
| IEEE GLOBECOM / ICC (main track, CISS area) | Good target, 6 pages, deadline-driven |
| SecureComm, NSS, ProvSec | Good fit for the protocol+proofs framing |
| ACM WiSec | Stretch without hardware, but the ablation methodology would be appreciated |
| COMSNETS / IEEE ANTS | Solid regional options with decent visibility |

My honest recommendation: **do Option A (Tamarin) plus the reference audit and
the ML-attack figure, then submit to Vehicular Communications or IEEE IoT-J as
a journal paper.** The work's volume (31 pages of real content) is journal
shaped; squeezing it into 6 conference pages throws away most of what makes it
strong.

---

## 7. Priority roadmap

**P0, blocking, do before anything else**
1. Resolve the Tamarin claim (write + run the model, or reword everywhere).
2. DOI-verify all references; delete or replace anything untraceable.
3. Reformat for the chosen venue; kill the thesis title page.

**P1, high value, roughly a week each**
4. ML modeling-attack curve on your arbiter model (pypuf, one figure).
5. Revocation + clock-sync + Phase-3 identity paragraphs (writing only).
6. DoS cost-asymmetry paragraph, optionally one flooding config.
7. Deepen related work to ~15 properly-read PUF/UAV papers, expand Table 1.
8. Fix stale counts (12 test suites, assertion total).

**P2, strengthens acceptance odds, not required**
9. Reproducibility artifact: Dockerfile + one-command regeneration (many venues
   now award artifact badges; your repo is 90% of the way there already).
10. XOR-arbiter results as a second realistic PUF datapoint in the main tables.

**P3, future work, keep as stated limitations**
11. FPGA / real-silicon PUF prototype.
12. Side-channel analysis of the two vendored primitives.
13. Dynamic membership (join/leave mid-flight).

---

## 8. Bottom line

The engineering and evaluation are already above the median of published papers
in this niche: real statistics, falsifiable attacks, honest performance story,
verified primitives, documented deviations. What stands between you and a
submission is not more simulation work. It is one false sentence about Tamarin,
a bibliography that will not survive a spot-check, and thesis formatting.

Fix the P0 list and this is a credible journal submission. Add the P1 list and
it is a strong one.
