# What Was Built, Explained Simply

A plain-language walkthrough of the whole rewrite: what the problem was, what got
built, what the numbers say, and what still needs doing. No jargon without an
explanation.

---

## 1. The situation before this work

You had a research paper and a simulation for a system that lets drones prove who
they are to each other. The idea is genuinely good, and it uses a clever trick:
instead of storing a secret password on the drone (which a thief could read out of
a captured drone), each drone has a **PUF** — a chip whose tiny manufacturing
imperfections make it unique, like a fingerprint in silicon. The "password" is the
chip itself, so there's nothing stored to steal.

An audit (`REPORT.md`) then found that the paper's security claims did not hold and
the code did not do what the paper said. The three worst problems:

1. **The locks had no keys in them.** The protocol "signed" its messages by
   hashing values that were all visible on the wire anyway. That's like sealing an
   envelope with a stamp anyone can buy — it proves nothing about who sent it.

2. **A fake ground station could interrogate a drone.** Because the drone never
   checked whether the ground station was real, an attacker could impersonate it
   and ask the drone to run its PUF over and over. Collect enough answers and you
   can build a software copy of the fingerprint — defeating the entire point.

3. **The error-correction code did nothing.** PUF readings are slightly noisy, so
   an error-correcting code is supposed to clean them up. The implemented one was
   mathematically broken: it never corrected anything and just handed back the
   noisy input while reporting success. The system appeared to work only because a
   loose tolerance check let it through.

Plus: results came from a single simulation run (so no error bars), and the speed
comparison put this system's laptop timings against other papers' numbers measured
on much slower hardware.

---

## 2. What was built

### The approach

Rather than patch the old code, the old version was archived (`old_implementation/`,
matching your existing `old_theory/` convention) and a fresh implementation written
against the corrected specification in `revised_theory/paper.tex`. The old code
stays readable and buildable for reference; the new tree is clean.

The work was done in stages, and **each stage had to pass a test before the next
one started**. That discipline is why several bugs got caught early instead of
surfacing in a published number.

### The building blocks, from the bottom up

**A single, unambiguous message format.** Every protocol message is encoded one
way, and that same encoding is used for three purposes: what goes on the wire,
what gets signed, and how message size is counted. Because there is one encoder,
those three can never disagree — which is a class of bug that simply cannot happen
now. Each field carries its own length tag, so "AB" + "C" can never be confused
with "A" + "BC".

**Real cryptography, in two flavours.** Two complete sets of algorithms:

| | `sha3` (for normal processors) | `spongent` (for tiny hardware) |
|---|---|---|
| fingerprinting | SHA3-256 | SPONGENT-160 |
| message signing | HMAC-SHA3 | keyed sponge |
| key generation | HKDF | sponge-based |
| encryption | ChaCha20-Poly1305 | Ascon-128a |
| key agreement | X25519 | X25519 |

All of it comes from OpenSSL (already on the machine) except the two lightweight
primitives, which were written from scratch.

One design point worth stating: the usual signing method (HMAC) **cannot** be used
with SPONGENT. HMAC needs to fit the key into a "block", and SPONGENT's block is
2 bytes — smaller than the key. So the standard sponge-based method is used
instead, and the fact that it provides 80-bit rather than 128-bit security is
stated openly rather than glossed over.

**The fingerprint reader (PUF models).** The old code claimed a realistic
128-stage PUF model but actually used a random-number generator; the real model was
present but never called. Now there are three genuine models, and — importantly —
noise is applied the way real hardware behaves: to the *timing race* inside the
chip rather than by randomly flipping output bits. The consequence is that bits
sitting near the decision boundary flip much more often than others, exactly as in
real silicon. Measured: the variation in per-bit flip rates is **98× higher** than
a naive random-flip model, which is the realism the old version lacked.

**The error-correction code, done correctly.** The old one used the wrong parity
length (144 bits instead of 124), which left the last 17 bits of every reading
completely unprotected. Building it properly gives BCH(255,131,18): it protects
all 128 bits and corrects up to 18 errors.

How thoroughly is it tested? For **every** error count from 1 to 18, a thousand
random trials each — 18,000 total, **all recovered exactly**. Beyond 18 errors it
correctly reports failure, and in 3,000 attempts it never once claimed success
while returning something wrong.

**Turning a noisy fingerprint into a stable key (the fuzzy extractor).** This
takes a slightly-different-every-time PUF reading and produces the exact same key
each time, using public "helper data" that is safe to publish.

There's an unavoidable trade here worth understanding: the helper data leaks some
information — 124 bits per block. So a 128-bit reading would leak almost all of
itself and be useless. That's why readings are 255 bits, and why several blocks are
combined. The code **refuses to start** if the arithmetic doesn't leave enough
secret information for the key size requested. It doesn't warn; it stops.

It also **fails closed**: if a reading can't be cleaned up, it returns *no key at
all* rather than a partial or uncorrected one. That is precisely the failure the
old code got wrong.

### The protocol itself, in four phases

**Phase 1 — Enrollment (once, in the factory).** The ground station reads the
drone's PUF, derives a master key, and stores it. The drone stores only public
things: its identity, its challenge, and the helper data. **Nothing secret is on
the drone.** Capture it and you get nothing useful.

**Phase 2 — Drone and ground station authenticate each other (4 messages).** The
drone regenerates its master key from its own PUF, then both sides exchange signed
messages. Two protections matter here:

- *The drone checks the ground station's signature before doing anything else.* A
  fake ground station gets no reply at all — so the interrogation attack from
  problem #2 is structurally impossible, not merely difficult.
- *The raw PUF reading never leaves the drone.* There is nothing on the wire to
  harvest.

At the end, both sides share a session key, and the ground station sends the
drone's peer credentials **encrypted**.

**Phase 3 — Drones authenticate each other (3 messages).** No ground station
needed, so it works when that link is down. Each *pair* of drones has its **own**
credential. The old design gave the whole swarm one shared secret, so capturing any
drone compromised everything. Now capturing one drone exposes only that drone's own
connections — measured at 3 of 6 pairs in a 4-drone test, versus all of them
before.

**Phase 4 — Session keys with forward secrecy.** Every session mixes in a fresh
throwaway key that is erased afterwards. So even if someone later steals the
long-term key, they cannot decrypt past conversations. This is now **mandatory** —
there is no code path that skips it.

### Proving it works

**Nine test suites, 432,000 checks, all passing.** Everything is checked against
published reference values wherever they exist:

| What | Checked against |
|---|---|
| SHA3, HMAC | NIST official test values |
| HKDF | RFC 5869 |
| ChaCha20-Poly1305 | RFC 8439 |
| X25519 | RFC 7748 |
| **Ascon-128a** | **all 1,089 official test vectors** |
| SPONGENT-160 | the designers' own reference code, byte for byte |

On honesty here: no official test-vector file exists for SPONGENT. So the code says
exactly that — it reports matching the designers' reference implementation, and
explicitly states it is *not* claiming a published test-vector match. Both
primitives carry a machine-readable "here is what was and wasn't verified" string,
and a test fails if anyone deletes the caveat later.

### Attacking our own system

Claiming "attacks fail" proves nothing if the attacker is broken. So there are two
arms:

- the **real protocol**, where attacks must fail;
- a **deliberately weakened copy** reproducing the original flaw, where the *same
  attack code* must succeed.

| Protocol version | Fake ground station attempts | Drone tricked into replying? |
|---|---|---|
| **New (hardened)** | 8 | **No — 0 times** |
| **Old (legacy)** | 8 | **Yes — the attack works** |

The attack succeeds against the old design and fails against the new one, so the
zero is meaningful evidence rather than an untested assumption. Other attacks
tested: replaying a captured message (refused), and reading the credential
package off the air (finds only encrypted data, 0 of 10 readable).

---

## 3. What the measurements say

Ten independent runs per setting, every number with a ± confidence range.

### Speed

| Setting | Time for a drone to authenticate | Drones succeeding |
|---|---|---|
| 10 drones, `sha3` | 1.5030 ± 0.0028 ms | 100 / 100 |
| 10 drones, `spongent` | 1.5085 ± 0.0030 ms | 100 / 100 |
| 5 drones | 1.1452 ± 0.0055 ms | 50 / 50 |
| 20 drones | 2.2239 ± 0.0044 ms | 200 / 200, all 3,800 pairs |

Drone-to-drone authentication takes about **0.42 ms** per pair.

### The four findings that change the paper

**Finding 1 — the "21× faster than RSA" claim is wrong.** The old paper cited
"8–15 ms" for RSA verification. Measured on this machine with the same library:
**33 microseconds** — off by a factor of about 300. Any speed multiplier built on
that number has to go.

**Finding 2 — this system is comparable to standard cryptography, not vastly
faster.** Each handshake needs about 190 µs of key-exchange work, against 91–155 µs
for standard ECDH/ECDSA. That's the honest price of mandatory forward secrecy. The
real advantages are the *properties*, not raw speed:

- nothing secret is stored on the drone, so capture yields no keys;
- no certificates or central key infrastructure;
- drones authenticate each other with no ground station involved;
- one captured drone exposes only its own links;
- the symmetric core is genuinely tiny (1 µs fingerprinting, 3.8 µs signing), which
  is what matters for a hardware chip — so the gate-count argument survives intact.

**Finding 3 — the "lightweight" algorithm is not faster in software.** SPONGENT's
signing takes 225 µs versus 2.1 µs for SHA3 — about 100× slower. But end-to-end
authentication times are nearly identical (1.5085 vs 1.5030 ms), because the shared
work (key exchange, PUF reading, error correction) dominates. SPONGENT's advantage
is *chip area*, not software speed. And the old paper's 750× figure came from a
non-conformant implementation, not from SPONGENT itself.

**Finding 4 — reliability has a real limit.** At 5% reading noise, **21 of 100
drones could not regenerate their key** and never even started authenticating.

This one deserves emphasis, because the old pipeline would have reported **100%
success** for the same runs — it only counted drones that managed to send a first
message. Two success rates are now recorded: among drones that tried, and among
*all* drones. The second is the honest one.

### Reliability across noise levels

Three error-correction settings, seven noise levels, measured failure rate:

| Reading noise | Standard | Stronger | Strongest (3× cost) |
|---|---|---|---|
| 1% | 0.000 | 0.000 | 0.000 |
| 3% | 0.033 | 0.000 | 0.000 |
| 5% | 0.167 | 0.000 | 0.000 |
| 7% | 0.800 | 0.133 | 0.000 |
| 10% | 1.000 | 1.000 | **0.000** |

20 of 21 points match the mathematical prediction within their confidence
interval — which is the real proof that error correction is genuinely happening. A
broken decoder would produce a flat line matching nothing.

Note the paper's original claim of a failure rate below 1 in 10¹⁵ is **not
achievable** with the standard setting; the true figure is about 1 in 1,000. The
strongest setting does reach it, at three times the PUF cost. That's a trade to
present honestly, not a claim to repeat.

---

## 4. Bugs the tests caught (in my own work)

Worth recording, because it shows the gates were doing their job rather than
rubber-stamping.

1. **Error-correction encoder bit ordering.** I mixed up two indexing conventions.
   Caught immediately: freshly-encoded data failed its own validity check.

2. **The repetition code made reliability *worse*.** The strongest setting measured
   a 96% failure rate where near-zero was predicted. The cause was conceptual: I
   was majority-voting three *different* PUF bits, which are independent values,
   not three noisy copies of one bit. Voting them destroys information instead of
   cleaning it. Fixed by publishing each copy's offset from a reference at
   enrollment, so the votes really are measurements of the same thing. After the
   fix: **0% failure, all the way to 10% noise.** The mismatch with prediction is
   exactly what exposed it.

3. **Four bugs in the attack harness** — including counting a drone's legitimate
   reply as a successful attack, and the attacker's own forged messages being
   routed back to itself so no victim ever received them. All found because the
   control arm refused to show the success it was supposed to.

4. **A configuration-file trap.** Settings in the general section silently
   overrode the attack sections, quietly disabling every attack. The attacks
   "passed" while doing nothing.

5. **Two-thirds of the noise sweep silently had no data** — the run count didn't
   cover all the combinations.

Every one of these would have produced a confident, wrong number in a paper.

---

## 5. Where everything lives

```
src/
  core/       message format, byte utilities
  crypto/     both algorithm suites, key exchange, random generator
  puf/        fingerprint models, entropy measurement
  fe/         error-correcting code, noisy-to-stable key conversion
  protocol/   the four phases
  nodes/      simulation modules (drone, ground station, radio, attacker)
tests/        9 test suites + reference test values
scripts/      build, run, export, analyse
simulations/  scenarios and results
docs/spec-deviations.md   every place the code differs from the paper, and why
```

Useful commands:

```bash
scripts/build_omnet_project.sh                 # build
bash tests/run_tests.sh                        # all tests (~2 min)
python3 scripts/run_experiments.py --runs 10   # run experiments
python3 scripts/analyze_results.py             # summarise with error bars
```

---

## 6. What is still not done

Stated plainly:

- **Formal verification** (ProVerif/Tamarin) — the machine-checked proof is not
  built. The security evidence is currently the tests and the attack simulation.
- **Realistic radio** (INET 802.11) — no signal collisions or retransmissions are
  modelled, so network delays are a best case. The paper should say so.
- **Real hardware** — everything is simulated; no FPGA prototype.
- **Side-channel analysis** — no timing-attack analysis of the two hand-written
  primitives. Their status strings say so.

---

## 7. The short version

The protocol was rebuilt so its security claims are actually true, and the
measurements are now honest — including where they are less flattering than the
original paper's. Nine test suites and 432,000 checks pass; the crypto matches
official reference values; attacks fail against the new design and demonstrably
succeed against the old one; and reliability limits are measured rather than
assumed.

Four claims in the paper need correcting (the RSA figure, the speed multiplier, the
SPONGENT ratio, and the reliability figure), and the honest story is now about
*properties* — no stored secrets, no certificates, no central dependency, contained
damage from capture — rather than about being dramatically faster. That's a
defensible paper. The previous version's headline numbers were not.
