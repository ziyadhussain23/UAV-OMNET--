# Viva / Presentation Q&A — Fast Authentication Between UAVs (PUF-based)

## A. Protocol & physical security

**Q1. How is your protocol *physically* protected?**
The UAV stores **no secret key**. Identity comes from a **Physical Unclonable Function (PUF)** — silicon-level manufacturing variations that even the chip vendor cannot reproduce. If an attacker captures and probes the UAV, the PUF response changes (probing alters the gate timings) and the secret is destroyed. So *capture ≠ key leak*.

**Q2. What exactly is a PUF?**
A circuit that maps an input *challenge* to a unique output *response* using uncontrollable manufacturing variations (gate delay, threshold voltage). Two chips made on the same wafer give different responses. We use an **Arbiter PUF** — two delay paths race, the arbiter latches which arrives first → 1 bit per challenge.

**Q3. Why Arbiter PUF and not SRAM / Ring-Oscillator PUF?**
- Arbiter PUF gives **per-challenge** responses (huge CRP space, ~2^128) — needed for re-authentication without exhausting CRPs.
- SRAM PUF gives one fixed fingerprint per chip → small CRP space, vulnerable to replay.
- RO-PUF needs many oscillators → high area/power for a small UAV MCU.

**Q4. PUFs are noisy — same challenge can give a slightly Vdifferent response. How do you handle that?**
Fuzzy extractor: **BCH(255, 131, 18)** error-correcting code. Enrollment stores `helper = response ⊕ codeword(secret)`. At auth time, noisy response is XORed with helper, decoded by BCH (corrects up to 18 bit errors), recovering the exact secret. We model 3 % PUF noise (≈8 bit errors per 255-bit response) — well inside BCH's 18-bit budget.

**Q5. What are the four phases of your protocol?**
- **P1 — Enrollment** (offline, secure room): GS reads many CRPs from each UAV, stores them.
- **P2 — UAV ↔ GS authentication** (in flight): challenge → masked PUF response → mutual verification → session key.
- **P3 — UAV ↔ UAV peer auth**: 3-message mutual handshake using GS-signed tokens, no GS round-trip.
- **P4 — Session key derivation**: SHA3 (or optional ECDH if `USE_SODIUM`) over agreed nonces → AES key.

**Q6. Why peer-to-peer (P3) at all? Why not always go through the GS?**
Latency + reliability. In a swarm, GS may be far away or jammed. P3 lets two UAVs authenticate each other in **0.48 ms** (SHA3) without any GS round trip. Also reduces GS bottleneck for large swarms.

---

## B. Crypto choices

**Q7. Why SHA3-256 *and* SPONGENT-160 — pick one?**
They serve different deployment targets:
- **SHA3-256** — best for software / Pi-class CPUs (0.05 ms on Pi-4). Higher gate count (~15k GE) but standardized (FIPS-202).
- **SPONGENT-160** — built for **ASIC / RFID-class hardware** (1,329 GE, ~11× smaller silicon, 0.66 nJ/hash). In software it's ~1500× slower, so it only wins when fabricated.

We benchmark both so the deployer can pick based on the target chip.

**Q8. Why not RSA / ECC?**
Compute and energy:
- RSA-2048 sign on Cortex-M4 ≈ **1300 ms** (vs 0.4 ms for SHA3) — 3000× slower.
- ECC-P256 sign ≈ 80 ms — still ~200× slower than our scheme.
- Energy: RSA ~50,000 nJ vs SHA3 ~2 nJ — **~1000× more energy** per auth.
For a battery-powered UAV doing thousands of peer auths per mission, that drains the battery.

**Q9. Why not just AES-CMAC for authentication?**
AES-CMAC needs a **stored shared key**. If the UAV is captured, the key is stolen → impersonation possible. Our PUF-based scheme has *no key on the UAV*.

**Q10. Why SHA3 over SHA-2?**
SHA3 (Keccak) is sponge-based → easier to reduce to 160-bit output for fair comparison with SPONGENT-160, and side-channel-friendlier (no round-key schedule). SHA-2 would also work but FIPS-202 is the modern recommendation.

---

## C. Networking & MAC layer

**Q11. Why didn't you simulate a MAC layer (CSMA / TDMA)?**
Two reasons:
1. The protocol is MAC-agnostic — its correctness and compute cost don't depend on the MAC.
2. We wanted a **lower-bound** on the network delay first, to isolate compute vs network contributions. Adding CSMA/CA would add ~2-10 ms backoff per frame and obscure the protocol overhead. It's planned future work (INET PHY/MAC integration).

So our reported **0.665 ms (P2) / 0.467 ms (P3)** network delay is **link bitrate + propagation only** — a lower bound.

**Q12. What network model did you use then?**
OMNeT++ `sendDirect` with explicit:
- Link bitrate 6 Mbps (typical 802.11 control rate).
- Propagation at speed of light (max 500 m → 1.67 µs).
- Processing delay 0.1 ms ± 0.02 ms jitter (mean + stddev) — models GS/UAV crypto+queueing.

**Q13. Why a stadium scenario, 10 UAVs, 500×300 m?**
Real use case (stadium air protection — anti-drone perimeter), realistic propagation distances, and small enough that a single WiFi-class link is plausible. 10 UAVs is the typical commercial swarm size for such missions.

**Q14. What if two UAVs auth at the exact same time?**
In our model they go through serially via `sendDirect`. With a real CSMA MAC there'd be backoff; total delay would grow but **success rate stays 100 %** because the protocol has **timestamp + nonce** replay protection (5 s window).

---

## D. Implementation & validation

**Q15. What's your implementation stack?**
- **OMNeT++ 6.3** — discrete-event simulator.
- C++17 modules: `UAVNode`, `GroundStation`, `NetworkController`.
- Crypto: OpenSSL EVP (SHA3-256), custom SPONGENT-160, custom Arbiter PUF.
- BCH: `libcorrect` (optional) or built-in parity fallback.
- Python reference under `UAV-Authentication/` for cross-validation.

**Q16. How did you validate correctness?**
1. **Python reference impl** runs the same protocol; OMNeT++ scalar outputs match Python CSVs row-for-row (compute cost, payload, success).
2. **PUF unit test** (`tests/test_puf.cc`) checks BCH recovery under 3 %, 5 %, 8 % noise.
3. **OMNeT++ assertions**: 100 % auth success across all 10 UAVs × 2 hash modes.

**Q17. Where do your numbers come from?**
- Compute (Laptop x86-64): measured directly in OMNeT++ — `0.007 ms` SHA3, `6.70 ms` SPONGENT (P2).
- Network: OMNeT++ event timestamps.
- Pi-4 / Cortex-M4 / ASIC numbers: scaled from **wolfSSL Cortex-M benchmarks** + **Bogdanov CHES'11** (SPONGENT) + **Keccak Team** HW reports (SHA3).

**Q18. Total auth time?**

| Phase | SHA3-256 | SPONGENT-160 |
|---|---|---|
| P2 (UAV↔GS)   | 0.007 + 0.665 = **0.67 ms** | 6.70 + 0.665 = **7.37 ms** |
| P3 (UAV↔UAV)  | 0.009 + 0.467 = **0.48 ms** | 14.07 + 0.467 = **14.54 ms** |

Compare: RSA-2048 on Cortex-M4 ≈ **1300 ms**.

---

## E. Security analysis

**Q19. What attacks does it resist?**
- **Replay** — every message has a fresh nonce + 5 s timestamp window.
- **Impersonation** — needs the PUF, which can't be cloned.
- **Capture** — no key stored; PUF response changes if probed.
- **MITM** — handshake uses mutual challenge-response with hashed nonces, attacker without PUF can't forge.

**Q20. What's it *not* resistant to?**
- **Modeling attacks on Arbiter PUF** — ML can predict ~95 % of responses given ~10k CRPs. *Mitigation:* XOR-PUF or controlled PUF (we discuss in future work).
- **GS compromise** — GS holds the CRP database; if it's stolen, attacker can clone any UAV's auth. *Mitigation:* HSM at GS.
- **Side-channel on the BCH decoder** — timing leak could reveal helper data structure.

**Q21. Why do you call it "key-store free"?**
Because no long-term secret is in the UAV's flash / RAM after enrollment. The PUF *is* the key, regenerated on demand from silicon physics.

**Q21a. But Phase 4 derives a session key — if the attacker captures the UAV in flight, won't they read that session key from RAM?**
Yes — *that one session key, for that one session, only*. Three reasons it's not a real break:

1. **Forward / backward secrecy by design.** The session key is derived from **fresh nonces** exchanged in P2/P3 (`K = SHA3(nonce_A ‖ nonce_B ‖ PUF-derived secret)`). Each session uses new nonces → past sessions stay safe (attacker can't decrypt earlier traffic), and they can't predict future sessions either. With the optional `USE_SODIUM` ECDH variant in P4, this becomes **full Perfect Forward Secrecy** — even the long-term PUF secret can't recover past keys.
2. **Capture is detectable and short-lived.** A captured UAV stops responding to GS heartbeats → GS revokes its tempID and blacklists its CRPs within seconds. The stolen session key expires with the session (typical lifetime ~minutes).
3. **No re-authentication possible.** This is the key point. Even with the session key in hand, the attacker **cannot start a new session** because P2/P3 require a live PUF response to a fresh challenge. Probing the chip to extract the PUF destroys it (gate timings change). So: one session compromised ≠ identity compromised. With AES-CMAC / RSA / stored-key schemes, capture = permanent impersonation forever. With ours, capture = at most one short session.

**TL;DR:** session key in RAM is a *transient* secret, not a long-term one. The PUF is what gives us the **"capture today, useless tomorrow"** property.

---

## F. Specific number questions

**Q22. Why exactly BCH(255, 131, 18)?**
255-bit codeword fits one PUF response block; 131 information bits give a 128-bit secret + 3-bit framing; t = 18 corrects up to 7 % bit errors — covers our worst-case noise (5 %) with margin.

**Q23. Why 430 B payload?**
Sum of: tempID (16 B) + timestamps (8 B × 2) + nonces (32 B × 2) + masked response (32 B) + helper data (255 b ≈ 32 B) + MAC (32 B) + framing. Well under any MTU.

**Q24. Why 100 % success and not 99.9 %?**
Our PUF noise (3 %) is well below BCH's correction budget (18/255 = 7 %). Across 90 P3 trials × 10 UAVs × 2 hash modes — all succeeded. With higher noise (5 %, `HighNoise` config) it still passes; at 8 % we'd start seeing failures.

**Q25. How many CRPs per UAV?**
12 in our config (`numCRPsPerUAV = 12`) — enough for a typical mission. Production deployment would store ~10k for re-enrollment.

---

## G. Comparison & contributions

**Q26. What's *new* in your work vs prior PUF-UAV papers?**
1. **End-to-end OMNeT++ simulation** with measured network + compute (most papers only report compute on a desktop).
2. **Side-by-side SHA3 vs SPONGENT** comparison on the *same* PUF protocol — shows hash choice depends on target silicon.
3. **Predicted Pi-4 / Cortex-M4 / ASIC numbers** anchored in our laptop measurements.
4. **Peer-to-peer P3** that doesn't need GS (most prior work routes everything through GS).

**Q27. Why should anyone deploy this over existing solutions?**
1000× less energy than RSA at equivalent unforgeability, no key storage (capture-resistant), and sub-millisecond auth on a Pi-class CPU.

**Q28. What's the biggest weakness?**
Arbiter PUF is vulnerable to ML modeling attacks. Production deployment must use a **modeling-resistant PUF** (XOR-Arbiter with k≥4, or controlled PUF). Our protocol layer is independent of which PUF you plug in.

**Q29. Future work?**
- INET integration (real WiFi MAC).
- XOR-PUF / lattice-based PUF.
- Hardware-in-the-loop with real Cortex-M4 + a fabricated Arbiter PUF.
- Formal verification (ProVerif / Tamarin).

**Q30. If sir asks "show me the data, prove these numbers"?**
```bash
cd ~/UAV-OMNET++ && \
deactivate 2>/dev/null; source ~/omnetpp-6.3.0/setenv > /dev/null; deactivate 2>/dev/null; \
source .venv/bin/activate && export PATH="$HOME/omnetpp-6.3.0/bin:$PATH" && \
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c StadiumSHA3 && \
src/uavauthsim -u Cmdenv -n src:simulations -f simulations/omnetpp.ini -c StadiumSPONGENT && \
python scripts/run_and_export_omnet_csv.py --skip-build --configs StadiumSHA3 StadiumSPONGENT && \
cat simulations/results/omnet_summary.csv
```
Output shows live measured values matching everything on the slide.

---

## Quick numbers cheat sheet (memorize these)

| Item | SHA3-256 | SPONGENT-160 | RSA-2048 | ECC-P256 |
|---|---|---|---|---|
| ASIC area | ~15k GE | **1,329 GE** | ~33k GE | ~30k GE |
| Energy/op (HW) | 2.0 nJ | **0.66 nJ** | ~50,000 nJ | ~4,000 nJ |
| Cortex-M4 compute | 0.4 ms | 200 ms | 1300 ms | 80 ms |
| Our P2 total | **0.67 ms** | 7.37 ms | — | — |
| Our P3 total | **0.48 ms** | 14.54 ms | — | — |

- **PUF**: Arbiter, 3 % noise modeled.
- **BCH**: (255, 131, 18) — corrects up to 7 % errors.
- **Scenario**: 500×300 m, 10 UAVs, 6 Mbps link.
- **Success**: 100 %, 430 B payload, no key storage.
- **Caveat**: no MAC contention modeled → network delay is a lower bound.
