# Glossary — Every Term in the Project (Simple & Concise)

> One-line definitions you can recall instantly in the viva. Grouped by topic.

---

## 1. Hardware / Chip Terms

| Term | Meaning (simple) |
|---|---|
| **ASIC** | *Application-Specific Integrated Circuit.* A custom chip built for **one** job (e.g. just SHA3). Smallest, fastest, lowest power — but you must fabricate silicon. Opposite of a general CPU. |
| **FPGA** | *Field-Programmable Gate Array.* A chip whose internal wiring you can re-program after manufacture. Slower than ASIC, faster than CPU; used for prototyping hardware. |
| **MCU** | *Microcontroller Unit.* A small CPU + RAM + flash on one chip (e.g. Arduino, STM32). Used inside drones, sensors. |
| **Cortex-M4** | ARM's 32-bit MCU core. Common in low-power UAVs (e.g. Pixhawk autopilot). 168 MHz typical. We use it as our "embedded" benchmark target. |
| **Pi-4** | Raspberry Pi 4 — credit-card Linux computer with quad-core 1.5 GHz Cortex-A72. Our "single-board computer" benchmark. |
| **GE** | *Gate Equivalents.* Unit measuring chip area = how many 2-input NAND gates the circuit costs. SPONGENT-160 = 1,329 GE → very small silicon. |
| **nJ** | *Nanojoule* (10⁻⁹ J). Energy per crypto operation. Lower = longer battery life. |
| **GHz / MHz** | Clock speed. 1 GHz = 1 billion cycles/sec. |
| **MTU** | *Maximum Transmission Unit.* Largest packet a network link will carry (WiFi ≈ 1500 B). Our 430 B payload fits easily. |

---

## 2. PUF (Physical Unclonable Function)

| Term | Meaning |
|---|---|
| **PUF** | A circuit that produces a unique, unclonable output based on tiny random differences from chip manufacturing. Like a silicon **fingerprint**. Two chips made the same way still differ. |
| **CRP** | *Challenge-Response Pair.* Input bits (challenge) → output bits (response) from the PUF. The "secret table" of the chip. |
| **Arbiter PUF** | PUF type we use. Two signal paths race through the chip; an arbiter latches **which one arrived first** → 1 bit of output. Different chips = different delays = different outputs. |
| **SRAM PUF** | PUF that uses the random startup state of SRAM cells. Gives only **one** fingerprint per chip (small CRP space). |
| **RO-PUF** | *Ring-Oscillator PUF.* Compares frequencies of many oscillator loops. Accurate but uses lots of area. |
| **XOR-PUF** | Several Arbiter PUFs whose outputs are XORed together → harder for ML to model. Future-work option. |
| **CRP space** | Total number of possible challenges. Arbiter PUF: ~2¹²⁸. Huge → can never be exhausted. |
| **PUF noise** | Same challenge sometimes gives slightly different bits (3–5 % flip rate) due to temperature/voltage. Fixed by fuzzy extractor. |
| **Modeling attack** | Attacker collects ~10k CRPs and trains a machine-learning model that predicts future responses. Main weakness of plain Arbiter PUF. |

---

## 3. Cryptography

| Term | Meaning |
|---|---|
| **Hash function** | One-way function: input of any size → fixed-size "digest". Easy to compute, infeasible to reverse. |
| **SHA3-256** | NIST-standard hash (Keccak family, FIPS-202). 256-bit output. Sponge construction. We use it as the "software-friendly" option. |
| **SHA-2** | Older NIST hash family (SHA-256 etc.). Still secure; we picked SHA3 for fair comparison with SPONGENT (both spongebased). |
| **SPONGENT-160** | **Lightweight** hash designed for tiny hardware (RFID, IoT). 160-bit output. Tiny in ASIC (1,329 GE) but slow in software. |
| **AES** | *Advanced Encryption Standard.* Symmetric block cipher (128-bit blocks). Used in P4 to encrypt session traffic with the derived key. |
| **AES-CMAC** | A *Message Authentication Code* built from AES. Proves a message came from someone holding the AES key. We **don't** use it because it requires storing a key on the UAV. |
| **MAC (crypto)** | *Message Authentication Code.* A short tag proving "this message wasn't tampered and came from the key holder". (Note: different from networking MAC.) |
| **HMAC** | Hash-based MAC. Standard way to authenticate a message using a hash + shared key. |
| **RSA-2048** | Public-key crypto, 2048-bit modulus. Very slow on MCUs (~1300 ms/sign). |
| **ECC / ECC-P256** | *Elliptic Curve Cryptography.* Public-key, much smaller keys than RSA, ~80 ms/sign on Cortex-M4. |
| **ECDH** | *Elliptic Curve Diffie-Hellman.* Key-exchange protocol. Optional in our P4 (`USE_SODIUM` flag) for full forward secrecy. |
| **Nonce** | "Number used once" — random fresh value, prevents replay attacks. |
| **Session key** | Short-lived symmetric key (minutes), derived per session, used to encrypt traffic. |
| **Long-term key** | Permanent secret stored on a device. We deliberately have **none** on the UAV. |
| **Forward secrecy (PFS)** | Property that compromising today's key does **not** decrypt yesterday's traffic. Achieved via fresh nonces / ECDH. |
| **Side-channel attack** | Attack using physical leakage (timing, power, EM) instead of math weaknesses. |
| **OpenSSL EVP** | High-level crypto API in OpenSSL library. We call it for SHA3-256. |

---

## 4. Error Correction (Fuzzy Extractor)

| Term | Meaning |
|---|---|
| **Fuzzy extractor** | Crypto trick that turns a *noisy* biometric/PUF input into a *stable* secret key. Has two functions: `Gen` (enrollment) and `Rep` (reproduction). |
| **Helper data** | Public string output during enrollment. Stored at GS. Used to correct future noisy PUF readings. Does **not** leak the secret. |
| **BCH code** | *Bose–Chaudhuri–Hocquenghem* — a class of error-correcting codes. We use **BCH(255, 131, 18)**: 255-bit codewords, 131 info bits, corrects up to 18 bit errors. |
| **Codeword / parity** | Codeword = info + parity bits. Parity bits are the "redundancy" used to detect & fix errors. |
| **t (correction capacity)** | How many bit errors the code can fix. For BCH(255,131): t = 18 → 7 % error tolerance. |
| **libcorrect** | Open-source C library implementing BCH/Reed-Solomon. We link it for real BCH; fall back to simple parity if unavailable. |

---

## 5. Networking & Simulation

| Term | Meaning |
|---|---|
| **OMNeT++** | Open-source discrete-event network simulator written in C++. Our main simulation tool (v6.3). |
| **NED** | *Network Description Language.* OMNeT++'s file format for declaring modules and connections (`.ned` files). |
| **INET** | OMNeT++ library with realistic TCP/IP, WiFi, MAC, mobility models. We **don't** use it yet — listed as future work. |
| **Discrete-event simulation** | Simulator advances time event-by-event (not in fixed ticks) → fast and exact for protocol timing. |
| **`sendDirect`** | OMNeT++ API to deliver a message straight to another module with a chosen delay — bypassing physical channel modeling. We use it for clean compute+propagation timing. |
| **MAC layer (network)** | *Medium Access Control.* Decides **who transmits when** on a shared wireless channel (CSMA/CA in WiFi). We don't simulate it → our delay is a lower bound. |
| **CSMA/CA** | *Carrier-Sense Multiple Access with Collision Avoidance.* WiFi's MAC scheme: listen first, back off if busy. |
| **TDMA** | *Time-Division Multiple Access.* Each node gets a fixed time slot. Alternative MAC. |
| **Bitrate** | Link speed (bits/sec). We use 6 Mbps = typical WiFi control rate. |
| **Propagation delay** | Time for the radio wave to travel = distance / speed-of-light. Negligible (1.67 µs at 500 m). |
| **Processing delay** | CPU time at sender/receiver (queueing, parsing). We model 0.1 ms ± 0.02 ms jitter. |
| **Jitter** | Variation in delay between packets (stddev around the mean). |
| **Payload** | Useful bytes inside a packet (excluding headers). Ours = 430 B. |
| **Heartbeat** | Periodic "I'm alive" message from UAV → GS. Used to detect capture / loss. |
| **tempID** | Temporary identifier given to a UAV per session. Revocable; replaces revealing the real ID. |

---

## 6. UAV / System Terms

| Term | Meaning |
|---|---|
| **UAV** | *Unmanned Aerial Vehicle.* Drone. |
| **GS** | *Ground Station.* Trusted server on the ground that did enrollment, holds the CRP database, and authenticates UAVs. |
| **Swarm** | Group of cooperating UAVs (we test 10). |
| **Stadium scenario** | Our test setup: 500 m × 300 m area, 10 UAVs guarding airspace over a stadium. Realistic anti-drone perimeter mission. |
| **Enrollment** | Offline, secure-room phase where GS reads many CRPs from each UAV and stores them. One-time. |
| **Re-authentication** | Authenticating again later in the mission, using a fresh CRP each time. |
| **HSM** | *Hardware Security Module.* Tamper-proof box for storing high-value secrets (e.g. the GS's CRP database). Suggested mitigation. |
| **Revocation** | GS removing a UAV's tempID + CRPs from active use (e.g. after capture detected). |

---

## 7. Project / Tooling Terms

| Term | Meaning |
|---|---|
| **`uavauthsim`** | The compiled OMNeT++ executable for our simulation (in `src/`). |
| **`opp_makemake`** | OMNeT++ tool that generates a Makefile from `.cc`/`.ned` files. |
| **`Cmdenv`** | OMNeT++ command-line runner (no GUI). Used for batch runs. |
| **`omnetpp.ini`** | Config file listing all simulation runs (`StadiumSHA3`, `StadiumSPONGENT`, `Swarm20`, `HighNoise`, etc.). |
| **`.sca` file** | OMNeT++ "scalar" output file — final per-run results (timings, success counts). |
| **`USE_SODIUM`** | Compile-time flag that enables the libsodium-based ECDH variant of P4 (full PFS). Off by default. |
| **libsodium** | Modern crypto library (Curve25519 ECDH, etc.). |
| **`.venv`** | Python virtual environment for the project's reference implementation. |
| **`scripts/run_and_export_omnet_csv.py`** | Driver that runs OMNeT++ configs and exports results as CSV. `--skip-build` skips re-compilation. |

---

## 8. Acronym Quick-Lookup (alphabetical)

| Acronym | Stands for |
|---|---|
| AES | Advanced Encryption Standard |
| ASIC | Application-Specific Integrated Circuit |
| BCH | Bose–Chaudhuri–Hocquenghem (error-correcting code) |
| CMAC | Cipher-based Message Authentication Code |
| CRP | Challenge-Response Pair |
| CSMA/CA | Carrier-Sense Multiple Access / Collision Avoidance |
| ECC | Elliptic Curve Cryptography |
| ECDH | Elliptic Curve Diffie–Hellman |
| EVP | Envelope (OpenSSL high-level API) |
| FIPS | Federal Information Processing Standard |
| FPGA | Field-Programmable Gate Array |
| GE | Gate Equivalents (chip area unit) |
| GS | Ground Station |
| HMAC | Hash-based Message Authentication Code |
| HSM | Hardware Security Module |
| INET | OMNeT++ networking framework |
| MAC | (a) Medium Access Control, (b) Message Authentication Code — context-dependent |
| MCU | Microcontroller Unit |
| MTU | Maximum Transmission Unit |
| NED | Network Description (OMNeT++ language) |
| NIST | National Institute of Standards and Technology |
| PFS | Perfect Forward Secrecy |
| PUF | Physical Unclonable Function |
| RAM | Random-Access Memory |
| RFID | Radio-Frequency Identification |
| RO-PUF | Ring-Oscillator PUF |
| RSA | Rivest–Shamir–Adleman (public-key crypto) |
| SHA | Secure Hash Algorithm |
| SRAM | Static RAM |
| TDMA | Time-Division Multiple Access |
| UAV | Unmanned Aerial Vehicle |
| WiFi | IEEE 802.11 wireless LAN |

---

## 9. One-Sentence "If sir asks 'what is X'" answers

- **PUF** — silicon fingerprint that can't be cloned, gives a chip-unique secret without storing it.
- **Arbiter PUF** — two delay paths race; arbiter latches the winner → 1 random-but-stable bit per challenge.
- **SHA3** — modern NIST hash (Keccak), 256-bit output, software-friendly.
- **SPONGENT** — lightweight hash for tiny ASIC/RFID hardware.
- **BCH(255,131,18)** — error-correcting code that fixes up to 18 noisy bits in our 255-bit PUF response.
- **Fuzzy extractor** — turns noisy PUF output into a stable cryptographic key using helper data.
- **Helper data** — public side-info stored at GS; helps recover the secret without leaking it.
- **Nonce** — single-use random number that blocks replay attacks.
- **Session key** — short-lived AES key derived per session from fresh nonces + PUF secret.
- **ECDH** — Diffie-Hellman on elliptic curves; gives forward secrecy.
- **ASIC** — custom chip built for one task; smallest area, lowest energy.
- **Cortex-M4** — small ARM CPU typical inside drone autopilots; our embedded benchmark.
- **GE** — chip-area unit (NAND-equivalents); SPONGENT = 1,329 GE.
- **OMNeT++** — discrete-event network simulator we run the protocol in.
- **MAC layer** — networking rule for who transmits when; we don't model it (future work).
- **Ground Station (GS)** — trusted server holding the CRP database and running enrollment + auth.
- **CRP** — one (challenge → response) pair from the PUF; the "rows" in GS's database.
- **Modeling attack** — ML attack that learns to predict Arbiter PUF responses from ~10k samples.
- **HSM** — tamper-proof secure box for the GS's secret database.
- **Forward secrecy** — yesterday's session stays safe even if today's key leaks.
