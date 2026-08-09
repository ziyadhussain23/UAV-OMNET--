# Instructions for AI: Protocol Theory Redesign

**Context:** Refer to the existing `REPORT.md` file for the complete audit and security analysis of the current protocol. 

**Task:** Completely redesign and rewrite the theoretical foundation of the PUF-based four-phase authentication protocol to ensure mathematical and cryptographic perfection.

**Execution Steps:**
1. **Analyze `REPORT.md`:** Review "Part A — Protocol security analysis" to understand the specific theoretical flaws (unkeyed hashes, plaintext credentials, PUF oracles, incorrect assumptions, and lack of forward secrecy).
2. **Setup:** Create a new directory named `revised_theory` and generate a new LaTeX file inside it named `uav_protocol_theory.tex`.
3. **Redesign Theory:** Write the fully corrected mathematical specification for all four phases. You must resolve every flaw identified in the report (e.g., implement keyed GS authentication, secure masking, per-pair PUF-rooted credential distribution via AEAD, domain separation, and mandatory ephemeral key exchange for PFS).
4. **Theorems and Proofs:** Define new, mathematically sound theorems for:
    * Mutual Authentication (GS-UAV and UAV-UAV)
    * Replay and MITM Resistance
    * Physical-Capture Resistance
    * Perfect Forward Secrecy
5. **Formal Proofs:** Provide rigorous, logically sound proofs for every theorem based strictly on the newly hardened architecture. Correct the helper-data mathematical assumption.

**Output Constraints:** 
* Output only the fully compliant, compilable LaTeX code within a single code block. 
* Do not generate or modify any implementation code (C++/Python) or simulation files. 
* Focus purely on a flawless cryptographic theory specification.