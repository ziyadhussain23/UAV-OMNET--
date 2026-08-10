"""Literature-sourced energy constants for the crypto primitives and radio
this protocol uses.

Every number here comes from a named, findable, peer-reviewed (or standards-
body) source, not from an assumption or a half-remembered figure. This
project already caught one instance of exactly that mistake -- an "RSA
verify: 8-15ms" citation that was wrong by ~300x versus a same-platform
re-measurement -- so every entry below states its confidence explicitly:

  "verified"   -- a human read the primary source's own table/figure directly
                  and the number is copied from it (or a one-line arithmetic
                  derivation from numbers the source states directly, e.g.
                  power x cycles/frequency = energy).
  "unverified" -- corroborated only by search-result summaries of a real,
                  findable paper; the primary source itself was not read.
                  Use with an explicit caveat, never silently.

No number here is derived from this project's own timing measurements: our
timing is measured on an x86-64 host, these energy figures are measured on
embedded microcontrollers/ASICs running at kHz-MHz clocks, and multiplying
mismatched-platform time by mismatched-platform power would produce a
number with no physical meaning. See export_energy_csv.py for how the two
are kept separate: literature unit costs are combined only with this
project's own MEASURED CALL COUNTS and MEASURED BYTE COUNTS (both real,
both already recorded per protocol run), never with its own timing.
"""

# ---------------------------------------------------------------------------
# Per-operation energy, one dict entry per (approximate) primitive.
#
# Fields:
#   energy_nJ / energy_uJ_per_byte -- the constant itself
#   platform      -- exact hardware the source measured
#   source        -- author, title, venue/year
#   url           -- where to find it
#   confidence    -- "verified" | "unverified" (see module docstring)
#   note          -- caveats: is this the EXACT primitive, or a real-but-
#                    different analog that needs disclosure alongside the
#                    number (e.g. a reduced-state permutation, or an upper
#                    bound rather than a point estimate)
# ---------------------------------------------------------------------------

SHA3_PERMUTATION = {
    "energy_nJ_per_call": 275.0,   # 12.5 uW * (22000 cycles / 1e6 Hz) = 275 nJ
    "platform": "130nm CMOS ASIC, 1 MHz (full Keccak-f[1600])",
    "source": "Pessl & Hutter, \"Pushing the Limits of SHA-3 Hardware "
              "Implementations to Fit on RFID,\" CHES 2013, Springer LNCS 8086",
    "url": "https://doi.org/10.1007/978-3-642-40349-1_8",
    "confidence": "unverified",
    "note": "Primary source (eprint.iacr.org/2013/439) returned HTTP 403 during "
            "research; the 12.5 uW @ 1MHz, ~22k cycles/block figures are "
            "corroborated by independent search summaries of the paper's own "
            "table, not personally read from the PDF. Report as unverified.",
}

SPONGENT160_PERMUTATION_SERIAL = {
    "energy_nJ_per_call": 112.8,   # 2.85 uW * (3960 cycles / 100e3 Hz) = 112.8 nJ
    "platform": "0.13um CMOS ASIC, 100 kHz, serial datapath (d=4)",
    "source": "Bogdanov, Knezevic, Leander, Toz, Varici, Verbauwhede, "
              "\"spongent: A Lightweight Hash Function,\" CHES 2011, "
              "Springer LNCS 6917, Table 2",
    "url": "https://iacr.org/archive/ches2011/69170311/69170311.pdf",
    "confidence": "verified",
    "note": "SPONGENT-160/160/16 (R=90 rounds), the exact variant this "
            "project's SpongentSuite implements. Serial datapath chosen to "
            "match this paper's existing GE citation for SPONGENT's compact "
            "profile (paper.tex already cites this same source for area).",
}

SPONGENT160_PERMUTATION_PARALLEL = {
    "energy_nJ_per_call": 4.02,    # 4.47 uW * (90 cycles / 100e3 Hz) = 4.02 nJ
    "platform": "0.13um CMOS ASIC, 100 kHz, parallel datapath (d=176, 1 round/cycle)",
    "source": "Bogdanov, Knezevic, Leander, Toz, Varici, Verbauwhede, "
              "\"spongent: A Lightweight Hash Function,\" CHES 2011, "
              "Springer LNCS 6917, Table 2",
    "url": "https://iacr.org/archive/ches2011/69170311/69170311.pdf",
    "confidence": "verified",
    "note": "SPONGENT-160/160/16, faster/larger datapath option from the same "
            "table -- an area/energy trade against SPONGENT160_PERMUTATION_SERIAL.",
}

ASCON128A_AEAD = {
    "energy_uJ_per_byte": 0.75,   # stated as an upper bound ("<0.75 uJ/byte")
    "platform": "Nordic Thingy:53 (nRF5340, dual-core ARM Cortex-M33)",
    "source": "Sorescu et al., \"Comparative Performance Analysis of "
              "Lightweight Cryptographic Algorithms on Resource-Constrained "
              "IoT Platforms,\" Sensors 2025, 25(18):5887",
    "url": "https://doi.org/10.3390/s25185887",
    "confidence": "unverified",
    "note": "Figure is an upper bound (\"<0.75 uJ/byte\"), not a point estimate; "
            "measured during a BLE-mesh network test, not an isolated "
            "per-operation benchmark; the paper labels the algorithm "
            "\"ASCON32,\" which could not be confirmed to be exactly Ascon-128a "
            "(the parameter set this project's suite uses) versus a related "
            "Ascon variant. Treat as an order-of-magnitude figure only.",
}

X25519_SCALARMULT = {
    "energy_mJ_per_call": 5.14,
    "platform": "STM32L152RE (ARM Cortex-M3) @ 8 MHz, Vdd=3.3V, "
                "constant-time/side-channel-resistant implementation",
    "source": "Franck, Grossschadl, Le Corre, Lenou Tago, \"Energy-Scalable "
              "Montgomery-Curve ECDH Key Exchange for ARM Cortex-M3 "
              "Microcontrollers,\" EMSICC 2018",
    "url": "https://orbilu.uni.lu/bitstream/10993/37497/1/EMSICC2018.pdf",
    "confidence": "verified",
    "note": "Curve25519, the exact curve X25519 uses. One scalar multiplication "
            "-- applies unmultiplied to EACH of this project's x25519Generate "
            "(keygen) and x25519Derive (derive) calls, which are each one "
            "scalar multiplication. A faster, non-constant-time variant in "
            "the same table measured 3.82 mJ; the constant-time figure is used "
            "here since the protocol's threat model assumes side-channel "
            "countermeasures (see paper.tex's stated threat-model assumption).",
}

# nJ/bit, IEEE 802.11a at 6 Mbps -- matches this project's own
# WirelessMedium/INET linkBitrateBps=6e6 exactly, so no rate-mismatch caveat
# is needed.
RADIO_80211_TX_NJ_PER_BIT = {
    "value": 50.0,
    "platform": "generic IEEE 802.11a radio, 6 Mbps (Atheros Communications "
                "2003 power figures, as tabulated by the source below)",
    "source": "Ergen & Varaiya, \"Decomposition of Energy Consumption in "
              "IEEE 802.11,\" UC Berkeley EECS",
    "url": "https://ptolemy.berkeley.edu/projects/ofdm/m/ergen/docs/paperv3PV.pdf",
    "confidence": "verified",
    "note": "0.3 W TX power / 6 Mbps = 50 nJ/bit, derived directly from the "
            "paper's own stated power and bitrate (simple division, not an "
            "external estimate).",
}

RADIO_80211_RX_NJ_PER_BIT = {
    "value": 30.8,
    "platform": "generic IEEE 802.11a radio, 6 Mbps (Atheros Communications "
                "2003 power figures, as tabulated by the source below)",
    "source": "Ergen & Varaiya, \"Decomposition of Energy Consumption in "
              "IEEE 802.11,\" UC Berkeley EECS",
    "url": "https://ptolemy.berkeley.edu/projects/ofdm/m/ergen/docs/paperv3PV.pdf",
    "confidence": "verified",
    "note": "0.185 W RX power / 6 Mbps = 30.8 nJ/bit, derived directly from the "
            "paper's own stated power and bitrate.",
}

# Primitives measured in omnet_primitive_costs.csv for which no literature
# energy figure was found for this exact construction (HMAC-SHA3, HKDF, the
# fuzzy-extractor's Extract step, and the PUF evaluation itself all compose
# the base hash/permutation above, but this project has no independent
# energy figure for the composed construction, only for the underlying
# permutation). Listed explicitly rather than silently omitted -- a missing
# citation is reported, not hidden.
NO_LITERATURE_FIGURE = {
    "mac": "HMAC-SHA3-256 / keyed-sponge MAC: no published energy figure "
           "found for this composed construction, only for the underlying "
           "hash/permutation (see SHA3_PERMUTATION / SPONGENT160_PERMUTATION_*).",
    "mac_verify": "Same construction as mac; see mac's note.",
    "kdf": "HKDF / one-pass-sponge KDF: no published energy figure found for "
           "this composed construction.",
    "extract": "Fuzzy-extractor Extract step (strong extractor over the PUF "
               "response): no published energy figure found.",
    "hash160": "Never invoked as a standalone in-protocol primitive (see the "
               "same finding already documented for the timing table in "
               "COMPLETE_ANALYSIS.md) -- no per-call count exists to attach "
               "an energy figure to.",
}
