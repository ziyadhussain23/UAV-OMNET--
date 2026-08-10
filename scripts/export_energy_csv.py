#!/usr/bin/env python3
"""Export an energy-cost table to omnet_energy_costs.csv.

Two kinds of row, and the `source` column says which on every single one:

  "estimate:lit"     -- a literature per-operation/per-byte energy constant
                        (scripts/energy_model.py), applied as-is. No data
                        this project measured is involved.
  "measured-derived"  -- a literature per-bit radio energy constant combined
                        with this project's OWN measured wire-byte counts
                        (from omnet_phase2_results.csv) -- real data times a
                        cited price, not a measurement of energy itself.

PrimitiveCounters.h/.cc is deliberately untouched by this whole exercise (see
the future-work plan): this script reads already-exported CSVs, it does not
add a new instrumentation path, and it does not multiply this project's own
x86 timing by an embedded platform's power draw -- that would combine two
unrelated platforms into a number with no physical meaning.

Two things this table does NOT include, and says so rather than guessing:
  - HMAC-SHA3/keyed-sponge MAC, HKDF/sponge KDF, and the fuzzy-extractor's
    Extract step: no literature energy figure was found for these composed
    constructions, only for the base hash/permutation they build on (see
    energy_model.NO_LITERATURE_FIGURE).
  - Any config this project has not itself run (radio-energy rows are
    produced only for configs actually present in omnet_phase2_results.csv).
"""

import argparse
import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import energy_model as em  # noqa: E402
import stats_util  # noqa: E402

# Structural fact, not a measurement: read directly from src/protocol/Protocol.cc
# -- UavProtocol::startPhase2 calls x25519Generate (1 keygen), and
# UavProtocol::handleM2 calls x25519Derive (1 derive) -- exactly one of each
# per side per Phase-2 handshake, deterministically (no branch skips it on
# the success path). Both crypto suites use X25519 identically, so this
# figure does not vary by suite.
X25519_OPS_PER_PHASE2_HANDSHAKE_PER_SIDE = 2   # 1 keygen + 1 derive


def unit_cost_rows():
    rows = []

    def add(primitive, entry, value_field, unit):
        rows.append({
            "row_type": "unit_cost",
            "primitive": primitive,
            "config": "",
            "value": entry[value_field],
            "unit": unit,
            "platform": entry["platform"],
            "source": "estimate:lit",
            "confidence": entry["confidence"],
            "citation": entry["source"],
            "citation_url": entry["url"],
            "note": entry["note"],
        })

    add("sha3_permutation (Keccak-f[1600])", em.SHA3_PERMUTATION,
        "energy_nJ_per_call", "nJ/call")
    add("spongent160_permutation_serial", em.SPONGENT160_PERMUTATION_SERIAL,
        "energy_nJ_per_call", "nJ/call")
    add("spongent160_permutation_parallel", em.SPONGENT160_PERMUTATION_PARALLEL,
        "energy_nJ_per_call", "nJ/call")
    add("ascon128a_aead", em.ASCON128A_AEAD, "energy_uJ_per_byte", "uJ/byte")
    add("x25519_scalarmult", em.X25519_SCALARMULT, "energy_mJ_per_call", "mJ/call")
    add("radio_802.11_tx", em.RADIO_80211_TX_NJ_PER_BIT, "value", "nJ/bit")
    add("radio_802.11_rx", em.RADIO_80211_RX_NJ_PER_BIT, "value", "nJ/bit")

    for primitive, note in em.NO_LITERATURE_FIGURE.items():
        rows.append({
            "row_type": "unit_cost", "primitive": primitive, "config": "",
            "value": "", "unit": "", "platform": "", "source": "unavailable",
            "confidence": "", "citation": "", "citation_url": "", "note": note,
        })
    return rows


def compute_energy_per_handshake_row():
    # x25519_scalarmult energy is per ONE side (UAV or GS); this is what a
    # battery-powered UAV itself spends on the ephemeral exchange for one
    # Phase-2 handshake, hence "per side" in the note, not system-wide.
    mj = (X25519_OPS_PER_PHASE2_HANDSHAKE_PER_SIDE *
          em.X25519_SCALARMULT["energy_mJ_per_call"])
    return {
        "row_type": "aggregate_per_handshake", "primitive": "x25519 (keygen+derive)",
        "config": "(suite-independent: both sha3 and spongent use X25519 identically)",
        "value": round(mj, 4), "unit": "mJ/Phase-2-handshake (one side)",
        "platform": em.X25519_SCALARMULT["platform"], "source": "estimate:lit",
        "confidence": em.X25519_SCALARMULT["confidence"],
        "citation": em.X25519_SCALARMULT["source"],
        "citation_url": em.X25519_SCALARMULT["url"],
        "note": f"{X25519_OPS_PER_PHASE2_HANDSHAKE_PER_SIDE} scalar multiplications "
                "per side per handshake is a structural fact of the protocol "
                "(src/protocol/Protocol.cc: UavProtocol::startPhase2 calls "
                "x25519Generate, UavProtocol::handleM2 calls x25519Derive), not a "
                "measurement; the per-operation energy is 100% literature.",
    }


def radio_energy_rows(results_dir):
    """Real measured wire-byte counts x literature nJ/bit -- the one genuinely
    measured-derived aggregate in this table."""
    phase2_path = results_dir / "omnet_phase2_results.csv"
    if not phase2_path.exists():
        return []
    with open(phase2_path, newline="") as fh:
        rows = list(csv.DictReader(fh))

    tx_rate = em.RADIO_80211_TX_NJ_PER_BIT["value"]
    rx_rate = em.RADIO_80211_RX_NJ_PER_BIT["value"]

    out = []
    for config in sorted({r["config"] for r in rows}):
        cfg_rows = [r for r in rows if r["config"] == config]
        # The UAV sends M1+M3 (TX) and receives M2+M4 (RX) -- see
        # src/nodes/UavNode.cc's sendToGs/handleMessage; bytes_m1..m4 are the
        # real, measured wire sizes from the canonical encoder (Message::encode()),
        # already present in omnet_phase2_results.csv.
        tx_bytes = [float(r["bytes_m1"]) + float(r["bytes_m3"]) for r in cfg_rows]
        rx_bytes = [float(r["bytes_m2"]) + float(r["bytes_m4"]) for r in cfg_rows]
        mean_tx_bytes = sum(tx_bytes) / len(tx_bytes)
        mean_rx_bytes = sum(rx_bytes) / len(rx_bytes)

        tx_uj = mean_tx_bytes * 8.0 * tx_rate / 1000.0    # nJ -> uJ
        rx_uj = mean_rx_bytes * 8.0 * rx_rate / 1000.0
        n_runs = len({r["run_id"] for r in cfg_rows})

        out.append({
            "row_type": "aggregate_per_handshake", "primitive": "radio (UAV TX+RX)",
            "config": config, "value": round(tx_uj + rx_uj, 4),
            "unit": "uJ/Phase-2-handshake (one UAV)",
            "platform": "802.11a @ 6 Mbps (matches this project's WirelessMedium/"
                        "INET linkBitrateBps)",
            "source": "measured-derived", "confidence": "verified",
            "citation": em.RADIO_80211_TX_NJ_PER_BIT["source"],
            "citation_url": em.RADIO_80211_TX_NJ_PER_BIT["url"],
            "note": f"TX energy {round(tx_uj,4)} uJ from mean measured "
                    f"{mean_tx_bytes:.1f} bytes (M1+M3) over {n_runs} run(s); "
                    f"RX energy {round(rx_uj,4)} uJ from mean measured "
                    f"{mean_rx_bytes:.1f} bytes (M2+M4). Byte counts are this "
                    "project's own data (omnet_phase2_results.csv); only the "
                    "nJ/bit price is from literature.",
        })
    return out


COLS = ["row_type", "primitive", "config", "value", "unit", "platform", "source",
        "confidence", "citation", "citation_url", "note"]


def export(results_dir):
    results_dir = Path(results_dir).resolve()
    rows = unit_cost_rows()
    rows.append(compute_energy_per_handshake_row())
    rows.extend(radio_energy_rows(results_dir))

    out_path = results_dir / "omnet_energy_costs.csv"
    with open(out_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    blank_source = [r for r in rows if not r.get("source")]
    if blank_source:
        raise AssertionError("every row must have a non-blank source: %r" % blank_source)

    print(f"wrote {len(rows)} rows to {out_path}")
    for row in rows:
        if row["row_type"] == "aggregate_per_handshake":
            print(f"  [{row['source']}] {row['primitive']:<22} "
                  f"{row['config']:<20} {row['value']} {row['unit']}")
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", default="simulations/results")
    args = ap.parse_args()
    export(args.results_dir)


if __name__ == "__main__":
    main()
