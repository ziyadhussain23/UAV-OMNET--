#include "crypto/spongent/Spongent160.h"

#include <algorithm>
#include <cstring>

namespace uavauth {
namespace crypto {
namespace raw {

namespace {

/// PRESENT S-box, as used unchanged by SPONGENT.
const uint8_t kSbox[16] = {0xE, 0xD, 0xB, 0x0, 0x2, 0x1, 0x4, 0xF,
                           0x7, 0xA, 0x8, 0x5, 0x9, 0xC, 0x3, 0x6};

/// Bit-reversal of a byte. The round constant is added twice per round: the
/// LFSR value at the least-significant end of the state, and its bit-reversal
/// at the most-significant end (the "retnuoCl" of the specification). Because
/// the LFSR is 7 bits wide its top bit is always 0, so reversing the whole byte
/// places the 7 counter bits in state bits 175..169 as required.
uint8_t reverseByte(uint8_t v) {
    v = static_cast<uint8_t>(((v & 0xF0u) >> 4) | ((v & 0x0Fu) << 4));
    v = static_cast<uint8_t>(((v & 0xCCu) >> 2) | ((v & 0x33u) << 2));
    v = static_cast<uint8_t>(((v & 0xAAu) >> 1) | ((v & 0x55u) << 1));
    return v;
}

/// Precomputed pLayer.
///
/// The bit permutation is linear, so the contribution of one input byte depends
/// only on (byte position, byte value) and the whole layer is the XOR of 22 such
/// contributions. This table is a deliberate optimisation -- please do NOT
/// "simplify" it back into the textbook bit-by-bit loop.
///
/// The bit-by-bit form costs 176 scattered read-modify-writes per round, ~16k per
/// permutation. Measured on this machine, 100k hashes of an 8-byte input take
/// 31 s that way (the designers' reference implementation, which uses that loop,
/// times the same), against 4.9 s with this table -- and 100k hashes is exactly
/// what the collision check in tests/test_spongent.cc does, so the naive form
/// would put half a minute into the fast test gate and slow every simulation run
/// that uses the spongent profile by the same factor.
///
/// The table is *generated from* spongentPLayerIndex(), so the formula in the
/// header stays the single source of truth -- there is no second, hand-written
/// copy of the permutation to drift out of sync. Rows are 24 bytes rather than
/// 22 so they can be XORed three 64-bit words at a time; the two trailing bytes
/// are always zero. The words are only ever used as an eight-byte XOR vehicle
/// (loaded and stored with memcpy), so the layout is byte-order independent.
struct PLayerTable {
    static constexpr size_t kRowBytes = 24;
    uint8_t row[kSpongentStateBytes][256][kRowBytes];

    PLayerTable() {
        std::memset(row, 0, sizeof(row));
        for (size_t byteIndex = 0; byteIndex < kSpongentStateBytes; ++byteIndex) {
            for (size_t value = 0; value < 256; ++value) {
                for (size_t bit = 0; bit < 8; ++bit) {
                    if (((value >> bit) & 1u) == 0) continue;
                    const size_t dst = spongentPLayerIndex(byteIndex * 8 + bit);
                    row[byteIndex][value][dst / 8] |= static_cast<uint8_t>(1u << (dst % 8));
                }
            }
        }
    }
};

const PLayerTable& pLayerTable() {
    // Function-local static: built once, thread-safe initialisation under C++11.
    static const PLayerTable table;
    return table;
}

/// Overwrite scratch state so intermediate values of a keyed sponge do not
/// linger on the stack. core::secureZero() only takes a Bytes.
void wipe(uint8_t* p, size_t n) {
    volatile uint8_t* v = p;
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}

} // namespace

uint8_t spongentSbox(uint8_t nibble) { return kSbox[nibble & 0x0Fu]; }

size_t spongentPLayerIndex(size_t bitIndex) {
    if (bitIndex == kSpongentStateBits - 1) return kSpongentStateBits - 1;
    return (bitIndex * (kSpongentStateBits / 4)) % (kSpongentStateBits - 1);
}

uint8_t spongentLfsrNext(uint8_t lfsr) {
    // x^7 + x^6 + 1: the new low bit is bit6 XOR bit5 of the previous state.
    const uint8_t feedback =
        static_cast<uint8_t>(((lfsr & 0x40u) >> 6) ^ ((lfsr & 0x20u) >> 5));
    return static_cast<uint8_t>(((lfsr << 1) | feedback) & 0x7Fu);
}

void spongentPermute(uint8_t state[kSpongentStateBytes]) {
    const PLayerTable& table = pLayerTable();
    uint8_t lfsr = kSpongentLfsrInit;

    for (int round = 0; round < kSpongentRounds; ++round) {
        // 1. Round constants: counter at the LSB end, its bit-reversal at the
        //    MSB end. Both ends are hit so that the constant cannot be cancelled
        //    by a symmetric state.
        state[0] = static_cast<uint8_t>(state[0] ^ lfsr);
        state[kSpongentStateBytes - 1] =
            static_cast<uint8_t>(state[kSpongentStateBytes - 1] ^ reverseByte(lfsr));
        lfsr = spongentLfsrNext(lfsr);

        // 2. sBoxLayer: the 4-bit S-box on each of the 44 nibbles.
        for (size_t i = 0; i < kSpongentStateBytes; ++i) {
            state[i] = static_cast<uint8_t>((spongentSbox(state[i] >> 4) << 4) |
                                            spongentSbox(state[i] & 0x0Fu));
        }

        // 3. pLayer, as the XOR of the 22 precomputed per-byte contributions.
        uint64_t w0 = 0, w1 = 0, w2 = 0;
        for (size_t i = 0; i < kSpongentStateBytes; ++i) {
            const uint8_t* r = table.row[i][state[i]];
            uint64_t r0, r1, r2;
            std::memcpy(&r0, r + 0, 8);
            std::memcpy(&r1, r + 8, 8);
            std::memcpy(&r2, r + 16, 8);
            w0 ^= r0;
            w1 ^= r1;
            w2 ^= r2;
        }
        uint8_t permuted[PLayerTable::kRowBytes];
        std::memcpy(permuted + 0, &w0, 8);
        std::memcpy(permuted + 8, &w1, 8);
        std::memcpy(permuted + 16, &w2, 8);
        std::memcpy(state, permuted, kSpongentStateBytes);
    }
}

} // namespace raw

const char* Spongent160::verificationStatus() {
    return "SPONGENT-160/160/16 (b=176, r=16, c=160, R=90), vendored. VERIFIED: "
           "byte-exact agreement with the SPONGENT designers' public-domain reference "
           "implementation (Spongent.cpp, sites.google.com/site/spongenthash, retrieved "
           "via a GitHub mirror) on the designers' \"Sponge + Present = Spongent\" "
           "example, on counting-byte messages of 0..100 bytes, and on a 1000-step "
           "iterated-hash chain; the digest of that example also matches an independent "
           "third-party listing of the SPONGENT vectors. Structural: S-box and pLayer are "
           "permutations, the round-constant LFSR has period 127 and never reaches zero, "
           "the permutation is injective over random states. Statistical: single-bit "
           "avalanche within 35-65%, no collisions over 100k random inputs. NOT VERIFIED: "
           "there is no official KAT file for SPONGENT and the CHES 2011 vector table was "
           "not retrievable, so these vectors are traceable to the reference code and not "
           "to the published paper; no constant-time or side-channel analysis was done.";
}

Bytes Spongent160::hash(const Bytes& m) const {
    return spongeAbsorbSqueeze(m, 20);
}

Bytes Spongent160::spongeAbsorbSqueeze(const Bytes& input, size_t outLen) const {
    using raw::kSpongentRateBytes;
    using raw::kSpongentStateBytes;

    uint8_t state[kSpongentStateBytes];
    std::memset(state, 0, sizeof(state));

    // Absorb: XOR each rate block into the r least-significant bits of the
    // state (state[0..1], matching the reference layout) and permute.
    size_t offset = 0;
    for (; offset + kSpongentRateBytes <= input.size(); offset += kSpongentRateBytes) {
        state[0] = static_cast<uint8_t>(state[0] ^ input[offset]);
        state[1] = static_cast<uint8_t>(state[1] ^ input[offset + 1]);
        raw::spongentPermute(state);
    }

    // Padding is 10*: a single 1 bit, then zeros to the end of the rate block.
    // The API is byte-granular, so the 1 bit is always the top bit of the first
    // unused byte (0x80). The padding block is unconditional -- an input whose
    // length is already a multiple of the rate still gets a full extra block,
    // which is what keeps the padding injective.
    uint8_t tail[kSpongentRateBytes];
    std::memset(tail, 0, sizeof(tail));
    const size_t remaining = input.size() - offset;
    for (size_t i = 0; i < remaining; ++i) tail[i] = input[offset + i];
    tail[remaining] = 0x80;
    state[0] = static_cast<uint8_t>(state[0] ^ tail[0]);
    state[1] = static_cast<uint8_t>(state[1] ^ tail[1]);
    raw::spongentPermute(state);

    // Squeeze: emit the rate, permute, repeat. The final block is emitted
    // without a trailing permutation, and a partial last block is truncated.
    Bytes out;
    out.reserve(outLen);
    while (out.size() < outLen) {
        const size_t take = std::min(kSpongentRateBytes, outLen - out.size());
        out.insert(out.end(), state, state + take);
        if (out.size() >= outLen) break;
        raw::spongentPermute(state);
    }

    raw::wipe(state, sizeof(state));
    return out;
}

} // namespace crypto
} // namespace uavauth
