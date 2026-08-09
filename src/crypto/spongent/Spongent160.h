#ifndef UAVAUTH_CRYPTO_SPONGENT_SPONGENT160_H
#define UAVAUTH_CRYPTO_SPONGENT_SPONGENT160_H

#include "core/Bytes.h"

#include <cstddef>
#include <cstdint>

namespace uavauth {
namespace crypto {

using core::Bytes;

/// SPONGENT-160/160/16 -- the hash primitive of the constrained-hardware suite.
///
/// Geometry (Bogdanov, Knezevic, Leander, Toz, Varici, Verbauwhede, "spongent: A
/// Lightweight Hash Function", CHES 2011):
///
///   b = 176 bits of state, r = 16 bits rate, c = 160 bits capacity,
///   R = 90 rounds, digest 160 bits.
///
/// The capacity fixes the security level: 80 bits against collisions, which is
/// why SpongentSuite reports securityLevelBits() == 80 while the sha3 profile
/// reports 128. Nothing in this file is a drop-in replacement for SHA3; it is
/// the deliberately weaker, deliberately smaller alternative whose cost is being
/// measured.
///
/// -------------------------------------------------------------------------
/// VERIFICATION STATUS -- read this before quoting any number produced here.
///
/// SPONGENT predates the NIST lightweight-crypto competition, so no official
/// NIST-style KAT file exists for it, and the vector table printed in the CHES
/// 2011 paper could not be retrieved. What this implementation *was* checked
/// against is the designers' own public-domain reference implementation
/// (Spongent.cpp / Spongent.h from https://sites.google.com/site/spongenthash/,
/// obtained through a GitHub mirror, carrying the authors' public-domain
/// header). Agreement is byte-exact on the designers' own example message
/// "Sponge + Present = Spongent", on counting-byte messages of 0..100 bytes, and
/// on a 1000-step iterated-hash chain; the digest of that example message also
/// matches an independent third-party listing of the SPONGENT test vectors.
/// The vectors embedded in tests/test_spongent.cc are therefore traceable to the
/// reference *code*, not to the paper, and that distinction is stated verbatim
/// in verificationStatus(). Do not upgrade the claim.
///
/// On top of the vectors, tests/test_spongent.cc checks the structure (S-box and
/// bit permutation are permutations, the round-constant LFSR has period 127 and
/// never reaches the absorbing zero state, the permutation is injective over
/// random states) and the statistics (single-bit avalanche in 35-65%, no
/// collisions over 100k random inputs).
///
/// Not verified at all: constant-time behaviour. This is a portable
/// table-assisted implementation, not a side-channel-hardened one.
/// -------------------------------------------------------------------------
class Spongent160 {
  public:
    /// Digest of `m`, 20 bytes. Equivalent to spongeAbsorbSqueeze(m, 20).
    Bytes hash(const Bytes& m) const;

    /// The bare sponge: absorb `input` (10* padded to the rate), then squeeze
    /// `outLen` bytes. The suite's MAC and KDF are modes over this call rather
    /// than over hash(), because a sponge with c > 0 can emit any output length
    /// directly and does not need a Merkle-Damgard-style wrapper.
    ///
    /// Note that squeezing is a stream: the first k bytes of an n-byte output
    /// are the n-byte output's prefix. Callers that must not have one derived
    /// key be a prefix of another have to bind the length into the *input* --
    /// which is exactly what SpongentSuite::kdf() does.
    Bytes spongeAbsorbSqueeze(const Bytes& input, size_t outLen) const;

    /// Exactly what has and has not been checked about this implementation.
    /// Recorded alongside results so a reader can calibrate how much to trust a
    /// spongent-profile measurement.
    static const char* verificationStatus();
};

/// Internals exposed for the structural tests. Mirrors the role of the `raw`
/// namespace in crypto/Sha3Suite.h: a test has to be able to reach the S-box,
/// the bit permutation, the LFSR and the bare permutation to show each is what
/// the specification says it is, without going through the sponge.
namespace raw {

constexpr size_t  kSpongentStateBits    = 176;   // b
constexpr size_t  kSpongentStateBytes   = 22;    // b/8
constexpr size_t  kSpongentRateBits     = 16;    // r
constexpr size_t  kSpongentRateBytes    = 2;     // r/8
constexpr size_t  kSpongentCapacityBits = 160;   // c
constexpr int     kSpongentRounds       = 90;    // R
constexpr uint8_t kSpongentLfsrInit     = 0x45;  // per-variant seed, 160/160/16

/// PRESENT 4-bit S-box, applied to every nibble of the state.
uint8_t spongentSbox(uint8_t nibble);

/// pLayer destination of state bit `bitIndex`:
///     P(j) = (j * b/4) mod (b-1)   for j < b-1,   P(b-1) = b-1
/// i.e. (j*44) mod 175 with bit 175 fixed. gcd(44,175) == 1, so this is a
/// permutation of 0..175 -- the test asserts it rather than assuming it.
size_t spongentPLayerIndex(size_t bitIndex);

/// One step of the 7-bit round-constant LFSR, feedback x^7 + x^6 + 1. The
/// polynomial is primitive, so from any non-zero seed the sequence has period
/// 127 > R = 90 and never emits 0.
uint8_t spongentLfsrNext(uint8_t lfsr);

/// The full 90-round permutation, in place over the 22-byte state.
///
/// Bit numbering follows the reference implementation: state bit j lives in
/// byte j/8 at bit position j%8 counted from the LSB, so bit 0 is the least
/// significant bit of state[0] and bit 175 is the most significant bit of
/// state[21]. This is deliberately *not* the MSB-first convention of
/// core::getBit(); it is local to the permutation and never escapes this file.
void spongentPermute(uint8_t state[kSpongentStateBytes]);

} // namespace raw

} // namespace crypto
} // namespace uavauth

#endif
