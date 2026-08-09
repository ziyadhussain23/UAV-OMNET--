#ifndef UAVAUTH_CRYPTO_DRBG_H
#define UAVAUTH_CRYPTO_DRBG_H

#include "core/Bytes.h"

#include <cstdint>

namespace uavauth {
namespace crypto {

using core::Bytes;

/// Deterministic random bit generator.
///
/// Every nonce, ephemeral scalar, fuzzy-extractor seed, and enrollment challenge
/// in the simulation comes from here, seeded from the OMNeT++ RNG. Using
/// RAND_bytes instead would make runs irreproducible and would silently render
/// the `seed-set` sweep meaningless for everything cryptographic -- the
/// repetitions would differ in ways the experiment could not control.
///
/// Construction: SHA3-256 in counter mode, keyed by SHA3-256(seed). Deterministic
/// by design; not a NIST SP 800-90A DRBG and not intended as one.
class Drbg {
  public:
    explicit Drbg(const Bytes& seed);

    /// Next `n` bytes of the stream.
    Bytes bytes(size_t n);

    /// Uniform integer in [0, bound). Rejection-sampled, so there is no modulo
    /// bias. Returns 0 when bound == 0.
    uint32_t uniform(uint32_t bound);

    /// Uniform double in [0, 1).
    double uniformDouble();

    /// Standard normal deviate (Box-Muller). Used by the arbiter-PUF delay model.
    double normal();

    /// Restart the stream from a new seed.
    void reseed(const Bytes& seed);

    /// Number of bytes drawn so far; useful for asserting that a routine which
    /// must be deterministic did not consume randomness.
    uint64_t bytesDrawn() const { return drawn_; }

  private:
    void refill();

    Bytes key_;       // 32 bytes
    Bytes buffer_;    // current block
    size_t offset_ = 0;
    uint64_t counter_ = 0;
    uint64_t drawn_ = 0;
    bool haveSpareNormal_ = false;
    double spareNormal_ = 0.0;
};

} // namespace crypto
} // namespace uavauth

#endif
