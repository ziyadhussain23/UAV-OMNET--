#ifndef UAVAUTH_PUF_IDEALPRFPUF_H
#define UAVAUTH_PUF_IDEALPRFPUF_H

#include "puf/PufModel.h"

namespace uavauth {
namespace puf {

/// A keyed PRF standing in for an ideal strong PUF.
///
/// The name is deliberate. This is *not* a PUF model: the whole response is a
/// single KMAC-256 squeeze, KMAC256(deviceKey, challenge) widened to the full
/// bit count in one call. Treating that as an arbiter PUF, as the previous
/// implementation effectively did by seeding an mt19937 from the challenge,
/// would overstate the entropy of the source by a wide margin, because a PRF
/// has no structure for a modelling attack to exploit and its response bits
/// are independent by construction.
///
/// The one-squeeze form replaces an earlier per-bit construction (one
/// HMAC-SHA3-256 per response bit). The two are the same object
/// cryptographically, a keyed PRF per device with independent uniform output
/// bits, but the per-bit form paid two hash evaluations per bit and made the
/// simulated PUF the slowest primitive in the protocol, the opposite of the
/// hardware it stands in for.
///
/// What it is good for, and why it is kept:
///   * it is the upper bound of the design space (min-entropy rate ~1.0), so it
///     is the source against which the fuzzy extractor's entropy budget and the
///     protocol's latency claims are stated;
///   * its noise process is an exact Bernoulli(p) channel with a p that is set,
///     not measured, which makes it the reference for the error-correction
///     experiments; ArbiterPuf can only *approach* a requested BER.
///
/// Noise: each response bit is flipped independently with probability
/// `noiseBer()`, decided by a 16-bit threshold on two DRBG bytes. The same two
/// bytes are drawn whatever the setting, so the DRBG stream position after an
/// evaluation does not depend on the noise level.
class IdealPrfPuf : public PufModel {
  public:
    /// `deviceSeed` is the per-device secret; the KMAC key is derived from it
    /// so that a caller may pass a short, human-readable seed.
    explicit IdealPrfPuf(const Bytes& deviceSeed);

    IdealPrfPuf(const IdealPrfPuf&) = delete;
    IdealPrfPuf& operator=(const IdealPrfPuf&) = delete;

    const char* name() const override { return "ideal-prf"; }
    size_t challengeBits() const override { return kSubChallengeBits; }

    Bytes evaluateIdeal(const Bytes& challenge, size_t bitCount) const override;
    Bytes evaluateNoisy(const Bytes& challenge, size_t bitCount,
                        crypto::Drbg& rng) const override;

    /// Per-bit flip probability of the field evaluation. Clamped to [0, 1].
    void setNoiseBer(double ber);
    double noiseBer() const { return ber_; }

    /// Empirical BER over `trials` field evaluations of one challenge. Present
    /// so the reliability test measures both models through the same interface;
    /// for this model the answer is a plain binomial estimate of noiseBer().
    double measureBer(const Bytes& challenge, size_t bitCount, crypto::Drbg& rng,
                      int trials) const;

  private:
    Bytes deviceKey_;   // 32 bytes
    double ber_ = 0.0;
};

} // namespace puf
} // namespace uavauth

#endif
