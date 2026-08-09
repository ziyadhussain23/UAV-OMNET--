#ifndef UAVAUTH_PUF_ARBITERPUF_H
#define UAVAUTH_PUF_ARBITERPUF_H

#include "puf/PufModel.h"

#include <vector>

namespace uavauth {
namespace puf {

/// 128-stage additive-delay arbiter PUF.
///
/// The model
/// -----------
/// A device is 129 stage-delay weights w[0..128] drawn once, deterministically,
/// from the device seed. For a 128-bit sub-challenge c the standard parity
/// (feature) vector is
///
///     phi[i] = prod_{k=i..127} (1 - 2*c[k])   for i in 0..127,   phi[128] = 1
///
/// and the delay difference at the arbiter is Delta = sum_i w[i]*phi[i]. The
/// noise-free response bit is (Delta > 0).
///
/// This is the actual physics abstraction the literature models, and it has two
/// consequences the previous PRNG-based stand-in did not reproduce:
///
///   * Response bits of one device are not independent -- they are all linear
///     functions of the same 129 weights, which is exactly why ~129 CRPs suffice
///     to model the device. An honest min-entropy measurement has to see that.
///
///   * Reliability is bit-dependent. Noise perturbs the *delay difference*, not
///     the output bit:  Delta_noisy = Delta + N(0, sigma). A bit whose Delta sits
///     near zero is metastable and flips constantly; a bit with a large |Delta|
///     almost never flips. The previous model flipped a fixed number of
///     uniformly chosen positions, which made every bit equally unreliable and
///     was not even a stochastic channel (the flip count had zero variance).
///
/// Calibration
/// -----------
/// sigma has no natural unit -- it is relative to the (unitless) weight scale --
/// so it is set indirectly from a target average BER via sigmaForTargetBer().
class ArbiterPuf : public PufModel {
  public:
    static constexpr size_t kStages = 128;

    explicit ArbiterPuf(const Bytes& deviceSeed);

    const char* name() const override { return "arbiter-128"; }
    size_t challengeBits() const override { return kStages; }

    Bytes evaluateIdeal(const Bytes& challenge, size_t bitCount) const override;
    Bytes evaluateNoisy(const Bytes& challenge, size_t bitCount,
                        crypto::Drbg& rng) const override;

    /// Standard deviation of the additive delay noise, in weight units.
    void setNoiseSigma(double sigma);
    double noiseSigma() const { return sigma_; }

    /// Delay difference for one 16-byte sub-challenge. Exposed because the
    /// XOR construction needs it (it derives each sub-challenge once and queries
    /// every chain), and because the reliability analysis is about the
    /// distribution of |Delta|.
    double deltaForSubChallenge(const Bytes& subChallenge) const;

    /// Delay differences for response bits 0..bitCount-1 of `challenge`.
    void computeDeltas(const Bytes& challenge, size_t bitCount,
                       std::vector<double>& out) const;

    /// sigma achieving `targetBer` averaged over the challenge population.
    ///
    /// `trials` random (challenge, bit index) pairs are drawn from `rng` to
    /// sample the |Delta| distribution; sigma is then bisected on
    ///     E[ Phi(-|Delta| / sigma) ]
    /// which is the exact flip probability conditioned on Delta. Using the
    /// closed form for the inner expectation rather than resampling the noise
    /// removes the Monte-Carlo error from the outer loop, so the calibration is
    /// limited only by how well `trials` samples the |Delta| distribution.
    ///
    /// Does not modify the device: pass the result to setNoiseSigma().
    double sigmaForTargetBer(double targetBer, crypto::Drbg& rng,
                             int trials = 20000) const;

    /// Empirical BER for one challenge at the current sigma, over `trials`
    /// independent field evaluations. Shares evaluateNoisy()'s arithmetic and
    /// its per-bit DRBG draw order, so the two agree bit for bit.
    double measureBer(const Bytes& challenge, size_t bitCount, crypto::Drbg& rng,
                      int trials) const;

    /// Per-bit flip rate for one challenge; the reliability profile that makes
    /// this model different from a uniform bit-flip channel.
    std::vector<double> measurePerBitFlipRate(const Bytes& challenge, size_t bitCount,
                                              crypto::Drbg& rng, int trials) const;

    const std::vector<double>& weights() const { return w_; }

  private:
    std::vector<double> w_;   // kStages + 1 entries
    double sigma_ = 0.0;
};

} // namespace puf
} // namespace uavauth

#endif
