#ifndef UAVAUTH_PUF_XORARBITERPUF_H
#define UAVAUTH_PUF_XORARBITERPUF_H

#include "puf/ArbiterPuf.h"

#include <memory>
#include <string>
#include <vector>

namespace uavauth {
namespace puf {

/// k-XOR arbiter PUF: k independent 128-stage chains driven by the same
/// sub-challenge, response bit = XOR of the k chain outputs.
///
/// This is the standard answer to the plain arbiter PUF's modelability, and it
/// is included precisely so the cost of that answer is visible rather than
/// assumed. XOR-ing k chains raises the number of CRPs a modelling attack needs
/// super-linearly in k, but every chain contributes its own metastability, so
/// the error rates compound:
///
///     BER_xor(k) = (1 - (1 - 2*p)^k) / 2
///
/// At a per-chain BER of 3%, k=4 gives 11.0% and k=8 gives 19.5%. That is the
/// trade-off the fuzzy extractor has to absorb, and it is why k is a parameter
/// of the experiment instead of a constant in the source.
class XorArbiterPuf : public PufModel {
  public:
    /// k independent chains, each seeded from `deviceSeed` with a distinct
    /// domain separator so the chains are independent but the device stays
    /// reproducible from one seed.
    XorArbiterPuf(const Bytes& deviceSeed, int k);

    const char* name() const override { return name_.c_str(); }
    size_t challengeBits() const override { return ArbiterPuf::kStages; }

    Bytes evaluateIdeal(const Bytes& challenge, size_t bitCount) const override;
    Bytes evaluateNoisy(const Bytes& challenge, size_t bitCount,
                        crypto::Drbg& rng) const override;

    int chains() const { return static_cast<int>(chains_.size()); }
    const ArbiterPuf& chain(int index) const { return *chains_.at(static_cast<size_t>(index)); }

    /// Set the same delay-noise sigma on every chain.
    void setNoiseSigma(double sigma);

    /// Calibrate every chain to `perChainBer`, and return the sigma used. The
    /// resulting device BER is the XOR-amplified value above, not perChainBer --
    /// that amplification is the point of the measurement.
    double setChainSigmaForTargetBer(double perChainBer, crypto::Drbg& rng,
                                     int trials = 20000);

    /// Empirical device BER for one challenge at the current sigma.
    double measureBer(const Bytes& challenge, size_t bitCount, crypto::Drbg& rng,
                      int trials) const;

    /// Closed-form BER of the XOR of k independent chains each at BER p.
    static double predictedBer(double perChainBer, int k);

  private:
    std::vector<std::unique_ptr<ArbiterPuf>> chains_;
    std::string name_;
};

} // namespace puf
} // namespace uavauth

#endif
