#ifndef UAVAUTH_PUF_MINENTROPY_H
#define UAVAUTH_PUF_MINENTROPY_H

#include "core/Bytes.h"

#include <cstddef>
#include <vector>

namespace uavauth {
namespace puf {

using core::Bytes;

/// Result of a min-entropy measurement over a population of devices.
///
/// The number that matters downstream is `minOfEstimates`: the fuzzy extractor
/// sizes its block count from the residual entropy left after the code-offset
/// sketch leaks n-k bits per block, so under-estimating is safe and
/// over-estimating silently produces a weak key.
struct EntropyEstimate {
    double mcvBitsPerBlock = 0.0;
    double mcvRatePerBit = 0.0;
    double compressionBitsPerBlock = 0.0;
    double minOfEstimates = 0.0;
    size_t devices = 0;
    size_t blockBits = 0;

    // --- Diagnostics (appended after the fields above so positional aggregate
    // initialisation of the six primary fields stays valid). ---

    /// MCV rate without the 99% confidence correction. Reported separately
    /// because the correction alone costs 2.576*sqrt(0.25/(D-1)) of probability
    /// mass, i.e. ~0.145 bits/bit at D=1000: at small device counts the
    /// corrected figure measures the sample size more than it measures the
    /// source. See the header comment on estimateMinEntropy().
    double mcvRateUncorrectedPerBit = 0.0;

    /// Context length used by the predictability estimate, in bits.
    int contextBits = 0;

    /// Largest single-bit-position bias observed, |p - 0.5|.
    double maxPositionBias = 0.0;
};

/// Min-entropy of a PUF response, measured across a population of devices that
/// were all given the same challenge.
///
/// Two estimators, and the conservative minimum of the two is returned.
///
/// 1. MCV (NIST SP 800-90B, IID track), applied per bit position i across the D
///    devices:
///        p_hat = max(freq0, freq1) / D
///        p_u   = min(1, p_hat + 2.576*sqrt(p_hat*(1-p_hat)/(D-1)))
///        H     = sum_i -log2(p_u)
///    This catches a *positional* bias: a bit position that leans the same way
///    on every device carries no entropy. It is blind to correlation between
///    positions, which is why a second estimator exists.
///
///    Note on sample size. p_u is a one-sided 99% upper confidence bound, so for
///    a perfectly unbiased source the estimate converges to 1 bit/bit only as D
///    grows: it is capped near 0.85 at D=1000, 0.95 at D=10^4 and 0.985 at
///    D=10^5. A measured rate below 1.0 at modest D is therefore a statement
///    about the experiment, not necessarily about the PUF -- compare against the
///    same estimator run on a known-uniform source of the same shape.
///
/// 2. A predictability ("compression") estimate: the average min-entropy of a
///    bit given the k bits preceding it within the same device's response,
///        p_guess = sum_ctx max(count0[ctx], count1[ctx]) / N
///        H       = -log2(upper-bounded p_guess) * blockBits
///    k is chosen as large as the sample supports (at least 16384 observations
///    per context), which is what keeps this estimator's own sampling bias below
///    ~0.01 bit/bit. It catches short-range structure inside a response that the
///    per-position MCV cannot see.
///
/// Neither estimator can see the arbiter PUF's defining weakness -- that its
/// bits are a linear function of 129 stage weights and so are predictable from
/// ~129 challenge/response pairs. That is a modelling attack against the
/// challenge-response map, not a bias in the response bits, and no estimator
/// that is handed responses without the challenges can detect it.
///
/// `responsesAcrossDevices` holds one MSB-first packed response per device, each
/// at least bytesForBits(blockBits) long. Throws std::invalid_argument if a
/// response is short.
EntropyEstimate estimateMinEntropy(const std::vector<Bytes>& responsesAcrossDevices,
                                   size_t blockBits);

} // namespace puf
} // namespace uavauth

#endif
