#include "puf/MinEntropy.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace uavauth {
namespace puf {

using core::bytesForBits;
using core::getBit;

namespace {

/// One-sided 99% upper confidence bound on a proportion (SP 800-90B uses the
/// normal approximation with z = 2.576).
double upperBound99(double pHat, size_t samples) {
    if (samples < 2) return 1.0;
    const double n = static_cast<double>(samples - 1);
    const double halfWidth = 2.576 * std::sqrt(pHat * (1.0 - pHat) / n);
    return std::min(1.0, pHat + halfWidth);
}

double minEntropyOf(double p) {
    if (p >= 1.0) return 0.0;
    if (p <= 0.0) return 0.0;
    return -std::log2(p);
}

/// Largest context length k in [0, kMaxContextBits] for which every one of the
/// 2^k contexts is expected to receive at least kMinPerContext observations.
///
/// The trade-off: a longer context detects longer-range structure but splits the
/// sample, and a context with few observations reports spurious predictability
/// (E[max(f0,f1)] ~ 0.5 + 0.4/sqrt(n)). Requiring 16384 observations per context
/// holds that artefact near 0.003, i.e. under 0.01 bit/bit.
int chooseContextBits(size_t devices, size_t blockBits) {
    constexpr int kMaxContextBits = 8;
    constexpr double kMinPerContext = 16384.0;
    int best = 0;
    for (int k = 1; k <= kMaxContextBits; ++k) {
        if (blockBits <= static_cast<size_t>(k)) break;
        const double observations =
            static_cast<double>(devices) * static_cast<double>(blockBits - static_cast<size_t>(k));
        if (observations < kMinPerContext * std::pow(2.0, k)) break;
        best = k;
    }
    return best;
}

} // namespace

EntropyEstimate estimateMinEntropy(const std::vector<Bytes>& responsesAcrossDevices,
                                   size_t blockBits) {
    EntropyEstimate est;
    est.devices = responsesAcrossDevices.size();
    est.blockBits = blockBits;
    if (est.devices == 0 || blockBits == 0) return est;

    const size_t needBytes = bytesForBits(blockBits);
    for (const Bytes& r : responsesAcrossDevices)
        if (r.size() < needBytes)
            throw std::invalid_argument("estimateMinEntropy: response shorter than blockBits");

    const size_t devices = est.devices;

    // --- 1. MCV per bit position across devices ------------------------------
    std::vector<size_t> ones(blockBits, 0);
    for (const Bytes& r : responsesAcrossDevices)
        for (size_t i = 0; i < blockBits; ++i)
            if (getBit(r, i)) ++ones[i];

    double mcvBits = 0.0;
    double mcvBitsRaw = 0.0;
    double maxBias = 0.0;
    for (size_t i = 0; i < blockBits; ++i) {
        const size_t major = std::max(ones[i], devices - ones[i]);
        const double pHat = static_cast<double>(major) / static_cast<double>(devices);
        mcvBitsRaw += minEntropyOf(pHat);
        mcvBits += minEntropyOf(upperBound99(pHat, devices));
        maxBias = std::max(maxBias, pHat - 0.5);
    }
    est.mcvBitsPerBlock = mcvBits;
    est.mcvRatePerBit = mcvBits / static_cast<double>(blockBits);
    est.mcvRateUncorrectedPerBit = mcvBitsRaw / static_cast<double>(blockBits);
    est.maxPositionBias = maxBias;

    // --- 2. Predictability given the preceding k bits of the same response ---
    const int k = chooseContextBits(devices, blockBits);
    est.contextBits = k;

    const size_t contexts = static_cast<size_t>(1) << k;
    std::vector<size_t> counts(contexts * 2, 0);
    size_t observations = 0;
    for (const Bytes& r : responsesAcrossDevices) {
        size_t ctx = 0;
        for (size_t i = 0; i < blockBits; ++i) {
            const bool bit = getBit(r, i);
            if (i >= static_cast<size_t>(k)) {
                counts[ctx * 2 + (bit ? 1u : 0u)] += 1;
                ++observations;
            }
            if (k > 0) ctx = ((ctx << 1) | (bit ? 1u : 0u)) & (contexts - 1);
        }
    }

    if (observations >= 2) {
        size_t correct = 0;
        for (size_t c = 0; c < contexts; ++c)
            correct += std::max(counts[c * 2], counts[c * 2 + 1]);
        const double pGuess = static_cast<double>(correct) / static_cast<double>(observations);
        const double rate = minEntropyOf(upperBound99(pGuess, observations));
        est.compressionBitsPerBlock = rate * static_cast<double>(blockBits);
    } else {
        est.compressionBitsPerBlock = 0.0;
    }

    est.minOfEstimates = std::min(est.mcvBitsPerBlock, est.compressionBitsPerBlock);
    return est;
}

} // namespace puf
} // namespace uavauth
