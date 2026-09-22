#include "puf/XorArbiterPuf.h"

#include <cmath>
#include <stdexcept>

namespace uavauth {
namespace puf {

using core::bytesForBits;
using core::fromString;
using core::setBit;
using core::u16be;
using crypto::Primitive;
using crypto::ScopedTimer;

namespace {
const char* kChainLabel = "uavauth/v1/puf/xor-chain";
} // namespace

XorArbiterPuf::XorArbiterPuf(const Bytes& deviceSeed, int k) {
    if (k < 1) throw std::invalid_argument("XorArbiterPuf: k must be >= 1");
    chains_.reserve(static_cast<size_t>(k));
    for (int i = 0; i < k; ++i) {
        Bytes seed = fromString(kChainLabel);
        const Bytes index = u16be(static_cast<uint16_t>(i));
        seed.insert(seed.end(), index.begin(), index.end());
        seed.insert(seed.end(), deviceSeed.begin(), deviceSeed.end());
        chains_.emplace_back(new ArbiterPuf(seed));
    }
    name_ = "xor-arbiter-" + std::to_string(k);
}

void XorArbiterPuf::setNoiseSigma(double sigma) {
    for (auto& c : chains_) c->setNoiseSigma(sigma);
}

double XorArbiterPuf::setChainSigmaForTargetBer(double perChainBer, crypto::Drbg& rng,
                                                int trials) {
    // The chains are statistically identical, so one calibration serves all of
    // them; calibrating each separately would only add sampling noise.
    const double sigma = chains_.front()->sigmaForTargetBer(perChainBer, rng, trials);
    setNoiseSigma(sigma);
    return sigma;
}

Bytes XorArbiterPuf::evaluateIdeal(const Bytes& challenge, size_t bitCount) const {
    requireValidBitCount(bitCount);
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out(bytesForBits(bitCount), 0);
    if (bitCount == 0) return out;
    // One squeezed stream feeds every chain, as in a real XOR APUF where all
    // chains see the same sub-challenge.
    const Bytes subs = subStream(challenge, bitCount);
    for (size_t j = 0; j < bitCount; ++j) {
        const uint8_t* sub = subs.data() + 16 * j;
        bool bit = false;
        for (const auto& c : chains_) bit ^= (c->deltaForSubChallengeRaw(sub) > 0.0);
        setBit(out, j, bit);
    }
    return out;
}

Bytes XorArbiterPuf::evaluateNoisy(const Bytes& challenge, size_t bitCount,
                                   crypto::Drbg& rng) const {
    requireValidBitCount(bitCount);
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out(bytesForBits(bitCount), 0);
    if (bitCount == 0) return out;
    const Bytes subs = subStream(challenge, bitCount);
    for (size_t j = 0; j < bitCount; ++j) {
        const uint8_t* sub = subs.data() + 16 * j;
        bool bit = false;
        for (const auto& c : chains_) {
            const double delta = c->deltaForSubChallengeRaw(sub);
            bit ^= ((delta + c->noiseSigma() * rng.normal()) > 0.0);
        }
        setBit(out, j, bit);
    }
    return out;
}

double XorArbiterPuf::measureBer(const Bytes& challenge, size_t bitCount,
                                 crypto::Drbg& rng, int trials) const {
    if (bitCount == 0 || trials <= 0) return 0.0;

    // deltas[j][chain]; derived once, then only the noise is resampled. Same
    // arithmetic and same DRBG draw order as evaluateNoisy.
    std::vector<std::vector<double>> deltas(bitCount);
    std::vector<bool> ideal(bitCount, false);
    const Bytes subs = subStream(challenge, bitCount);
    for (size_t j = 0; j < bitCount; ++j) {
        const uint8_t* sub = subs.data() + 16 * j;
        deltas[j].resize(chains_.size());
        bool bit = false;
        for (size_t c = 0; c < chains_.size(); ++c) {
            deltas[j][c] = chains_[c]->deltaForSubChallengeRaw(sub);
            bit ^= (deltas[j][c] > 0.0);
        }
        ideal[j] = bit;
    }

    size_t flips = 0;
    for (int t = 0; t < trials; ++t) {
        for (size_t j = 0; j < bitCount; ++j) {
            bool bit = false;
            for (size_t c = 0; c < chains_.size(); ++c)
                bit ^= ((deltas[j][c] + chains_[c]->noiseSigma() * rng.normal()) > 0.0);
            if (bit != ideal[j]) ++flips;
        }
    }
    return static_cast<double>(flips) /
           (static_cast<double>(trials) * static_cast<double>(bitCount));
}

double XorArbiterPuf::predictedBer(double perChainBer, int k) {
    return 0.5 * (1.0 - std::pow(1.0 - 2.0 * perChainBer, k));
}

} // namespace puf
} // namespace uavauth
