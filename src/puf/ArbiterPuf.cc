#include "puf/ArbiterPuf.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace uavauth {
namespace puf {

using core::bytesForBits;
using core::fromString;
using core::getBit;
using core::setBit;
using crypto::Primitive;
using crypto::ScopedTimer;

namespace {

const char* kWeightLabel = "uavauth/v1/puf/arbiter-weights";

/// Phi(-x) for x >= 0: the probability that a N(0,1) deviate falls below -x.
inline double normalTail(double x) {
    static const double kInvSqrt2 = 0.7071067811865476;
    return 0.5 * std::erfc(x * kInvSqrt2);
}

} // namespace

ArbiterPuf::ArbiterPuf(const Bytes& deviceSeed) {
    Bytes seed = fromString(kWeightLabel);
    seed.insert(seed.end(), deviceSeed.begin(), deviceSeed.end());

    // A dedicated DRBG: the weight vector is device manufacturing variation, and
    // must not move when the device later consumes randomness for noise.
    crypto::Drbg wrng(seed);
    w_.resize(kStages + 1);
    for (size_t i = 0; i <= kStages; ++i) w_[i] = wrng.normal();
}

void ArbiterPuf::setNoiseSigma(double sigma) { sigma_ = std::max(0.0, sigma); }

double ArbiterPuf::deltaForSubChallenge(const Bytes& subChallenge) const {
    if (subChallenge.size() * 8 < kStages)
        throw std::invalid_argument("ArbiterPuf: sub-challenge shorter than 128 bits");

    // phi[i] = prod_{k=i..127} (1-2c[k]); build it with one running product,
    // walking the stages from the arbiter end back to the input.
    double delta = w_[kStages];
    double parity = 1.0;
    for (size_t i = kStages; i-- > 0;) {
        parity = getBit(subChallenge, i) ? -parity : parity;
        delta += w_[i] * parity;
    }
    return delta;
}

void ArbiterPuf::computeDeltas(const Bytes& challenge, size_t bitCount,
                               std::vector<double>& out) const {
    requireValidBitCount(bitCount);
    out.resize(bitCount);
    for (size_t j = 0; j < bitCount; ++j)
        out[j] = deltaForSubChallenge(deriveSubChallenge(challenge, static_cast<uint16_t>(j)));
}

Bytes ArbiterPuf::evaluateIdeal(const Bytes& challenge, size_t bitCount) const {
    requireValidBitCount(bitCount);
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out(bytesForBits(bitCount), 0);
    for (size_t j = 0; j < bitCount; ++j) {
        const double delta =
            deltaForSubChallenge(deriveSubChallenge(challenge, static_cast<uint16_t>(j)));
        setBit(out, j, delta > 0.0);
    }
    return out;
}

Bytes ArbiterPuf::evaluateNoisy(const Bytes& challenge, size_t bitCount,
                                crypto::Drbg& rng) const {
    requireValidBitCount(bitCount);
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out(bytesForBits(bitCount), 0);
    for (size_t j = 0; j < bitCount; ++j) {
        const double delta =
            deltaForSubChallenge(deriveSubChallenge(challenge, static_cast<uint16_t>(j)));
        // The noise is on the delay difference. One draw per bit whatever sigma
        // is, so the stream position does not depend on the noise setting.
        const double noise = sigma_ * rng.normal();
        setBit(out, j, (delta + noise) > 0.0);
    }
    return out;
}

double ArbiterPuf::sigmaForTargetBer(double targetBer, crypto::Drbg& rng,
                                     int trials) const {
    if (targetBer <= 0.0) return 0.0;
    const double target = std::min(targetBer, 0.4999);
    const int n = std::max(1, trials);

    std::vector<double> absDelta;
    absDelta.reserve(static_cast<size_t>(n));
    for (int t = 0; t < n; ++t) {
        const Bytes challenge = rng.bytes(16);
        const uint16_t j = static_cast<uint16_t>(rng.uniform(256));
        absDelta.push_back(std::fabs(deltaForSubChallenge(deriveSubChallenge(challenge, j))));
    }

    // Ascending order lets the sum stop as soon as the terms become negligible:
    // a bit with |Delta| > 9*sigma contributes under 1e-19, and every later term
    // is smaller still. At a 1% target that skips most of the sample.
    std::sort(absDelta.begin(), absDelta.end());

    // Strictly increasing in sigma: 0 at sigma -> 0, 0.5 at sigma -> inf.
    const auto meanFlip = [&absDelta](double sigma) {
        if (sigma <= 0.0) return 0.0;
        const double cutoff = 9.0 * sigma;
        double sum = 0.0;
        for (double d : absDelta) {
            if (d > cutoff) break;
            sum += normalTail(d / sigma);
        }
        return sum / static_cast<double>(absDelta.size());
    };

    double lo = 0.0;
    double hi = 1.0;
    int guard = 0;
    while (meanFlip(hi) < target && guard++ < 64) hi *= 2.0;
    // 40 halvings of [0, hi] leave a relative precision of ~1e-12, far below the
    // sampling error of the |Delta| population itself.
    for (int i = 0; i < 40; ++i) {
        const double mid = 0.5 * (lo + hi);
        if (meanFlip(mid) < target)
            lo = mid;
        else
            hi = mid;
    }
    return 0.5 * (lo + hi);
}

double ArbiterPuf::measureBer(const Bytes& challenge, size_t bitCount,
                              crypto::Drbg& rng, int trials) const {
    if (bitCount == 0 || trials <= 0) return 0.0;
    std::vector<double> deltas;
    computeDeltas(challenge, bitCount, deltas);

    size_t flips = 0;
    for (int t = 0; t < trials; ++t) {
        for (size_t j = 0; j < bitCount; ++j) {
            const bool ideal = deltas[j] > 0.0;
            const bool noisy = (deltas[j] + sigma_ * rng.normal()) > 0.0;
            if (ideal != noisy) ++flips;
        }
    }
    return static_cast<double>(flips) /
           (static_cast<double>(trials) * static_cast<double>(bitCount));
}

std::vector<double> ArbiterPuf::measurePerBitFlipRate(const Bytes& challenge,
                                                      size_t bitCount,
                                                      crypto::Drbg& rng,
                                                      int trials) const {
    std::vector<double> rate(bitCount, 0.0);
    if (bitCount == 0 || trials <= 0) return rate;

    std::vector<double> deltas;
    computeDeltas(challenge, bitCount, deltas);
    std::vector<size_t> flips(bitCount, 0);
    for (int t = 0; t < trials; ++t) {
        for (size_t j = 0; j < bitCount; ++j) {
            const bool ideal = deltas[j] > 0.0;
            const bool noisy = (deltas[j] + sigma_ * rng.normal()) > 0.0;
            if (ideal != noisy) ++flips[j];
        }
    }
    for (size_t j = 0; j < bitCount; ++j)
        rate[j] = static_cast<double>(flips[j]) / static_cast<double>(trials);
    return rate;
}

} // namespace puf
} // namespace uavauth
