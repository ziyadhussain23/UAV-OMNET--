#include "PUFSimulator.h"

#include <algorithm>
#include <cmath>

namespace uavauth {
namespace crypto {

PUFSimulator::PUFSimulator(int seed, double noise, int challengeSize, int responseSize)
    : deviceSeed(seed),
      noiseLevel(noise),
      challengeBits(challengeSize),
      responseBits(responseSize),
      pufRng(static_cast<uint32_t>(seed)),
      noiseRng(static_cast<uint32_t>(seed + 10000)) {
    const int stages = challengeBits;
    delayWeights.resize(static_cast<size_t>(stages) * 2U);

    std::normal_distribution<double> dist(0.0, 1.0);
    for (double& weight : delayWeights) {
        weight = dist(pufRng);
    }
}

uint64_t PUFSimulator::makeChallengeSeed(const std::vector<uint8_t>& challenge) const {
    uint64_t hash = 1469598103934665603ULL; // FNV offset basis
    for (uint8_t b : challenge) {
        hash ^= b;
        hash *= 1099511628211ULL; // FNV prime
    }
    hash ^= static_cast<uint64_t>(deviceSeed);
    hash *= 1099511628211ULL;
    return hash;
}

std::vector<uint8_t> PUFSimulator::evaluate(const std::vector<uint8_t>& challenge) {
    std::vector<uint8_t> response(static_cast<size_t>(responseBits / 8), 0);

    const uint64_t combinedSeed = makeChallengeSeed(challenge);
    pufRng.seed(static_cast<uint32_t>(combinedSeed ^ (combinedSeed >> 32U)));

    for (int bitIndex = 0; bitIndex < responseBits; ++bitIndex) {
        const uint32_t rnd = pufRng();
        const uint8_t challengeMix =
            static_cast<uint8_t>((combinedSeed >> static_cast<unsigned>(bitIndex % 64)) & 0x1U);
        const int bit = static_cast<int>(((rnd >> (bitIndex % 24)) & 0x1U) ^ challengeMix);

        if (bit == 1) {
            const int byteIdx = bitIndex / 8;
            const int bitInByte = bitIndex % 8;
            response[static_cast<size_t>(byteIdx)] |= static_cast<uint8_t>(1U << bitInByte);
        }
    }

    addNoise(response);
    return response;
}

int PUFSimulator::evaluateArbiterBit(const std::vector<bool>& challengeVector) {
    double upperDelay = 0.0;
    double lowerDelay = 0.0;

    const int stages = std::min(static_cast<int>(challengeVector.size()), challengeBits);
    for (int i = 0; i < stages; ++i) {
        const double w0 = delayWeights[static_cast<size_t>(i * 2)];
        const double w1 = delayWeights[static_cast<size_t>(i * 2 + 1)];
        if (challengeVector[static_cast<size_t>(i)]) {
            upperDelay += w0;
            lowerDelay += w1;
        } else {
            upperDelay += w1;
            lowerDelay += w0;
        }
    }

    return (upperDelay - lowerDelay) >= 0.0 ? 1 : 0;
}

int PUFSimulator::evaluateROPUFBit(int ro1Index, int ro2Index) {
    const double f1 = std::abs(delayWeights[static_cast<size_t>(ro1Index % static_cast<int>(delayWeights.size()))]);
    const double f2 = std::abs(delayWeights[static_cast<size_t>(ro2Index % static_cast<int>(delayWeights.size()))]);
    return f1 > f2 ? 1 : 0;
}

void PUFSimulator::addNoise(std::vector<uint8_t>& response) {
    if (noiseLevel <= 0.0) {
        return;
    }

    const int totalBits = static_cast<int>(response.size() * 8);
    const int errorBits = static_cast<int>(std::round(totalBits * noiseLevel));
    if (errorBits <= 0) {
        return;
    }

    std::uniform_int_distribution<int> bitDist(0, totalBits - 1);
    for (int i = 0; i < errorBits; ++i) {
        const int bitPos = bitDist(noiseRng);
        const int byteIdx = bitPos / 8;
        const int bitInByte = bitPos % 8;
        response[static_cast<size_t>(byteIdx)] ^= static_cast<uint8_t>(1U << bitInByte);
    }
}

double PUFSimulator::calculateUniqueness(const std::vector<uint8_t>& resp1,
                                         const std::vector<uint8_t>& resp2) {
    const int distance = hammingDistance(resp1, resp2);
    const int totalBits = static_cast<int>(std::min(resp1.size(), resp2.size()) * 8);
    if (totalBits == 0) {
        return 0.0;
    }
    return static_cast<double>(distance) * 100.0 / static_cast<double>(totalBits);
}

int PUFSimulator::hammingDistance(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
    const size_t len = std::min(lhs.size(), rhs.size());
    int distance = 0;

    for (size_t i = 0; i < len; ++i) {
        uint8_t x = static_cast<uint8_t>(lhs[i] ^ rhs[i]);
        while (x != 0U) {
            distance += (x & 1U) != 0U ? 1 : 0;
            x >>= 1U;
        }
    }

    return distance;
}

} // namespace crypto
} // namespace uavauth
