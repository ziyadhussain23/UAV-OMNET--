#ifndef UAVAUTH_CRYPTO_PUFSIMULATOR_H
#define UAVAUTH_CRYPTO_PUFSIMULATOR_H

#include <cstdint>
#include <random>
#include <vector>

namespace uavauth {
namespace crypto {

class PUFSimulator {
  private:
    int deviceSeed;
    double noiseLevel;
    int challengeBits;
    int responseBits;

    std::vector<double> delayWeights;

    mutable std::mt19937 pufRng;
    mutable std::mt19937 noiseRng;

    uint64_t makeChallengeSeed(const std::vector<uint8_t>& challenge) const;

  public:
    explicit PUFSimulator(int seed, double noise = 0.03, int challengeSize = 128, int responseSize = 128);

    std::vector<uint8_t> evaluate(const std::vector<uint8_t>& challenge);

    int evaluateArbiterBit(const std::vector<bool>& challengeVector);

    int evaluateROPUFBit(int ro1Index, int ro2Index);

    void addNoise(std::vector<uint8_t>& response);

    static double calculateUniqueness(const std::vector<uint8_t>& resp1, const std::vector<uint8_t>& resp2);

    static int hammingDistance(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs);
};

} // namespace crypto
} // namespace uavauth

#endif
