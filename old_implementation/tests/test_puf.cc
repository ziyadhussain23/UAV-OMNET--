#include "../src/crypto/PUFSimulator.h"

#include <cassert>
#include <iostream>
#include <vector>

using uavauth::crypto::PUFSimulator;

static void testPUFUniqueness() {
    PUFSimulator puf1(42, 0.03);
    PUFSimulator puf2(43, 0.03);

    std::vector<uint8_t> challenge(16, 0xAA);

    const auto resp1 = puf1.evaluate(challenge);
    const auto resp2 = puf2.evaluate(challenge);

    const double uniqueness = PUFSimulator::calculateUniqueness(resp1, resp2);
    std::cout << "Inter-chip Hamming distance: " << uniqueness << "%" << std::endl;

    assert(uniqueness > 35.0 && uniqueness < 65.0);
}

static void testPUFReliability() {
    PUFSimulator puf(42, 0.03);
    std::vector<uint8_t> challenge(16, 0xBB);

    std::vector<std::vector<uint8_t>> responses;
    for (int i = 0; i < 10; ++i) {
        responses.push_back(puf.evaluate(challenge));
    }

    double avgDistance = 0.0;
    for (size_t i = 1; i < responses.size(); ++i) {
        avgDistance += PUFSimulator::calculateUniqueness(responses[0], responses[i]);
    }
    avgDistance /= static_cast<double>(responses.size() - 1);

    std::cout << "Intra-chip Hamming distance: " << avgDistance << "%" << std::endl;
    assert(avgDistance < 10.0);
}

int main() {
    testPUFUniqueness();
    testPUFReliability();

    std::cout << "All PUF tests passed." << std::endl;
    return 0;
}
