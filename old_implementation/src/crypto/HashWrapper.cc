#include "HashWrapper.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace uavauth {
namespace crypto {

HashWrapper::HashWrapper(HashMode hashMode, int outputBits)
    : mode(hashMode),
      sha3(outputBits),
      spongent(outputBits),
      sha3TimeMs(0.0),
      spongentTimeMs(0.0),
      sha3CallCount(0),
      spongentCallCount(0) {}

void HashWrapper::setMode(HashMode hashMode) {
    mode = hashMode;
}

HashMode HashWrapper::getMode() const {
    return mode;
}

std::vector<uint8_t> HashWrapper::hash(const std::vector<uint8_t>& message) const {
    const auto start = std::chrono::steady_clock::now();
    std::vector<uint8_t> result;

    if (mode == HashMode::SHA3) {
        result = sha3.hash(message);
        const auto end = std::chrono::steady_clock::now();
        sha3TimeMs += std::chrono::duration<double, std::milli>(end - start).count();
        ++sha3CallCount;
    } else {
        result = spongent.hash(message);
        const auto end = std::chrono::steady_clock::now();
        spongentTimeMs += std::chrono::duration<double, std::milli>(end - start).count();
        ++spongentCallCount;
    }

    return result;
}

std::vector<uint8_t> HashWrapper::hashMultiple(const std::vector<std::vector<uint8_t>>& inputs) const {
    const auto start = std::chrono::steady_clock::now();
    std::vector<uint8_t> result;

    if (mode == HashMode::SHA3) {
        result = sha3.hashMultiple(inputs);
        const auto end = std::chrono::steady_clock::now();
        sha3TimeMs += std::chrono::duration<double, std::milli>(end - start).count();
        ++sha3CallCount;
    } else {
        result = spongent.hashMultiple(inputs);
        const auto end = std::chrono::steady_clock::now();
        spongentTimeMs += std::chrono::duration<double, std::milli>(end - start).count();
        ++spongentCallCount;
    }

    return result;
}

std::vector<uint8_t> HashWrapper::hashDual(const std::vector<uint8_t>& message,
                                            double& sha3Ms, double& spongentMs) const {
    // Compute SHA3 timing
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint8_t> sha3Result = sha3.hash(message);
    auto t1 = std::chrono::steady_clock::now();
    sha3Ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    sha3TimeMs += sha3Ms;
    ++sha3CallCount;

    // Compute SPONGENT timing
    t0 = std::chrono::steady_clock::now();
    std::vector<uint8_t> spongentResult = spongent.hash(message);
    t1 = std::chrono::steady_clock::now();
    spongentMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    spongentTimeMs += spongentMs;
    ++spongentCallCount;

    // Return based on current mode
    return (mode == HashMode::SHA3) ? sha3Result : spongentResult;
}

std::vector<uint8_t> HashWrapper::hashMultipleDual(const std::vector<std::vector<uint8_t>>& inputs,
                                                    double& sha3Ms, double& spongentMs) const {
    // Compute SHA3 timing
    auto t0 = std::chrono::steady_clock::now();
    std::vector<uint8_t> sha3Result = sha3.hashMultiple(inputs);
    auto t1 = std::chrono::steady_clock::now();
    sha3Ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    sha3TimeMs += sha3Ms;
    ++sha3CallCount;

    // Compute SPONGENT timing
    t0 = std::chrono::steady_clock::now();
    std::vector<uint8_t> spongentResult = spongent.hashMultiple(inputs);
    t1 = std::chrono::steady_clock::now();
    spongentMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    spongentTimeMs += spongentMs;
    ++spongentCallCount;

    // Return based on current mode
    return (mode == HashMode::SHA3) ? sha3Result : spongentResult;
}

void HashWrapper::resetTimingStats() {
    sha3TimeMs = 0.0;
    spongentTimeMs = 0.0;
    sha3CallCount = 0;
    spongentCallCount = 0;
}

HashMode HashWrapper::modeFromString(const std::string& s) {
    if (s == "sha3" || s == "SHA3") {
        return HashMode::SHA3;
    } else if (s == "spongent" || s == "SPONGENT") {
        return HashMode::SPONGENT;
    }
    throw std::invalid_argument("Unknown hash mode: " + s);
}

std::string HashWrapper::modeToString(HashMode m) {
    switch (m) {
        case HashMode::SHA3: return "sha3";
        case HashMode::SPONGENT: return "spongent";
        default: return "unknown";
    }
}

} // namespace crypto
} // namespace uavauth
