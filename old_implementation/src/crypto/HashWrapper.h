#ifndef UAVAUTH_CRYPTO_HASHWRAPPER_H
#define UAVAUTH_CRYPTO_HASHWRAPPER_H

#include "SHA3Hash.h"
#include "SPONGENT.h"

#include <cstdint>
#include <string>
#include <vector>

namespace uavauth {
namespace crypto {

/**
 * Hash mode selector for dual-mode operation.
 */
enum class HashMode {
    SHA3,      // SHA3-256 truncated to 160 bits (fast, matches Python)
    SPONGENT   // SPONGENT-160 software implementation (slow, hardware-accurate)
};

/**
 * Wrapper class that provides unified hash interface for both SHA3 and SPONGENT.
 * Tracks timing for both modes to enable performance comparison.
 */
class HashWrapper {
  private:
    HashMode mode;
    SHA3Hash sha3;
    SPONGENT spongent;

    // Timing accumulators (in milliseconds)
    mutable double sha3TimeMs;
    mutable double spongentTimeMs;
    mutable int sha3CallCount;
    mutable int spongentCallCount;

  public:
    explicit HashWrapper(HashMode hashMode = HashMode::SHA3, int outputBits = 160);

    // Set the active hash mode
    void setMode(HashMode hashMode);
    HashMode getMode() const;

    // Hash operations (use current mode)
    std::vector<uint8_t> hash(const std::vector<uint8_t>& message) const;
    std::vector<uint8_t> hashMultiple(const std::vector<std::vector<uint8_t>>& inputs) const;

    // Dual-mode operations (compute both, return based on mode)
    std::vector<uint8_t> hashDual(const std::vector<uint8_t>& message,
                                   double& sha3Ms, double& spongentMs) const;
    std::vector<uint8_t> hashMultipleDual(const std::vector<std::vector<uint8_t>>& inputs,
                                           double& sha3Ms, double& spongentMs) const;

    // Timing statistics
    double getSha3TimeMs() const { return sha3TimeMs; }
    double getSpongentTimeMs() const { return spongentTimeMs; }
    int getSha3CallCount() const { return sha3CallCount; }
    int getSpongentCallCount() const { return spongentCallCount; }
    void resetTimingStats();

    // Utility
    static HashMode modeFromString(const std::string& s);
    static std::string modeToString(HashMode m);
};

} // namespace crypto
} // namespace uavauth

#endif
