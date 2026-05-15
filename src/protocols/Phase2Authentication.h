#ifndef UAVAUTH_PROTOCOLS_PHASE2AUTHENTICATION_H
#define UAVAUTH_PROTOCOLS_PHASE2AUTHENTICATION_H

#include "../crypto/HashWrapper.h"

#include <cstdint>
#include <string>
#include <vector>

namespace uavauth {
namespace protocols {

/**
 * Phase 2: UAV-GS Mutual Authentication Protocol
 * Supports dual hash mode (SHA3 or SPONGENT) with separate timing tracking.
 */
class Phase2Authentication {
  private:
    uavauth::crypto::HashWrapper hash;

    // Dual-mode timing accumulators
    mutable double sha3TotalMs;
    mutable double spongentTotalMs;
    mutable int hashCallCount;

    static std::vector<uint8_t> toBytes(const std::string& text);

  public:
    explicit Phase2Authentication(uavauth::crypto::HashMode mode = uavauth::crypto::HashMode::SHA3);

    // Set/get hash mode
    void setHashMode(uavauth::crypto::HashMode mode);
    uavauth::crypto::HashMode getHashMode() const;

    // Protocol operations (standard interface)
    std::vector<uint8_t> computeAuthRequestHash(const std::string& tempId,
                                                uint32_t timestamp,
                                                const std::vector<uint8_t>& nonceUav);

    std::vector<uint8_t> computeChallengeMac(const std::string& tempId,
                                             const std::vector<uint8_t>& challenge,
                                             const std::vector<uint8_t>& nonceGs,
                                             uint32_t timestamp);

    std::vector<uint8_t> maskResponse(const std::vector<uint8_t>& pufResponse,
                                      const std::vector<uint8_t>& nonceGs);

    std::vector<uint8_t> unmaskResponse(const std::vector<uint8_t>& maskedResponse,
                                        const std::vector<uint8_t>& nonceGs);

    std::vector<uint8_t> deriveSessionKey(const std::vector<uint8_t>& pufResponse,
                                          const std::vector<uint8_t>& nonceUav,
                                          const std::vector<uint8_t>& nonceGs,
                                          uint32_t timestamp);

    std::vector<uint8_t> computeAuthToken(const std::vector<uint8_t>& maskedResponse,
                                          const std::vector<uint8_t>& sessionKey);

    bool verifyAuthRequest(const std::string& tempId,
                           uint32_t timestamp,
                           const std::vector<uint8_t>& nonceUav,
                           const std::vector<uint8_t>& receivedHash);

    bool verifyChallengeMac(const std::string& tempId,
                            const std::vector<uint8_t>& challenge,
                            const std::vector<uint8_t>& nonceGs,
                            uint32_t timestamp,
                            const std::vector<uint8_t>& receivedMac);

    bool verifyAuthToken(const std::vector<uint8_t>& maskedResponse,
                         const std::vector<uint8_t>& sessionKey,
                         const std::vector<uint8_t>& receivedToken);

    // Dual-mode operations with separate timing
    std::vector<uint8_t> computeAuthRequestHashDual(const std::string& tempId,
                                                     uint32_t timestamp,
                                                     const std::vector<uint8_t>& nonceUav,
                                                     double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> computeChallengeMacDual(const std::string& tempId,
                                                  const std::vector<uint8_t>& challenge,
                                                  const std::vector<uint8_t>& nonceGs,
                                                  uint32_t timestamp,
                                                  double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> maskResponseDual(const std::vector<uint8_t>& pufResponse,
                                           const std::vector<uint8_t>& nonceGs,
                                           double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> deriveSessionKeyDual(const std::vector<uint8_t>& pufResponse,
                                               const std::vector<uint8_t>& nonceUav,
                                               const std::vector<uint8_t>& nonceGs,
                                               uint32_t timestamp,
                                               double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> computeAuthTokenDual(const std::vector<uint8_t>& maskedResponse,
                                               const std::vector<uint8_t>& sessionKey,
                                               double& sha3Ms, double& spongentMs);

    // Timing statistics
    double getSha3TotalMs() const { return sha3TotalMs; }
    double getSpongentTotalMs() const { return spongentTotalMs; }
    double getHashSha3TimeMs() const { return hash.getSha3TimeMs(); }
    double getHashSpongentTimeMs() const { return hash.getSpongentTimeMs(); }
    int getHashCallCount() const { return hashCallCount; }
    void resetTimingStats();

    // Warmup: run one throwaway hash to absorb first-call init overhead, then reset stats.
    void warmupHash(const std::vector<uint8_t>& dummy) {
        hash.hash(dummy);
        hash.resetTimingStats();
        sha3TotalMs = 0.0;
        spongentTotalMs = 0.0;
        hashCallCount = 0;
    }
};

} // namespace protocols
} // namespace uavauth

#endif
