#ifndef UAVAUTH_PROTOCOLS_PHASE3PEERAUTH_H
#define UAVAUTH_PROTOCOLS_PHASE3PEERAUTH_H

#include "../crypto/HashWrapper.h"

#include <cstdint>
#include <vector>

namespace uavauth {
namespace protocols {

/**
 * Phase 3: UAV-to-UAV Peer Authentication Protocol
 * Supports dual hash mode (SHA3 or SPONGENT) with separate timing tracking.
 */
class Phase3PeerAuth {
  private:
    uavauth::crypto::HashWrapper hash;

    // Dual-mode timing accumulators
    mutable double sha3TotalMs;
    mutable double spongentTotalMs;
    mutable int hashCallCount;

    static std::vector<uint8_t> idPairBytes(int a, int b);

  public:
    explicit Phase3PeerAuth(uavauth::crypto::HashMode mode = uavauth::crypto::HashMode::SHA3);

    // Set/get hash mode
    void setHashMode(uavauth::crypto::HashMode mode);
    uavauth::crypto::HashMode getHashMode() const;

    // Protocol operations (standard interface)
    std::vector<uint8_t> buildRequestToken(int requesterId,
                                           int responderId,
                                           const std::vector<uint8_t>& nonceA,
                                           const std::vector<uint8_t>& credential);

    std::vector<uint8_t> buildResponseToken(int responderId,
                                            int requesterId,
                                            const std::vector<uint8_t>& nonceA,
                                            const std::vector<uint8_t>& nonceB,
                                            const std::vector<uint8_t>& credential);

    std::vector<uint8_t> buildCompletionToken(int requesterId,
                                              int responderId,
                                              const std::vector<uint8_t>& nonceB,
                                              const std::vector<uint8_t>& credential);

    bool verifyRequestToken(int requesterId,
                            int responderId,
                            const std::vector<uint8_t>& nonceA,
                            const std::vector<uint8_t>& credential,
                            const std::vector<uint8_t>& token);

    bool verifyResponseToken(int responderId,
                             int requesterId,
                             const std::vector<uint8_t>& nonceA,
                             const std::vector<uint8_t>& nonceB,
                             const std::vector<uint8_t>& credential,
                             const std::vector<uint8_t>& token);

    bool verifyCompletionToken(int requesterId,
                               int responderId,
                               const std::vector<uint8_t>& nonceB,
                               const std::vector<uint8_t>& credential,
                               const std::vector<uint8_t>& token);

    std::vector<uint8_t> derivePeerSessionKey(int uavA,
                                              int uavB,
                                              const std::vector<uint8_t>& nonceA,
                                              const std::vector<uint8_t>& nonceB,
                                              const std::vector<uint8_t>& credential);

    // Dual-mode operations with separate timing
    std::vector<uint8_t> buildRequestTokenDual(int requesterId,
                                                int responderId,
                                                const std::vector<uint8_t>& nonceA,
                                                const std::vector<uint8_t>& credential,
                                                double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> buildResponseTokenDual(int responderId,
                                                 int requesterId,
                                                 const std::vector<uint8_t>& nonceA,
                                                 const std::vector<uint8_t>& nonceB,
                                                 const std::vector<uint8_t>& credential,
                                                 double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> buildCompletionTokenDual(int requesterId,
                                                   int responderId,
                                                   const std::vector<uint8_t>& nonceB,
                                                   const std::vector<uint8_t>& credential,
                                                   double& sha3Ms, double& spongentMs);

    std::vector<uint8_t> derivePeerSessionKeyDual(int uavA,
                                                   int uavB,
                                                   const std::vector<uint8_t>& nonceA,
                                                   const std::vector<uint8_t>& nonceB,
                                                   const std::vector<uint8_t>& credential,
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
