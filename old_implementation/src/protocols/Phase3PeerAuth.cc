#include "Phase3PeerAuth.h"

#include "../crypto/CryptoUtils.h"

namespace uavauth {
namespace protocols {

Phase3PeerAuth::Phase3PeerAuth(uavauth::crypto::HashMode mode)
    : hash(mode, 160),
      sha3TotalMs(0.0),
      spongentTotalMs(0.0),
      hashCallCount(0) {}

void Phase3PeerAuth::setHashMode(uavauth::crypto::HashMode mode) {
    hash.setMode(mode);
}

uavauth::crypto::HashMode Phase3PeerAuth::getHashMode() const {
    return hash.getMode();
}

void Phase3PeerAuth::resetTimingStats() {
    sha3TotalMs = 0.0;
    spongentTotalMs = 0.0;
    hashCallCount = 0;
    hash.resetTimingStats();
}

std::vector<uint8_t> Phase3PeerAuth::idPairBytes(int a, int b) {
    return uavauth::crypto::concat({
        uavauth::crypto::toBytes32(static_cast<uint32_t>(a)),
        uavauth::crypto::toBytes32(static_cast<uint32_t>(b))
    });
}

std::vector<uint8_t> Phase3PeerAuth::buildRequestToken(int requesterId,
                                                        int responderId,
                                                        const std::vector<uint8_t>& nonceA,
                                                        const std::vector<uint8_t>& credential) {
    ++hashCallCount;
    return hash.hashMultiple({idPairBytes(requesterId, responderId), nonceA, credential});
}

std::vector<uint8_t> Phase3PeerAuth::buildResponseToken(int responderId,
                                                         int requesterId,
                                                         const std::vector<uint8_t>& nonceA,
                                                         const std::vector<uint8_t>& nonceB,
                                                         const std::vector<uint8_t>& credential) {
    ++hashCallCount;
    return hash.hashMultiple({idPairBytes(responderId, requesterId), nonceA, nonceB, credential});
}

std::vector<uint8_t> Phase3PeerAuth::buildCompletionToken(int requesterId,
                                                           int responderId,
                                                           const std::vector<uint8_t>& nonceB,
                                                           const std::vector<uint8_t>& credential) {
    ++hashCallCount;
    return hash.hashMultiple({idPairBytes(requesterId, responderId), nonceB, credential});
}

bool Phase3PeerAuth::verifyRequestToken(int requesterId,
                                        int responderId,
                                        const std::vector<uint8_t>& nonceA,
                                        const std::vector<uint8_t>& credential,
                                        const std::vector<uint8_t>& token) {
    const std::vector<uint8_t> expected = buildRequestToken(requesterId, responderId, nonceA, credential);
    return uavauth::crypto::constantTimeEqual(expected, token);
}

bool Phase3PeerAuth::verifyResponseToken(int responderId,
                                         int requesterId,
                                         const std::vector<uint8_t>& nonceA,
                                         const std::vector<uint8_t>& nonceB,
                                         const std::vector<uint8_t>& credential,
                                         const std::vector<uint8_t>& token) {
    const std::vector<uint8_t> expected = buildResponseToken(responderId, requesterId, nonceA, nonceB, credential);
    return uavauth::crypto::constantTimeEqual(expected, token);
}

bool Phase3PeerAuth::verifyCompletionToken(int requesterId,
                                           int responderId,
                                           const std::vector<uint8_t>& nonceB,
                                           const std::vector<uint8_t>& credential,
                                           const std::vector<uint8_t>& token) {
    const std::vector<uint8_t> expected = buildCompletionToken(requesterId, responderId, nonceB, credential);
    return uavauth::crypto::constantTimeEqual(expected, token);
}

std::vector<uint8_t> Phase3PeerAuth::derivePeerSessionKey(int uavA,
                                                           int uavB,
                                                           const std::vector<uint8_t>& nonceA,
                                                           const std::vector<uint8_t>& nonceB,
                                                           const std::vector<uint8_t>& credential) {
    ++hashCallCount;
    return hash.hashMultiple({idPairBytes(uavA, uavB), nonceA, nonceB, credential});
}

// Dual-mode operations
std::vector<uint8_t> Phase3PeerAuth::buildRequestTokenDual(int requesterId,
                                                            int responderId,
                                                            const std::vector<uint8_t>& nonceA,
                                                            const std::vector<uint8_t>& credential,
                                                            double& sha3Ms, double& spongentMs) {
    ++hashCallCount;
    auto result = hash.hashMultipleDual({idPairBytes(requesterId, responderId), nonceA, credential}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

std::vector<uint8_t> Phase3PeerAuth::buildResponseTokenDual(int responderId,
                                                             int requesterId,
                                                             const std::vector<uint8_t>& nonceA,
                                                             const std::vector<uint8_t>& nonceB,
                                                             const std::vector<uint8_t>& credential,
                                                             double& sha3Ms, double& spongentMs) {
    ++hashCallCount;
    auto result = hash.hashMultipleDual({idPairBytes(responderId, requesterId), nonceA, nonceB, credential}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

std::vector<uint8_t> Phase3PeerAuth::buildCompletionTokenDual(int requesterId,
                                                               int responderId,
                                                               const std::vector<uint8_t>& nonceB,
                                                               const std::vector<uint8_t>& credential,
                                                               double& sha3Ms, double& spongentMs) {
    ++hashCallCount;
    auto result = hash.hashMultipleDual({idPairBytes(requesterId, responderId), nonceB, credential}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

std::vector<uint8_t> Phase3PeerAuth::derivePeerSessionKeyDual(int uavA,
                                                               int uavB,
                                                               const std::vector<uint8_t>& nonceA,
                                                               const std::vector<uint8_t>& nonceB,
                                                               const std::vector<uint8_t>& credential,
                                                               double& sha3Ms, double& spongentMs) {
    ++hashCallCount;
    auto result = hash.hashMultipleDual({idPairBytes(uavA, uavB), nonceA, nonceB, credential}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

} // namespace protocols
} // namespace uavauth
