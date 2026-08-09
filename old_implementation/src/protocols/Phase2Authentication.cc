#include "Phase2Authentication.h"

#include "../crypto/CryptoUtils.h"

namespace uavauth {
namespace protocols {

Phase2Authentication::Phase2Authentication(uavauth::crypto::HashMode mode)
    : hash(mode, 160),
      sha3TotalMs(0.0),
      spongentTotalMs(0.0),
      hashCallCount(0) {}

void Phase2Authentication::setHashMode(uavauth::crypto::HashMode mode) {
    hash.setMode(mode);
}

uavauth::crypto::HashMode Phase2Authentication::getHashMode() const {
    return hash.getMode();
}

void Phase2Authentication::resetTimingStats() {
    sha3TotalMs = 0.0;
    spongentTotalMs = 0.0;
    hashCallCount = 0;
    hash.resetTimingStats();
}

std::vector<uint8_t> Phase2Authentication::toBytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::vector<uint8_t> Phase2Authentication::computeAuthRequestHash(const std::string& tempId,
                                                                   uint32_t timestamp,
                                                                   const std::vector<uint8_t>& nonceUav) {
    const std::vector<uint8_t> t = uavauth::crypto::toBytes32(timestamp);
    ++hashCallCount;
    return hash.hashMultiple({toBytes(tempId), t, nonceUav});
}

std::vector<uint8_t> Phase2Authentication::computeChallengeMac(const std::string& tempId,
                                                                const std::vector<uint8_t>& challenge,
                                                                const std::vector<uint8_t>& nonceGs,
                                                                uint32_t timestamp) {
    const std::vector<uint8_t> t = uavauth::crypto::toBytes32(timestamp);
    ++hashCallCount;
    return hash.hashMultiple({toBytes(tempId), challenge, nonceGs, t});
}

std::vector<uint8_t> Phase2Authentication::maskResponse(const std::vector<uint8_t>& pufResponse,
                                                         const std::vector<uint8_t>& nonceGs) {
    ++hashCallCount;
    const std::vector<uint8_t> mask = hash.hash(nonceGs);
    return uavauth::crypto::xorBuffers(pufResponse, mask, pufResponse.size());
}

std::vector<uint8_t> Phase2Authentication::unmaskResponse(const std::vector<uint8_t>& maskedResponse,
                                                           const std::vector<uint8_t>& nonceGs) {
    ++hashCallCount;
    const std::vector<uint8_t> mask = hash.hash(nonceGs);
    return uavauth::crypto::xorBuffers(maskedResponse, mask, maskedResponse.size());
}

std::vector<uint8_t> Phase2Authentication::deriveSessionKey(const std::vector<uint8_t>& pufResponse,
                                                             const std::vector<uint8_t>& nonceUav,
                                                             const std::vector<uint8_t>& nonceGs,
                                                             uint32_t timestamp) {
    const std::vector<uint8_t> t = uavauth::crypto::toBytes32(timestamp);
    ++hashCallCount;
    return hash.hashMultiple({pufResponse, nonceUav, nonceGs, t});
}

std::vector<uint8_t> Phase2Authentication::computeAuthToken(const std::vector<uint8_t>& maskedResponse,
                                                             const std::vector<uint8_t>& sessionKey) {
    ++hashCallCount;
    return hash.hashMultiple({maskedResponse, sessionKey});
}

bool Phase2Authentication::verifyAuthRequest(const std::string& tempId,
                                              uint32_t timestamp,
                                              const std::vector<uint8_t>& nonceUav,
                                              const std::vector<uint8_t>& receivedHash) {
    const std::vector<uint8_t> expected = computeAuthRequestHash(tempId, timestamp, nonceUav);
    return uavauth::crypto::constantTimeEqual(expected, receivedHash);
}

bool Phase2Authentication::verifyChallengeMac(const std::string& tempId,
                                               const std::vector<uint8_t>& challenge,
                                               const std::vector<uint8_t>& nonceGs,
                                               uint32_t timestamp,
                                               const std::vector<uint8_t>& receivedMac) {
    const std::vector<uint8_t> expected = computeChallengeMac(tempId, challenge, nonceGs, timestamp);
    return uavauth::crypto::constantTimeEqual(expected, receivedMac);
}

bool Phase2Authentication::verifyAuthToken(const std::vector<uint8_t>& maskedResponse,
                                            const std::vector<uint8_t>& sessionKey,
                                            const std::vector<uint8_t>& receivedToken) {
    const std::vector<uint8_t> expected = computeAuthToken(maskedResponse, sessionKey);
    return uavauth::crypto::constantTimeEqual(expected, receivedToken);
}

// Dual-mode operations
std::vector<uint8_t> Phase2Authentication::computeAuthRequestHashDual(const std::string& tempId,
                                                                       uint32_t timestamp,
                                                                       const std::vector<uint8_t>& nonceUav,
                                                                       double& sha3Ms, double& spongentMs) {
    const std::vector<uint8_t> t = uavauth::crypto::toBytes32(timestamp);
    ++hashCallCount;
    auto result = hash.hashMultipleDual({toBytes(tempId), t, nonceUav}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

std::vector<uint8_t> Phase2Authentication::computeChallengeMacDual(const std::string& tempId,
                                                                    const std::vector<uint8_t>& challenge,
                                                                    const std::vector<uint8_t>& nonceGs,
                                                                    uint32_t timestamp,
                                                                    double& sha3Ms, double& spongentMs) {
    const std::vector<uint8_t> t = uavauth::crypto::toBytes32(timestamp);
    ++hashCallCount;
    auto result = hash.hashMultipleDual({toBytes(tempId), challenge, nonceGs, t}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

std::vector<uint8_t> Phase2Authentication::maskResponseDual(const std::vector<uint8_t>& pufResponse,
                                                             const std::vector<uint8_t>& nonceGs,
                                                             double& sha3Ms, double& spongentMs) {
    ++hashCallCount;
    const std::vector<uint8_t> mask = hash.hashDual(nonceGs, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return uavauth::crypto::xorBuffers(pufResponse, mask, pufResponse.size());
}

std::vector<uint8_t> Phase2Authentication::deriveSessionKeyDual(const std::vector<uint8_t>& pufResponse,
                                                                 const std::vector<uint8_t>& nonceUav,
                                                                 const std::vector<uint8_t>& nonceGs,
                                                                 uint32_t timestamp,
                                                                 double& sha3Ms, double& spongentMs) {
    const std::vector<uint8_t> t = uavauth::crypto::toBytes32(timestamp);
    ++hashCallCount;
    auto result = hash.hashMultipleDual({pufResponse, nonceUav, nonceGs, t}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

std::vector<uint8_t> Phase2Authentication::computeAuthTokenDual(const std::vector<uint8_t>& maskedResponse,
                                                                 const std::vector<uint8_t>& sessionKey,
                                                                 double& sha3Ms, double& spongentMs) {
    ++hashCallCount;
    auto result = hash.hashMultipleDual({maskedResponse, sessionKey}, sha3Ms, spongentMs);
    sha3TotalMs += sha3Ms;
    spongentTotalMs += spongentMs;
    return result;
}

} // namespace protocols
} // namespace uavauth
