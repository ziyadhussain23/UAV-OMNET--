#ifndef UAVAUTH_CRYPTO_CRYPTOUTILS_H
#define UAVAUTH_CRYPTO_CRYPTOUTILS_H

#include <cstdint>
#include <initializer_list>
#include <string>
#include <vector>

namespace uavauth {
namespace crypto {

std::vector<uint8_t> xorBuffers(const std::vector<uint8_t>& lhs,
                                const std::vector<uint8_t>& rhs,
                                size_t outputLen = 0);

std::vector<uint8_t> concat(const std::initializer_list<std::vector<uint8_t>>& chunks);

std::vector<uint8_t> toBytes32(uint32_t value);

uint32_t fromBytes32(const std::vector<uint8_t>& bytes, size_t offset = 0);

std::string bytesToHex(const std::vector<uint8_t>& bytes);

std::vector<uint8_t> hexToBytes(const std::string& hex);

bool constantTimeEqual(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs);

} // namespace crypto
} // namespace uavauth

#endif
