#include "CryptoUtils.h"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace uavauth {
namespace crypto {

std::vector<uint8_t> xorBuffers(const std::vector<uint8_t>& lhs,
                                const std::vector<uint8_t>& rhs,
                                size_t outputLen) {
    const size_t len = outputLen == 0 ? std::min(lhs.size(), rhs.size()) : outputLen;
    std::vector<uint8_t> out(len, 0);
    for (size_t i = 0; i < len; ++i) {
        const uint8_t l = i < lhs.size() ? lhs[i] : 0;
        const uint8_t r = i < rhs.size() ? rhs[i] : 0;
        out[i] = l ^ r;
    }
    return out;
}

std::vector<uint8_t> concat(const std::initializer_list<std::vector<uint8_t>>& chunks) {
    size_t totalSize = 0;
    for (const auto& chunk : chunks) {
        totalSize += chunk.size();
    }

    std::vector<uint8_t> out;
    out.reserve(totalSize);
    for (const auto& chunk : chunks) {
        out.insert(out.end(), chunk.begin(), chunk.end());
    }
    return out;
}

std::vector<uint8_t> toBytes32(uint32_t value) {
    return {
        static_cast<uint8_t>((value >> 24U) & 0xFFU),
        static_cast<uint8_t>((value >> 16U) & 0xFFU),
        static_cast<uint8_t>((value >> 8U) & 0xFFU),
        static_cast<uint8_t>(value & 0xFFU)
    };
}

uint32_t fromBytes32(const std::vector<uint8_t>& bytes, size_t offset) {
    if (bytes.size() < offset + 4) {
        throw std::out_of_range("fromBytes32 requires at least 4 bytes from offset");
    }

    return (static_cast<uint32_t>(bytes[offset]) << 24U) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16U) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8U) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::invalid_argument("hex string length must be even");
    }

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        const std::string token = hex.substr(i, 2);
        const auto value = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
        out.push_back(value);
    }

    return out;
}

bool constantTimeEqual(const std::vector<uint8_t>& lhs, const std::vector<uint8_t>& rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }

    uint8_t diff = 0;
    for (size_t i = 0; i < lhs.size(); ++i) {
        diff |= static_cast<uint8_t>(lhs[i] ^ rhs[i]);
    }
    return diff == 0;
}

} // namespace crypto
} // namespace uavauth
