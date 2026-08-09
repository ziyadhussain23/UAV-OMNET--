#include "SHA3Hash.h"

#include <openssl/evp.h>
#include <stdexcept>

namespace uavauth {
namespace crypto {

SHA3Hash::SHA3Hash(int outBits) : outputBits(outBits) {
    if (outputBits <= 0 || outputBits > 256) {
        throw std::invalid_argument("SHA3Hash outputBits must be 1-256");
    }
}

std::vector<uint8_t> SHA3Hash::hash(const std::vector<uint8_t>& message) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(ctx, message.data(), message.size()) != 1) {

        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    std::vector<uint8_t> digest(32);  // SHA3-256 produces 32 bytes
    unsigned int digestLen = 0;

    if (EVP_DigestFinal_ex(ctx, digest.data(), &digestLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);

    // Truncate to outputBits (e.g., 160 bits = 20 bytes)
    const size_t outputBytes = static_cast<size_t>(outputBits / 8);
    if (digest.size() > outputBytes) {
        digest.resize(outputBytes);
    }

    return digest;
}

std::vector<uint8_t> SHA3Hash::hashMultiple(const std::vector<std::vector<uint8_t>>& inputs) const {
    std::vector<uint8_t> concatenated;
    size_t totalSize = 0;
    for (const auto& chunk : inputs) {
        totalSize += chunk.size();
    }
    concatenated.reserve(totalSize);

    for (const auto& chunk : inputs) {
        concatenated.insert(concatenated.end(), chunk.begin(), chunk.end());
    }

    return hash(concatenated);
}

} // namespace crypto
} // namespace uavauth
