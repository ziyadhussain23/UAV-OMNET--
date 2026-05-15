#ifndef UAVAUTH_CRYPTO_SHA3HASH_H
#define UAVAUTH_CRYPTO_SHA3HASH_H

#include <cstdint>
#include <vector>

namespace uavauth {
namespace crypto {

/**
 * SHA3-256 hash truncated to 160 bits (20 bytes).
 * Matches the Python implementation using Crypto.Hash.SHA3_256.
 * Uses OpenSSL EVP API for hardware-optimized performance.
 */
class SHA3Hash {
  private:
    int outputBits;

  public:
    explicit SHA3Hash(int outputBits = 160);

    std::vector<uint8_t> hash(const std::vector<uint8_t>& message) const;
    std::vector<uint8_t> hashMultiple(const std::vector<std::vector<uint8_t>>& inputs) const;
};

} // namespace crypto
} // namespace uavauth

#endif
