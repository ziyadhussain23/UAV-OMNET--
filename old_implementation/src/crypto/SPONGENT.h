#ifndef UAVAUTH_CRYPTO_SPONGENT_H
#define UAVAUTH_CRYPTO_SPONGENT_H

#include <cstdint>
#include <vector>

namespace uavauth {
namespace crypto {

class SPONGENT {
  private:
    int rateBits;
    int capacityBits;
    int outputBits;

    mutable std::vector<uint8_t> state;

    void permutation() const;
    void sBoxLayer() const;
    void pLayer() const;
    void absorb(const std::vector<uint8_t>& input) const;
    std::vector<uint8_t> squeeze() const;

    static const uint8_t SBOX[16];

  public:
    explicit SPONGENT(int outputBits = 160);

    std::vector<uint8_t> hash(const std::vector<uint8_t>& message) const;
    std::vector<uint8_t> hashMultiple(const std::vector<std::vector<uint8_t>>& inputs) const;
};

} // namespace crypto
} // namespace uavauth

#endif
