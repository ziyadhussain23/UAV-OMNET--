#include "Phase4SessionKey.h"

#include "../crypto/CryptoUtils.h"

#if defined(USE_SODIUM)
#include <sodium.h>
#endif

namespace uavauth {
namespace protocols {

std::vector<uint8_t> Phase4SessionKey::deriveBasicKey(const std::vector<uint8_t>& pufResponse,
                                                      const std::vector<uint8_t>& nonce1,
                                                      const std::vector<uint8_t>& nonce2,
                                                      uavauth::crypto::SPONGENT& hash) {
    return hash.hashMultiple({pufResponse, nonce1, nonce2});
}

std::vector<uint8_t> Phase4SessionKey::deriveWithECDH(const std::vector<uint8_t>& basicKey,
                                                      const std::vector<uint8_t>& localPublicKey,
                                                      const std::vector<uint8_t>& remotePublicKey) {
    uavauth::crypto::SPONGENT hash(160);

#if defined(USE_SODIUM)
    if (localPublicKey.size() == crypto_scalarmult_SCALARBYTES &&
        remotePublicKey.size() == crypto_scalarmult_BYTES) {
        std::vector<uint8_t> shared(static_cast<size_t>(crypto_scalarmult_BYTES), 0);
        if (crypto_scalarmult(shared.data(), localPublicKey.data(), remotePublicKey.data()) == 0) {
            return hash.hashMultiple({basicKey, shared});
        }
    }
#endif

    // Portable fallback when libsodium is not available.
    return hash.hashMultiple({basicKey, localPublicKey, remotePublicKey});
}

} // namespace protocols
} // namespace uavauth
