#ifndef UAVAUTH_PROTOCOLS_PHASE4SESSIONKEY_H
#define UAVAUTH_PROTOCOLS_PHASE4SESSIONKEY_H

#include "../crypto/SPONGENT.h"

#include <vector>

namespace uavauth {
namespace protocols {

class Phase4SessionKey {
  public:
    static std::vector<uint8_t> deriveBasicKey(const std::vector<uint8_t>& pufResponse,
                                               const std::vector<uint8_t>& nonce1,
                                               const std::vector<uint8_t>& nonce2,
                                               uavauth::crypto::SPONGENT& hash);

    static std::vector<uint8_t> deriveWithECDH(const std::vector<uint8_t>& basicKey,
                                               const std::vector<uint8_t>& localPublicKey,
                                               const std::vector<uint8_t>& remotePublicKey);
};

} // namespace protocols
} // namespace uavauth

#endif
