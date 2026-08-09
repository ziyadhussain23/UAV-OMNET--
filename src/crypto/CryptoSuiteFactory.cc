#include "crypto/CryptoSuite.h"

#include "crypto/Sha3Suite.h"

#include <stdexcept>

// The spongent profile is compiled in as soon as its sources land; until then
// the factory still builds and reports the suite as unavailable rather than
// silently substituting a different one. The previous implementation defaulted
// to SHA3 on an unrecognised name, which would mislabel every result in a run.
#if __has_include("crypto/SpongentSuite.h")
#include "crypto/SpongentSuite.h"
#define UAVAUTH_HAVE_SPONGENT_SUITE 1
#endif

namespace uavauth {
namespace crypto {

std::unique_ptr<CryptoSuite> makeCryptoSuite(const std::string& name) {
    if (name == "sha3") return std::make_unique<Sha3Suite>();
    if (name == "sha3-kmac") return std::make_unique<Sha3Suite>(/*useKmac=*/true);
#ifdef UAVAUTH_HAVE_SPONGENT_SUITE
    if (name == "spongent") return std::make_unique<SpongentSuite>();
#else
    if (name == "spongent")
        throw std::invalid_argument(
            "makeCryptoSuite: the 'spongent' suite is not compiled into this build");
#endif
    throw std::invalid_argument("makeCryptoSuite: unknown suite '" + name +
                                "' (expected 'sha3', 'sha3-kmac' or 'spongent')");
}

} // namespace crypto
} // namespace uavauth
