#include "crypto/SignatureSuite.h"

#include "crypto/EcdsaSuite.h"
#include "crypto/RsaSuite.h"

#include <openssl/evp.h>

#include <stdexcept>
#include <utility>

namespace uavauth {
namespace crypto {

SignatureKeyPair::SignatureKeyPair(SignatureKeyPair&& other) noexcept
    : impl_(other.impl_) {
    other.impl_ = nullptr;
}

SignatureKeyPair& SignatureKeyPair::operator=(SignatureKeyPair&& other) noexcept {
    if (this != &other) {
        if (impl_ != nullptr) EVP_PKEY_free(static_cast<EVP_PKEY*>(impl_));
        impl_ = other.impl_;
        other.impl_ = nullptr;
    }
    return *this;
}

SignatureKeyPair::~SignatureKeyPair() {
    if (impl_ != nullptr) EVP_PKEY_free(static_cast<EVP_PKEY*>(impl_));
}

std::unique_ptr<SignatureSuite> makeSignatureSuite(const std::string& name) {
    if (name == "rsa2048") return std::make_unique<RsaSuite>();
    if (name == "ecdsa-p256") return std::make_unique<EcdsaSuite>();
    throw std::invalid_argument("makeSignatureSuite: unknown suite '" + name + "'");
}

} // namespace crypto
} // namespace uavauth
