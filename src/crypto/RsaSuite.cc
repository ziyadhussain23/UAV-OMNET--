#include "crypto/RsaSuite.h"

#include "crypto/OsslCommon.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace uavauth {
namespace crypto {

namespace {
constexpr int kRsaBits = 2048;
}

SignatureKeyPair RsaSuite::generateKeypair() const {
    SignatureKeyPair kp;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (ctx == nullptr) return kp;
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, kRsaBits) == 1) {
        EVP_PKEY_keygen(ctx, &key);
    }
    EVP_PKEY_CTX_free(ctx);
    kp.impl_ = key;
    return kp;
}

Bytes RsaSuite::publicKeyBytes(const SignatureKeyPair& kp) const {
    auto* key = static_cast<EVP_PKEY*>(kp.impl_);
    if (key == nullptr) return {};
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(key, &der);
    if (len <= 0) return {};
    Bytes out(der, der + len);
    OPENSSL_free(der);
    return out;
}

std::unique_ptr<SignatureKeyPair> RsaSuite::keyFromPublicBytes(const Bytes& spki) const {
    const unsigned char* p = spki.data();
    EVP_PKEY* key = d2i_PUBKEY(nullptr, &p, static_cast<long>(spki.size()));
    if (key == nullptr) return nullptr;
    auto kp = std::make_unique<SignatureKeyPair>();
    kp->impl_ = key;
    return kp;
}

Bytes RsaSuite::sign(const SignatureKeyPair& kp, const Bytes& message) const {
    ScopedTimer timer(counters_, Primitive::Sign, message.size());
    auto* key = static_cast<EVP_PKEY*>(kp.impl_);
    Bytes out;
    if (key == nullptr) return out;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return out;
    size_t len = 0;
    bool ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
              EVP_DigestSign(ctx, nullptr, &len, message.data(), message.size()) == 1;
    if (ok) {
        out.resize(len);
        ok = EVP_DigestSign(ctx, out.data(), &len, message.data(), message.size()) == 1;
        out.resize(len);
    }
    EVP_MD_CTX_free(ctx);
    if (!ok) out.clear();
    return out;
}

bool RsaSuite::verify(const SignatureKeyPair& kp, const Bytes& message,
                      const Bytes& signature) const {
    ScopedTimer timer(counters_, Primitive::Verify, message.size());
    auto* key = static_cast<EVP_PKEY*>(kp.impl_);
    if (key == nullptr) return false;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    const bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
                    EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                     message.data(), message.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace crypto
} // namespace uavauth
