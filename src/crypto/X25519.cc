#include "crypto/X25519.h"

#include "crypto/OsslCommon.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <stdexcept>

namespace uavauth {
namespace crypto {

void X25519KeyPair::erase() {
    if (!secret.empty()) OPENSSL_cleanse(secret.data(), secret.size());
    secret.clear();
    erased = true;
}

X25519KeyPair x25519Generate(const Bytes& seed32, PrimitiveCounters& counters) {
    if (seed32.size() != kX25519KeyLen)
        throw std::invalid_argument("x25519Generate: seed must be 32 bytes");

    ScopedTimer timer(counters, Primitive::DhKeygen, kX25519KeyLen);

    // Load the scalar from caller-supplied bytes rather than using
    // EVP_PKEY_keygen, so the run stays reproducible from the simulation seed.
    EVP_PKEY* key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                 seed32.data(), seed32.size());
    if (key == nullptr) throwOsslError("EVP_PKEY_new_raw_private_key(X25519)");

    X25519KeyPair pair;
    pair.secret = seed32;
    pair.publicKey.resize(kX25519KeyLen);
    size_t pubLen = kX25519KeyLen;
    if (EVP_PKEY_get_raw_public_key(key, pair.publicKey.data(), &pubLen) != 1) {
        EVP_PKEY_free(key);
        throwOsslError("EVP_PKEY_get_raw_public_key(X25519)");
    }
    EVP_PKEY_free(key);
    pair.publicKey.resize(pubLen);
    return pair;
}

bool x25519Derive(const Bytes& secret32, const Bytes& peerPublic32, Bytes& sharedOut,
                  PrimitiveCounters& counters) {
    sharedOut.clear();
    if (secret32.size() != kX25519KeyLen || peerPublic32.size() != kX25519KeyLen)
        return false;

    ScopedTimer timer(counters, Primitive::DhDerive, kX25519KeyLen);

    EVP_PKEY* localKey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
                                                      secret32.data(), secret32.size());
    if (localKey == nullptr) return false;

    EVP_PKEY* peerKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                    peerPublic32.data(),
                                                    peerPublic32.size());
    if (peerKey == nullptr) {
        EVP_PKEY_free(localKey);
        return false;
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(localKey, nullptr);
    bool ok = ctx != nullptr && EVP_PKEY_derive_init(ctx) == 1 &&
              EVP_PKEY_derive_set_peer(ctx, peerKey) == 1;

    Bytes shared(kX25519KeyLen);
    size_t sharedLen = shared.size();
    // OpenSSL fails here for low-order peer points, which is exactly the case
    // that would otherwise produce an all-zero "shared secret".
    if (ok) ok = EVP_PKEY_derive(ctx, shared.data(), &sharedLen) == 1;

    if (ctx != nullptr) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peerKey);
    EVP_PKEY_free(localKey);

    if (!ok) {
        OPENSSL_cleanse(shared.data(), shared.size());
        return false;
    }
    shared.resize(sharedLen);
    sharedOut = shared;
    return true;
}

} // namespace crypto
} // namespace uavauth
