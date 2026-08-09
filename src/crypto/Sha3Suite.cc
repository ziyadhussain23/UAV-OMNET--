#include "crypto/Sha3Suite.h"

#include "core/Encoding.h"
#include "crypto/OsslCommon.h"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <cstring>
#include <stdexcept>

namespace uavauth {
namespace crypto {

using core::append;
using core::kDomainHash;
using core::kDomainKdf;
using core::kDomainMac;
using core::lengthPrefixed;
using core::u16be;

namespace raw {

Bytes sha3_256(const Bytes& message) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throwOsslError("EVP_MD_CTX_new");
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    const bool ok =
        EVP_DigestInit_ex(ctx, OsslCommon::instance().sha3_256(), nullptr) == 1 &&
        (message.empty() || EVP_DigestUpdate(ctx, message.data(), message.size()) == 1) &&
        EVP_DigestFinal_ex(ctx, out, &outLen) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throwOsslError("SHA3-256");
    return Bytes(out, out + outLen);
}

Bytes hmacSha3_256(const Bytes& key, const Bytes& message) {
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(OsslCommon::instance().hmac());
    if (ctx == nullptr) throwOsslError("EVP_MAC_CTX_new(HMAC)");

    char digest[] = "SHA3-256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_end();

    // An empty key must still be passed as a valid pointer.
    static const unsigned char kEmpty[1] = {0};
    const unsigned char* keyPtr = key.empty() ? kEmpty : key.data();

    unsigned char out[EVP_MAX_MD_SIZE];
    size_t outLen = 0;
    const bool ok =
        EVP_MAC_init(ctx, keyPtr, key.size(), params) == 1 &&
        (message.empty() || EVP_MAC_update(ctx, message.data(), message.size()) == 1) &&
        EVP_MAC_final(ctx, out, &outLen, sizeof(out)) == 1;
    EVP_MAC_CTX_free(ctx);
    if (!ok) throwOsslError("HMAC-SHA3-256");
    return Bytes(out, out + outLen);
}

Bytes kmac256(const Bytes& key, const Bytes& message, size_t outLen,
              const Bytes& customisation) {
    EVP_MAC* kmac = OsslCommon::instance().kmac256();
    if (kmac == nullptr) throw std::runtime_error("KMAC-256 unavailable in this OpenSSL build");
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(kmac);
    if (ctx == nullptr) throwOsslError("EVP_MAC_CTX_new(KMAC-256)");

    size_t requested = outLen;
    OSSL_PARAM params[3];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE, &requested);
    if (!customisation.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_MAC_PARAM_CUSTOM,
            const_cast<unsigned char*>(customisation.data()), customisation.size());
    }
    params[idx] = OSSL_PARAM_construct_end();

    static const unsigned char kEmpty[1] = {0};
    const unsigned char* keyPtr = key.empty() ? kEmpty : key.data();

    Bytes out(outLen);
    size_t produced = 0;
    const bool ok =
        EVP_MAC_init(ctx, keyPtr, key.size(), params) == 1 &&
        (message.empty() || EVP_MAC_update(ctx, message.data(), message.size()) == 1) &&
        EVP_MAC_final(ctx, out.data(), &produced, out.size()) == 1;
    EVP_MAC_CTX_free(ctx);
    if (!ok) throwOsslError("KMAC-256");
    out.resize(produced);
    return out;
}

namespace {
Bytes hkdfMode(const std::string& digest, int mode, const Bytes& ikm, const Bytes& salt,
               const Bytes& info, size_t outLen) {
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(OsslCommon::instance().hkdf());
    if (ctx == nullptr) throwOsslError("EVP_KDF_CTX_new(HKDF)");

    std::string digestCopy = digest;
    int modeCopy = mode;
    OSSL_PARAM params[6];
    int idx = 0;
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                     digestCopy.data(), 0);
    params[idx++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &modeCopy);
    params[idx++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(ikm.data()), ikm.size());
    if (!salt.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size());
    }
    if (!info.empty()) {
        params[idx++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<unsigned char*>(info.data()), info.size());
    }
    params[idx] = OSSL_PARAM_construct_end();

    Bytes out(outLen);
    const bool ok = EVP_KDF_derive(ctx, out.data(), out.size(), params) == 1;
    EVP_KDF_CTX_free(ctx);
    if (!ok) throwOsslError("HKDF derive");
    return out;
}
} // namespace

Bytes hkdf(const std::string& digest, const Bytes& ikm, const Bytes& salt,
           const Bytes& info, size_t outLen) {
    return hkdfMode(digest, EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND, ikm, salt, info, outLen);
}

Bytes hkdfExtract(const std::string& digest, const Bytes& salt, const Bytes& ikm) {
    const size_t len = (digest == "SHA3-256" || digest == "SHA2-256") ? 32u : 32u;
    return hkdfMode(digest, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, ikm, salt, Bytes{}, len);
}

Bytes hkdfExpand(const std::string& digest, const Bytes& prk, const Bytes& info,
                 size_t outLen) {
    return hkdfMode(digest, EVP_KDF_HKDF_MODE_EXPAND_ONLY, prk, Bytes{}, info, outLen);
}

bool chachaPoly1305Seal(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                        const Bytes& plaintext, Bytes& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    bool ok = EVP_EncryptInit_ex2(ctx, OsslCommon::instance().chacha20poly1305(),
                                  key.data(), nonce.data(), nullptr) == 1;
    int len = 0;
    if (ok && !aad.empty())
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                               static_cast<int>(aad.size())) == 1;

    Bytes ct(plaintext.size());
    int ctLen = 0;
    if (ok && !plaintext.empty()) {
        ok = EVP_EncryptUpdate(ctx, ct.data(), &len, plaintext.data(),
                               static_cast<int>(plaintext.size())) == 1;
        ctLen = len;
    }
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, ct.data() + ctLen, &len) == 1;
        ctLen += len;
    }

    unsigned char tag[16];
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    ct.resize(static_cast<size_t>(ctLen));
    out = ct;
    out.insert(out.end(), tag, tag + 16);
    return true;
}

bool chachaPoly1305Open(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                        const Bytes& ciphertext, Bytes& out) {
    if (ciphertext.size() < 16) return false;
    const size_t bodyLen = ciphertext.size() - 16;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;

    bool ok = EVP_DecryptInit_ex2(ctx, OsslCommon::instance().chacha20poly1305(),
                                  key.data(), nonce.data(), nullptr) == 1;
    int len = 0;
    if (ok && !aad.empty())
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                               static_cast<int>(aad.size())) == 1;

    Bytes pt(bodyLen);
    int ptLen = 0;
    if (ok && bodyLen > 0) {
        ok = EVP_DecryptUpdate(ctx, pt.data(), &len, ciphertext.data(),
                               static_cast<int>(bodyLen)) == 1;
        ptLen = len;
    }
    if (ok) {
        unsigned char tag[16];
        std::memcpy(tag, ciphertext.data() + bodyLen, 16);
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1;
    }
    // This is the INT-CTXT check: a forged or tampered ciphertext fails here.
    if (ok) ok = EVP_DecryptFinal_ex(ctx, pt.data() + ptLen, &len) == 1;
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        out.clear();   // never hand back unauthenticated plaintext
        return false;
    }
    pt.resize(bodyLen);
    out = pt;
    return true;
}

} // namespace raw

Sha3Suite::Sha3Suite(bool useKmac) : useKmac_(useKmac) {}

std::string Sha3Suite::implTag(Primitive p) const {
    const std::string v = "/openssl-" + OsslCommon::instance().versionString();
    switch (p) {
        case Primitive::Hash160:
            return "sha3-256-t160" + v;
        case Primitive::Mac:
        case Primitive::MacVerify:
            return (useKmac_ ? std::string("kmac-256") : std::string("hmac-sha3-256")) + v;
        case Primitive::Kdf:
        case Primitive::Extract:
            return "hkdf-sha3-256" + v;
        case Primitive::AeadSeal:
        case Primitive::AeadOpen:
            return "chacha20poly1305" + v;
        default:
            return std::string(primitiveName(p)) + v;
    }
}

Bytes Sha3Suite::hash160(const Bytes& message) const {
    ScopedTimer timer(counters_, Primitive::Hash160, message.size());
    // Domain byte plus length prefix: the protocol hash is a distinct function
    // from the bare primitive, and from the MAC and KDF modes.
    Bytes input;
    input.push_back(kDomainHash);
    append(input, lengthPrefixed(message));
    Bytes digest = raw::sha3_256(input);
    digest.resize(hashLen());
    return digest;
}

Bytes Sha3Suite::mac(const Bytes& key, const Bytes& message) const {
    ScopedTimer timer(counters_, Primitive::Mac, message.size());
    Bytes input;
    input.push_back(kDomainMac);
    append(input, message);

    Bytes tag;
    if (useKmac_) {
        tag = raw::kmac256(key, input, macLen(), Bytes{kDomainMac});
    } else {
        tag = raw::hmacSha3_256(key, input);
        tag.resize(macLen());
    }
    return tag;
}

bool Sha3Suite::macVerify(const Bytes& key, const Bytes& message,
                          const Bytes& tag) const {
    ScopedTimer timer(counters_, Primitive::MacVerify, message.size());
    if (tag.size() != macLen()) return false;
    Bytes input;
    input.push_back(kDomainMac);
    append(input, message);

    Bytes expected;
    if (useKmac_) {
        expected = raw::kmac256(key, input, macLen(), Bytes{kDomainMac});
    } else {
        expected = raw::hmacSha3_256(key, input);
        expected.resize(macLen());
    }
    return CRYPTO_memcmp(expected.data(), tag.data(), macLen()) == 0;
}

Bytes Sha3Suite::kdf(const Bytes& ikm, const Bytes& salt, const std::string& label,
                     const Bytes& info, size_t outLen) const {
    ScopedTimer timer(counters_, Primitive::Kdf, ikm.size());
    Bytes fullInfo;
    fullInfo.push_back(kDomainKdf);
    append(fullInfo, lengthPrefixed(label));
    append(fullInfo, lengthPrefixed(info));
    return raw::hkdf("SHA3-256", ikm, salt, fullInfo, outLen);
}

Bytes Sha3Suite::extract(const Bytes& salt, const Bytes& source) const {
    ScopedTimer timer(counters_, Primitive::Extract, source.size());
    return raw::hkdfExtract("SHA3-256", salt, source);
}

bool Sha3Suite::aeadSeal(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                         const Bytes& plaintext, Bytes& ciphertextOut) const {
    ScopedTimer timer(counters_, Primitive::AeadSeal, plaintext.size());
    if (key.size() != aeadKeyLen() || nonce.size() != aeadNonceLen()) return false;
    return raw::chachaPoly1305Seal(key, nonce, aad, plaintext, ciphertextOut);
}

bool Sha3Suite::aeadOpen(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                         const Bytes& ciphertext, Bytes& plaintextOut) const {
    ScopedTimer timer(counters_, Primitive::AeadOpen, ciphertext.size());
    if (key.size() != aeadKeyLen() || nonce.size() != aeadNonceLen()) {
        plaintextOut.clear();
        return false;
    }
    return raw::chachaPoly1305Open(key, nonce, aad, ciphertext, plaintextOut);
}

} // namespace crypto
} // namespace uavauth
