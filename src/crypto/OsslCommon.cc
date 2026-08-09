#include "crypto/OsslCommon.h"

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#include <stdexcept>
#include <string>

namespace uavauth {
namespace crypto {

void throwOsslError(const char* context) {
    std::string msg(context);
    unsigned long code;
    bool any = false;
    while ((code = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(code, buf, sizeof(buf));
        msg += any ? "; " : ": ";
        msg += buf;
        any = true;
    }
    if (!any) msg += ": (no OpenSSL error queued)";
    throw std::runtime_error(msg);
}

OsslCommon::OsslCommon() {
    sha3_256_ = EVP_MD_fetch(nullptr, "SHA3-256", nullptr);
    if (sha3_256_ == nullptr) throwOsslError("EVP_MD_fetch(SHA3-256)");

    // SHA-256 is used only by the test-vector path for RFC 5869 HKDF, which has
    // no SHA3 vectors published.
    sha256_ = EVP_MD_fetch(nullptr, "SHA2-256", nullptr);
    if (sha256_ == nullptr) throwOsslError("EVP_MD_fetch(SHA2-256)");

    hmac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (hmac_ == nullptr) throwOsslError("EVP_MAC_fetch(HMAC)");

    // KMAC is optional: it is offered as an alternative MAC for the SHA3 suite
    // but the protocol does not require it.
    kmac256_ = EVP_MAC_fetch(nullptr, "KMAC-256", nullptr);

    hkdf_ = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (hkdf_ == nullptr) throwOsslError("EVP_KDF_fetch(HKDF)");

    chacha_ = EVP_CIPHER_fetch(nullptr, "ChaCha20-Poly1305", nullptr);
    if (chacha_ == nullptr) throwOsslError("EVP_CIPHER_fetch(ChaCha20-Poly1305)");

    const char* v = OpenSSL_version(OPENSSL_VERSION_STRING);
    version_ = (v != nullptr) ? v : "unknown";
}

OsslCommon::~OsslCommon() {
    if (sha3_256_ != nullptr) EVP_MD_free(sha3_256_);
    if (sha256_ != nullptr) EVP_MD_free(sha256_);
    if (hmac_ != nullptr) EVP_MAC_free(hmac_);
    if (kmac256_ != nullptr) EVP_MAC_free(kmac256_);
    if (hkdf_ != nullptr) EVP_KDF_free(hkdf_);
    if (chacha_ != nullptr) EVP_CIPHER_free(chacha_);
}

const OsslCommon& OsslCommon::instance() {
    static const OsslCommon singleton;
    return singleton;
}

} // namespace crypto
} // namespace uavauth
