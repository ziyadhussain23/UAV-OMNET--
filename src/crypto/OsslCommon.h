#ifndef UAVAUTH_CRYPTO_OSSLCOMMON_H
#define UAVAUTH_CRYPTO_OSSLCOMMON_H

#include <openssl/evp.h>

#include <string>

namespace uavauth {
namespace crypto {

/// Process-wide cache of fetched OpenSSL 3.x algorithm handles.
///
/// Fetching inside each call (EVP_MD_fetch / EVP_MAC_fetch per operation) is the
/// classic OpenSSL-3 performance trap: it performs a provider lookup every time
/// and would inflate the measured cost of every hash in this project by an order
/// of magnitude. Fetch once, reuse everywhere.
class OsslCommon {
  public:
    static const OsslCommon& instance();

    EVP_MD* sha3_256() const { return sha3_256_; }
    EVP_MD* sha256() const { return sha256_; }
    EVP_MAC* hmac() const { return hmac_; }
    EVP_MAC* kmac256() const { return kmac256_; }
    EVP_KDF* hkdf() const { return hkdf_; }
    EVP_CIPHER* chacha20poly1305() const { return chacha_; }

    /// Runtime OpenSSL version, e.g. "3.5.5". Recorded in the results so a
    /// reader can tell which library produced the timings.
    const std::string& versionString() const { return version_; }

  private:
    OsslCommon();
    ~OsslCommon();
    OsslCommon(const OsslCommon&) = delete;
    OsslCommon& operator=(const OsslCommon&) = delete;

    EVP_MD* sha3_256_ = nullptr;
    EVP_MD* sha256_ = nullptr;
    EVP_MAC* hmac_ = nullptr;
    EVP_MAC* kmac256_ = nullptr;
    EVP_KDF* hkdf_ = nullptr;
    EVP_CIPHER* chacha_ = nullptr;
    std::string version_;
};

/// Throw std::runtime_error carrying the OpenSSL error queue contents.
[[noreturn]] void throwOsslError(const char* context);

} // namespace crypto
} // namespace uavauth

#endif
