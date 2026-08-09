#ifndef UAVAUTH_CRYPTO_SHA3SUITE_H
#define UAVAUTH_CRYPTO_SHA3SUITE_H

#include "crypto/CryptoSuite.h"

namespace uavauth {
namespace crypto {

/// Software-efficient profile.
///
///   hash  SHA3-256 truncated to 160 bits
///   MAC   HMAC-SHA3-256, tag truncated to 128 bits
///   KDF   HKDF (extract-then-expand) over SHA3-256
///   AEAD  ChaCha20-Poly1305
///
/// All four come from OpenSSL 3.x. The AEAD and the (suite-external) X25519 key
/// exchange both sit at the 128-bit level, and the 160-bit hash gives 80-bit
/// collision resistance, so securityLevelBits() reports the 128-bit
/// authentication/confidentiality level of the keyed primitives.
class Sha3Suite : public CryptoSuite {
  public:
    /// `useKmac` selects OpenSSL's KMAC-256 instead of HMAC-SHA3-256 as the MAC.
    /// Both are standard keyed constructions over Keccak; HMAC is the default
    /// because it has published test vectors for SHA3.
    explicit Sha3Suite(bool useKmac = false);

    SuiteId id() const override { return SuiteId::SHA3; }
    const char* name() const override { return "sha3"; }
    std::string implTag(Primitive p) const override;
    int securityLevelBits() const override { return 128; }

    size_t hashLen() const override { return 20; }
    size_t macLen() const override { return 16; }
    size_t keyLen() const override { return 32; }
    size_t aeadKeyLen() const override { return 32; }
    size_t aeadNonceLen() const override { return 12; }
    size_t aeadTagLen() const override { return 16; }

    Bytes hash160(const Bytes& message) const override;
    Bytes mac(const Bytes& key, const Bytes& message) const override;
    bool macVerify(const Bytes& key, const Bytes& message,
                   const Bytes& tag) const override;
    Bytes kdf(const Bytes& ikm, const Bytes& salt, const std::string& label,
              const Bytes& info, size_t outLen) const override;
    Bytes extract(const Bytes& salt, const Bytes& source) const override;
    bool aeadSeal(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                  const Bytes& plaintext, Bytes& ciphertextOut) const override;
    bool aeadOpen(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                  const Bytes& ciphertext, Bytes& plaintextOut) const override;

  private:
    bool useKmac_;
};

/// Raw primitives exposed for the known-answer tests, so a test can compare the
/// library output against a published vector before the domain separation and
/// truncation that the protocol layers on top.
namespace raw {
Bytes sha3_256(const Bytes& message);
Bytes hmacSha3_256(const Bytes& key, const Bytes& message);
/// HKDF with an explicit digest name ("SHA2-256" or "SHA3-256"), used to check
/// the EVP_KDF wiring against RFC 5869, whose vectors are SHA-256 only.
Bytes hkdf(const std::string& digest, const Bytes& ikm, const Bytes& salt,
           const Bytes& info, size_t outLen);
Bytes hkdfExtract(const std::string& digest, const Bytes& salt, const Bytes& ikm);
Bytes hkdfExpand(const std::string& digest, const Bytes& prk, const Bytes& info,
                 size_t outLen);
bool chachaPoly1305Seal(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                        const Bytes& plaintext, Bytes& out);
bool chachaPoly1305Open(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                        const Bytes& ciphertext, Bytes& out);
} // namespace raw

} // namespace crypto
} // namespace uavauth

#endif
