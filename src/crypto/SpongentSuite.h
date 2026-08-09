#ifndef UAVAUTH_CRYPTO_SPONGENTSUITE_H
#define UAVAUTH_CRYPTO_SPONGENTSUITE_H

#include "crypto/CryptoSuite.h"
#include "crypto/spongent/Spongent160.h"

// Self-contained by design: crypto/CryptoSuiteFactory.cc includes this header
// directly, so everything it names is included here rather than assumed.
#include <cstddef>
#include <cstdint>
#include <string>

namespace uavauth {
namespace crypto {

/// Constrained-hardware profile.
///
///   hash  SPONGENT-160/160/16
///   MAC   prefix keyed sponge over the same permutation, tag 128 bits
///   KDF   one-pass sponge, output length bound into the absorbed input
///   AEAD  Ascon-128a v1.2
///
/// Nothing here comes from OpenSSL except CRYPTO_memcmp, so implTag() marks
/// every primitive "/vendored": these are portable C++ implementations and must
/// not be compared like-for-like against the sha3 profile's assembly-optimised
/// OpenSSL primitives.
///
/// securityLevelBits() reports 80, not 128. The capacity is 160 bits, so the
/// hash and MAC layers sit at c/2 = 80 bits -- genuinely weaker than the sha3
/// profile, which is the point of measuring both. The AEAD and the
/// (suite-external) X25519 exchange are still at the 128-bit level, so 80 bits is
/// the *floor* of the profile and the number a reviewer should hold it to.
///
/// ---------------------------------------------------------------------------
/// Why the MAC is a prefix keyed sponge and not HMAC.
///
/// HMAC is defined as H(K' xor opad || H(K' xor ipad || m)) with K' the key
/// padded to the hash's *block size*. SPONGENT-160/160/16 has a rate of 16 bits
/// -- two bytes -- so "pad the key to the block size" is not merely awkward, it
/// is impossible for any useful key: a 16-byte key is eight blocks long, and the
/// ipad/opad masking HMAC relies on is not defined for that case. Truncating or
/// pre-hashing the key to two bytes would obviously be absurd.
///
/// The nesting HMAC performs is also unnecessary here. HMAC's outer hash exists
/// to defeat length-extension in Merkle-Damgard constructions, where the digest
/// *is* the full internal state. A sponge with capacity c > 0 never exposes the
/// capacity, so from an r-bit output an adversary cannot continue the absorption
/// -- there is no length-extension property to patch over.
///
/// What is used instead is the keyed sponge: absorb the key first, then the
/// message, then squeeze. Its PRF security is proved in Bertoni, Daemen,
/// Peeters and Van Assche, "On the security of the keyed sponge construction"
/// (SKEW 2011), and tightened in Andreeva, Daemen, Mennink and Van Assche,
/// "Security of Keyed Sponge Constructions Using a Modular Proof Approach"
/// (FSE 2015). It is the same construction NIST standardised as KMAC over
/// Keccak in SP 800-185, which is why Sha3Suite can offer KMAC as its
/// alternative MAC: the two profiles then differ only in the permutation.
///
/// The absorbed input is
///     u8(kDomainMac) || u8(kSuiteVersion) || lengthPrefixed(key) || message
/// The domain byte separates the MAC from the hash and KDF modes over the same
/// permutation; the suite-version byte lets the transcript format change without
/// old and new tags ever colliding; and the key is length-prefixed so that
/// (key, message) pairs cannot be re-cut -- without it, mac("ab", "c") and
/// mac("a", "bc") would absorb identical bytes and produce identical tags.
/// ---------------------------------------------------------------------------
class SpongentSuite : public CryptoSuite {
  public:
    /// Version of *this suite's* MAC/KDF input formats, absorbed into both. It is
    /// deliberately separate from core::kProtoVersion, which versions the wire
    /// encoding: a change to either must invalidate old authenticators, but the
    /// two can move independently.
    static constexpr uint8_t kSuiteVersion = 0x01;

    SuiteId id() const override { return SuiteId::SPONGENT; }
    const char* name() const override { return "spongent"; }
    std::string implTag(Primitive p) const override;
    int securityLevelBits() const override { return 80; }

    size_t hashLen() const override { return 20; }
    size_t macLen() const override { return 16; }
    size_t keyLen() const override { return 32; }
    size_t aeadKeyLen() const override { return 16; }    // Ascon-128a
    size_t aeadNonceLen() const override { return 16; }  // Ascon-128a
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
    /// Shared by mac() and macVerify() so the two can never drift apart.
    Bytes macRaw(const Bytes& key, const Bytes& message) const;

    /// Shared by kdf() and extract(), for the same reason, and so that neither
    /// charges its cost to the other's counter through a nested ScopedTimer.
    Bytes kdfRaw(const Bytes& ikm, const Bytes& salt, const std::string& label,
                 const Bytes& info, size_t outLen) const;

    Spongent160 sponge_;
};

} // namespace crypto
} // namespace uavauth

#endif
