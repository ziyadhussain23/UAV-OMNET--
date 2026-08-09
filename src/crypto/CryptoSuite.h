#ifndef UAVAUTH_CRYPTO_CRYPTOSUITE_H
#define UAVAUTH_CRYPTO_CRYPTOSUITE_H

#include "core/Bytes.h"
#include "crypto/PrimitiveCounters.h"

#include <memory>
#include <string>

namespace uavauth {
namespace crypto {

using core::Bytes;

/// Suite identifiers. The value is mixed into every MAC transcript, so two
/// suites can never produce a colliding authenticator.
enum class SuiteId : uint8_t { SHA3 = 0x01, SPONGENT = 0x02 };

/// Key-derivation labels. Every derived key carries exactly one of these, so a
/// key minted for one purpose can never be mistaken for another.
namespace label {
constexpr const char* kFeRoot     = "uavauth/v1/fe-root";
constexpr const char* kFeExtract  = "uavauth/v1/fe-extract";
constexpr const char* kP2Auth     = "uavauth/v1/p2-auth";
constexpr const char* kP2Sess     = "uavauth/v1/p2-sess";
constexpr const char* kP2Aead     = "uavauth/v1/p2-aead";
constexpr const char* kPairCred   = "uavauth/v1/pair-cred";
constexpr const char* kPeerAuth   = "uavauth/v1/peer-auth";
constexpr const char* kPeerSess   = "uavauth/v1/peer-sess";
constexpr const char* kTidRotate  = "uavauth/v1/tid-rotate";
} // namespace label

/// Abstract cryptographic suite.
///
/// Two instantiations exist:
///
///   "sha3"     SHA3-256/160 + HMAC-SHA3-256 + HKDF + ChaCha20-Poly1305
///              (software-efficient profile, 128-bit AEAD/KEX security)
///   "spongent" SPONGENT-160/160/16 + prefix keyed sponge MAC + sponge KDF
///              + Ascon-128a (constrained-hardware profile, 80-bit hash level)
///
/// X25519 is deliberately NOT part of the suite: both profiles use the same
/// curve, so it lives in crypto/X25519.h.
///
/// Every method charges its cost to `counters()` so per-primitive timings can be
/// reported without the protocol code carrying timing statements.
class CryptoSuite {
  public:
    virtual ~CryptoSuite() = default;

    virtual SuiteId id() const = 0;
    virtual const char* name() const = 0;

    /// Concrete implementation string for the results CSV, e.g.
    /// "sha3-256/openssl-3.5.5" or "spongent160-176-16/vendored". Recording this
    /// keeps a vendored primitive from being silently compared against an
    /// assembly-optimised one.
    virtual std::string implTag(Primitive p) const = 0;

    /// Nominal security level of the hash/MAC layer, in bits. 128 for the sha3
    /// suite; 80 for the spongent suite (capacity 160 => c/2).
    virtual int securityLevelBits() const = 0;

    virtual size_t hashLen() const = 0;       // 20 bytes (160 bits), both suites
    virtual size_t macLen() const = 0;        // 16 bytes (128-bit tag), both
    virtual size_t keyLen() const = 0;        // 32 bytes for mk / SK / Cred
    virtual size_t aeadKeyLen() const = 0;    // 32 ChaCha20-Poly1305 | 16 Ascon-128a
    virtual size_t aeadNonceLen() const = 0;  // 12 ChaCha20-Poly1305 | 16 Ascon-128a
    virtual size_t aeadTagLen() const = 0;    // 16, both

    /// Protocol hash h(.), domain-separated from the MAC and KDF modes.
    virtual Bytes hash160(const Bytes& message) const = 0;

    /// Keyed MAC. Output is macLen() bytes.
    virtual Bytes mac(const Bytes& key, const Bytes& message) const = 0;

    /// Constant-time MAC verification. Implementations must not early-return on
    /// the first differing byte.
    virtual bool macVerify(const Bytes& key, const Bytes& message,
                           const Bytes& tag) const = 0;

    /// Labelled key derivation.
    virtual Bytes kdf(const Bytes& ikm, const Bytes& salt, const std::string& label,
                      const Bytes& info, size_t outLen) const = 0;

    /// Strong extractor used by the fuzzy extractor: compresses a high-entropy
    /// but non-uniform PUF response into a near-uniform key.
    virtual Bytes extract(const Bytes& salt, const Bytes& source) const = 0;

    /// AEAD. Returns false on authentication failure, which callers must treat
    /// as a protocol abort (this is the INT-CTXT check).
    virtual bool aeadSeal(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                          const Bytes& plaintext, Bytes& ciphertextOut) const = 0;
    virtual bool aeadOpen(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                          const Bytes& ciphertext, Bytes& plaintextOut) const = 0;

    PrimitiveCounters& counters() const { return counters_; }

  protected:
    mutable PrimitiveCounters counters_;
};

/// Construct a suite from the NED `hashMode` string ("sha3" | "spongent").
/// Throws std::invalid_argument on an unknown name -- the previous
/// implementation silently fell back to SHA3, which would mislabel results.
std::unique_ptr<CryptoSuite> makeCryptoSuite(const std::string& name);

} // namespace crypto
} // namespace uavauth

#endif
