#ifndef UAVAUTH_CRYPTO_SIGNATURESUITE_H
#define UAVAUTH_CRYPTO_SIGNATURESUITE_H

#include "core/Bytes.h"
#include "crypto/PrimitiveCounters.h"

#include <memory>
#include <string>

namespace uavauth {
namespace crypto {

using core::Bytes;

/// A long-term asymmetric keypair. Unlike X25519KeyPair, this is not
/// ephemeral -- it is generated once, at enrollment, and reused across every
/// handshake, exactly like a real deployment's RSA/ECDSA identity key. Held
/// opaquely (as an OpenSSL EVP_PKEY, via a private impl) rather than as raw
/// bytes, since neither RSA nor ECDSA keys are a fixed-width byte string the
/// way an X25519 key is.
class SignatureKeyPair {
  public:
    SignatureKeyPair() = default;
    SignatureKeyPair(SignatureKeyPair&&) noexcept;
    SignatureKeyPair& operator=(SignatureKeyPair&&) noexcept;
    SignatureKeyPair(const SignatureKeyPair&) = delete;
    SignatureKeyPair& operator=(const SignatureKeyPair&) = delete;
    ~SignatureKeyPair();

    bool valid() const { return impl_ != nullptr; }

  private:
    friend class RsaSuite;
    friend class EcdsaSuite;
    void* impl_ = nullptr;   // EVP_PKEY*, owned
};

/// Abstract sibling to CryptoSuite, for the RSA/ECDSA protocol baseline
/// (src/protocol/BaselineSigAuth.h). Deliberately NOT part of the CryptoSuite
/// hierarchy: that interface is entirely symmetric (every method takes one
/// shared key), with no keypair/sign/verify concept anywhere in it, and
/// bending it to fit asymmetric signatures would be a worse fit than a
/// sibling class -- the same reasoning that already keeps X25519 outside
/// CryptoSuite (see CryptoSuite.h's own comment).
///
/// Every sign/verify call charges Primitive::Sign/Primitive::Verify via
/// counters(), exactly as CryptoSuite's methods charge their own primitives,
/// so this baseline's cost flows into the same CSV export pipeline with zero
/// exporter changes.
class SignatureSuite {
  public:
    virtual ~SignatureSuite() = default;

    virtual const char* name() const = 0;

    /// One-time enrollment cost, not charged to any per-handshake primitive
    /// (see PrimitiveCounters.h's comment on Sign/Verify) -- mirrors how a
    /// real deployment provisions a long-term identity key once, and how
    /// this project's own PUF/fuzzy-extractor enrollment happens once in
    /// Phase 1, out of band from Phase 2's per-handshake timing.
    virtual SignatureKeyPair generateKeypair() const = 0;

    /// Opaque public-key bytes suitable for another party to verify with
    /// (an SPKI DER encoding). Not sent on the wire in the baseline protocol
    /// -- see BaselineSigAuth.h's header comment -- but needed so a
    /// verifier can be constructed from bytes alone, matching how a real
    /// deployment distributes public keys once, out of band.
    virtual Bytes publicKeyBytes(const SignatureKeyPair& kp) const = 0;
    virtual std::unique_ptr<SignatureKeyPair> keyFromPublicBytes(const Bytes& spki) const = 0;

    /// Sign/verify over an arbitrary message. Charges Primitive::Sign /
    /// Primitive::Verify to counters().
    virtual Bytes sign(const SignatureKeyPair& kp, const Bytes& message) const = 0;
    virtual bool verify(const SignatureKeyPair& kp, const Bytes& message,
                        const Bytes& signature) const = 0;

    PrimitiveCounters& counters() const { return counters_; }

  protected:
    mutable PrimitiveCounters counters_;
};

std::unique_ptr<SignatureSuite> makeSignatureSuite(const std::string& name);   // "rsa2048" | "ecdsa-p256"

} // namespace crypto
} // namespace uavauth

#endif
