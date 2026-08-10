#ifndef UAVAUTH_CRYPTO_ECDSASUITE_H
#define UAVAUTH_CRYPTO_ECDSASUITE_H

#include "crypto/SignatureSuite.h"

namespace uavauth {
namespace crypto {

/// ECDSA P-256 signatures (over SHA-256, via EVP_DigestSign/Verify), promoted
/// from tests/bench_pki_baseline.cc's file-local genEc/signOnce/verifyOnce
/// into a reusable class -- see RsaSuite.h for the shared rationale.
class EcdsaSuite : public SignatureSuite {
  public:
    const char* name() const override { return "ecdsa-p256"; }

    SignatureKeyPair generateKeypair() const override;
    Bytes publicKeyBytes(const SignatureKeyPair& kp) const override;
    std::unique_ptr<SignatureKeyPair> keyFromPublicBytes(const Bytes& spki) const override;
    Bytes sign(const SignatureKeyPair& kp, const Bytes& message) const override;
    bool verify(const SignatureKeyPair& kp, const Bytes& message,
               const Bytes& signature) const override;
};

} // namespace crypto
} // namespace uavauth

#endif
