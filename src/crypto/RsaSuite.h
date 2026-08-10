#ifndef UAVAUTH_CRYPTO_RSASUITE_H
#define UAVAUTH_CRYPTO_RSASUITE_H

#include "crypto/SignatureSuite.h"

namespace uavauth {
namespace crypto {

/// RSA-2048 signatures (PKCS#1 v1.5 over SHA-256, via EVP_DigestSign/Verify),
/// promoted from tests/bench_pki_baseline.cc's file-local genRsa/signOnce/
/// verifyOnce into a reusable class: same OpenSSL calls, now instrumented via
/// PrimitiveCounters and with explicit key erasure, neither of which the
/// original benchmark had.
class RsaSuite : public SignatureSuite {
  public:
    const char* name() const override { return "rsa2048"; }

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
