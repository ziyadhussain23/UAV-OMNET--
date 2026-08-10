// RSA-2048 / ECDSA P-256 signature suite: keygen/sign/verify round trip and
// tamper rejection, for both concrete SignatureSuite implementations.
//
// DEPS: core/Bytes.cc crypto/OsslCommon.cc crypto/PrimitiveCounters.cc crypto/SignatureSuite.cc crypto/RsaSuite.cc crypto/EcdsaSuite.cc

#include "core/Bytes.h"
#include "crypto/EcdsaSuite.h"
#include "crypto/RsaSuite.h"
#include "crypto/SignatureSuite.h"
#include "tests/TestUtil.h"

using namespace uavauth::core;
using namespace uavauth::crypto;

namespace {

void testRoundTrip(const SignatureSuite& suite, const char* name) {
    const SignatureKeyPair kp = suite.generateKeypair();
    CHECK_MSG(kp.valid(), std::string(name) + ": keygen failed");
    if (!kp.valid()) return;

    const Bytes msg = fromString("UAV authentication handshake transcript");
    const Bytes sig = suite.sign(kp, msg);
    CHECK_MSG(!sig.empty(), std::string(name) + ": sign produced no output");
    CHECK_MSG(suite.verify(kp, msg, sig), std::string(name) + ": verify(own signature) failed");

    // Wrong message.
    const Bytes other = fromString("a different message entirely");
    CHECK_MSG(!suite.verify(kp, other, sig), std::string(name) + ": verify accepted wrong message");

    // Tampered signature (flip one bit).
    Bytes tampered = sig;
    tampered[tampered.size() / 2] ^= 0x01;
    CHECK_MSG(!suite.verify(kp, msg, tampered),
             std::string(name) + ": verify accepted a tampered signature");

    // Verifying with a DIFFERENT keypair's public key must fail.
    const SignatureKeyPair other_kp = suite.generateKeypair();
    CHECK_MSG(other_kp.valid(), std::string(name) + ": second keygen failed");
    CHECK_MSG(!suite.verify(other_kp, msg, sig),
             std::string(name) + ": verify accepted signature under the wrong key");
}

void testPublicKeyRoundTrip(const SignatureSuite& suite, const char* name) {
    const SignatureKeyPair kp = suite.generateKeypair();
    CHECK(kp.valid());

    const Bytes spki = suite.publicKeyBytes(kp);
    CHECK_MSG(!spki.empty(), std::string(name) + ": publicKeyBytes produced no output");

    const std::unique_ptr<SignatureKeyPair> pubOnly = suite.keyFromPublicBytes(spki);
    CHECK_MSG(pubOnly != nullptr, std::string(name) + ": keyFromPublicBytes failed to parse");
    if (pubOnly == nullptr) return;

    const Bytes msg = fromString("verify with a public-key-only handle");
    const Bytes sig = suite.sign(kp, msg);
    CHECK_MSG(suite.verify(*pubOnly, msg, sig),
             std::string(name) + ": verify failed using a key reconstructed from public bytes alone");
}

void testFactory() {
    auto rsa = makeSignatureSuite("rsa2048");
    CHECK(rsa != nullptr);
    CHECK_EQ(std::string(rsa->name()), std::string("rsa2048"));

    auto ecdsa = makeSignatureSuite("ecdsa-p256");
    CHECK(ecdsa != nullptr);
    CHECK_EQ(std::string(ecdsa->name()), std::string("ecdsa-p256"));

    CHECK_THROWS(makeSignatureSuite("unknown-suite"));
}

void testPrimitiveCountersCharged(const SignatureSuite& suite, const char* name) {
    suite.counters().reset();
    const SignatureKeyPair kp = suite.generateKeypair();
    const Bytes msg = fromString("counters check");
    const Bytes sig = suite.sign(kp, msg);
    (void)suite.verify(kp, msg, sig);

    CHECK_MSG(suite.counters().get(Primitive::Sign).calls == 1,
             std::string(name) + ": sign() did not charge Primitive::Sign exactly once");
    CHECK_MSG(suite.counters().get(Primitive::Verify).calls == 1,
             std::string(name) + ": verify() did not charge Primitive::Verify exactly once");
}

} // namespace

int main() {
    RsaSuite rsa;
    EcdsaSuite ecdsa;

    testRoundTrip(rsa, "rsa2048");
    testRoundTrip(ecdsa, "ecdsa-p256");
    testPublicKeyRoundTrip(rsa, "rsa2048");
    testPublicKeyRoundTrip(ecdsa, "ecdsa-p256");
    testPrimitiveCountersCharged(rsa, "rsa2048");
    testPrimitiveCountersCharged(ecdsa, "ecdsa-p256");
    testFactory();

    return uavauth::test::summarise("test_signature_suite");
}
