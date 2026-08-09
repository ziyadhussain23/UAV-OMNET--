// Stage-2 gate: X25519 ephemeral key exchange.
//
// Checked against RFC 7748 Section 6.1 (the Alice/Bob worked example). Also
// covers the two properties the forward-secrecy argument depends on: the secret
// scalar is genuinely erased after use, and a degenerate peer key is rejected
// rather than silently yielding an all-zero shared secret.
//
// DEPS: core/Bytes.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/X25519.cc crypto/Drbg.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/X25519.h"
#include "tests/TestUtil.h"

using namespace uavauth::core;
using namespace uavauth::crypto;

namespace {

PrimitiveCounters counters;

void testRfc7748Section61() {
    // RFC 7748 Section 6.1.
    const Bytes aliceSecret =
        fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const Bytes bobSecret =
        fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");

    const X25519KeyPair alice = x25519Generate(aliceSecret, counters);
    const X25519KeyPair bob = x25519Generate(bobSecret, counters);

    CHECK_HEX_EQ(alice.publicKey,
                 "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    CHECK_HEX_EQ(bob.publicKey,
                 "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    const std::string expectedShared =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    Bytes sharedA, sharedB;
    CHECK(x25519Derive(alice.secret, bob.publicKey, sharedA, counters));
    CHECK(x25519Derive(bob.secret, alice.publicKey, sharedB, counters));
    CHECK_HEX_EQ(sharedA, expectedShared);
    CHECK_HEX_EQ(sharedB, expectedShared);
    CHECK(sharedA == sharedB);
}

void testDeterminismAndIndependence() {
    // The same seed must reproduce the same key pair: this is what makes a
    // simulation run repeatable from its RNG seed.
    const Bytes seed = fromHex("0102030405060708090a0b0c0d0e0f10"
                               "1112131415161718191a1b1c1d1e1f20");
    const X25519KeyPair k1 = x25519Generate(seed, counters);
    const X25519KeyPair k2 = x25519Generate(seed, counters);
    CHECK(k1.publicKey == k2.publicKey);
    CHECK_EQ(k1.publicKey.size(), 32u);

    // Distinct seeds give distinct keys and distinct shared secrets.
    Drbg rng(fromString("x25519-independence"));
    const X25519KeyPair a = x25519Generate(rng.bytes(32), counters);
    const X25519KeyPair b = x25519Generate(rng.bytes(32), counters);
    const X25519KeyPair c = x25519Generate(rng.bytes(32), counters);
    CHECK(a.publicKey != b.publicKey);

    Bytes ab, ac;
    CHECK(x25519Derive(a.secret, b.publicKey, ab, counters));
    CHECK(x25519Derive(a.secret, c.publicKey, ac, counters));
    CHECK(ab != ac);   // fresh ephemerals => independent session secrets
}

void testErasure() {
    // Forward secrecy holds only if the scalar is really gone.
    Drbg rng(fromString("x25519-erase"));
    X25519KeyPair k = x25519Generate(rng.bytes(32), counters);
    CHECK_EQ(k.secret.size(), 32u);
    CHECK(!k.erased);

    const Bytes publicBefore = k.publicKey;
    k.erase();
    CHECK(k.erased);
    CHECK(k.secret.empty());
    CHECK(k.publicKey == publicBefore);   // public part stays usable in transcripts

    // Deriving with an erased scalar must fail rather than use a zero key.
    Bytes shared;
    CHECK(!x25519Derive(k.secret, publicBefore, shared, counters));
    CHECK(shared.empty());
}

void testMalformedInputsRejected() {
    Drbg rng(fromString("x25519-malformed"));
    const X25519KeyPair good = x25519Generate(rng.bytes(32), counters);
    Bytes shared;

    // Wrong-length seed.
    CHECK_THROWS(x25519Generate(Bytes(31, 0x01), counters));
    CHECK_THROWS(x25519Generate(Bytes(33, 0x01), counters));

    // Wrong-length secret or peer key.
    CHECK(!x25519Derive(Bytes(16, 0x01), good.publicKey, shared, counters));
    CHECK(!x25519Derive(good.secret, Bytes(16, 0x02), shared, counters));
    CHECK(shared.empty());

    // Low-order peer points must be rejected: OpenSSL errors on these rather
    // than returning an all-zero secret, and the wrapper must propagate that.
    const char* lowOrder[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    };
    for (const char* hex : lowOrder) {
        Bytes out;
        const bool ok = x25519Derive(good.secret, fromHex(hex), out, counters);
        CHECK_MSG(!ok, "low-order peer point was accepted");
        CHECK_MSG(out.empty(), "shared secret written despite failure");
    }
}

void testCountersRecorded() {
    CHECK(counters.get(Primitive::DhKeygen).calls > 0);
    CHECK(counters.get(Primitive::DhDerive).calls > 0);
    CHECK(counters.get(Primitive::DhKeygen).totalNs > 0.0);
}

} // namespace

int main() {
    testRfc7748Section61();
    testDeterminismAndIndependence();
    testErasure();
    testMalformedInputsRejected();
    testCountersRecorded();
    return uavauth::test::summarise("x25519");
}
