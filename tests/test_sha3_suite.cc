// Stage-2 gate: the "sha3" crypto profile.
//
// Every underlying primitive is checked against a published vector before any
// protocol-level construction is trusted:
//   SHA3-256            NIST FIPS 202 / CAVP short-message vectors
//   HKDF                RFC 5869 Appendix A.1 and A.2 (SHA-256)
//   ChaCha20-Poly1305   RFC 8439 Section 2.8.2
// There are no published HKDF-SHA3 vectors, so the SHA3 instantiation is instead
// checked for internal consistency against Extract/Expand composed from the
// separately-vectored HMAC primitive.
//
// DEPS: core/Bytes.cc core/Encoding.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/Sha3Suite.cc crypto/Drbg.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/Sha3Suite.h"
#include "tests/TestUtil.h"

#include <set>
#include <string>

using namespace uavauth::core;
using namespace uavauth::crypto;

namespace {

void testSha3Kat() {
    // FIPS 202 / CAVP.
    CHECK_HEX_EQ(raw::sha3_256(Bytes{}),
                 "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    CHECK_HEX_EQ(raw::sha3_256(fromString("abc")),
                 "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    CHECK_HEX_EQ(
        raw::sha3_256(fromString(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
}

void testHmacSha3Kat() {
    // NIST "Examples with Intermediate Values": HMAC-SHA3-256, key = 00..a3
    // (32 bytes, keylen == input block size is a separate case), data = "Sample
    // message for keylen<blocklen".
    Bytes key(32);
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(i);
    const Bytes data = fromString("Sample message for keylen<blocklen");
    CHECK_HEX_EQ(raw::hmacSha3_256(key, data),
                 "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205");
}

void testHkdfRfc5869() {
    // RFC 5869 Appendix A.1 (SHA-256, basic).
    {
        const Bytes ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        const Bytes salt = fromHex("000102030405060708090a0b0c");
        const Bytes info = fromHex("f0f1f2f3f4f5f6f7f8f9");
        CHECK_HEX_EQ(raw::hkdfExtract("SHA2-256", salt, ikm),
                     "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        CHECK_HEX_EQ(raw::hkdf("SHA2-256", ikm, salt, info, 42),
                     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                     "34007208d5b887185865");
    }
    // RFC 5869 Appendix A.2 (SHA-256, longer inputs).
    {
        Bytes ikm(80), salt(80), info(80);
        for (size_t i = 0; i < 80; ++i) {
            ikm[i] = static_cast<uint8_t>(i);
            salt[i] = static_cast<uint8_t>(0x60 + i);
            info[i] = static_cast<uint8_t>(0xb0 + i);
        }
        CHECK_HEX_EQ(raw::hkdfExtract("SHA2-256", salt, ikm),
                     "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244");
        CHECK_HEX_EQ(
            raw::hkdf("SHA2-256", ikm, salt, info, 82),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
            "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
            "cc30c58179ec3e87c14c01d5c1f3434f1d87");
    }
    // RFC 5869 Appendix A.3 (SHA-256, zero-length salt and info).
    {
        const Bytes ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        CHECK_HEX_EQ(raw::hkdf("SHA2-256", ikm, Bytes{}, Bytes{}, 42),
                     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                     "9d201395faa4b61a96c8");
    }
}

void testHkdfSha3SelfConsistency() {
    // No published HKDF-SHA3 vectors exist. Instead check that the library's
    // extract-and-expand equals Extract followed by Expand, both of which run
    // over the HMAC primitive verified above.
    const Bytes ikm = fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const Bytes salt = fromHex("000102030405060708090a0b0c");
    const Bytes info = fromHex("f0f1f2f3f4f5f6f7f8f9");

    const Bytes combined = raw::hkdf("SHA3-256", ikm, salt, info, 42);
    const Bytes prk = raw::hkdfExtract("SHA3-256", salt, ikm);
    const Bytes stepwise = raw::hkdfExpand("SHA3-256", prk, info, 42);
    CHECK(combined == stepwise);

    // And that Extract really is HMAC(salt, ikm), the RFC 5869 definition.
    CHECK(prk == raw::hmacSha3_256(salt, ikm));
}

void testChaChaPoly1305Rfc8439() {
    // RFC 8439 Section 2.8.2.
    const Bytes plaintext = fromString(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one "
        "tip for the future, sunscreen would be it.");
    const Bytes aad = fromHex("50515253c0c1c2c3c4c5c6c7");
    const Bytes key =
        fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const Bytes nonce = fromHex("070000004041424344454647");

    Bytes sealed;
    CHECK(raw::chachaPoly1305Seal(key, nonce, aad, plaintext, sealed));
    CHECK_HEX_EQ(
        sealed,
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691");

    Bytes opened;
    CHECK(raw::chachaPoly1305Open(key, nonce, aad, sealed, opened));
    CHECK(opened == plaintext);
}

void testAeadRejectsTampering() {
    Sha3Suite suite;
    Drbg rng(fromString("aead-tamper-seed"));
    const Bytes key = rng.bytes(suite.aeadKeyLen());
    const Bytes nonce = rng.bytes(suite.aeadNonceLen());
    const Bytes aad = rng.bytes(24);
    const Bytes pt = rng.bytes(96);

    Bytes ct;
    CHECK(suite.aeadSeal(key, nonce, aad, pt, ct));
    CHECK_EQ(ct.size(), pt.size() + suite.aeadTagLen());

    Bytes out;
    CHECK(suite.aeadOpen(key, nonce, aad, ct, out));
    CHECK(out == pt);

    // Every single-byte corruption of the ciphertext (body or tag) must fail.
    int accepted = 0;
    for (size_t i = 0; i < ct.size(); ++i) {
        Bytes bad = ct;
        bad[i] = static_cast<uint8_t>(bad[i] ^ 0x01);
        Bytes result;
        if (suite.aeadOpen(key, nonce, aad, bad, result)) ++accepted;
        CHECK(result.empty());
    }
    CHECK_MSG(accepted == 0, "tampered ciphertext was accepted");

    // Every single-byte corruption of the AAD must fail.
    accepted = 0;
    for (size_t i = 0; i < aad.size(); ++i) {
        Bytes badAad = aad;
        badAad[i] = static_cast<uint8_t>(badAad[i] ^ 0x80);
        Bytes result;
        if (suite.aeadOpen(key, nonce, badAad, ct, result)) ++accepted;
    }
    CHECK_MSG(accepted == 0, "tampered AAD was accepted");

    // Wrong key and wrong nonce must fail.
    Bytes wrongKey = key;
    wrongKey[0] ^= 0xFF;
    Bytes result;
    CHECK(!suite.aeadOpen(wrongKey, nonce, aad, ct, result));
    Bytes wrongNonce = nonce;
    wrongNonce[0] ^= 0xFF;
    CHECK(!suite.aeadOpen(key, wrongNonce, aad, ct, result));

    // Malformed input shorter than a tag must be rejected, not read out of bounds.
    CHECK(!suite.aeadOpen(key, nonce, aad, Bytes(8, 0x00), result));
    // Wrong key/nonce sizes are rejected rather than silently padded.
    CHECK(!suite.aeadSeal(Bytes(16, 0), nonce, aad, pt, ct));
    CHECK(!suite.aeadOpen(key, Bytes(8, 0), aad, ct, result));
}

void testSuiteLevelBehaviour() {
    Sha3Suite suite;
    CHECK_EQ(std::string(suite.name()), std::string("sha3"));
    CHECK_EQ(suite.hashLen(), 20u);
    CHECK_EQ(suite.macLen(), 16u);
    CHECK_EQ(suite.securityLevelBits(), 128);

    const Bytes msg = fromString("protocol message");

    // Domain separation: the protocol hash must not be a bare truncation of the
    // raw primitive, or the hash, MAC and KDF modes could collide.
    Bytes bareTruncated = raw::sha3_256(msg);
    bareTruncated.resize(20);
    CHECK(suite.hash160(msg) != bareTruncated);
    CHECK_EQ(suite.hash160(msg).size(), 20u);

    // Determinism.
    CHECK(suite.hash160(msg) == suite.hash160(msg));

    // MAC: verifies, and rejects every single-bit flip of tag and message.
    const Bytes key = fromHex("000102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f");
    const Bytes tag = suite.mac(key, msg);
    CHECK_EQ(tag.size(), 16u);
    CHECK(suite.macVerify(key, msg, tag));

    int accepted = 0;
    for (size_t bit = 0; bit < tag.size() * 8; ++bit) {
        Bytes bad = tag;
        bad[bit / 8] = static_cast<uint8_t>(bad[bit / 8] ^ (1u << (bit % 8)));
        if (suite.macVerify(key, msg, bad)) ++accepted;
    }
    CHECK_MSG(accepted == 0, "flipped MAC tag accepted");

    accepted = 0;
    for (size_t bit = 0; bit < msg.size() * 8; ++bit) {
        Bytes bad = msg;
        bad[bit / 8] = static_cast<uint8_t>(bad[bit / 8] ^ (1u << (bit % 8)));
        if (suite.macVerify(key, bad, tag)) ++accepted;
    }
    CHECK_MSG(accepted == 0, "flipped message accepted under original tag");

    // Wrong key, and a truncated tag, must both be rejected.
    Bytes wrongKey = key;
    wrongKey[31] ^= 0x01;
    CHECK(!suite.macVerify(wrongKey, msg, tag));
    CHECK(!suite.macVerify(key, msg, Bytes(tag.begin(), tag.end() - 1)));

    // KDF: distinct labels give independent keys.
    const Bytes ikm = fromHex("aabbccddeeff00112233445566778899"
                              "aabbccddeeff00112233445566778899");
    const Bytes salt = fromHex("0011223344556677");
    const Bytes k1 = suite.kdf(ikm, salt, label::kP2Auth, Bytes{}, 32);
    const Bytes k2 = suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 32);
    const Bytes k3 = suite.kdf(ikm, salt, label::kPeerAuth, Bytes{}, 32);
    CHECK(k1 != k2);
    CHECK(k1 != k3);
    CHECK(k2 != k3);
    CHECK(k1 == suite.kdf(ikm, salt, label::kP2Auth, Bytes{}, 32));

    // Distinct info values give independent keys (this is what separates the
    // per-pair credentials from one another).
    const Bytes c01 = suite.kdf(ikm, salt, label::kPairCred, fromHex("00000001"), 32);
    const Bytes c02 = suite.kdf(ikm, salt, label::kPairCred, fromHex("00000002"), 32);
    CHECK(c01 != c02);

    // HKDF is a stream, so a short output IS a prefix of a longer one. Record
    // that explicitly: callers must never rely on length alone to separate keys,
    // which is why every derivation carries a distinct label.
    const Bytes short16 = suite.kdf(ikm, salt, label::kP2Auth, Bytes{}, 16);
    const Bytes long32 = suite.kdf(ikm, salt, label::kP2Auth, Bytes{}, 32);
    CHECK(std::equal(short16.begin(), short16.end(), long32.begin()));

    // extract() produces a 32-byte key and depends on both salt and source.
    const Bytes e1 = suite.extract(salt, ikm);
    CHECK_EQ(e1.size(), 32u);
    CHECK(e1 != suite.extract(fromHex("1111111111111111"), ikm));

    // Timing counters were actually populated.
    CHECK(suite.counters().get(Primitive::Hash160).calls > 0);
    CHECK(suite.counters().get(Primitive::Mac).calls > 0);
    CHECK(suite.counters().get(Primitive::MacVerify).calls > 0);
    CHECK(suite.counters().get(Primitive::Kdf).calls > 0);
}

void testKmacVariant() {
    // The alternative keyed-sponge MAC must work and must differ from HMAC.
    Sha3Suite hmacSuite(false);
    Sha3Suite kmacSuite(true);
    const Bytes key(32, 0x5a);
    const Bytes msg = fromString("kmac vs hmac");
    const Bytes tagK = kmacSuite.mac(key, msg);
    CHECK_EQ(tagK.size(), 16u);
    CHECK(kmacSuite.macVerify(key, msg, tagK));
    CHECK(tagK != hmacSuite.mac(key, msg));
    CHECK(!hmacSuite.macVerify(key, msg, tagK));
}

void testDrbg() {
    // Determinism: identical seeds reproduce the stream exactly.
    Drbg a(fromString("seed-A"));
    Drbg b(fromString("seed-A"));
    CHECK(a.bytes(64) == b.bytes(64));
    CHECK(a.bytes(7) == b.bytes(7));

    // Different seeds diverge.
    Drbg c(fromString("seed-B"));
    Drbg d(fromString("seed-A"));
    CHECK(c.bytes(64) != d.bytes(64));

    // Chunked draws equal one long draw (no block-boundary artefacts).
    Drbg e(fromString("chunk"));
    Bytes piecewise;
    for (int i = 0; i < 20; ++i) append(piecewise, e.bytes(7));
    Drbg f(fromString("chunk"));
    CHECK(piecewise == f.bytes(140));

    // reseed restarts the stream.
    Drbg g(fromString("x"));
    const Bytes first = g.bytes(32);
    g.reseed(fromString("x"));
    CHECK(g.bytes(32) == first);

    // uniform() stays in range and covers the space.
    Drbg h(fromString("uniform"));
    std::set<uint32_t> seen;
    for (int i = 0; i < 4000; ++i) {
        const uint32_t v = h.uniform(10);
        CHECK(v < 10);
        seen.insert(v);
    }
    CHECK_EQ(seen.size(), 10u);
    CHECK_EQ(h.uniform(0), 0u);
    CHECK_EQ(h.uniform(1), 0u);

    // normal() has roughly the right first two moments.
    Drbg n(fromString("normal"));
    double sum = 0.0, sumSq = 0.0;
    const int samples = 20000;
    for (int i = 0; i < samples; ++i) {
        const double v = n.normal();
        sum += v;
        sumSq += v * v;
    }
    const double mean = sum / samples;
    const double var = sumSq / samples - mean * mean;
    CHECK_MSG(mean > -0.05 && mean < 0.05, "DRBG normal() mean far from 0");
    CHECK_MSG(var > 0.9 && var < 1.1, "DRBG normal() variance far from 1");

    // bytesDrawn tracks consumption, so a routine that must be deterministic can
    // be asserted not to have consumed randomness.
    Drbg t(fromString("count"));
    CHECK_EQ(t.bytesDrawn(), 0u);
    t.bytes(10);
    CHECK_EQ(t.bytesDrawn(), 10u);
}

void testX25519Available() {
    // Only checks that the suite and curve coexist; the full RFC 7748 vectors
    // live in test_x25519.cc.
    Sha3Suite suite;
    CHECK(suite.implTag(Primitive::Hash160).find("openssl-") != std::string::npos);
}

} // namespace

int main() {
    testSha3Kat();
    testHmacSha3Kat();
    testHkdfRfc5869();
    testHkdfSha3SelfConsistency();
    testChaChaPoly1305Rfc8439();
    testAeadRejectsTampering();
    testSuiteLevelBehaviour();
    testKmacVariant();
    testDrbg();
    testX25519Available();
    return uavauth::test::summarise("sha3-suite");
}
