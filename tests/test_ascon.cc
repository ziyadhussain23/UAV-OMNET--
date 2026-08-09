// Stage-2 gate: Ascon-128a v1.2, the AEAD of the "spongent" profile.
//
// Unlike SPONGENT, Ascon has an official known-answer test. Every one of the
// 1089 vectors in crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt from the
// designers' reference repository github.com/ascon/ascon-c (tag v1.2.8) is
// reproduced here: twelve are written out in tests/kat/ascon128a_kat.h for a
// human to read, and the whole set is covered by regenerating the inputs from
// the file's documented pattern and hashing the concatenated ciphertexts. No
// network access is needed -- the digest and the sample vectors are committed.
//
// SHA3-256 is computed through OpenSSL directly rather than through Sha3Suite so
// that this test links only the Ascon implementation; a failure here then points
// at Ascon and nothing else.
//
// DEPS: core/Bytes.cc crypto/ascon/Ascon128a.cc

#include "core/Bytes.h"
#include "crypto/ascon/Ascon128a.h"
#include "tests/TestUtil.h"
#include "tests/kat/ascon128a_kat.h"

#include <openssl/evp.h>

#include <algorithm>
#include <string>
#include <vector>

using namespace uavauth::core;
using namespace uavauth::crypto;
using namespace uavauth::test::kat;

namespace {

Bytes sha3_256(const Bytes& message) {
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool ok = ctx != nullptr &&
                    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) == 1 &&
                    (message.empty() ||
                     EVP_DigestUpdate(ctx, message.data(), message.size()) == 1) &&
                    EVP_DigestFinal_ex(ctx, out.data(), &outLen) == 1;
    if (ctx != nullptr) EVP_MD_CTX_free(ctx);
    CHECK_MSG(ok, "OpenSSL SHA3-256 failed");
    out.resize(outLen);
    return out;
}

/// The KAT file's input pattern: the first `n` bytes of 00 01 02 ... 1f.
Bytes katPrefix(int n) {
    Bytes b(static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) b[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    return b;
}

// ---------------------------------------------------------------------------
// Official known-answer tests.
// ---------------------------------------------------------------------------

void testOfficialVectors() {
    const Bytes key = fromHex(kAscon128aKeyHex);
    const Bytes nonce = fromHex(kAscon128aNonceHex);
    CHECK_EQ(key.size(), kAsconKeyBytes);
    CHECK_EQ(nonce.size(), kAsconNonceBytes);
    CHECK_EQ(kAscon128aVectorCount, 12u);

    for (size_t i = 0; i < kAscon128aVectorCount; ++i) {
        const Ascon128aVector& v = kAscon128aVectors[i];
        const Bytes ad = fromHex(v.adHex);
        const Bytes pt = fromHex(v.ptHex);

        // The vector's own Count field must agree with the file's index rule,
        // which is what makes the regenerated full-KAT sweep below trustworthy.
        CHECK_EQ(v.count, 33 * static_cast<int>(pt.size()) +
                              static_cast<int>(ad.size()) + 1);

        Bytes ct;
        CHECK(ascon128aEncrypt(key, nonce, ad, pt, ct));
        CHECK_HEX_EQ(ct, v.ctHex);
        CHECK_EQ(ct.size(), pt.size() + kAsconTagBytes);

        Bytes recovered;
        CHECK(ascon128aDecrypt(key, nonce, ad, fromHex(v.ctHex), recovered));
        CHECK(recovered == pt);
    }
}

void testFullKatDigest() {
    // Regenerate all 1089 inputs in Count order, concatenate the ciphertexts and
    // compare one digest. This covers every (|PT|, |AD|) pair from 0 to 32,
    // including all four padding-boundary combinations.
    const Bytes key = fromHex(kAscon128aKeyHex);
    const Bytes nonce = fromHex(kAscon128aNonceHex);

    Bytes allCiphertexts;
    int vectors = 0;
    for (int ptLen = 0; ptLen <= kAscon128aFullKatMaxLen; ++ptLen) {
        for (int adLen = 0; adLen <= kAscon128aFullKatMaxLen; ++adLen) {
            const Bytes pt = katPrefix(ptLen);
            const Bytes ad = katPrefix(adLen);
            Bytes ct;
            if (!ascon128aEncrypt(key, nonce, ad, pt, ct)) {
                CHECK_MSG(false, "encryption failed during the full KAT sweep");
                return;
            }
            append(allCiphertexts, ct);
            ++vectors;

            // Decryption must also round-trip for every vector.
            Bytes back;
            if (!ascon128aDecrypt(key, nonce, ad, ct, back) || back != pt) {
                CHECK_MSG(false, "round-trip failed during the full KAT sweep");
                return;
            }
        }
    }
    CHECK_EQ(vectors, kAscon128aFullKatCount);
    CHECK_EQ(allCiphertexts.size(), 34848u);
    CHECK_HEX_EQ(sha3_256(allCiphertexts), kAscon128aAllCiphertextsSha3_256);
}

// ---------------------------------------------------------------------------
// Round-trip behaviour.
// ---------------------------------------------------------------------------

/// Deterministic filler; the test needs varied bytes, not unpredictable ones.
Bytes filler(size_t n, uint8_t seed) {
    Bytes b(n);
    uint8_t x = seed;
    for (size_t i = 0; i < n; ++i) {
        x = static_cast<uint8_t>(x * 31u + 17u);
        b[i] = x;
    }
    return b;
}

void testRoundTrip() {
    const Bytes key = filler(kAsconKeyBytes, 0x11);
    const Bytes nonce = filler(kAsconNonceBytes, 0x22);

    // Empty plaintext, empty associated data: nothing but initialisation,
    // one plaintext padding block, and finalisation.
    {
        Bytes ct;
        CHECK(ascon128aEncrypt(key, nonce, Bytes{}, Bytes{}, ct));
        CHECK_EQ(ct.size(), kAsconTagBytes);
        Bytes pt;
        CHECK(ascon128aDecrypt(key, nonce, Bytes{}, ct, pt));
        CHECK(pt.empty());
    }

    // Empty plaintext with associated data, and plaintext with empty associated
    // data -- the two asymmetric cases, since empty AD absorbs no block at all
    // while empty plaintext still absorbs a padding block.
    {
        const Bytes ad = filler(20, 0x33);
        Bytes ct;
        CHECK(ascon128aEncrypt(key, nonce, ad, Bytes{}, ct));
        CHECK_EQ(ct.size(), kAsconTagBytes);
        Bytes pt;
        CHECK(ascon128aDecrypt(key, nonce, ad, ct, pt));
        CHECK(pt.empty());
        // The tag must depend on the associated data.
        Bytes ctNoAd;
        CHECK(ascon128aEncrypt(key, nonce, Bytes{}, Bytes{}, ctNoAd));
        CHECK(ct != ctNoAd);
    }

    // Multi-block plaintext and associated data, plus every partial-block length
    // around the 16-byte rate.
    static const size_t kPtLens[] = {1, 15, 16, 17, 31, 32, 33, 48, 64, 129};
    static const size_t kAdLens[] = {0, 1, 15, 16, 17, 48};
    for (size_t ptLen : kPtLens) {
        for (size_t adLen : kAdLens) {
            const Bytes pt = filler(ptLen, 0x44);
            const Bytes ad = filler(adLen, 0x55);
            Bytes ct;
            CHECK(ascon128aEncrypt(key, nonce, ad, pt, ct));
            CHECK_EQ(ct.size(), ptLen + kAsconTagBytes);
            Bytes back;
            CHECK(ascon128aDecrypt(key, nonce, ad, ct, back));
            CHECK(back == pt);
            // Ciphertext must not equal plaintext (the keystream is applied).
            CHECK(!std::equal(pt.begin(), pt.end(), ct.begin()));
        }
    }

    // Determinism: the same inputs give the same ciphertext (Ascon is a
    // deterministic, nonce-based AEAD, so this must hold exactly).
    const Bytes pt = filler(40, 0x66);
    const Bytes ad = filler(9, 0x77);
    Bytes a, b;
    CHECK(ascon128aEncrypt(key, nonce, ad, pt, a));
    CHECK(ascon128aEncrypt(key, nonce, ad, pt, b));
    CHECK(a == b);

    // A different nonce gives a different ciphertext under the same key.
    Bytes otherNonce = nonce;
    otherNonce[15] = static_cast<uint8_t>(otherNonce[15] ^ 0x01);
    Bytes c;
    CHECK(ascon128aEncrypt(key, otherNonce, ad, pt, c));
    CHECK(a != c);
}

// ---------------------------------------------------------------------------
// Authentication failures. Every path must reject *and* clear the output.
// ---------------------------------------------------------------------------

void testEveryCiphertextCorruptionFails() {
    const Bytes key = filler(kAsconKeyBytes, 0x81);
    const Bytes nonce = filler(kAsconNonceBytes, 0x82);
    const Bytes ad = filler(24, 0x83);
    const Bytes pt = filler(40, 0x84);

    Bytes ct;
    CHECK(ascon128aEncrypt(key, nonce, ad, pt, ct));

    // Every single-byte corruption of the ciphertext, body and tag alike. Each of
    // the 56 positions is tried with two different perturbations so a corruption
    // cannot coincidentally cancel.
    int accepted = 0;
    int leaked = 0;
    for (size_t i = 0; i < ct.size(); ++i) {
        for (uint8_t mask : {uint8_t{0x01}, uint8_t{0x80}}) {
            Bytes bad = ct;
            bad[i] = static_cast<uint8_t>(bad[i] ^ mask);
            Bytes out = filler(99, 0x99);   // pre-filled: must be cleared
            if (ascon128aDecrypt(key, nonce, ad, bad, out)) ++accepted;
            if (!out.empty()) ++leaked;
        }
    }
    CHECK_MSG(accepted == 0, "a corrupted ciphertext was accepted");
    CHECK_MSG(leaked == 0, "plaintext was released after a failed tag check");
}

void testEveryAdCorruptionFails() {
    const Bytes key = filler(kAsconKeyBytes, 0x91);
    const Bytes nonce = filler(kAsconNonceBytes, 0x92);
    const Bytes ad = filler(24, 0x93);
    const Bytes pt = filler(40, 0x94);

    Bytes ct;
    CHECK(ascon128aEncrypt(key, nonce, ad, pt, ct));

    int accepted = 0;
    int leaked = 0;
    for (size_t i = 0; i < ad.size(); ++i) {
        for (uint8_t mask : {uint8_t{0x01}, uint8_t{0x80}}) {
            Bytes badAad = ad;
            badAad[i] = static_cast<uint8_t>(badAad[i] ^ mask);
            Bytes out = filler(99, 0x9a);
            if (ascon128aDecrypt(key, nonce, badAad, ct, out)) ++accepted;
            if (!out.empty()) ++leaked;
        }
    }
    CHECK_MSG(accepted == 0, "corrupted associated data was accepted");
    CHECK_MSG(leaked == 0, "plaintext was released after a failed tag check");

    // Truncating or extending the associated data must also fail: the length is
    // absorbed through Ascon's padding, so this is not a re-cut vulnerability.
    Bytes out;
    CHECK(!ascon128aDecrypt(key, nonce, Bytes(ad.begin(), ad.end() - 1), ct, out));
    CHECK(out.empty());
    Bytes longerAd = ad;
    longerAd.push_back(0x00);
    CHECK(!ascon128aDecrypt(key, nonce, longerAd, ct, out));
    CHECK(out.empty());
    CHECK(!ascon128aDecrypt(key, nonce, Bytes{}, ct, out));
    CHECK(out.empty());
}

void testWrongKeyAndNonceFail() {
    const Bytes key = filler(kAsconKeyBytes, 0xa1);
    const Bytes nonce = filler(kAsconNonceBytes, 0xa2);
    const Bytes ad = filler(8, 0xa3);
    const Bytes pt = filler(33, 0xa4);

    Bytes ct;
    CHECK(ascon128aEncrypt(key, nonce, ad, pt, ct));

    // Every single-bit flip of the key, and of the nonce, must be rejected.
    int accepted = 0;
    int leaked = 0;
    for (size_t bit = 0; bit < key.size() * 8; ++bit) {
        Bytes badKey = key;
        badKey[bit / 8] = static_cast<uint8_t>(badKey[bit / 8] ^ (1u << (bit % 8)));
        Bytes out = filler(7, 0xa5);
        if (ascon128aDecrypt(badKey, nonce, ad, ct, out)) ++accepted;
        if (!out.empty()) ++leaked;
    }
    for (size_t bit = 0; bit < nonce.size() * 8; ++bit) {
        Bytes badNonce = nonce;
        badNonce[bit / 8] = static_cast<uint8_t>(badNonce[bit / 8] ^ (1u << (bit % 8)));
        Bytes out = filler(7, 0xa6);
        if (ascon128aDecrypt(key, badNonce, ad, ct, out)) ++accepted;
        if (!out.empty()) ++leaked;
    }
    CHECK_MSG(accepted == 0, "a wrong key or nonce was accepted");
    CHECK_MSG(leaked == 0, "plaintext was released under a wrong key or nonce");
}

void testMalformedInputRejected() {
    const Bytes key = filler(kAsconKeyBytes, 0xb1);
    const Bytes nonce = filler(kAsconNonceBytes, 0xb2);
    const Bytes ad = filler(4, 0xb3);
    const Bytes pt = filler(20, 0xb4);

    Bytes ct;
    CHECK(ascon128aEncrypt(key, nonce, ad, pt, ct));

    // Anything shorter than a tag cannot carry one: reject, do not read out of
    // bounds.
    for (size_t n = 0; n < kAsconTagBytes; ++n) {
        Bytes out = filler(5, 0xb5);
        CHECK(!ascon128aDecrypt(key, nonce, ad, Bytes(n, 0x00), out));
        CHECK(out.empty());
    }

    // A truncated or extended valid ciphertext must fail the tag check.
    Bytes out;
    CHECK(!ascon128aDecrypt(key, nonce, ad, Bytes(ct.begin(), ct.end() - 1), out));
    CHECK(out.empty());
    Bytes longer = ct;
    longer.push_back(0x00);
    CHECK(!ascon128aDecrypt(key, nonce, ad, longer, out));
    CHECK(out.empty());

    // Bare tag-length input (i.e. an empty ciphertext body) is well-formed but
    // must still fail unless it is the genuine tag for the empty plaintext.
    CHECK(!ascon128aDecrypt(key, nonce, ad, Bytes(kAsconTagBytes, 0x00), out));
    CHECK(out.empty());

    // Wrong key and nonce *lengths* are rejected on both directions rather than
    // padded or truncated to fit.
    for (size_t n : {size_t{0}, size_t{8}, size_t{15}, size_t{17}, size_t{32}}) {
        Bytes sealed = filler(3, 0xb6);
        CHECK(!ascon128aEncrypt(Bytes(n, 0x00), nonce, ad, pt, sealed));
        CHECK(sealed.empty());
        CHECK(!ascon128aEncrypt(key, Bytes(n, 0x00), ad, pt, sealed));
        CHECK(sealed.empty());

        Bytes opened = filler(3, 0xb7);
        CHECK(!ascon128aDecrypt(Bytes(n, 0x00), nonce, ad, ct, opened));
        CHECK(opened.empty());
        CHECK(!ascon128aDecrypt(key, Bytes(n, 0x00), ad, ct, opened));
        CHECK(opened.empty());
    }
}

void testVerificationStatusStaysHonest() {
    // As in test_spongent.cc: the status string is part of the result record, so
    // it must keep saying what has not been checked.
    const std::string status = asconVerificationStatus();
    CHECK(!status.empty());
    CHECK_MSG(status.find("NOT VERIFIED") != std::string::npos,
              "asconVerificationStatus() no longer states what was not verified");
    CHECK_MSG(status.find("1089") != std::string::npos,
              "asconVerificationStatus() no longer cites the KAT it passes");
    CHECK_MSG(status.find("Ascon-128a v1.2") != std::string::npos,
              "asconVerificationStatus() no longer names the variant");
}

} // namespace

int main() {
    testOfficialVectors();
    testFullKatDigest();
    testRoundTrip();
    testEveryCiphertextCorruptionFails();
    testEveryAdCorruptionFails();
    testWrongKeyAndNonceFail();
    testMalformedInputRejected();
    testVerificationStatusStaysHonest();
    return uavauth::test::summarise("ascon-128a");
}
