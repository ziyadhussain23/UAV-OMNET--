// Stage-2 gate: the "spongent" crypto profile.
//
// SPONGENT is older than the NIST lightweight-crypto competition, so there is no
// official KAT file for it and the vector table printed in the CHES 2011 paper
// could not be retrieved. The vectors below therefore come from the designers'
// own public-domain reference implementation (Spongent.cpp / Spongent.h from
// https://sites.google.com/site/spongenthash/, obtained through a GitHub mirror
// and compiled with -D_SPONGENT160160016_), which was run against this
// implementation over 1572 random inputs of length 0..130 with zero mismatches.
// The one vector that is independently published -- the designers' own example
// message "Sponge + Present = Spongent" -- is included and also matches a
// third-party listing of the SPONGENT test vectors.
//
// The claim is therefore "agrees with the reference implementation", NOT "passes
// a published KAT". Spongent160::verificationStatus() says so verbatim, and
// testVerificationStatusStaysHonest() below fails if anyone quietly upgrades the
// wording without adding the evidence.
//
// On top of the vectors the permutation is checked structurally (S-box, bit
// permutation, LFSR, bijectivity) and statistically (avalanche, collisions),
// because vector agreement alone would also be satisfied by faithfully copying a
// broken reference.
//
// DEPS: core/Bytes.cc core/Encoding.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/Drbg.cc crypto/spongent/Spongent160.cc crypto/ascon/Ascon128a.cc crypto/SpongentSuite.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/SpongentSuite.h"
#include "crypto/spongent/Spongent160.h"
#include "tests/TestUtil.h"

#include <algorithm>
#include <set>
#include <string>
#include <vector>

using namespace uavauth::core;
using namespace uavauth::crypto;

namespace {

/// Message of `n` bytes 00 01 02 ... (n-1), the shape used for the length sweep.
Bytes countingBytes(size_t n) {
    Bytes m(n);
    for (size_t i = 0; i < n; ++i) m[i] = static_cast<uint8_t>(i);
    return m;
}

// ---------------------------------------------------------------------------
// Vectors from the designers' reference implementation.
// ---------------------------------------------------------------------------

void testReferenceVectors() {
    Spongent160 sponge;

    // The designers' own example message. This is the single value in this file
    // that is independently published rather than only reproduced locally.
    CHECK_HEX_EQ(sponge.hash(fromString("Sponge + Present = Spongent")),
                 "13188a4917ea29e258362c047b9bf00c22b5fe91");

    // Empty input: exercises the unconditional padding block on its own.
    CHECK_HEX_EQ(sponge.hash(Bytes{}), "be201ce0a911807d2e3bcad55eb73f0ed42affa7");

    // Length sweep over the rate (2 bytes) and around block boundaries.
    struct Case {
        size_t len;
        const char* digest;
    };
    static const Case kCases[] = {
        {1, "5343b620b7beb2146f46f3e9fed8709a7703c81e"},
        {2, "98969c7fda598fce99a56948fbda2c17f11b1fc0"},
        {3, "8d2206d094f0d0091cbd425bc387325e3bf0a04a"},
        {4, "bfc939f6952286a728bf7b809b73468aa01d1a63"},
        {15, "95d71cb39dc0367807c2aa1c2c3422b071e591af"},
        {16, "392aa46f1a9469aeec471d86d5587f15b6fa7d72"},
        {17, "03ee620a19df59077797ae10477ce382d1d59e10"},
        {31, "cdfb85bb7bde37d0bf16ad43e355eac80b1e6e14"},
        {32, "e45dc51553acfbf9445c4385dd683ee3ccf9ff6e"},
        {33, "5b3c954784b9b2e1909359dc41b6aaadbee07642"},
        {64, "6ff49069ff03114384b85f1126e1e9b9fa1b6690"},
        {100, "58245b96d39ebb3c113b012a26d3fbb7869e1e0d"},
    };
    for (const Case& c : kCases)
        CHECK_HEX_EQ(sponge.hash(countingBytes(c.len)), c.digest);

    // A 1000-step iterated chain, h_0 = hash(""), h_{i+1} = hash(h_i). One
    // mismatched bit anywhere in the permutation diverges the whole chain, so
    // this covers far more state than the individual vectors do.
    Bytes h = sponge.hash(Bytes{});
    for (int i = 1; i < 1000; ++i) h = sponge.hash(h);
    CHECK_HEX_EQ(h, "c5592b53826b21c0215f5683b3667d3a9624a912");
}

// ---------------------------------------------------------------------------
// Structural checks on the permutation.
// ---------------------------------------------------------------------------

void testSboxIsPermutation() {
    // The PRESENT S-box, as SPONGENT reuses it.
    static const uint8_t kExpected[16] = {0xE, 0xD, 0xB, 0x0, 0x2, 0x1, 0x4, 0xF,
                                          0x7, 0xA, 0x8, 0x5, 0x9, 0xC, 0x3, 0x6};
    bool hit[16] = {false};
    for (uint8_t n = 0; n < 16; ++n) {
        const uint8_t out = raw::spongentSbox(n);
        CHECK_EQ(out, kExpected[n]);
        CHECK(out < 16);
        CHECK_MSG(!hit[out], "S-box output value produced twice");
        hit[out] = true;
    }
    for (int v = 0; v < 16; ++v) CHECK_MSG(hit[v], "S-box misses an output value");

    // A non-injective S-box would collapse state and is the classic typo in a
    // hand-copied table, so also assert it has no fixed-point-only structure:
    // at least one input must move.
    int moved = 0;
    for (uint8_t n = 0; n < 16; ++n)
        if (raw::spongentSbox(n) != n) ++moved;
    CHECK(moved > 0);
}

void testPLayerIsPermutation() {
    // Every one of the 176 destinations must be hit exactly once.
    std::vector<int> timesHit(raw::kSpongentStateBits, 0);
    for (size_t j = 0; j < raw::kSpongentStateBits; ++j) {
        const size_t dst = raw::spongentPLayerIndex(j);
        CHECK(dst < raw::kSpongentStateBits);
        ++timesHit[dst];
    }
    bool allOnce = true;
    for (size_t i = 0; i < timesHit.size(); ++i)
        if (timesHit[i] != 1) allOnce = false;
    CHECK_MSG(allOnce, "pLayer is not a permutation of 0..175");

    // The specified formula: P(j) = (j*44) mod 175, with the top bit fixed.
    CHECK_EQ(raw::spongentPLayerIndex(0), 0u);
    CHECK_EQ(raw::spongentPLayerIndex(1), 44u);
    CHECK_EQ(raw::spongentPLayerIndex(2), 88u);
    CHECK_EQ(raw::spongentPLayerIndex(4), (4u * 44u) % 175u);
    CHECK_EQ(raw::spongentPLayerIndex(174), (174u * 44u) % 175u);
    CHECK_EQ(raw::spongentPLayerIndex(175), 175u);
}

void testLfsrPeriodAndNonZero() {
    // x^7 + x^6 + 1 is primitive, so from the seed 0x45 the counter must cycle
    // through all 127 non-zero 7-bit values before repeating. If it ever reached
    // 0 the round constants would stop varying and the permutation would have
    // 90 identical rounds from that point on.
    const uint8_t seed = raw::kSpongentLfsrInit;
    CHECK(seed != 0);
    CHECK(seed <= 0x7F);

    std::set<uint8_t> seen;
    uint8_t lfsr = seed;
    for (int i = 0; i < 127; ++i) {
        CHECK_MSG(lfsr != 0, "round-constant LFSR reached the zero state");
        CHECK(lfsr <= 0x7F);
        seen.insert(lfsr);
        lfsr = raw::spongentLfsrNext(lfsr);
    }
    CHECK_EQ(seen.size(), 127u);
    CHECK_MSG(lfsr == seed, "round-constant LFSR period is not 127");

    // R = 90 < 127, so no round constant repeats within one permutation.
    CHECK(raw::kSpongentRounds < 127);
}

void testPermutationIsBijection() {
    // A permutation must be injective. Exhaustive proof is out of reach for a
    // 176-bit state, so this samples: distinct random states must give distinct
    // images. (A random non-injective function on 2^176 points would still
    // almost never collide on 4000 samples, so this catches gross structural
    // damage -- e.g. a pLayer that drops a bit -- rather than proving
    // bijectivity. The vector agreement is what pins the exact function.)
    Drbg rng(fromString("spongent-permutation-bijection"));
    std::set<Bytes> inputs;
    std::set<Bytes> images;
    const int kTrials = 4000;
    for (int i = 0; i < kTrials; ++i) {
        Bytes state = rng.bytes(raw::kSpongentStateBytes);
        inputs.insert(state);
        Bytes image = state;
        raw::spongentPermute(image.data());
        CHECK_EQ(image.size(), raw::kSpongentStateBytes);
        images.insert(image);
    }
    CHECK_EQ(inputs.size(), static_cast<size_t>(kTrials));
    CHECK_MSG(images.size() == inputs.size(),
              "distinct states collided under the permutation");

    // The all-zero state must not be a fixed point: the round constants exist
    // precisely to break that symmetry.
    Bytes zero(raw::kSpongentStateBytes, 0x00);
    Bytes permutedZero = zero;
    raw::spongentPermute(permutedZero.data());
    CHECK(permutedZero != zero);

    // And the permutation must be deterministic.
    Bytes again = zero;
    raw::spongentPermute(again.data());
    CHECK(again == permutedZero);
}

// ---------------------------------------------------------------------------
// Statistical checks.
// ---------------------------------------------------------------------------

void testAvalanche() {
    // Flipping one input bit should change about half the output bits.
    //
    // The mean over all trials is what carries the 35-65% requirement. A
    // per-trial 35-65% bound would be a flaky assertion, not a strict one: the
    // change count is ~Binomial(160, 1/2) with sd 6.3 bits, so 35% and 65% sit
    // only 3.8 sd out and a clean implementation would breach them roughly once
    // every 3500 trials. The per-trial bound is therefore set at 20-80%
    // (~10 sd), which no correct implementation will ever hit but a broken one
    // -- say a permutation that leaves a byte untouched -- will.
    Spongent160 sponge;
    Drbg rng(fromString("spongent-avalanche"));

    const int kTrials = 1000;
    const size_t kOutBits = 160;
    size_t totalChanged = 0;
    int outsideLoose = 0;
    size_t minChanged = kOutBits;
    size_t maxChanged = 0;

    for (int t = 0; t < kTrials; ++t) {
        Bytes msg = rng.bytes(8);
        const size_t bit = rng.uniform(static_cast<uint32_t>(msg.size() * 8));
        Bytes flipped = msg;
        setBit(flipped, bit, !getBit(flipped, bit));
        CHECK(flipped != msg);

        const size_t changed = hammingDistance(sponge.hash(msg), sponge.hash(flipped));
        totalChanged += changed;
        minChanged = std::min(minChanged, changed);
        maxChanged = std::max(maxChanged, changed);
        const double fraction = static_cast<double>(changed) / kOutBits;
        if (fraction < 0.20 || fraction > 0.80) ++outsideLoose;
    }

    const double mean = static_cast<double>(totalChanged) / (kTrials * kOutBits);
    CHECK_MSG(mean >= 0.35 && mean <= 0.65, "mean avalanche outside 35-65%");
    CHECK_MSG(outsideLoose == 0, "an individual trial changed <20% or >80% of bits");
    // No trial may leave the digest untouched or invert it wholesale.
    CHECK(minChanged > 0);
    CHECK(maxChanged < kOutBits);
}

void testNoCollisions() {
    // 100k distinct inputs, no colliding digest.
    //
    // The inputs are a 4-byte counter followed by 4 random bytes, so they are
    // distinct *by construction*. With 8 purely random bytes about one duplicate
    // input would be expected per 100k draws at this scale, and a duplicate input
    // would be misreported as a hash collision.
    //
    // Cost note: this is the slowest check in the file (~5 s), because it is
    // 100k * 14 permutations. It is why the pLayer is table-driven.
    Spongent160 sponge;
    Drbg rng(fromString("spongent-collisions"));

    const int kInputs = 100000;
    std::set<Bytes> digests;
    for (int i = 0; i < kInputs; ++i) {
        Bytes msg = u32be(static_cast<uint32_t>(i));
        append(msg, rng.bytes(4));
        Bytes digest = sponge.hash(msg);
        CHECK_EQ(digest.size(), 20u);
        digests.insert(digest);
    }
    CHECK_MSG(digests.size() == static_cast<size_t>(kInputs),
              "collision among 100k distinct inputs");
}

void testDeterminismAndOutputLength() {
    Spongent160 sponge;
    const Bytes msg = fromString("determinism");

    CHECK_EQ(sponge.hash(msg).size(), 20u);
    CHECK(sponge.hash(msg) == sponge.hash(msg));
    CHECK(sponge.hash(msg) != sponge.hash(fromString("determinisn")));

    // hash() is exactly the sponge squeezed to 20 bytes.
    CHECK(sponge.hash(msg) == sponge.spongeAbsorbSqueeze(msg, 20));

    // Arbitrary output lengths, including 0 and lengths that are not a multiple
    // of the 2-byte rate.
    CHECK_EQ(sponge.spongeAbsorbSqueeze(msg, 0).size(), 0u);
    CHECK_EQ(sponge.spongeAbsorbSqueeze(msg, 1).size(), 1u);
    CHECK_EQ(sponge.spongeAbsorbSqueeze(msg, 17).size(), 17u);
    CHECK_EQ(sponge.spongeAbsorbSqueeze(msg, 64).size(), 64u);

    // Squeezing is a stream, so a short output IS a prefix of a longer one. This
    // is a property of the bare sponge, recorded here because it is exactly the
    // reason SpongentSuite::kdf() has to absorb the output length -- see
    // testKdfOutputLengthIsBound().
    const Bytes short16 = sponge.spongeAbsorbSqueeze(msg, 16);
    const Bytes long40 = sponge.spongeAbsorbSqueeze(msg, 40);
    CHECK(std::equal(short16.begin(), short16.end(), long40.begin()));

    // The padding is unconditional, so a message and that message plus a byte
    // that "looks like" padding must not collide.
    Bytes padded = msg;
    padded.push_back(0x80);
    CHECK(sponge.hash(msg) != sponge.hash(padded));
}

// ---------------------------------------------------------------------------
// Suite-level behaviour.
// ---------------------------------------------------------------------------

void testSuiteParameters() {
    SpongentSuite suite;
    CHECK_EQ(std::string(suite.name()), std::string("spongent"));
    CHECK(suite.id() == SuiteId::SPONGENT);
    CHECK_EQ(suite.hashLen(), 20u);
    CHECK_EQ(suite.macLen(), 16u);
    CHECK_EQ(suite.keyLen(), 32u);
    CHECK_EQ(suite.aeadKeyLen(), 16u);     // Ascon-128a, not ChaCha20's 32
    CHECK_EQ(suite.aeadNonceLen(), 16u);   // Ascon-128a, not ChaCha20's 12
    CHECK_EQ(suite.aeadTagLen(), 16u);
    // 80, not 128: capacity 160 => c/2. Recording the weaker number is the whole
    // point of having a second profile.
    CHECK_EQ(suite.securityLevelBits(), 80);

    // implTag must name a vendored implementation, so a reader cannot mistake
    // these timings for OpenSSL-optimised ones.
    CHECK(suite.implTag(Primitive::Hash160) == "spongent160-176-16/vendored");
    CHECK(suite.implTag(Primitive::Mac) == "keyed-sponge-spongent160/vendored");
    CHECK(suite.implTag(Primitive::MacVerify) == "keyed-sponge-spongent160/vendored");
    CHECK(suite.implTag(Primitive::Kdf).find("spongent160") != std::string::npos);
    CHECK(suite.implTag(Primitive::AeadSeal) == "ascon128a-v12/vendored");
    CHECK(suite.implTag(Primitive::AeadOpen) == "ascon128a-v12/vendored");
    CHECK(suite.implTag(Primitive::PufEval).find("vendored") != std::string::npos);
}

void testHash160DomainSeparation() {
    SpongentSuite suite;
    Spongent160 sponge;
    const Bytes msg = fromString("protocol message");

    CHECK_EQ(suite.hash160(msg).size(), 20u);
    CHECK(suite.hash160(msg) == suite.hash160(msg));

    // The protocol hash must not be the bare primitive. Unlike the sha3 profile
    // there is no truncation involved -- SPONGENT-160 already emits 160 bits --
    // so without the domain byte and length prefix h(.) would literally *be* the
    // raw digest, and a raw digest computed anywhere else could be replayed as
    // an h(.) value.
    CHECK(suite.hash160(msg) != sponge.hash(msg));

    // Distinct messages, distinct digests (and the length prefix means a message
    // cannot be re-cut into a different one).
    CHECK(suite.hash160(fromString("ab")) != suite.hash160(fromString("ba")));
    // Note Bytes{0x00} rather than fromString("\x00"): the latter goes through
    // std::string(const char*), which stops at the NUL and yields an empty
    // string, so it would compare the empty message against itself.
    CHECK(suite.hash160(Bytes{}) != suite.hash160(Bytes{0x00}));
}

void testMac() {
    SpongentSuite suite;
    const Bytes key = fromHex("000102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f");
    const Bytes msg = fromString("protocol message");

    const Bytes tag = suite.mac(key, msg);
    CHECK_EQ(tag.size(), 16u);
    CHECK(suite.macVerify(key, msg, tag));
    CHECK(tag == suite.mac(key, msg));

    // Every single-bit flip of the tag must be rejected.
    int accepted = 0;
    for (size_t bit = 0; bit < tag.size() * 8; ++bit) {
        Bytes bad = tag;
        bad[bit / 8] = static_cast<uint8_t>(bad[bit / 8] ^ (1u << (bit % 8)));
        if (suite.macVerify(key, msg, bad)) ++accepted;
    }
    CHECK_MSG(accepted == 0, "flipped MAC tag accepted");

    // Every single-bit flip of the message must be rejected under the old tag.
    accepted = 0;
    for (size_t bit = 0; bit < msg.size() * 8; ++bit) {
        Bytes bad = msg;
        bad[bit / 8] = static_cast<uint8_t>(bad[bit / 8] ^ (1u << (bit % 8)));
        if (suite.macVerify(key, bad, tag)) ++accepted;
    }
    CHECK_MSG(accepted == 0, "flipped message accepted under original tag");

    // Every single-bit flip of the key must be rejected.
    accepted = 0;
    for (size_t bit = 0; bit < key.size() * 8; ++bit) {
        Bytes bad = key;
        bad[bit / 8] = static_cast<uint8_t>(bad[bit / 8] ^ (1u << (bit % 8)));
        if (suite.macVerify(bad, msg, tag)) ++accepted;
    }
    CHECK_MSG(accepted == 0, "flipped key accepted");

    // A truncated or over-long tag is a length mismatch, not a prefix match.
    CHECK(!suite.macVerify(key, msg, Bytes(tag.begin(), tag.end() - 1)));
    Bytes longer = tag;
    longer.push_back(0x00);
    CHECK(!suite.macVerify(key, msg, longer));
    CHECK(!suite.macVerify(key, msg, Bytes{}));

    // The key is length-prefixed, so (key, message) cannot be re-cut: these two
    // calls absorb the same concatenation only if the prefix is missing.
    CHECK(suite.mac(fromString("ab"), fromString("c")) !=
          suite.mac(fromString("a"), fromString("bc")));

    // Keys of unusual lengths are accepted -- the keyed sponge has no block-size
    // constraint, which is the reason it is used instead of HMAC.
    CHECK_EQ(suite.mac(Bytes{}, msg).size(), 16u);
    CHECK_EQ(suite.mac(Bytes(1, 0x5a), msg).size(), 16u);
    CHECK_EQ(suite.mac(Bytes(1000, 0x5a), msg).size(), 16u);
    CHECK(suite.mac(Bytes{}, msg) != suite.mac(Bytes(1, 0x00), msg));

    // The MAC must not be the plain hash of key || message.
    Spongent160 sponge;
    Bytes naive = sponge.hash(concat({key, msg}));
    naive.resize(16);
    CHECK(tag != naive);
}

void testKdfLabelsAndLengths() {
    SpongentSuite suite;
    const Bytes ikm = fromHex("aabbccddeeff00112233445566778899"
                              "aabbccddeeff00112233445566778899");
    const Bytes salt = fromHex("0011223344556677");

    const Bytes k1 = suite.kdf(ikm, salt, label::kP2Auth, Bytes{}, 32);
    const Bytes k2 = suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 32);
    const Bytes k3 = suite.kdf(ikm, salt, label::kPeerAuth, Bytes{}, 32);
    CHECK_EQ(k1.size(), 32u);
    CHECK(k1 != k2);
    CHECK(k1 != k3);
    CHECK(k2 != k3);
    CHECK(k1 == suite.kdf(ikm, salt, label::kP2Auth, Bytes{}, 32));

    // Distinct info values give independent keys: this is what separates the
    // per-pair credentials from one another.
    const Bytes c01 = suite.kdf(ikm, salt, label::kPairCred, fromHex("00000001"), 32);
    const Bytes c02 = suite.kdf(ikm, salt, label::kPairCred, fromHex("00000002"), 32);
    CHECK(c01 != c02);

    // Salt and ikm both matter.
    CHECK(k1 != suite.kdf(ikm, fromHex("1111111111111111"), label::kP2Auth, Bytes{}, 32));
    CHECK(k1 != suite.kdf(fromHex("00"), salt, label::kP2Auth, Bytes{}, 32));

    // Fields are length-prefixed, so moving a byte between adjacent fields
    // changes the derived key rather than producing the same absorbed string.
    CHECK(suite.kdf(fromString("ab"), fromString("c"), label::kP2Auth, Bytes{}, 32) !=
          suite.kdf(fromString("a"), fromString("bc"), label::kP2Auth, Bytes{}, 32));
}

void testKdfOutputLengthIsBound() {
    // The load-bearing difference from HKDF. Squeezing is a stream, so if the
    // requested length were not absorbed, kdf(...,16) would be the exact prefix
    // of kdf(...,32) and a protocol using both for different purposes would be
    // issuing related keys. testDeterminismAndOutputLength() shows the bare
    // sponge really does have that prefix property, so this is not a vacuous
    // check.
    SpongentSuite suite;
    const Bytes ikm = fromHex("aabbccddeeff00112233445566778899");
    const Bytes salt = fromHex("0011223344556677");

    const Bytes k16 = suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 16);
    const Bytes k32 = suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 32);
    CHECK_EQ(k16.size(), 16u);
    CHECK_EQ(k32.size(), 32u);
    CHECK_MSG(!std::equal(k16.begin(), k16.end(), k32.begin()),
              "16-byte KDF output is a prefix of the 32-byte one");

    // Same for a couple of other length pairs, so the property does not hold by
    // accident for one particular size.
    const Bytes k20 = suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 20);
    const Bytes k40 = suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 40);
    CHECK(!std::equal(k20.begin(), k20.end(), k40.begin()));
    CHECK(!std::equal(k16.begin(), k16.end(), k20.begin()));

    // The length is absorbed as a u16be, so lengths that would wrap it must be
    // refused rather than aliased onto a shorter request.
    CHECK_EQ(suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 0xFFFF).size(), 0xFFFFu);
    CHECK_THROWS(suite.kdf(ikm, salt, label::kP2Sess, Bytes{}, 0x10000));
}

void testExtract() {
    SpongentSuite suite;
    const Bytes salt = fromHex("0011223344556677");
    const Bytes source = fromHex("aabbccddeeff00112233445566778899");

    const Bytes e1 = suite.extract(salt, source);
    CHECK_EQ(e1.size(), 32u);
    CHECK(e1 == suite.extract(salt, source));
    CHECK(e1 != suite.extract(fromHex("1111111111111111"), source));
    CHECK(e1 != suite.extract(salt, fromHex("aabbccddeeff00112233445566778890")));

    // extract() is the KDF under the fe-extract label, so it must equal that
    // call and differ from every other label.
    CHECK(e1 == suite.kdf(source, salt, label::kFeExtract, Bytes{}, 32));
    CHECK(e1 != suite.kdf(source, salt, label::kFeRoot, Bytes{}, 32));
    CHECK(e1 != suite.kdf(source, salt, label::kP2Sess, Bytes{}, 32));
}

void testAeadThroughSuite() {
    // Ascon itself is exercised in test_ascon.cc; this checks the suite's
    // wiring, in particular that it enforces Ascon's 16-byte key and nonce
    // rather than the sha3 profile's 32/12.
    SpongentSuite suite;
    Drbg rng(fromString("spongent-aead"));
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

    // Tampering must fail and must not release plaintext.
    Bytes bad = ct;
    bad[0] = static_cast<uint8_t>(bad[0] ^ 0x01);
    CHECK(!suite.aeadOpen(key, nonce, aad, bad, out));
    CHECK(out.empty());

    Bytes badAad = aad;
    badAad[0] = static_cast<uint8_t>(badAad[0] ^ 0x80);
    CHECK(!suite.aeadOpen(key, nonce, badAad, ct, out));
    CHECK(out.empty());

    // Wrong key/nonce *lengths* are rejected rather than silently padded: a
    // 32-byte key is valid for the sha3 profile and must not be accepted here.
    CHECK(!suite.aeadSeal(Bytes(32, 0), nonce, aad, pt, ct));
    CHECK(ct.empty());
    CHECK(!suite.aeadOpen(key, Bytes(12, 0), aad, ct, out));
    CHECK(out.empty());
}

void testCountersPopulated() {
    SpongentSuite suite;
    const Bytes key(32, 0x5a);
    const Bytes msg = fromString("counters");

    suite.hash160(msg);
    const Bytes tag = suite.mac(key, msg);
    suite.macVerify(key, msg, tag);
    suite.kdf(key, Bytes{}, label::kP2Sess, Bytes{}, 32);
    suite.extract(Bytes{}, key);
    Bytes ct, pt;
    suite.aeadSeal(Bytes(16, 1), Bytes(16, 2), Bytes{}, msg, ct);
    suite.aeadOpen(Bytes(16, 1), Bytes(16, 2), Bytes{}, ct, pt);

    CHECK(suite.counters().get(Primitive::Hash160).calls > 0);
    CHECK(suite.counters().get(Primitive::Mac).calls > 0);
    CHECK(suite.counters().get(Primitive::MacVerify).calls > 0);
    CHECK(suite.counters().get(Primitive::Kdf).calls > 0);
    CHECK(suite.counters().get(Primitive::Extract).calls > 0);
    CHECK(suite.counters().get(Primitive::AeadSeal).calls > 0);
    CHECK(suite.counters().get(Primitive::AeadOpen).calls > 0);
    CHECK(suite.counters().totalMs() >= 0.0);

    // extract() must charge Extract only, not Kdf as well: it shares kdfRaw()
    // with kdf() precisely so a nested ScopedTimer cannot double-count.
    SpongentSuite fresh;
    fresh.extract(Bytes{}, key);
    CHECK_EQ(fresh.counters().get(Primitive::Extract).calls, 1u);
    CHECK_EQ(fresh.counters().get(Primitive::Kdf).calls, 0u);
}

void testVerificationStatusStaysHonest() {
    // A guard against the failure mode this file exists to prevent: someone
    // reading "verified" and quietly deleting the caveat. If the verification
    // evidence genuinely improves -- say the CHES 2011 table is obtained -- these
    // assertions should be updated in the same commit that adds the new vectors.
    const std::string status = Spongent160::verificationStatus();
    CHECK(!status.empty());
    CHECK_MSG(status.find("NOT VERIFIED") != std::string::npos,
              "verificationStatus() no longer states what was not verified");
    CHECK_MSG(status.find("reference") != std::string::npos,
              "verificationStatus() no longer credits the reference implementation");
    CHECK_MSG(status.find("SPONGENT-160/160/16") != std::string::npos,
              "verificationStatus() no longer names the variant");
}

} // namespace

int main() {
    testReferenceVectors();
    testSboxIsPermutation();
    testPLayerIsPermutation();
    testLfsrPeriodAndNonZero();
    testPermutationIsBijection();
    testAvalanche();
    testNoCollisions();
    testDeterminismAndOutputLength();
    testSuiteParameters();
    testHash160DomainSeparation();
    testMac();
    testKdfLabelsAndLengths();
    testKdfOutputLengthIsBound();
    testExtract();
    testAeadThroughSuite();
    testCountersPopulated();
    testVerificationStatusStaysHonest();
    return uavauth::test::summarise("spongent-suite");
}
