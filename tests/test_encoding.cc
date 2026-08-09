// Stage-1 gate: canonical TLV encoding.
//
// The encoded byte string is simultaneously the wire format, the MAC input, and
// the byte count that drives link delay, so it must be injective (no two field
// sets share an encoding) and canonical (each field set has exactly one).
//
// DEPS: core/Bytes.cc core/Encoding.cc

#include "core/Bytes.h"
#include "core/Encoding.h"
#include "tests/TestUtil.h"

#include <cstdint>
#include <random>
#include <set>
#include <string>

using namespace uavauth::core;

namespace {

std::mt19937 rng(20260809u);

Bytes randomBytes(size_t n) {
    Bytes out(n);
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(rng() & 0xFF);
    return out;
}

const FieldId kAllTags[] = {
    FieldId::TID,        FieldId::TID_NEW,    FieldId::NONCE_1,    FieldId::NONCE_2,
    FieldId::TIMESTAMP,  FieldId::EPK_A,      FieldId::EPK_B,      FieldId::MAC_TAG,
    FieldId::CRED_PKG,   FieldId::AEAD_NONCE, FieldId::SENDER_ID,  FieldId::RECEIVER_ID,
    FieldId::HELPER_S,   FieldId::HELPER_SEED};

void testByteHelpers() {
    CHECK_HEX_EQ(u16be(0x0102), "0102");
    CHECK_HEX_EQ(u32be(0xDEADBEEF), "deadbeef");
    CHECK_EQ(readU16be(fromHex("0102"), 0), 0x0102u);
    CHECK_EQ(readU32be(fromHex("deadbeef"), 0), 0xDEADBEEFu);

    CHECK_HEX_EQ(xorBytes(fromHex("f0f0"), fromHex("0ff0")), "ff00");
    CHECK_THROWS(xorBytes(fromHex("f0"), fromHex("f0f0")));

    CHECK(ctEqual(fromHex("aabb"), fromHex("aabb")));
    CHECK(!ctEqual(fromHex("aabb"), fromHex("aabc")));
    CHECK(!ctEqual(fromHex("aabb"), fromHex("aa")));

    // Round-trip hex.
    const Bytes r = randomBytes(64);
    CHECK(fromHex(toHex(r)) == r);

    // Bit access is MSB-first: bit 0 is the top bit of byte 0.
    Bytes bits(2, 0x00);
    setBit(bits, 0, true);
    CHECK_HEX_EQ(bits, "8000");
    setBit(bits, 15, true);
    CHECK_HEX_EQ(bits, "8001");
    CHECK(getBit(bits, 0));
    CHECK(getBit(bits, 15));
    CHECK(!getBit(bits, 1));
    CHECK_EQ(popcount(bits), 2u);

    CHECK_EQ(hammingDistance(fromHex("00"), fromHex("ff")), 8u);
    CHECK_EQ(hammingDistance(fromHex("0f"), fromHex("0e")), 1u);
    CHECK_EQ(bytesForBits(255), 32u);
    CHECK_EQ(bytesForBits(256), 32u);
    CHECK_EQ(bytesForBits(257), 33u);

    Bytes secret = fromHex("0123456789abcdef");
    secureZero(secret);
    CHECK_EQ(popcount(secret), 0u);
}

void testRoundTrip() {
    for (int trial = 0; trial < 10000; ++trial) {
        FieldMap fields;
        const int numFields = 1 + static_cast<int>(rng() % 8);
        for (int f = 0; f < numFields; ++f) {
            const FieldId tag = kAllTags[rng() % (sizeof(kAllTags) / sizeof(kAllTags[0]))];
            fields[tag] = randomBytes(rng() % 40);
        }
        const uint8_t suite = static_cast<uint8_t>(1 + (rng() % 2));
        const uint8_t type = static_cast<uint8_t>(rng() & 0xFF);

        const Bytes encoded = encodeFields(suite, type, fields);
        const DecodedFields decoded = decodeFields(encoded);

        CHECK_EQ(decoded.suiteId, suite);
        CHECK_EQ(decoded.typeTag, type);
        CHECK(decoded.fields == fields);
    }
}

void testInjectivity() {
    // No two distinct (suite, type, fields) triples may share an encoding.
    std::set<std::string> seen;
    int collisions = 0;
    for (int trial = 0; trial < 10000; ++trial) {
        FieldMap fields;
        const int numFields = 1 + static_cast<int>(rng() % 4);
        for (int f = 0; f < numFields; ++f)
            fields[kAllTags[rng() % 6]] = randomBytes(rng() % 8);
        const uint8_t type = static_cast<uint8_t>(rng() % 4);

        const std::string encoded = toHex(encodeFields(0x01, type, fields));
        // Distinct semantic key for the same content.
        std::string key = std::to_string(type);
        for (const auto& e : fields)
            key += "|" + std::to_string(static_cast<int>(e.first)) + ":" + toHex(e.second);

        static std::set<std::string> byEncoding;
        static std::set<std::string> byKey;
        const bool newEncoding = byEncoding.insert(encoded).second;
        const bool newKey = byKey.insert(key).second;
        if (newEncoding != newKey) ++collisions;
        (void)seen;
    }
    CHECK_MSG(collisions == 0, "distinct field sets produced identical encodings");

    // A concrete near-miss that a naive concatenation would confuse:
    // {TID="ab", NONCE_1=""} vs {TID="", NONCE_1="ab"} must differ.
    FieldMap a{{FieldId::TID, fromHex("ab")}, {FieldId::NONCE_1, Bytes{}}};
    FieldMap b{{FieldId::TID, Bytes{}}, {FieldId::NONCE_1, fromHex("ab")}};
    CHECK(encodeFields(1, 0x11, a) != encodeFields(1, 0x11, b));

    // Same fields, different message type tags must differ (blocks cross-step replay).
    FieldMap c{{FieldId::NONCE_1, fromHex("00112233")}};
    CHECK(encodeFields(1, 0x21, c) != encodeFields(1, 0x23, c));

    // Same fields, different suite ids must differ (blocks cross-suite confusion).
    CHECK(encodeFields(1, 0x11, c) != encodeFields(2, 0x11, c));
}

void testCanonicalRejection() {
    FieldMap fields{{FieldId::TID, fromHex("aabb")}, {FieldId::NONCE_1, fromHex("ccdd")}};
    const Bytes good = encodeFields(0x01, 0x11, fields);
    CHECK(decodeFields(good).fields.size() == 2);

    // Truncated body.
    Bytes truncated(good.begin(), good.end() - 1);
    CHECK_THROWS(decodeFields(truncated));

    // Trailing garbage.
    Bytes trailing = good;
    trailing.push_back(0x00);
    CHECK_THROWS(decodeFields(trailing));

    // Wrong protocol version.
    Bytes badVersion = good;
    badVersion[0] = 0x02;
    CHECK_THROWS(decodeFields(badVersion));

    // Hand-built descending tag order must be rejected as non-canonical.
    Bytes descending;
    descending.push_back(kProtoVersion);
    descending.push_back(0x01);
    descending.push_back(0x11);
    append(descending, u16be(2));
    descending.push_back(static_cast<uint8_t>(FieldId::NONCE_1)); // 0x03 first
    append(descending, u16be(1));
    descending.push_back(0xAA);
    descending.push_back(static_cast<uint8_t>(FieldId::TID));     // 0x01 second
    append(descending, u16be(1));
    descending.push_back(0xBB);
    CHECK_THROWS(decodeFields(descending));

    // Duplicate tags must be rejected.
    Bytes duplicate;
    duplicate.push_back(kProtoVersion);
    duplicate.push_back(0x01);
    duplicate.push_back(0x11);
    append(duplicate, u16be(2));
    for (int i = 0; i < 2; ++i) {
        duplicate.push_back(static_cast<uint8_t>(FieldId::TID));
        append(duplicate, u16be(1));
        duplicate.push_back(0xAA);
    }
    CHECK_THROWS(decodeFields(duplicate));
}

void testLengthPrefixAndTranscript() {
    CHECK_HEX_EQ(lengthPrefixed(fromHex("aabb")), "0002aabb");
    CHECK_HEX_EQ(lengthPrefixed(std::string("abc")), "0003616263");

    // Length prefixing removes the classic concatenation ambiguity:
    // ("ab","c") and ("a","bc") must encode differently.
    CHECK(concat({lengthPrefixed(fromString("ab")), lengthPrefixed(fromString("c"))}) !=
          concat({lengthPrefixed(fromString("a")), lengthPrefixed(fromString("bc"))}));

    Transcript t;
    CHECK_EQ(t.size(), 0u);
    const Bytes m1 = encodeFields(1, 0x11, {{FieldId::NONCE_1, randomBytes(16)}});
    const Bytes m2 = encodeFields(1, 0x12, {{FieldId::NONCE_2, randomBytes(16)}});
    t.append(m1);
    t.append(m2);
    CHECK_EQ(t.size(), m1.size() + m2.size());
    CHECK(t.bytes() == concat({m1, m2}));
    t.clear();
    CHECK_EQ(t.size(), 0u);
}

void testEmptyAndLargeFields() {
    FieldMap empty;
    const Bytes e = encodeFields(1, 0x00, empty);
    CHECK_EQ(e.size(), 5u); // version + suite + type + count
    CHECK_EQ(decodeFields(e).fields.size(), 0u);

    FieldMap big{{FieldId::CRED_PKG, randomBytes(4096)}};
    const Bytes b = encodeFields(1, 0x14, big);
    CHECK_EQ(b.size(), 5u + 3u + 4096u);
    CHECK(decodeFields(b).fields == big);
}

} // namespace

int main() {
    testByteHelpers();
    testRoundTrip();
    testInjectivity();
    testCanonicalRejection();
    testLengthPrefixAndTranscript();
    testEmptyAndLargeFields();
    return uavauth::test::summarise("encoding");
}
