// Message::encode() / decodeMessage() round trip.
//
// The in-process transport passes protocol::Message by value and never
// serializes it, so this path was previously untested by construction -- it
// only exists for a real byte-level transport (INET's UDP stack). A broken
// round trip here would surface as a mysterious MAC-verify failure three
// layers away, so it is tested in isolation first.
//
// DEPS: core/Bytes.cc core/Encoding.cc protocol/Wire.cc

#include "core/Bytes.h"
#include "core/Encoding.h"
#include "protocol/Wire.h"
#include "tests/TestUtil.h"

#include <cstdint>
#include <random>

using namespace uavauth::core;
using namespace uavauth::protocol;

namespace {

std::mt19937 rng(20260810u);

Bytes randomBytes(size_t n) {
    Bytes out(n);
    for (size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>(rng() & 0xFF);
    return out;
}

void testRoundTripEachMessageType() {
    const MessageType types[] = {
        MessageType::ENROLL_REQUEST,  MessageType::ENROLL_CHALLENGE,
        MessageType::ENROLL_RESPONSE, MessageType::ENROLL_COMMIT,
        MessageType::P2_M1_AUTH_REQUEST, MessageType::P2_M2_GS_RESPONSE,
        MessageType::P2_M3_UAV_CONFIRM,  MessageType::P2_M4_GS_CONFIRM,
        MessageType::P3_P1_PEER_REQUEST, MessageType::P3_P2_PEER_RESPONSE,
        MessageType::P3_P3_PEER_COMPLETE,
    };
    for (MessageType t : types) {
        Message original;
        original.type = t;
        original.suiteId = 0x02;
        original.senderId = 7;     // not on the wire; decode is told this separately
        original.receiverId = -1;
        original.set(FieldId::TID, randomBytes(16));
        original.set(FieldId::NONCE_1, randomBytes(16));
        original.set(FieldId::MAC_TAG, randomBytes(16));

        const Bytes wire = original.encode();
        const Message decoded = decodeMessage(wire, /*senderId=*/3, /*receiverId=*/9);

        CHECK_EQ(static_cast<int>(decoded.type), static_cast<int>(t));
        CHECK_EQ(static_cast<int>(decoded.suiteId), static_cast<int>(original.suiteId));
        // senderId/receiverId are supplied by the caller at decode time, not
        // recovered from the wire bytes -- verify decode used what it was given,
        // not what the original happened to hold.
        CHECK_EQ(decoded.senderId, 3);
        CHECK_EQ(decoded.receiverId, 9);
        CHECK_EQ(decoded.get(FieldId::TID), original.get(FieldId::TID));
        CHECK_EQ(decoded.get(FieldId::NONCE_1), original.get(FieldId::NONCE_1));
        CHECK_EQ(decoded.get(FieldId::MAC_TAG), original.get(FieldId::MAC_TAG));
        CHECK_EQ(decoded.encode(), wire);   // decode-then-reencode is idempotent
    }
}

void testTagReverseLookupIsExactInverse() {
    const MessageType types[] = {
        MessageType::ENROLL_REQUEST,  MessageType::ENROLL_CHALLENGE,
        MessageType::ENROLL_RESPONSE, MessageType::ENROLL_COMMIT,
        MessageType::P2_M1_AUTH_REQUEST, MessageType::P2_M2_GS_RESPONSE,
        MessageType::P2_M3_UAV_CONFIRM,  MessageType::P2_M4_GS_CONFIRM,
        MessageType::P3_P1_PEER_REQUEST, MessageType::P3_P2_PEER_RESPONSE,
        MessageType::P3_P3_PEER_COMPLETE,
    };
    for (MessageType t : types) {
        MessageType back;
        CHECK(messageTypeFromTag(macTypeTag(t), back));
        CHECK_EQ(static_cast<int>(back), static_cast<int>(t));
    }
}

void testUnrecognizedTagIsRejected() {
    MessageType out;
    CHECK(!messageTypeFromTag(macTypeTag(MessageType::CTRL_ABORT), out));  // 0x7F: never on the wire
    CHECK(!messageTypeFromTag(0xFF, out));
    CHECK(!messageTypeFromTag(0x00, out));

    // A message with an unrecognized tag is exactly what an attacker-forged or
    // corrupted packet looks like -- must fail closed, not decode into garbage.
    Message m;
    m.type = MessageType::P2_M1_AUTH_REQUEST;
    m.set(FieldId::TID, randomBytes(4));
    Bytes wire = m.encode();
    wire[2] = 0xEE;  // clobber the type-tag byte (u8 version, u8 suiteId, u8 typeTag, ...)
    CHECK_THROWS(decodeMessage(wire, 0));
}

void testTruncatedInputThrows() {
    Message m;
    m.type = MessageType::P3_P1_PEER_REQUEST;
    m.set(FieldId::NONCE_1, randomBytes(16));
    const Bytes wire = m.encode();
    for (size_t cut : {size_t{0}, size_t{1}, size_t{2}, wire.size() - 1}) {
        const Bytes truncated(wire.begin(), wire.begin() + static_cast<long>(cut));
        CHECK_THROWS(decodeMessage(truncated, 0));
    }
}

} // namespace

int main() {
    testRoundTripEachMessageType();
    testTagReverseLookupIsExactInverse();
    testUnrecognizedTagIsRejected();
    testTruncatedInputThrows();
    return uavauth::test::summarise("test_wire_roundtrip");
}
