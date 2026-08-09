#include "protocol/Wire.h"

#include <stdexcept>

namespace uavauth {
namespace protocol {

const char* messageTypeName(MessageType t) {
    switch (t) {
        case MessageType::ENROLL_REQUEST:      return "ENROLL_REQUEST";
        case MessageType::ENROLL_CHALLENGE:    return "ENROLL_CHALLENGE";
        case MessageType::ENROLL_RESPONSE:     return "ENROLL_RESPONSE";
        case MessageType::ENROLL_COMMIT:       return "ENROLL_COMMIT";
        case MessageType::P2_M1_AUTH_REQUEST:  return "P2_M1_AUTH_REQUEST";
        case MessageType::P2_M2_GS_RESPONSE:   return "P2_M2_GS_RESPONSE";
        case MessageType::P2_M3_UAV_CONFIRM:   return "P2_M3_UAV_CONFIRM";
        case MessageType::P2_M4_GS_CONFIRM:    return "P2_M4_GS_CONFIRM";
        case MessageType::P3_P1_PEER_REQUEST:  return "P3_P1_PEER_REQUEST";
        case MessageType::P3_P2_PEER_RESPONSE: return "P3_P2_PEER_RESPONSE";
        case MessageType::P3_P3_PEER_COMPLETE: return "P3_P3_PEER_COMPLETE";
        case MessageType::CTRL_ABORT:          return "CTRL_ABORT";
    }
    return "UNKNOWN";
}

const char* messageLabel(MessageType t) {
    switch (t) {
        case MessageType::ENROLL_REQUEST:      return "e1";
        case MessageType::ENROLL_CHALLENGE:    return "e2";
        case MessageType::ENROLL_RESPONSE:     return "e3";
        case MessageType::ENROLL_COMMIT:       return "e4";
        case MessageType::P2_M1_AUTH_REQUEST:  return "m1";
        case MessageType::P2_M2_GS_RESPONSE:   return "m2";
        case MessageType::P2_M3_UAV_CONFIRM:   return "m3";
        case MessageType::P2_M4_GS_CONFIRM:    return "m4";
        case MessageType::P3_P1_PEER_REQUEST:  return "p1";
        case MessageType::P3_P2_PEER_RESPONSE: return "p2";
        case MessageType::P3_P3_PEER_COMPLETE: return "p3";
        case MessageType::CTRL_ABORT:          return "abort";
    }
    return "unknown";
}

uint8_t macTypeTag(MessageType t) {
    switch (t) {
        case MessageType::ENROLL_REQUEST:      return 0x01;
        case MessageType::ENROLL_CHALLENGE:    return 0x02;
        case MessageType::ENROLL_RESPONSE:     return 0x03;
        case MessageType::ENROLL_COMMIT:       return 0x04;
        case MessageType::P2_M1_AUTH_REQUEST:  return 0x11;
        case MessageType::P2_M2_GS_RESPONSE:   return 0x12;
        case MessageType::P2_M3_UAV_CONFIRM:   return 0x13;
        case MessageType::P2_M4_GS_CONFIRM:    return 0x14;
        case MessageType::P3_P1_PEER_REQUEST:  return 0x21;
        case MessageType::P3_P2_PEER_RESPONSE: return 0x22;
        case MessageType::P3_P3_PEER_COMPLETE: return 0x23;
        case MessageType::CTRL_ABORT:          return 0x7F;
    }
    return 0xFF;
}

const char* abortReasonName(AbortReason r) {
    switch (r) {
        case AbortReason::None:                 return "none";
        case AbortReason::UnknownIdentity:      return "unknown_identity";
        case AbortReason::StaleTimestamp:       return "stale_timestamp";
        case AbortReason::ReplayedNonce:        return "replayed_nonce";
        case AbortReason::MacVerifyFailed:      return "mac_verify_failed";
        case AbortReason::AeadOpenFailed:       return "aead_open_failed";
        case AbortReason::MissingField:         return "missing_field";
        case AbortReason::MalformedField:       return "malformed_field";
        case AbortReason::DhFailed:             return "dh_failed";
        case AbortReason::FuzzyExtractorFailed: return "fuzzy_extractor_failed";
        case AbortReason::NoSuchPeer:           return "no_such_peer";
        case AbortReason::NotAuthenticated:     return "not_authenticated";
        case AbortReason::UnexpectedMessage:    return "unexpected_message";
    }
    return "unknown";
}

bool Message::has(FieldId id) const { return fields.find(id) != fields.end(); }

const Bytes& Message::get(FieldId id) const {
    const auto it = fields.find(id);
    if (it == fields.end())
        throw std::runtime_error(std::string("Message::get: missing field ") +
                                 core::fieldName(id) + " on " + messageTypeName(type));
    return it->second;
}

Bytes Message::getOr(FieldId id, const Bytes& fallback) const {
    const auto it = fields.find(id);
    return it == fields.end() ? fallback : it->second;
}

void Message::set(FieldId id, Bytes value) { fields[id] = std::move(value); }

Bytes Message::encode() const {
    return core::encodeFields(suiteId, macTypeTag(type), fields);
}

size_t Message::wireBytes() const { return encode().size(); }

Bytes macInput(uint8_t suiteId, MessageType type, const FieldMap& fields) {
    return core::encodeFields(suiteId, macTypeTag(type), fields);
}

Bytes encodeId(int id) {
    // Ground station is -1 on the wire; encode as 0xFFFF.
    const uint16_t v = (id < 0) ? 0xFFFFu : static_cast<uint16_t>(id);
    return core::u16be(v);
}

int decodeId(const Bytes& b) {
    if (b.size() != 2) throw std::runtime_error("decodeId: expected 2 bytes");
    const uint16_t v = core::readU16be(b, 0);
    return (v == 0xFFFFu) ? -1 : static_cast<int>(v);
}

Bytes encodeTimestamp(uint32_t ms) { return core::u32be(ms); }

uint32_t decodeTimestamp(const Bytes& b) {
    if (b.size() != 4) throw std::runtime_error("decodeTimestamp: expected 4 bytes");
    return core::readU32be(b, 0);
}

} // namespace protocol
} // namespace uavauth
