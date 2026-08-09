#ifndef UAVAUTH_PROTOCOL_WIRE_H
#define UAVAUTH_PROTOCOL_WIRE_H

#include "core/Bytes.h"
#include "core/Encoding.h"

#include <cstdint>
#include <string>

namespace uavauth {
namespace protocol {

using core::Bytes;
using core::FieldId;
using core::FieldMap;

/// Message types. The numbering keeps phases in separate hundreds so a message
/// from one phase can never be mistaken for another by value alone.
enum class MessageType : int16_t {
    ENROLL_REQUEST      = 100,   // E1  UAV -> GS
    ENROLL_CHALLENGE    = 101,   // E2  GS  -> UAV
    ENROLL_RESPONSE     = 102,   // E3  UAV -> GS
    ENROLL_COMMIT       = 103,   // E4  GS  -> UAV

    P2_M1_AUTH_REQUEST  = 200,   // M1  UAV -> GS
    P2_M2_GS_RESPONSE   = 201,   // M2  GS  -> UAV
    P2_M3_UAV_CONFIRM   = 202,   // M3  UAV -> GS
    P2_M4_GS_CONFIRM    = 203,   // M4  GS  -> UAV

    P3_P1_PEER_REQUEST  = 300,   // P1  UAV_i -> UAV_j
    P3_P2_PEER_RESPONSE = 301,   // P2  UAV_j -> UAV_i
    P3_P3_PEER_COMPLETE = 302,   // P3  UAV_i -> UAV_j

    CTRL_ABORT          = 900
};

const char* messageTypeName(MessageType t);
const char* messageLabel(MessageType t);   // "e1".."p3", for the results CSV

/// Domain-separation tag mixed into the MAC transcript for each message type.
/// Distinct tags are what stop a token minted for one step being replayed as
/// another (the reflection attack the previous Phase 3 permitted).
uint8_t macTypeTag(MessageType t);

/// Reasons a handler can reject a message. Recorded per exchange so the results
/// show *why* an authentication failed rather than only that it did.
enum class AbortReason : uint8_t {
    None = 0,
    UnknownIdentity,
    StaleTimestamp,
    ReplayedNonce,
    MacVerifyFailed,
    AeadOpenFailed,
    MissingField,
    MalformedField,
    DhFailed,
    FuzzyExtractorFailed,
    NoSuchPeer,
    NotAuthenticated,
    UnexpectedMessage
};
const char* abortReasonName(AbortReason r);

/// Transport-agnostic protocol message.
///
/// Payload is a canonical TLV field map rather than a handful of opaque numbered
/// slots: M1 alone carries four payload fields and the credential package is
/// variable length, and one encoder then serves the wire format, the MAC
/// transcript, and the byte accounting. Reading an absent field throws instead
/// of yielding an empty buffer, which turns a silent MAC-over-nothing bug into a
/// loud error.
struct Message {
    MessageType type = MessageType::CTRL_ABORT;
    uint8_t suiteId = 0;
    int senderId = -1;      // -1 == ground station
    int receiverId = -1;
    uint32_t sessionId = 0;
    FieldMap fields;

    bool has(FieldId id) const;
    const Bytes& get(FieldId id) const;          // throws if absent
    Bytes getOr(FieldId id, const Bytes& fallback) const;
    void set(FieldId id, Bytes value);

    /// Canonical encoding of this message, used both as the wire image and as
    /// the MAC transcript contribution.
    Bytes encode() const;

    /// Exact wire size in bytes. Because it comes from the same encoder the
    /// protocol actually uses, overhead accounting cannot drift from reality.
    size_t wireBytes() const;
};

/// Build the byte string a MAC is computed over: the canonical encoding of a
/// field subset under this message's type tag.
Bytes macInput(uint8_t suiteId, MessageType type, const FieldMap& fields);

/// Helpers for the small fixed-width fields.
Bytes encodeId(int id);
int decodeId(const Bytes& b);
Bytes encodeTimestamp(uint32_t ms);
uint32_t decodeTimestamp(const Bytes& b);

} // namespace protocol
} // namespace uavauth

#endif
