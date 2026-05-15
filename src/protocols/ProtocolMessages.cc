#include "ProtocolMessages.h"

namespace uavauth {
namespace protocols {

ProtocolMessage::ProtocolMessage(const char* name, MessageType msgType)
    : cMessage(name, static_cast<short>(msgType)),
      type(msgType),
      senderId(-1),
      receiverId(-1),
      timestamp(0),
            sentAtUs(0),
            metricA(0.0),
            metricB(0.0),
            metricC(0.0),
            metricD(0.0),
      success(false) {}

ProtocolMessage::ProtocolMessage(const ProtocolMessage& other)
    : cMessage(other) {
    copyFrom(other);
}

ProtocolMessage& ProtocolMessage::operator=(const ProtocolMessage& other) {
    if (this == &other) {
        return *this;
    }
    cMessage::operator=(other);
    copyFrom(other);
    return *this;
}

ProtocolMessage* ProtocolMessage::dup() const {
    return new ProtocolMessage(*this);
}

void ProtocolMessage::copyFrom(const ProtocolMessage& other) {
    type = other.type;
    senderId = other.senderId;
    receiverId = other.receiverId;
    tempId = other.tempId;
    timestamp = other.timestamp;
    sentAtUs = other.sentAtUs;
    metricA = other.metricA;
    metricB = other.metricB;
    metricC = other.metricC;
    metricD = other.metricD;
    field1 = other.field1;
    field2 = other.field2;
    field3 = other.field3;
    success = other.success;
}

} // namespace protocols
} // namespace uavauth
