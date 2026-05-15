#ifndef UAVAUTH_PROTOCOLS_PROTOCOLMESSAGES_H
#define UAVAUTH_PROTOCOLS_PROTOCOLMESSAGES_H

#include <omnetpp.h>

#include <cstdint>
#include <string>
#include <vector>

namespace uavauth {
namespace protocols {

enum class MessageType : int {
    AUTH_REQUEST = 100,
    CHALLENGE_ISSUANCE = 101,
    PUF_RESPONSE = 102,
    AUTH_CONFIRMATION = 103,
    PEER_AUTH_REQUEST = 200,
    PEER_AUTH_RESPONSE = 201,
    PEER_AUTH_COMPLETE = 202
};

class ProtocolMessage : public omnetpp::cMessage {
  public:
    MessageType type;
    int senderId;
    int receiverId;

    std::string tempId;
    uint32_t timestamp;
    uint64_t sentAtUs;
    double metricA;
    double metricB;
    double metricC;
    double metricD;

    std::vector<uint8_t> field1;
    std::vector<uint8_t> field2;
    std::vector<uint8_t> field3;

    bool success;

    explicit ProtocolMessage(const char* name = nullptr, MessageType msgType = MessageType::AUTH_REQUEST);
    ProtocolMessage(const ProtocolMessage& other);
    ProtocolMessage& operator=(const ProtocolMessage& other);
    virtual ProtocolMessage* dup() const override;

  private:
    void copyFrom(const ProtocolMessage& other);
};

} // namespace protocols
} // namespace uavauth

#endif
