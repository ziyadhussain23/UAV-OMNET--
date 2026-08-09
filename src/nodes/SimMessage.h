#ifndef UAVAUTH_NODES_SIMMESSAGE_H
#define UAVAUTH_NODES_SIMMESSAGE_H

#include <omnetpp.h>

#include "protocol/Protocol.h"
#include "protocol/Wire.h"

namespace uavauth {
namespace nodes {

/// OMNeT++ carrier for a protocol message.
///
/// The payload is the transport-agnostic protocol::Message, so the protocol
/// logic never depends on the simulation kernel and stays unit-testable.
///
/// `sentAt` is a simtime_t rather than an integer microsecond count: propagation
/// over 500 m is 1.67 us, which integer truncation would distort. `peer` carries
/// the sender's own timing breakdown to the receiver so that a single node can
/// report an end-to-end per-message decomposition without a global collector.
class SimMessage : public omnetpp::cMessage {
  public:
    protocol::Message payload;
    omnetpp::simtime_t sentAt = 0;
    protocol::StepTiming peer;      // sender-side timings, piggybacked
    double prevNetMs = 0.0;         // delay of the hop that produced this message
    bool injectedByAttacker = false;
    bool tampered = false;

    explicit SimMessage(const char* name = nullptr)
        : omnetpp::cMessage(name, static_cast<short>(protocol::MessageType::CTRL_ABORT)) {}

    SimMessage(const SimMessage& other) : omnetpp::cMessage(other) { copyFrom(other); }

    SimMessage& operator=(const SimMessage& other) {
        if (this == &other) return *this;
        cMessage::operator=(other);
        copyFrom(other);
        return *this;
    }

    SimMessage* dup() const override { return new SimMessage(*this); }

    size_t wireBytes() const { return payload.wireBytes(); }

  private:
    void copyFrom(const SimMessage& other) {
        payload = other.payload;
        sentAt = other.sentAt;
        peer = other.peer;
        prevNetMs = other.prevNetMs;
        injectedByAttacker = other.injectedByAttacker;
        tampered = other.tampered;
    }
};

} // namespace nodes
} // namespace uavauth

#endif
