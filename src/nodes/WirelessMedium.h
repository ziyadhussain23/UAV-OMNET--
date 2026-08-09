#ifndef UAVAUTH_NODES_WIRELESSMEDIUM_H
#define UAVAUTH_NODES_WIRELESSMEDIUM_H

#include <omnetpp.h>

#include "nodes/SimMessage.h"

#include <cstdio>
#include <string>
#include <vector>

namespace uavauth {
namespace nodes {

/// The single transmission path for every protocol message.
///
/// Two reasons this exists rather than each node calling sendDirect itself.
/// First, it removes the seven helper functions the previous implementation
/// duplicated verbatim between the UAV and the ground station, including the
/// link-delay model, so there is exactly one definition of what a hop costs.
/// Second, it gives the attacker a place to stand: with sendDirect there is no
/// channel object to intercept, so a wiretap needs a common relay.
///
/// When `tapEnabled` is false the medium short-circuits straight to delivery, so
/// baseline runs behave exactly as a direct send and their timings stay
/// comparable with attack runs.
class WirelessMedium : public omnetpp::cSimpleModule {
  public:
    /// What the medium does with a message. Set by the attack policy.
    enum class Action { Forward, Drop, Delay, Duplicate, Modify, Redirect, CopyTo };

    /// Delay decomposition for one hop, reported per message so the
    /// "network-bound" claim can be broken into its parts rather than asserted.
    struct DelayBreakdown {
        double propagationMs = 0.0;
        double serializationMs = 0.0;
        double processingMs = 0.0;
        double jitterMs = 0.0;
        double totalMs() const {
            return propagationMs + serializationMs + processingMs + jitterMs;
        }
    };

    /// Accept a message for delivery. Takes ownership.
    void transmit(SimMessage* msg, omnetpp::cModule* source, omnetpp::cModule* dest);

    /// Link delay between two modules for a payload of the given size.
    DelayBreakdown computeDelay(const omnetpp::cModule* from, const omnetpp::cModule* to,
                                size_t payloadBytes) const;

    /// Locate the medium from any node in the network.
    static WirelessMedium* get(omnetpp::cModule* anyModule);

    void registerAttacker(omnetpp::cModule* attacker) { attacker_ = attacker; }
    bool tapEnabled() const { return tapEnabled_; }

    /// Message-level trace rows, flushed to CSV by the metrics collector.
    struct TraceRow {
        double txTime = 0.0;
        double rxTime = 0.0;
        std::string phase;
        std::string label;
        int msgTypeCode = 0;
        int srcId = -1;
        int dstId = -1;
        size_t wireBytes = 0;
        DelayBreakdown delay;
        double senderComputeMs = 0.0;
        bool delivered = false;
        bool dropped = false;
        bool tampered = false;
        bool injected = false;
    };
    const std::vector<TraceRow>& trace() const { return trace_; }

  protected:
    void initialize() override;
    void handleMessage(omnetpp::cMessage* msg) override;

  private:
    static double coordinate(const omnetpp::cModule* module, const char* axis);

    double linkBitrateBps_ = 6e6;
    double propagationSpeedMps_ = 299792458.0;
    double processingDelayMs_ = 0.1;
    double jitterStddevMs_ = 0.02;
    bool enableJitter_ = true;
    bool tapEnabled_ = false;
    std::string attackMode_ = "none";

    omnetpp::cModule* attacker_ = nullptr;
    std::vector<TraceRow> trace_;
};

} // namespace nodes
} // namespace uavauth

#endif
