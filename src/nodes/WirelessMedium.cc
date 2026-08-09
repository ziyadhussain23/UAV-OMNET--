#include "nodes/WirelessMedium.h"

#include <cmath>

namespace uavauth {
namespace nodes {

using namespace omnetpp;

Define_Module(WirelessMedium);

void WirelessMedium::initialize() {
    linkBitrateBps_ = par("linkBitrateBps").doubleValue();
    propagationSpeedMps_ = par("propagationSpeedMps").doubleValue();
    processingDelayMs_ = par("processingDelayMs").doubleValue();
    jitterStddevMs_ = par("jitterStddevMs").doubleValue();
    enableJitter_ = par("enableJitter").boolValue();
    tapEnabled_ = par("tapEnabled").boolValue();
    attackMode_ = par("attackMode").stdstringValue();
}

void WirelessMedium::handleMessage(cMessage* msg) {
    // The medium never schedules anything for itself; every message is passed
    // straight through in transmit().
    delete msg;
}

WirelessMedium* WirelessMedium::get(cModule* anyModule) {
    cModule* network = anyModule->getParentModule();
    if (network == nullptr) throw cRuntimeError("WirelessMedium::get: no parent network");
    cModule* medium = network->getSubmodule("medium");
    if (medium == nullptr) throw cRuntimeError("WirelessMedium::get: no 'medium' submodule");
    auto* typed = dynamic_cast<WirelessMedium*>(medium);
    if (typed == nullptr) throw cRuntimeError("WirelessMedium::get: 'medium' has wrong type");
    return typed;
}

double WirelessMedium::coordinate(const cModule* module, const char* axis) {
    // Positions come from real NED parameters, not from parsing the display
    // string: a display string is presentation, and parsing it made the previous
    // implementation silently fall back to (0,0) whenever the format changed.
    if (module->hasPar(axis)) return const_cast<cModule*>(module)->par(axis).doubleValue();
    return 0.0;
}

WirelessMedium::DelayBreakdown WirelessMedium::computeDelay(const cModule* from,
                                                            const cModule* to,
                                                            size_t payloadBytes) const {
    DelayBreakdown d;

    const double dx = coordinate(from, "xpos") - coordinate(to, "xpos");
    const double dy = coordinate(from, "ypos") - coordinate(to, "ypos");
    const double distance = std::sqrt(dx * dx + dy * dy);

    d.propagationMs = (distance / propagationSpeedMps_) * 1000.0;
    d.serializationMs = (8.0 * static_cast<double>(payloadBytes) / linkBitrateBps_) * 1000.0;
    d.processingMs = processingDelayMs_;
    if (enableJitter_) {
        // Half-normal: jitter delays, never advances.
        d.jitterMs = std::fabs(normal(0.0, jitterStddevMs_));
    }
    return d;
}

void WirelessMedium::transmit(SimMessage* msg, cModule* source, cModule* dest) {
    // transmit() is called from inside another module's event handler, so the
    // kernel needs to be told the context is switching, and ownership of the
    // message has to move to this module before it can be sent.
    Enter_Method_Silent("transmit(%s)", protocol::messageLabel(msg->payload.type));
    take(msg);

    if (dest == nullptr) {
        delete msg;
        return;
    }

    const size_t bytes = msg->wireBytes();
    const DelayBreakdown delay = computeDelay(source, dest, bytes);
    const simtime_t delaySec = SimTime(delay.totalMs() / 1000.0);

    msg->sentAt = simTime();
    msg->prevNetMs = delay.totalMs();

    TraceRow row;
    row.txTime = simTime().dbl();
    row.rxTime = (simTime() + delaySec).dbl();
    const auto type = msg->payload.type;
    const int code = static_cast<int>(type);
    row.phase = (code < 200) ? "phase1" : (code < 300 ? "phase2" : "phase3");
    row.label = protocol::messageLabel(type);
    row.msgTypeCode = code;
    row.srcId = msg->payload.senderId;
    row.dstId = msg->payload.receiverId;
    row.wireBytes = bytes;
    row.delay = delay;
    row.senderComputeMs = msg->peer.computeMs;
    row.injected = msg->injectedByAttacker;
    row.tampered = msg->tampered;

    // Fast path: with no attacker attached this is exactly a direct send, so
    // baseline timings remain comparable with the attack configurations.
    if (!tapEnabled_ || attacker_ == nullptr) {
        row.delivered = true;
        trace_.push_back(row);
        sendDirect(msg, delaySec, SIMTIME_ZERO, dest, "in");
        return;
    }

    // Passive eavesdropping: the attacker sees a copy, the victim still receives
    // the original.
    if (attackMode_ == "eavesdrop" || attackMode_ == "credsniff") {
        auto* copy = msg->dup();
        sendDirect(copy, delaySec, SIMTIME_ZERO, attacker_, "in");
        row.delivered = true;
        trace_.push_back(row);
        sendDirect(msg, delaySec, SIMTIME_ZERO, dest, "in");
        return;
    }

    // Active interception: the attacker receives the message instead of the
    // victim and decides what to do with it.
    if (attackMode_ == "mitm" || attackMode_ == "tamper") {
        row.delivered = false;
        trace_.push_back(row);
        sendDirect(msg, delaySec, SIMTIME_ZERO, attacker_, "in");
        return;
    }

    row.delivered = true;
    trace_.push_back(row);
    sendDirect(msg, delaySec, SIMTIME_ZERO, dest, "in");
}

} // namespace nodes
} // namespace uavauth
