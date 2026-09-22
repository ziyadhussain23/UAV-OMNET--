#include "GroundStationNodeInetApp.h"

#include "UavNodeInetApp.h"
#include "core/Bytes.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"

using namespace inet;
using namespace omnetpp;

namespace uavauth {
namespace inet_apps {

Define_Module(GroundStationNodeInetApp);

void GroundStationNodeInetApp::initialize(int stage) {
    ApplicationBase::initialize(stage);   // may synchronously call handleStartOperation()
    if (stage == INITSTAGE_LOCAL) enrollTimer_ = new cMessage("enrollAllInet");
    if (stage != INITSTAGE_APPLICATION_LAYER) return;

    numUavs_ = par("numUAVs").intValue();
    suiteName_ = par("suite").stdstringValue();
    localPort_ = par("localPort").intValue();

    suite_ = crypto::makeCryptoSuite(suiteName_);
    const fe::FeParams feParams = fe::FeParams::profile(par("feProfile").stdstringValue());

    core::Bytes rngSeed(32);
    for (size_t i = 0; i < rngSeed.size(); ++i)
        rngSeed[i] = static_cast<uint8_t>(intrand(256));
    rng_ = std::make_unique<crypto::Drbg>(rngSeed);

    proto_ = std::make_unique<protocol::GroundStationProtocol>(
        *suite_, feParams, *rng_, static_cast<uint32_t>(par("timestampWindowMs").intValue()));
    proto_->setNumUavs(numUavs_);
}

void GroundStationNodeInetApp::enrollAll() {
    // Enrollment (Phase 1) is an offline, trusted-channel step in both the
    // paper and the non-INET implementation -- a direct C++ call, not a
    // network exchange, deliberately mirroring GroundStationNode::enrollAll().
    cModule* network = getParentModule()->getParentModule();
    for (int i = 0; i < numUavs_; ++i) {
        cModule* uavHost = network->getSubmodule("uav", i);
        if (uavHost == nullptr) throw cRuntimeError("enrollAll: no uav[%d]", i);
        auto* uav = check_and_cast<UavNodeInetApp*>(uavHost->getSubmodule("app", 0));

        protocol::DeviceRecord rec;
        protocol::DeviceState state;
        protocol::StepTiming timing;
        if (!proto_->enroll(i, uav->devicePuf(), rec, state, timing))
            throw cRuntimeError("enrollAll: enrollment failed for uav[%d]", i);
        uav->provision(state);
    }
}

void GroundStationNodeInetApp::handleStartOperation(LifecycleOperation*) {
    // NOT safe to call enrollAll() here: ApplicationBase's lifecycle mixin
    // calls handleStartOperation() *synchronously from inside* each module's
    // own initialize(INITSTAGE_APPLICATION_LAYER) call, interleaved with
    // other modules' initialize() calls in submodule order -- so if the GS
    // happens to initialize before some uav[i], that UAV's PUF would not
    // exist yet. Scheduling a zero-delay self-message instead defers the
    // actual enrollment to the first real simulation event, which the kernel
    // guarantees only runs after EVERY module has finished ALL init stages,
    // regardless of declaration order.
    scheduleAt(simTime(), enrollTimer_);

    socket_.setOutputGate(gate("socketOut"));
    socket_.bind(localPort_);
    socket_.setCallback(this);
}

void GroundStationNodeInetApp::handleStopOperation(LifecycleOperation*) {
    cancelEvent(enrollTimer_);
    socket_.close();
}

void GroundStationNodeInetApp::handleCrashOperation(LifecycleOperation*) {
    cancelEvent(enrollTimer_);
    socket_.destroy();
}

void GroundStationNodeInetApp::sendMessage(const protocol::Message& msg, const L3Address& destAddr,
                                           int destPort) {
    const core::Bytes wire = msg.encode();
    Packet* packet = new Packet(protocol::messageTypeName(msg.type));
    packet->insertAtBack(makeShared<BytesChunk>(wire.data(), wire.size()));
    socket_.sendTo(packet, destAddr, destPort);
}

void GroundStationNodeInetApp::handleMessageWhenUp(cMessage* msg) {
    if (msg == enrollTimer_) {
        enrollAll();
        return;
    }
    socket_.processMessage(msg);
}

void GroundStationNodeInetApp::socketDataArrived(UdpSocket*, Packet* packet) {
    const L3Address srcAddr = packet->getTag<L3AddressInd>()->getSrcAddress();
    const int srcPort = packet->getTag<L4PortInd>()->getSrcPort();
    const auto chunk = packet->peekDataAsBytes();
    const auto& raw = chunk->getBytes();
    const core::Bytes wire(raw.begin(), raw.end());
    delete packet;

    // The GS identifies the sending device from the message's own TID field
    // (handleM1/handleM3 look it up via findByTid), not from the network
    // address -- the address is only needed to know where to send the reply.
    protocol::Message decoded;
    try {
        decoded = protocol::decodeMessage(wire, /*senderId=*/-1);
    } catch (const std::exception&) {
        return;   // malformed/foreign traffic; drop rather than crash
    }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    if (decoded.type == protocol::MessageType::P2_M1_AUTH_REQUEST) {
        ++attemptsM1_;
        const protocol::StepResult r = proto_->handleM1(decoded, nowMs);
        if (r.ok) {
            gsComputeMs_ += r.timing.computeMs;
            sendMessage(r.reply, srcAddr, srcPort);
        }
    } else if (decoded.type == protocol::MessageType::P2_M3_UAV_CONFIRM) {
        const protocol::StepResult r = proto_->handleM3(decoded, nowMs);
        if (r.ok) {
            gsComputeMs_ += r.timing.computeMs;
            ++successesM4_;
            sendMessage(r.reply, srcAddr, srcPort);
        }
    }
}

void GroundStationNodeInetApp::socketErrorArrived(UdpSocket*, Indication* indication) {
    delete indication;
}

void GroundStationNodeInetApp::socketClosed(UdpSocket*) {
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(0);
}

void GroundStationNodeInetApp::finish() {
    recordScalar("inetM1Attempts", static_cast<double>(attemptsM1_));
    recordScalar("inetM4Successes", static_cast<double>(successesM4_));
    recordScalar("inetReplayHits", static_cast<double>(proto_->replayHits()));
    // Ground-station-side compute for Phase 2, host-clock, same convention as
    // the UAV side's inetPhase2ComputeMs.
    recordScalar("inetGsComputeMs", gsComputeMs_);
    ApplicationBase::finish();
}

} // namespace inet_apps
} // namespace uavauth
