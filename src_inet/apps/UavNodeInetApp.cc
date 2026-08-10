#include "UavNodeInetApp.h"

#include "core/Bytes.h"
#include "puf/ArbiterPuf.h"
#include "puf/IdealPrfPuf.h"

#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/packet/chunk/BytesChunk.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"

using namespace inet;
using namespace omnetpp;

namespace uavauth {
namespace inet_apps {

Define_Module(UavNodeInetApp);

void UavNodeInetApp::initialize(int stage) {
    ApplicationBase::initialize(stage);   // may synchronously call handleStartOperation()
                                          // below if this stage is the trigger stage --
                                          // startTimer_ must already exist by then, so it
                                          // is built at INITSTAGE_LOCAL, not here.
    if (stage == INITSTAGE_LOCAL) startTimer_ = new cMessage("startPhase2Inet");
    if (stage != INITSTAGE_APPLICATION_LAYER) return;

    uavId_ = par("uavId").intValue();
    suiteName_ = par("suite").stdstringValue();
    feProfile_ = par("feProfile").stdstringValue();
    localPort_ = par("localPort").intValue();
    gsPort_ = par("gsPort").intValue();

    suite_ = crypto::makeCryptoSuite(suiteName_);
    feParams_ = fe::FeParams::profile(feProfile_);
    feParams_.assumedMinEntropyRate = par("assumedMinEntropyRate").doubleValue();

    const std::string model = par("pufModel").stdstringValue();
    const double ber = par("pufNoiseBer").doubleValue();
    const core::Bytes seed = core::fromString("uav-puf-" + std::to_string(uavId_));
    if (model == "ideal") {
        auto p = std::make_unique<puf::IdealPrfPuf>(seed);
        p->setNoiseBer(ber);
        puf_ = std::move(p);
    } else if (model == "arbiter") {
        auto p = std::make_unique<puf::ArbiterPuf>(seed);
        if (ber > 0.0) {
            crypto::Drbg calibRng(core::fromString("calib-" + std::to_string(uavId_)));
            p->setNoiseSigma(p->sigmaForTargetBer(ber, calibRng));
        } else {
            p->setNoiseSigma(0.0);
        }
        puf_ = std::move(p);
    } else {
        throw cRuntimeError("unknown pufModel '%s'", model.c_str());
    }

    core::Bytes rngSeed(32);
    for (size_t i = 0; i < rngSeed.size(); ++i)
        rngSeed[i] = static_cast<uint8_t>(intrand(256));
    rng_ = std::make_unique<crypto::Drbg>(rngSeed);

    proto_ = std::make_unique<protocol::UavProtocol>(
        uavId_, *suite_, feParams_, *puf_, *rng_,
        static_cast<uint32_t>(par("timestampWindowMs").intValue()));
}

void UavNodeInetApp::handleStartOperation(LifecycleOperation*) {
    socket_.setOutputGate(gate("socketOut"));
    socket_.bind(localPort_);
    socket_.setCallback(this);

    cModule* gsHost = getParentModule()->getParentModule()->getSubmodule("groundStation");
    gsAddr_ = L3AddressResolver().addressOf(gsHost);

    const simtime_t authStart = par("authStartTime").doubleValue();
    scheduleAt(std::max(simTime(), authStart), startTimer_);
}

void UavNodeInetApp::handleStopOperation(LifecycleOperation*) {
    cancelEvent(startTimer_);
    socket_.close();
}

void UavNodeInetApp::handleCrashOperation(LifecycleOperation*) {
    cancelEvent(startTimer_);
    socket_.destroy();
}

void UavNodeInetApp::sendMessage(const protocol::Message& msg, const L3Address& destAddr,
                                 int destPort) {
    const core::Bytes wire = msg.encode();
    bytesSent_ += wire.size();
    Packet* packet = new Packet(protocol::messageTypeName(msg.type));
    packet->insertAtBack(makeShared<BytesChunk>(wire.data(), wire.size()));
    socket_.sendTo(packet, destAddr, destPort);
}

void UavNodeInetApp::startPhase2() {
    phase2Start_ = simTime();
    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    const protocol::StepResult r = proto_->startPhase2(nowMs);
    if (!r.ok) return;   // could not regenerate mk from the PUF; never sends M1
    sendMessage(r.reply, gsAddr_, gsPort_);
}

void UavNodeInetApp::handleMessageWhenUp(cMessage* msg) {
    if (msg == startTimer_) {
        startPhase2();
        return;
    }
    socket_.processMessage(msg);
}

void UavNodeInetApp::socketDataArrived(UdpSocket*, Packet* packet) {
    const auto chunk = packet->peekDataAsBytes();
    const auto& raw = chunk->getBytes();
    bytesReceived_ += raw.size();
    const core::Bytes wire(raw.begin(), raw.end());
    delete packet;

    // Only the ground station ever sends this app anything on this track
    // (Phase 3 peer traffic is out of scope, see the .ned file), so the
    // sender's logical id is always the GS.
    protocol::Message decoded;
    try {
        decoded = protocol::decodeMessage(wire, /*senderId=*/-1);
    } catch (const std::exception&) {
        return;   // malformed/foreign traffic; drop rather than crash
    }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    if (decoded.type == protocol::MessageType::P2_M2_GS_RESPONSE) {
        const protocol::StepResult r = proto_->handleM2(decoded, nowMs);
        if (r.ok) sendMessage(r.reply, gsAddr_, gsPort_);
    } else if (decoded.type == protocol::MessageType::P2_M4_GS_CONFIRM) {
        const protocol::StepResult r = proto_->handleM4(decoded, nowMs);
        if (r.ok) {
            phase2Success_ = true;
            wallLatencyMs_ = (simTime() - phase2Start_).dbl() * 1000.0;
        }
    }
}

void UavNodeInetApp::socketErrorArrived(UdpSocket*, Indication* indication) { delete indication; }

void UavNodeInetApp::socketClosed(UdpSocket*) {
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(0);
}

void UavNodeInetApp::finish() {
    recordScalar("uavId", uavId_);
    recordScalar("inetPhase2Success", phase2Success_ ? 1.0 : 0.0);
    recordScalar("inetPhase2WallLatencyMs", wallLatencyMs_);
    recordScalar("inetBytesSent", static_cast<double>(bytesSent_));
    recordScalar("inetBytesReceived", static_cast<double>(bytesReceived_));
    ApplicationBase::finish();
}

} // namespace inet_apps
} // namespace uavauth
