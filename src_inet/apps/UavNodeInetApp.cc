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
    if (stage == INITSTAGE_LOCAL) {
        startTimer_ = new cMessage("startPhase2Inet");
        peerTimer_ = new cMessage("startPhase3Inet");
    }
    if (stage != INITSTAGE_APPLICATION_LAYER) return;

    // The device's logical id is its index in uav[], read from the host rather
    // than from a parameter. `*.uav[*].app[0].uavId = index` in the ini does not
    // do what it looks like: with two wildcards, `index` is the INNER one, so
    // every app received 0. That was invisible while nothing depended on the
    // value; it is not invisible now, because each UAV binds its own port
    // (peerBasePort + id) and all ten collided on one port, leaving nine binds
    // failed and every peer datagram answered with ICMP destination-unreachable.
    uavId_ = getParentModule()->getIndex();
    numUavs_ = par("numUAVs").intValue();
    fullMesh_ = par("fullMesh").boolValue();
    peerAuthStart_ = par("peerAuthStartTime").doubleValue();
    suiteName_ = par("suite").stdstringValue();
    feProfile_ = par("feProfile").stdstringValue();
    gsPort_ = par("gsPort").intValue();
    peerBasePort_ = par("peerBasePort").intValue();
    // One port per device: the GS conversation and every peer conversation share
    // it, and the source port of an incoming datagram is what identifies its
    // sender (see peerByPort).
    localPort_ = peerBasePort_ + uavId_;

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
    // The bind port is computed HERE, not read from a member set in
    // initialize(). ApplicationBase's lifecycle mixin can call this before
    // initialize(INITSTAGE_APPLICATION_LAYER) has run, so a member assigned
    // there is still its default -- every UAV bound 9300, which still passed
    // Phase 2 (the GS replies to the source port it saw) but made ports 9301+
    // unreachable, so no peer ever received a P1. Reading the index is cheap
    // and has no ordering dependency.
    uavId_ = getParentModule()->getIndex();
    localPort_ = peerBasePort_ + uavId_;

    socket_.setOutputGate(gate("socketOut"));
    socket_.bind(localPort_);
    socket_.setCallback(this);

    cModule* gsHost = getParentModule()->getParentModule()->getSubmodule("groundStation");
    gsAddr_ = L3AddressResolver().addressOf(gsHost);

    const simtime_t authStart = par("authStartTime").doubleValue();
    scheduleAt(std::max(simTime(), authStart), startTimer_);
}

/// Every peer's address, resolved once. Doing it lazily (at any event after all
/// modules have initialised) rather than in initialize() matters: AdhocHost
/// assigns L3 addresses during its own initialisation, which is not guaranteed
/// to have happened for every peer when this app's initialise runs.
void UavNodeInetApp::buildPeerTable() {
    if (!peerAddr_.empty()) return;
    cModule* network = getParentModule()->getParentModule();
    L3AddressResolver resolver;
    for (int i = 0; i < numUavs_; ++i) {
        if (i == uavId_) continue;
        cModule* host = network->getSubmodule("uav", i);
        if (host == nullptr) continue;
        peerAddr_[i] = resolver.addressOf(host);
    }
}

int UavNodeInetApp::peerByPort(int srcPort) const {
    const int id = srcPort - peerBasePort_;
    return (id >= 0 && id < numUavs_ && id != uavId_) ? id : -1;
}

void UavNodeInetApp::startPhase3Round() {
    if (!fullMesh_) return;
    // Each unordered pair is driven by the lower-numbered UAV, as on the
    // idealised track, so the two sides never both initiate.
    for (int peer = uavId_ + 1; peer < numUavs_; ++peer) {
        const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
        const protocol::StepResult r = proto_->startPhase3(peer, nowMs);
        if (!r.ok) continue;
        PeerRec& rec = peers_[peer];
        rec.initiator = true;
        rec.start = simTime();
        rec.computeMs += r.timing.computeMs;
        p3ComputeMs_ += r.timing.computeMs;
        const auto it = peerAddr_.find(peer);
        if (it == peerAddr_.end()) continue;
        sendMessage(r.reply, it->second, peerBasePort_ + peer);
    }
}

void UavNodeInetApp::handleStopOperation(LifecycleOperation*) {
    cancelEvent(startTimer_);
    cancelEvent(peerTimer_);
    socket_.close();
}

void UavNodeInetApp::handleCrashOperation(LifecycleOperation*) {
    cancelEvent(startTimer_);
    cancelEvent(peerTimer_);
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
    buildPeerTable();
    phase2Start_ = simTime();
    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    const protocol::StepResult r = proto_->startPhase2(nowMs);
    if (!r.ok) return;   // could not regenerate mk from the PUF; never sends M1
    p2ComputeMs_ += r.timing.computeMs;
    sendMessage(r.reply, gsAddr_, gsPort_);
}

void UavNodeInetApp::handleMessageWhenUp(cMessage* msg) {
    if (msg == startTimer_) {
        startPhase2();
        return;
    }
    if (msg == peerTimer_) {
        startPhase3Round();
        return;
    }
    socket_.processMessage(msg);
}

void UavNodeInetApp::socketDataArrived(UdpSocket*, Packet* packet) {
    const int srcPort = packet->getTag<L4PortInd>()->getSrcPort();
    const auto chunk = packet->peekDataAsBytes();
    const auto& raw = chunk->getBytes();
    bytesReceived_ += raw.size();
    const core::Bytes wire(raw.begin(), raw.end());
    delete packet;

    // Phase 2 messages come from the GS, which has no uavId: senderId = -1.
    // Phase 3's P2/P3 carry no identity field on the wire at all, so the sender
    // is named by the source port it was sent from (see peerByPort). Recovering
    // it from the L3 address instead does not work -- a host has several
    // addresses and the routed source is not the one the resolver returns --
    // and the failure is silent: handleP2 finds no session and drops.
    const int sender = (srcPort == gsPort_) ? -1 : peerByPort(srcPort);

    protocol::Message decoded;
    try {
        decoded = protocol::decodeMessage(wire, sender);
    } catch (const std::exception&) {
        return;   // malformed/foreign traffic; drop rather than crash
    }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    switch (decoded.type) {
        case protocol::MessageType::P2_M2_GS_RESPONSE: {
            const protocol::StepResult r = proto_->handleM2(decoded, nowMs);
            if (r.ok) {
                p2ComputeMs_ += r.timing.computeMs;
                sendMessage(r.reply, gsAddr_, gsPort_);
            }
            break;
        }
        case protocol::MessageType::P2_M4_GS_CONFIRM: {
            const protocol::StepResult r = proto_->handleM4(decoded, nowMs);
            if (r.ok) {
                p2ComputeMs_ += r.timing.computeMs;
                phase2Success_ = true;
                wallLatencyMs_ = (simTime() - phase2Start_).dbl() * 1000.0;
                // Credentials have arrived, so peer authentication can start.
                scheduleAt(std::max(simTime(), peerAuthStart_), peerTimer_);
            }
            break;
        }
        case protocol::MessageType::P3_P1_PEER_REQUEST: {
            const protocol::StepResult r = proto_->handleP1(decoded, nowMs);
            if (!r.ok) break;
            PeerRec& rec = peers_[decoded.senderId];
            rec.initiator = false;
            rec.start = simTime();
            rec.computeMs += r.timing.computeMs;
            p3ComputeMs_ += r.timing.computeMs;
            const auto it = peerAddr_.find(decoded.senderId);
            if (it != peerAddr_.end())
                sendMessage(r.reply, it->second, peerBasePort_ + decoded.senderId);
            break;
        }
        case protocol::MessageType::P3_P2_PEER_RESPONSE: {
            const protocol::StepResult r = proto_->handleP2(decoded, nowMs);
            if (!r.ok) break;
            PeerRec& rec = peers_[decoded.senderId];
            rec.computeMs += r.timing.computeMs;
            rec.success = true;
            p3ComputeMs_ += r.timing.computeMs;
            p3Successes_ += 1;
            const auto it = peerAddr_.find(decoded.senderId);
            if (it != peerAddr_.end())
                sendMessage(r.reply, it->second, peerBasePort_ + decoded.senderId);
            break;
        }
        case protocol::MessageType::P3_P3_PEER_COMPLETE: {
            const protocol::StepResult r = proto_->handleP3(decoded, nowMs);
            if (!r.ok) break;
            PeerRec& rec = peers_[decoded.senderId];
            rec.computeMs += r.timing.computeMs;
            rec.success = true;
            p3ComputeMs_ += r.timing.computeMs;
            p3Successes_ += 1;
            break;
        }
        default:
            break;
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
    // Compute on this side, measured by the protocol's own ScopedTimers. Net is
    // derived as wall - compute by the exporter, never recorded, so the file
    // cannot present a derived number as a measurement.
    recordScalar("inetPhase2ComputeMs", p2ComputeMs_);
    recordScalar("inetBytesSent", static_cast<double>(bytesSent_));
    recordScalar("inetBytesReceived", static_cast<double>(bytesReceived_));

    recordScalar("inetPhase3Peers", static_cast<double>(peers_.size()));
    recordScalar("inetPhase3Successes", static_cast<double>(p3Successes_));
    recordScalar("inetPhase3ComputeMs", p3ComputeMs_);

    // Per-peer wall and compute, so the exporter can join on peer id exactly as
    // the idealised track's phase3_peer_<id>_* scalars do.
    for (const auto& entry : peers_) {
        const std::string p = "inetP3Peer_" + std::to_string(entry.first) + "_";
        const PeerRec& r = entry.second;
        recordScalar((p + "success").c_str(), r.success ? 1.0 : 0.0);
        recordScalar((p + "computeMs").c_str(), r.computeMs);
    }
    ApplicationBase::finish();
}

} // namespace inet_apps
} // namespace uavauth
