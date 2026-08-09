#include "nodes/UavNode.h"

#include "nodes/WirelessMedium.h"
#include "puf/ArbiterPuf.h"
#include "puf/IdealPrfPuf.h"

namespace uavauth {
namespace nodes {

using namespace omnetpp;
using core::Bytes;
using core::fromString;

Define_Module(UavNode);

void UavNode::initialize(int stage) {
    if (stage == 0) {
        uavId_ = par("uavId").intValue();
        suiteName_ = par("suite").stdstringValue();
        feProfile_ = par("feProfile").stdstringValue();
        numUavs_ = getParentModule()->par("numUAVs").intValue();
        fullMesh_ = par("fullMesh").boolValue();

        suite_ = crypto::makeCryptoSuite(suiteName_);
        feParams_ = fe::FeParams::profile(feProfile_);
        feParams_.assumedMinEntropyRate = par("assumedMinEntropyRate").doubleValue();

        // The device PUF is created here, in stage 0, so the ground station can
        // interrogate this very instance during enrollment in stage 1. Both
        // sides derive it from the same seed string, mirroring a real device
        // whose silicon is fixed before deployment.
        const std::string model = par("pufModel").stdstringValue();
        const double ber = par("pufNoiseBer").doubleValue();
        const Bytes seed = fromString("uav-puf-" + std::to_string(uavId_));
        if (model == "ideal") {
            auto p = std::make_unique<puf::IdealPrfPuf>(seed);
            p->setNoiseBer(ber);
            puf_ = std::move(p);
        } else if (model == "arbiter") {
            auto p = std::make_unique<puf::ArbiterPuf>(seed);
            // The arbiter model's noise lives on the delay difference, not on the
            // output bit, so a target BER has to be calibrated into a sigma. That
            // is the point of the model: bits whose delay difference sits near
            // zero flip far more often than the rest, which a uniform bit-flip
            // channel cannot reproduce.
            if (ber > 0.0) {
                crypto::Drbg calibRng(fromString("calib-" + std::to_string(uavId_)));
                p->setNoiseSigma(p->sigmaForTargetBer(ber, calibRng));
            } else {
                p->setNoiseSigma(0.0);
            }
            puf_ = std::move(p);
        } else {
            throw cRuntimeError("unknown pufModel '%s'", model.c_str());
        }

        Bytes rngSeed(32);
        for (size_t i = 0; i < rngSeed.size(); ++i)
            rngSeed[i] = static_cast<uint8_t>(intrand(256));
        rng_ = std::make_unique<crypto::Drbg>(rngSeed);

        proto_ = std::make_unique<protocol::UavProtocol>(
            uavId_, *suite_, feParams_, *puf_, *rng_,
            static_cast<uint32_t>(par("timestampWindowMs").intValue()));

        authLatencySignal_ = registerSignal("authLatency");
        peerAuthLatencySignal_ = registerSignal("peerAuthLatency");
        commOverheadSignal_ = registerSignal("commOverhead");
        return;
    }

    // Stage 1: the ground station has now enrolled us, so schedule the handshake.
    const simtime_t authStart = par("authStartTime").doubleValue();
    scheduleAt(simTime() + authStart, new cMessage("startPhase2"));
}

void UavNode::provision(const protocol::DeviceState& state) { proto_->provision(state); }

void UavNode::sendToGs(const protocol::Message& payload, const protocol::StepTiming& t) {
    auto* msg = new SimMessage(protocol::messageTypeName(payload.type));
    msg->payload = payload;
    msg->setKind(static_cast<short>(payload.type));
    msg->peer = t;
    emit(commOverheadSignal_, static_cast<double>(msg->wireBytes()));
    phase2_.overheadBytes += msg->wireBytes();
    WirelessMedium::get(this)->transmit(msg, this,
                                        getParentModule()->getSubmodule("groundStation"));
}

void UavNode::sendToPeer(int peerId, const protocol::Message& payload,
                         const protocol::StepTiming& t) {
    cModule* peer = getParentModule()->getSubmodule("uav", peerId);
    if (peer == nullptr) return;
    auto* msg = new SimMessage(protocol::messageTypeName(payload.type));
    msg->payload = payload;
    msg->setKind(static_cast<short>(payload.type));
    msg->peer = t;
    emit(commOverheadSignal_, static_cast<double>(msg->wireBytes()));
    phase3_[peerId].overheadBytes += msg->wireBytes();
    WirelessMedium::get(this)->transmit(msg, this, peer);
}

void UavNode::startPhase3Round() {
    if (!fullMesh_) return;
    // Each unordered pair is run once, by the lower-numbered UAV.
    for (int peer = uavId_ + 1; peer < numUavs_; ++peer) {
        const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
        const protocol::StepResult r = proto_->startPhase3(peer, nowMs);
        Phase3Record& rec = phase3_[peer];
        rec.initiator = true;
        if (!r.ok) {
            rec.abortReason = protocol::abortReasonName(r.abort);
            continue;
        }
        phase3Start_[peer] = simTime();
        rec.p1ComputeMs = r.timing.computeMs;
        rec.macMs += r.timing.macMs;
        rec.kdfMs += r.timing.kdfMs;
        rec.dhMs += r.timing.dhMs;
        sendToPeer(peer, r.reply, r.timing);
    }
}

void UavNode::handleMessage(cMessage* raw) {
    if (raw->isSelfMessage()) {
        const std::string name = raw->getName();
        delete raw;
        if (name == "startPhase2") {
            phase2Start_ = simTime();
            const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
            const protocol::StepResult r = proto_->startPhase2(nowMs);
            phase2_.m1ComputeMs = r.timing.computeMs;
            phase2_.pufMs += r.timing.pufMs;
            phase2_.feMs += r.timing.feMs;
            phase2_.macMs += r.timing.macMs;
            phase2_.kdfMs += r.timing.kdfMs;
            phase2_.dhMs += r.timing.dhMs;
            if (!r.ok) {
                phase2_.abortReason = protocol::abortReasonName(r.abort);
                return;
            }
            phase2_.bytesM1 = r.reply.wireBytes();
            sendToGs(r.reply, r.timing);
        } else if (name == "startPhase3") {
            startPhase3Round();
        }
        return;
    }

    auto* msg = dynamic_cast<SimMessage*>(raw);
    if (msg == nullptr) { delete raw; return; }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    const double netMs = (simTime() - msg->sentAt).dbl() * 1000.0;

    switch (msg->payload.type) {
        case protocol::MessageType::P2_M2_GS_RESPONSE: {
            phase2_.m2NetMs = netMs;
            phase2_.bytesM2 = msg->wireBytes();
            phase2_.overheadBytes += msg->wireBytes();
            const protocol::StepResult r = proto_->handleM2(msg->payload, nowMs);
            phase2_.m2VerifyMs = r.timing.computeMs;
            phase2_.macMs += r.timing.macMs;
            phase2_.kdfMs += r.timing.kdfMs;
            phase2_.dhMs += r.timing.dhMs;
            if (!r.ok) {
                phase2_.abortReason = protocol::abortReasonName(r.abort);
                break;
            }
            phase2_.bytesM3 = r.reply.wireBytes();
            phase2_.m3ComputeMs = r.timing.computeMs;
            sendToGs(r.reply, r.timing);
            break;
        }
        case protocol::MessageType::P2_M4_GS_CONFIRM: {
            phase2_.m4NetMs = netMs;
            phase2_.bytesM4 = msg->wireBytes();
            phase2_.overheadBytes += msg->wireBytes();
            const protocol::StepResult r = proto_->handleM4(msg->payload, nowMs);
            phase2_.m4ComputeMs = r.timing.computeMs;
            phase2_.aeadMs += r.timing.aeadMs;
            if (!r.ok) {
                phase2_.abortReason = protocol::abortReasonName(r.abort);
                break;
            }
            phase2_.success = true;
            phase2_.ephemeralErased = proto_->ephemeralErased();
            phase2_.walletLatencyMs = (simTime() - phase2Start_).dbl() * 1000.0;
            emit(authLatencySignal_, phase2_.walletLatencyMs);

            // Peer authentication can only begin once credentials have arrived.
            const simtime_t peerStart = par("peerAuthStartTime").doubleValue();
            const simtime_t at = std::max(simTime(), peerStart);
            scheduleAt(at, new cMessage("startPhase3"));
            break;
        }
        case protocol::MessageType::P3_P1_PEER_REQUEST: {
            const int peer = msg->payload.senderId;
            Phase3Record& rec = phase3_[peer];
            rec.overheadBytes += msg->wireBytes();
            rec.initiator = false;
            rec.p1NetMs = netMs;
            phase3Start_[peer] = simTime();
            const protocol::StepResult r = proto_->handleP1(msg->payload, nowMs);
            rec.p2ComputeMs = r.timing.computeMs;
            rec.macMs += r.timing.macMs;
            rec.kdfMs += r.timing.kdfMs;
            rec.dhMs += r.timing.dhMs;
            if (!r.ok) { rec.abortReason = protocol::abortReasonName(r.abort); break; }
            sendToPeer(peer, r.reply, r.timing);
            break;
        }
        case protocol::MessageType::P3_P2_PEER_RESPONSE: {
            const int peer = msg->payload.senderId;
            Phase3Record& rec = phase3_[peer];
            rec.overheadBytes += msg->wireBytes();
            rec.p2NetMs = netMs;
            const protocol::StepResult r = proto_->handleP2(msg->payload, nowMs);
            rec.p3ComputeMs = r.timing.computeMs;
            rec.macMs += r.timing.macMs;
            rec.kdfMs += r.timing.kdfMs;
            rec.dhMs += r.timing.dhMs;
            if (!r.ok) { rec.abortReason = protocol::abortReasonName(r.abort); break; }
            sendToPeer(peer, r.reply, r.timing);
            break;
        }
        case protocol::MessageType::P3_P3_PEER_COMPLETE: {
            const int peer = msg->payload.senderId;
            Phase3Record& rec = phase3_[peer];
            rec.overheadBytes += msg->wireBytes();
            rec.p3NetMs = netMs;
            const protocol::StepResult r = proto_->handleP3(msg->payload, nowMs);
            rec.macMs += r.timing.macMs;
            rec.kdfMs += r.timing.kdfMs;
            rec.dhMs += r.timing.dhMs;
            if (!r.ok) { rec.abortReason = protocol::abortReasonName(r.abort); break; }
            rec.success = true;
            rec.latencyMs = (simTime() - phase3Start_[peer]).dbl() * 1000.0;
            emit(peerAuthLatencySignal_, rec.latencyMs);
            break;
        }
        default:
            break;
    }

    // The initiator completes when it sends P3; record that here rather than on
    // an acknowledgement the protocol does not have.
    if (msg->payload.type == protocol::MessageType::P3_P2_PEER_RESPONSE) {
        const int peer = msg->payload.senderId;
        Bytes key;
        if (proto_->peerSessionKey(peer, key)) {
            Phase3Record& rec = phase3_[peer];
            rec.success = true;
            rec.latencyMs = (simTime() - phase3Start_[peer]).dbl() * 1000.0;
            emit(peerAuthLatencySignal_, rec.latencyMs);
        }
    }

    delete msg;
}

void UavNode::finish() {
    recordScalar("uavId", uavId_);
    recordScalar("hashMode", suiteName_ == "spongent" ? 1.0 : 0.0);
    recordScalar("isPhase2Authenticated", proto_->phase2Established() ? 1.0 : 0.0);
    recordScalar("numPeerSessionKeys", static_cast<double>(phase3_.size()));

    const Phase2Record& p = phase2_;
    const double compute = p.m1ComputeMs + p.m2VerifyMs + p.m3ComputeMs + p.m4ComputeMs;
    const double net = p.m1NetMs + p.m2NetMs + p.m3NetMs + p.m4NetMs;

    recordScalar("phase2Success", p.success ? 1.0 : 0.0);
    recordScalar("phase2ComputeMs", compute);
    recordScalar("phase2NetMs", net);
    recordScalar("phase2LatencyMs", compute + net);
    recordScalar("phase2_wall_latency_ms", p.walletLatencyMs);
    recordScalar("phase2OverheadBytes", static_cast<double>(p.overheadBytes));

    recordScalar("m1_uav_compute_ms", p.m1ComputeMs);
    recordScalar("m2_uav_verify_ms", p.m2VerifyMs);
    recordScalar("m3_uav_compute_ms", p.m3ComputeMs);
    recordScalar("m4_uav_compute_ms", p.m4ComputeMs);
    recordScalar("m1_net_ms", p.m1NetMs);
    recordScalar("m2_net_ms", p.m2NetMs);
    recordScalar("m3_net_ms", p.m3NetMs);
    recordScalar("m4_net_ms", p.m4NetMs);
    recordScalar("puf_eval_ms", p.pufMs);
    recordScalar("fe_rep_ms", p.feMs);
    recordScalar("bch_ms", p.feMs);   // legacy name kept for the exporter
    recordScalar("mac_ms", p.macMs);
    recordScalar("kdf_ms", p.kdfMs);
    recordScalar("dh_ms", p.dhMs);
    recordScalar("aead_ms", p.aeadMs);
    recordScalar("bytes_m1", static_cast<double>(p.bytesM1));
    recordScalar("bytes_m2", static_cast<double>(p.bytesM2));
    recordScalar("bytes_m3", static_cast<double>(p.bytesM3));
    recordScalar("bytes_m4", static_cast<double>(p.bytesM4));
    recordScalar("ephemeral_erased", p.ephemeralErased ? 1.0 : 0.0);
    recordScalar("replay_cache_hits", static_cast<double>(proto_->replayHits()));

    for (const auto& entry : phase3_) {
        const std::string pre = "phase3_peer_" + std::to_string(entry.first) + "_";
        const Phase3Record& r = entry.second;
        const double c = r.p1ComputeMs + r.p2ComputeMs + r.p3ComputeMs;
        const double n = r.p1NetMs + r.p2NetMs + r.p3NetMs;
        recordScalar((pre + "success").c_str(), r.success ? 1.0 : 0.0);
        recordScalar((pre + "initiator").c_str(), r.initiator ? 1.0 : 0.0);
        recordScalar((pre + "compute_ms").c_str(), c);
        recordScalar((pre + "net_ms").c_str(), n);
        recordScalar((pre + "latency_ms").c_str(), r.latencyMs > 0 ? r.latencyMs : c + n);
        recordScalar((pre + "overhead_bytes").c_str(), static_cast<double>(r.overheadBytes));
        recordScalar((pre + "p1_i_compute_ms").c_str(), r.p1ComputeMs);
        recordScalar((pre + "p1_p2_j_compute_ms").c_str(), r.p2ComputeMs);
        recordScalar((pre + "p2_p3_i_compute_ms").c_str(), r.p3ComputeMs);
        recordScalar((pre + "p1_net_ms").c_str(), r.p1NetMs);
        recordScalar((pre + "p2_net_ms").c_str(), r.p2NetMs);
        recordScalar((pre + "p3_net_ms").c_str(), r.p3NetMs);
        recordScalar((pre + "mac_ms").c_str(), r.macMs);
        recordScalar((pre + "kdf_ms").c_str(), r.kdfMs);
        recordScalar((pre + "dh_ms").c_str(), r.dhMs);
    }

    for (int i = 0; i < static_cast<int>(crypto::Primitive::COUNT); ++i) {
        const auto prim = static_cast<crypto::Primitive>(i);
        const auto& stat = suite_->counters().get(prim);
        if (stat.calls == 0) continue;
        const std::string pre = std::string("prim_") + crypto::primitiveName(prim) + "_";
        recordScalar((pre + "calls").c_str(), static_cast<double>(stat.calls));
        recordScalar((pre + "total_ms").c_str(), stat.totalNs / 1.0e6);
        recordScalar((pre + "mean_us").c_str(), stat.meanNs() / 1000.0);
        recordScalar((pre + "median_us").c_str(), stat.medianNs() / 1000.0);
        recordScalar((pre + "p95_us").c_str(), stat.percentileNs(0.95) / 1000.0);
    }
}

} // namespace nodes
} // namespace uavauth
