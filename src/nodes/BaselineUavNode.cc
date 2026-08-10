#include "nodes/BaselineUavNode.h"

#include "nodes/WirelessMedium.h"

namespace uavauth {
namespace nodes {

using namespace omnetpp;
using core::Bytes;

Define_Module(BaselineUavNode);

void BaselineUavNode::initialize(int stage) {
    if (stage == 0) {
        uavId_ = par("uavId").intValue();
        sigSuiteName_ = par("sigSuite").stdstringValue();
        sigSuite_ = crypto::makeSignatureSuite(sigSuiteName_);

        Bytes rngSeed(32);
        for (size_t i = 0; i < rngSeed.size(); ++i)
            rngSeed[i] = static_cast<uint8_t>(intrand(256));
        rng_ = std::make_unique<crypto::Drbg>(rngSeed);

        proto_ = std::make_unique<protocol::BaselineUavProtocol>(
            uavId_, *sigSuite_, symSuite_, *rng_,
            static_cast<uint32_t>(par("timestampWindowMs").intValue()));

        authLatencySignal_ = registerSignal("authLatency");
        commOverheadSignal_ = registerSignal("commOverhead");
        return;
    }

    // Stage 1: BaselineGroundStationNode's own stage-1 enrollAll() has already
    // run by the time any module reaches its own stage 1 (OMNeT++ completes
    // every module's every init stage, in order, before advancing -- the same
    // guarantee UavNode/GroundStationNode already rely on), so the public-key
    // exchange is complete and the handshake can be scheduled.
    const simtime_t authStart = par("authStartTime").doubleValue();
    scheduleAt(simTime() + authStart, new cMessage("startBaselineAuth"));
}

void BaselineUavNode::send(const protocol::Message& payload, const protocol::StepTiming& t) {
    auto* msg = new SimMessage(protocol::messageTypeName(payload.type));
    msg->payload = payload;
    msg->setKind(static_cast<short>(payload.type));
    msg->peer = t;
    emit(commOverheadSignal_, static_cast<double>(msg->wireBytes()));
    rec_.overheadBytes += msg->wireBytes();
    WirelessMedium::get(this)->transmit(msg, this,
                                        getParentModule()->getSubmodule("groundStation"));
}

void BaselineUavNode::handleMessage(cMessage* raw) {
    if (raw->isSelfMessage()) {
        delete raw;
        phase2Start_ = simTime();
        const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
        const protocol::StepResult r = proto_->startPhase2(nowMs);
        rec_.m1ComputeMs = r.timing.computeMs;
        rec_.signMs += r.timing.signMs;
        rec_.dhMs += r.timing.dhMs;
        if (!r.ok) {
            rec_.abortReason = protocol::abortReasonName(r.abort);
            return;
        }
        rec_.bytesM1 = r.reply.wireBytes();
        send(r.reply, r.timing);
        return;
    }

    auto* msg = dynamic_cast<SimMessage*>(raw);
    if (msg == nullptr) { delete raw; return; }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    const double netMs = (simTime() - msg->sentAt).dbl() * 1000.0;

    switch (msg->payload.type) {
        case protocol::MessageType::B1_M2_GS_RESPONSE: {
            rec_.m2NetMs = netMs;
            rec_.bytesM2 = msg->wireBytes();
            rec_.overheadBytes += msg->wireBytes();
            const protocol::StepResult r = proto_->handleM2(msg->payload, nowMs);
            rec_.m2VerifyMs = r.timing.computeMs;
            rec_.verifyMs += r.timing.verifyMs;
            rec_.dhMs += r.timing.dhMs;
            rec_.kdfMs += r.timing.kdfMs;
            rec_.macMs += r.timing.macMs;
            if (!r.ok) {
                rec_.abortReason = protocol::abortReasonName(r.abort);
                break;
            }
            rec_.bytesM3 = r.reply.wireBytes();
            rec_.m3ComputeMs = r.timing.computeMs;
            send(r.reply, r.timing);
            break;
        }
        case protocol::MessageType::B1_M4_GS_CONFIRM: {
            rec_.m4NetMs = netMs;
            rec_.bytesM4 = msg->wireBytes();
            rec_.overheadBytes += msg->wireBytes();
            const protocol::StepResult r = proto_->handleM4(msg->payload, nowMs);
            rec_.m4ComputeMs = r.timing.computeMs;
            rec_.macMs += r.timing.macMs;
            if (!r.ok) {
                rec_.abortReason = protocol::abortReasonName(r.abort);
                break;
            }
            rec_.success = true;
            rec_.wallLatencyMs = (simTime() - phase2Start_).dbl() * 1000.0;
            emit(authLatencySignal_, rec_.wallLatencyMs);
            break;
        }
        default:
            break;
    }

    delete msg;
}

void BaselineUavNode::finish() {
    recordScalar("uavId", uavId_);
    recordScalar("baselineSuite", sigSuiteName_ == "ecdsa-p256" ? 1.0 : 0.0);

    const double compute = rec_.m1ComputeMs + rec_.m2VerifyMs + rec_.m3ComputeMs + rec_.m4ComputeMs;
    const double net = rec_.m1NetMs + rec_.m2NetMs + rec_.m3NetMs + rec_.m4NetMs;

    recordScalar("baselineSuccess", rec_.success ? 1.0 : 0.0);
    recordScalar("baselineComputeMs", compute);
    recordScalar("baselineNetMs", net);
    recordScalar("baselineWallLatencyMs", rec_.wallLatencyMs);
    recordScalar("baselineOverheadBytes", static_cast<double>(rec_.overheadBytes));
    recordScalar("baseline_sign_ms", rec_.signMs);
    recordScalar("baseline_verify_ms", rec_.verifyMs);
    recordScalar("baseline_mac_ms", rec_.macMs);
    recordScalar("baseline_kdf_ms", rec_.kdfMs);
    recordScalar("baseline_dh_ms", rec_.dhMs);
    recordScalar("bytes_b1", static_cast<double>(rec_.bytesM1));
    recordScalar("bytes_b2", static_cast<double>(rec_.bytesM2));
    recordScalar("bytes_b3", static_cast<double>(rec_.bytesM3));
    recordScalar("bytes_b4", static_cast<double>(rec_.bytesM4));
    recordScalar("baseline_replay_cache_hits", static_cast<double>(proto_->replayHits()));

    // Per-primitive cost for BOTH counter sets (the symmetric KDF/MAC/DH suite
    // and the asymmetric Sign/Verify suite), using the exact "prim_<name>_..."
    // naming convention the existing exporter already parses generically --
    // no exporter change needed for these new primitives to flow into
    // omnet_primitive_costs.csv.
    for (int i = 0; i < static_cast<int>(crypto::Primitive::COUNT); ++i) {
        const auto prim = static_cast<crypto::Primitive>(i);
        for (const crypto::PrimitiveCounters* counters :
             {&symSuite_.counters(), &sigSuite_->counters()}) {
            const auto& stat = counters->get(prim);
            if (stat.calls == 0) continue;
            const std::string p = std::string("prim_") + crypto::primitiveName(prim) + "_";
            recordScalar((p + "calls").c_str(), static_cast<double>(stat.calls));
            recordScalar((p + "total_ms").c_str(), stat.totalNs / 1.0e6);
            recordScalar((p + "mean_us").c_str(), stat.meanNs() / 1000.0);
            recordScalar((p + "median_us").c_str(), stat.medianNs() / 1000.0);
            recordScalar((p + "p95_us").c_str(), stat.percentileNs(0.95) / 1000.0);
        }
    }
}

} // namespace nodes
} // namespace uavauth
