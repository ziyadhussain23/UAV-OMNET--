#include "nodes/BaselineGroundStationNode.h"

#include "nodes/BaselineUavNode.h"
#include "nodes/WirelessMedium.h"

namespace uavauth {
namespace nodes {

using namespace omnetpp;
using core::Bytes;

Define_Module(BaselineGroundStationNode);

void BaselineGroundStationNode::initialize(int stage) {
    if (stage != 0) { enrollAll(); return; }

    numUavs_ = par("numUAVs").intValue();
    sigSuiteName_ = par("sigSuite").stdstringValue();
    sigSuite_ = crypto::makeSignatureSuite(sigSuiteName_);

    Bytes seed(32);
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(intrand(256));
    rng_ = std::make_unique<crypto::Drbg>(seed);

    proto_ = std::make_unique<protocol::BaselineGroundStationProtocol>(
        *sigSuite_, symSuite_, *rng_,
        static_cast<uint32_t>(par("timestampWindowMs").intValue()));

    authSuccessSignal_ = registerSignal("authSuccess");
    commOverheadSignal_ = registerSignal("commOverhead");
}

void BaselineGroundStationNode::enrollAll() {
    // One-time public-key exchange, over the trusted enrollment channel --
    // analogous to GroundStationNode::enrollAll()'s PUF interrogation, but
    // this baseline has no physical root of trust to interrogate: a
    // conventional PKI's "enrollment" is registering a public key, not
    // measuring a chip.
    proto_->ensureOwnKeypair();
    for (int i = 0; i < numUavs_; ++i) {
        cModule* mod = getParentModule()->getSubmodule("uav", i);
        if (mod == nullptr) throw cRuntimeError("no uav[%d] submodule", i);
        auto* uav = dynamic_cast<BaselineUavNode*>(mod);
        if (uav == nullptr) throw cRuntimeError("uav[%d] has unexpected type", i);

        uav->ensureOwnKeypair();
        proto_->enrollUav(i, uav->publicKeyBytes());
        uav->provisionGsPublicKey(proto_->publicKeyBytes());
    }
    EV_INFO << "baseline: enrolled " << numUavs_ << " UAVs (sigSuite=" << sigSuiteName_ << ")"
            << endl;
}

void BaselineGroundStationNode::send(const protocol::Message& payload, int destUavId,
                                     const protocol::StepTiming& t) {
    auto* msg = new SimMessage(protocol::messageTypeName(payload.type));
    msg->payload = payload;
    msg->setKind(static_cast<short>(payload.type));
    msg->peer = t;

    cModule* dest = getParentModule()->getSubmodule("uav", destUavId);
    emit(commOverheadSignal_, static_cast<double>(msg->wireBytes()));
    WirelessMedium::get(this)->transmit(msg, this, dest);
}

void BaselineGroundStationNode::handleMessage(cMessage* raw) {
    auto* msg = dynamic_cast<SimMessage*>(raw);
    if (msg == nullptr) { delete raw; return; }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    const double netMs = (simTime() - msg->sentAt).dbl() * 1000.0;
    const int uavId = msg->payload.senderId;

    switch (msg->payload.type) {
        case protocol::MessageType::B1_M1_AUTH_REQUEST: {
            ++authAttempts_;
            const protocol::StepResult r = proto_->handleM1(msg->payload, nowMs);
            Record& rec = records_[uavId];
            rec.m1NetMs = netMs;
            rec.m1ComputeMs = r.timing.computeMs;
            rec.verifyMs += r.timing.verifyMs;
            rec.signMs += r.timing.signMs;
            rec.dhMs += r.timing.dhMs;
            if (!r.ok) {
                rec.abortReason = protocol::abortReasonName(r.abort);
                emit(authSuccessSignal_, 0.0);
                break;
            }
            rec.bytesM2 = r.reply.wireBytes();
            send(r.reply, uavId, r.timing);
            break;
        }
        case protocol::MessageType::B1_M3_UAV_CONFIRM: {
            const protocol::StepResult r = proto_->handleM3(msg->payload, nowMs);
            Record& rec = records_[uavId];
            rec.m3NetMs = netMs;
            rec.m3ComputeMs = r.timing.computeMs;
            rec.dhMs += r.timing.dhMs;
            rec.kdfMs += r.timing.kdfMs;
            rec.macMs += r.timing.macMs;
            if (!r.ok) {
                rec.abortReason = protocol::abortReasonName(r.abort);
                emit(authSuccessSignal_, 0.0);
                break;
            }
            rec.success = true;
            rec.bytesM4 = r.reply.wireBytes();
            ++authSuccesses_;
            emit(authSuccessSignal_, 1.0);
            send(r.reply, uavId, r.timing);
            break;
        }
        default:
            EV_WARN << "baseline ground station ignoring unexpected "
                    << protocol::messageTypeName(msg->payload.type) << endl;
            break;
    }
    delete msg;
}

void BaselineGroundStationNode::finish() {
    recordScalar("numUAVs", numUavs_);
    recordScalar("baselineSuite", sigSuiteName_ == "ecdsa-p256" ? 1.0 : 0.0);
    recordScalar("totalAuthAttempts", authAttempts_);
    recordScalar("totalAuthSuccess", authSuccesses_);
    recordScalar("authSuccessRate",
                 authAttempts_ > 0 ? static_cast<double>(authSuccesses_) / authAttempts_ : 0.0);
    recordScalar("numEnrolled", numUavs_);
    recordScalar("deviceAuthSuccessRate",
                 numUavs_ > 0 ? static_cast<double>(authSuccesses_) / numUavs_ : 0.0);

    for (const auto& entry : records_) {
        const std::string p = "baselineGs_uav_" + std::to_string(entry.first) + "_";
        const Record& r = entry.second;
        recordScalar((p + "success").c_str(), r.success ? 1.0 : 0.0);
        recordScalar((p + "m1_net_ms").c_str(), r.m1NetMs);
        recordScalar((p + "m1_gs_compute_ms").c_str(), r.m1ComputeMs);
        recordScalar((p + "m3_net_ms").c_str(), r.m3NetMs);
        recordScalar((p + "m3_gs_compute_ms").c_str(), r.m3ComputeMs);
        recordScalar((p + "sign_ms").c_str(), r.signMs);
        recordScalar((p + "verify_ms").c_str(), r.verifyMs);
        recordScalar((p + "mac_ms").c_str(), r.macMs);
        recordScalar((p + "kdf_ms").c_str(), r.kdfMs);
        recordScalar((p + "dh_ms").c_str(), r.dhMs);
        recordScalar((p + "bytes_b2").c_str(), static_cast<double>(r.bytesM2));
        recordScalar((p + "bytes_b4").c_str(), static_cast<double>(r.bytesM4));
    }

    for (int i = 0; i < static_cast<int>(crypto::Primitive::COUNT); ++i) {
        const auto prim = static_cast<crypto::Primitive>(i);
        for (const crypto::PrimitiveCounters* counters :
             {&symSuite_.counters(), &sigSuite_->counters()}) {
            const auto& stat = counters->get(prim);
            if (stat.calls == 0) continue;
            const std::string p = std::string("prim_gs_") + crypto::primitiveName(prim) + "_";
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
