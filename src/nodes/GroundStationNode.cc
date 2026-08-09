#include "nodes/GroundStationNode.h"

#include "nodes/UavNode.h"
#include "nodes/WirelessMedium.h"

#include <string>

namespace uavauth {
namespace nodes {

using namespace omnetpp;
using core::Bytes;
using core::fromString;

Define_Module(GroundStationNode);


void GroundStationNode::initialize(int stage) {
    if (stage != 0) { enrollAll(); return; }

    numUavs_ = par("numUAVs").intValue();
    suiteName_ = par("suite").stdstringValue();
    feProfile_ = par("feProfile").stdstringValue();
    timestampWindowMs_ = static_cast<uint32_t>(par("timestampWindowMs").intValue());

    suite_ = crypto::makeCryptoSuite(suiteName_);
    feParams_ = fe::FeParams::profile(feProfile_);
    feParams_.assumedMinEntropyRate = par("assumedMinEntropyRate").doubleValue();

    // Seed the DRBG from the OMNeT++ RNG so an entire run -- including every
    // nonce and ephemeral key -- is reproducible from the configured seed set.
    Bytes seed(32);
    for (size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<uint8_t>(intrand(256));
    rng_ = std::make_unique<crypto::Drbg>(seed);

    proto_ = std::make_unique<protocol::GroundStationProtocol>(*suite_, feParams_, *rng_,
                                                               timestampWindowMs_);
    proto_->setNumUavs(numUavs_);

    authSuccessSignal_ = registerSignal("authSuccess");
    commOverheadSignal_ = registerSignal("commOverhead");
}

void GroundStationNode::enrollAll() {
    for (int i = 0; i < numUavs_; ++i) {
        cModule* mod = getParentModule()->getSubmodule("uav", i);
        if (mod == nullptr) throw cRuntimeError("no uav[%d] submodule", i);
        auto* uav = dynamic_cast<UavNode*>(mod);
        if (uav == nullptr) throw cRuntimeError("uav[%d] has unexpected type", i);

        // Interrogate the device's OWN PUF instance over the trusted enrollment
        // channel, exactly as a factory would: the ground station never holds a
        // copy of the silicon, only the derived master key.
        protocol::DeviceRecord rec;
        protocol::DeviceState state;
        protocol::StepTiming timing;
        const bool ok = proto_->enroll(i, uav->devicePuf(), rec, state, timing);

        GsPhase1Record p1;
        p1.success = ok;
        p1.pufMs = timing.pufMs;
        p1.feMs = timing.feMs;
        p1.totalMs = timing.computeMs;
        p1.challengeBytes = rec.challenge.size();
        for (const Bytes& sk : rec.helper.sketch) p1.helperBytes += sk.size();
        p1.helperBytes += rec.helper.seed.size();
        phase1_[i] = p1;

        if (!ok) throw cRuntimeError("enrollment failed for UAV %d", i);
        uav->provision(state);
    }
    EV_INFO << "enrolled " << numUavs_ << " UAVs (suite=" << suiteName_
            << ", feProfile=" << feProfile_ << ")" << endl;
}

void GroundStationNode::send(protocol::Message&& payload, int destUavId,
                             const protocol::StepTiming& timing) {
    auto* msg = new SimMessage(protocol::messageTypeName(payload.type));
    msg->payload = std::move(payload);
    msg->setKind(static_cast<short>(msg->payload.type));
    msg->peer = timing;

    cModule* dest = getParentModule()->getSubmodule("uav", destUavId);
    emit(commOverheadSignal_, static_cast<double>(msg->wireBytes()));
    WirelessMedium::get(this)->transmit(msg, this, dest);
}

void GroundStationNode::handleMessage(cMessage* raw) {
    auto* msg = dynamic_cast<SimMessage*>(raw);
    if (msg == nullptr) { delete raw; return; }

    const uint32_t nowMs = static_cast<uint32_t>(simTime().dbl() * 1000.0);
    const double netMs = (simTime() - msg->sentAt).dbl() * 1000.0;
    const int uavId = msg->payload.senderId;

    switch (msg->payload.type) {
        case protocol::MessageType::P2_M1_AUTH_REQUEST: {
            ++authAttempts_;
            const protocol::StepResult r = proto_->handleM1(msg->payload, nowMs);
            GsPhase2Record& rec = phase2_[uavId];
            rec.m1NetMs = netMs;
            rec.m1ComputeMs = r.timing.computeMs;
            rec.macMs += r.timing.macMs;
            rec.kdfMs += r.timing.kdfMs;
            rec.dhMs += r.timing.dhMs;
            if (!r.ok) {
                rec.abortReason = protocol::abortReasonName(r.abort);
                emit(authSuccessSignal_, 0.0);
                break;
            }
            rec.bytesM2 = r.reply.wireBytes();
            send(protocol::Message(r.reply), uavId, r.timing);
            break;
        }
        case protocol::MessageType::P2_M3_UAV_CONFIRM: {
            const protocol::StepResult r = proto_->handleM3(msg->payload, nowMs);
            GsPhase2Record& rec = phase2_[uavId];
            rec.m3NetMs = netMs;
            rec.m3ComputeMs = r.timing.computeMs;
            rec.macMs += r.timing.macMs;
            rec.kdfMs += r.timing.kdfMs;
            rec.dhMs += r.timing.dhMs;
            rec.aeadMs += r.timing.aeadMs;
            if (!r.ok) {
                rec.abortReason = protocol::abortReasonName(r.abort);
                emit(authSuccessSignal_, 0.0);
                break;
            }
            rec.success = true;
            rec.bytesM4 = r.reply.wireBytes();
            ++authSuccesses_;
            emit(authSuccessSignal_, 1.0);
            send(protocol::Message(r.reply), uavId, r.timing);
            break;
        }
        default:
            EV_WARN << "ground station ignoring unexpected "
                    << protocol::messageTypeName(msg->payload.type) << endl;
            break;
    }
    delete msg;
}

void GroundStationNode::finish() {
    recordScalar("numUAVs", numUavs_);
    recordScalar("suite", suiteName_ == "spongent" ? 1.0 : 0.0);
    recordScalar("hashMode", suiteName_ == "spongent" ? 1.0 : 0.0);  // legacy name
    recordScalar("totalAuthAttempts", authAttempts_);
    recordScalar("totalAuthSuccess", authSuccesses_);
    // Two different rates, both reported, because they answer different
    // questions. authSuccessRate counts only devices that managed to send M1;
    // deviceAuthSuccessRate counts every enrolled device. They diverge when a
    // device's fuzzy extractor cannot reproduce its master key -- it then never
    // starts the handshake at all, and reporting only the former would hide the
    // reliability failure entirely.
    recordScalar("authSuccessRate",
                 authAttempts_ > 0 ? static_cast<double>(authSuccesses_) / authAttempts_ : 0.0);
    recordScalar("numEnrolled", numUavs_);
    recordScalar("deviceAuthSuccessRate",
                 numUavs_ > 0 ? static_cast<double>(authSuccesses_) / numUavs_ : 0.0);
    recordScalar("feReproductionFailures", numUavs_ - authAttempts_);

    for (const auto& entry : phase1_) {
        const std::string p = "phase1_uav_" + std::to_string(entry.first) + "_";
        recordScalar((p + "puf_eval_ms").c_str(), entry.second.pufMs);
        recordScalar((p + "fe_gen_ms").c_str(), entry.second.feMs);
        recordScalar((p + "total_ms").c_str(), entry.second.totalMs);
        recordScalar((p + "helper_bytes").c_str(), static_cast<double>(entry.second.helperBytes));
        recordScalar((p + "challenge_bytes").c_str(),
                     static_cast<double>(entry.second.challengeBytes));
        recordScalar((p + "success").c_str(), entry.second.success ? 1.0 : 0.0);
    }

    for (const auto& entry : phase2_) {
        const std::string p = "phase2Gs_uav_" + std::to_string(entry.first) + "_";
        const GsPhase2Record& r = entry.second;
        recordScalar((p + "success").c_str(), r.success ? 1.0 : 0.0);
        recordScalar((p + "m1_net_ms").c_str(), r.m1NetMs);
        recordScalar((p + "m1_gs_compute_ms").c_str(), r.m1ComputeMs);
        recordScalar((p + "m3_net_ms").c_str(), r.m3NetMs);
        recordScalar((p + "m3_gs_compute_ms").c_str(), r.m3ComputeMs);
        recordScalar((p + "mac_ms").c_str(), r.macMs);
        recordScalar((p + "kdf_ms").c_str(), r.kdfMs);
        recordScalar((p + "dh_ms").c_str(), r.dhMs);
        recordScalar((p + "aead_ms").c_str(), r.aeadMs);
        recordScalar((p + "bytes_m2").c_str(), static_cast<double>(r.bytesM2));
        recordScalar((p + "bytes_m4").c_str(), static_cast<double>(r.bytesM4));
    }

    // Per-primitive cost, so a vendored primitive is never silently compared
    // against an assembly-optimised one.
    for (int i = 0; i < static_cast<int>(crypto::Primitive::COUNT); ++i) {
        const auto prim = static_cast<crypto::Primitive>(i);
        const auto& stat = suite_->counters().get(prim);
        if (stat.calls == 0) continue;
        const std::string p = std::string("prim_gs_") + crypto::primitiveName(prim) + "_";
        recordScalar((p + "calls").c_str(), static_cast<double>(stat.calls));
        recordScalar((p + "total_ms").c_str(), stat.totalNs / 1.0e6);
        recordScalar((p + "mean_us").c_str(), stat.meanNs() / 1000.0);
        recordScalar((p + "median_us").c_str(), stat.medianNs() / 1000.0);
        recordScalar((p + "p95_us").c_str(), stat.percentileNs(0.95) / 1000.0);
    }
}

} // namespace nodes
} // namespace uavauth
