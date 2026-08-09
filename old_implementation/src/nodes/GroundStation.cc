#include "GroundStation.h"

#include "../crypto/CryptoUtils.h"
#include "../crypto/PUFSimulator.h"

#include <algorithm>
#include <cmath>

using namespace omnetpp;
using uavauth::protocols::MessageType;
using uavauth::protocols::ProtocolMessage;

Define_Module(GroundStation);

GroundStation::GroundStation()
    : numUavs(0),
      numCrpsPerUav(12),
      pufSeedBase(1000),
      responseDistanceThreshold(20),
      defaultPufNoise(0.03),
      timestampWindowMs(5000),
      linkBitrateBps(6e6),
      propagationSpeedMps(299792458.0),
      processingDelayMean(0),
      queueJitterStddev(0),
      enableRandomJitter(true),
      hashModeStr("sha3"),
      hashMode(uavauth::crypto::HashMode::SHA3),
      totalAuthAttempts(0),
      totalAuthSuccess(0),
      phase2GsComputeMsTotal(0.0),
      phase2GsComputeSamples(0),
      phase2GsSha3MsTotal(0.0),
      phase2GsSpongentMsTotal(0.0),
      enrollment(nullptr),
      bchCodec(255, 131, 18) {}

GroundStation::~GroundStation() {
    delete enrollment;
    enrollment = nullptr;
}

void GroundStation::initialize() {
    numUavs = par("numUAVs").intValue();
    numCrpsPerUav = par("numCRPsPerUAV").intValue();
    pufSeedBase = par("pufSeedBase").intValue();
    responseDistanceThreshold = par("responseDistanceThreshold").intValue();
    defaultPufNoise = par("defaultPUFNoise").doubleValue();
    timestampWindowMs = static_cast<uint32_t>(par("timestampWindowMs").intValue());

    linkBitrateBps = par("linkBitrateBps").doubleValue();
    propagationSpeedMps = par("propagationSpeedMps").doubleValue();
    processingDelayMean = par("processingDelayMean");
    queueJitterStddev = par("queueJitterStddev");
    enableRandomJitter = par("enableRandomJitter").boolValue();

    // Hash mode configuration.
    hashModeStr = par("hashMode").stdstringValue();
    if (hashModeStr == "spongent") {
        hashMode = uavauth::crypto::HashMode::SPONGENT;
    } else {
        hashMode = uavauth::crypto::HashMode::SHA3;
    }
    phase2.setHashMode(hashMode);

    enrollment = new uavauth::protocols::Phase1Enrollment(numCrpsPerUav);
    for (int i = 0; i < numUavs; ++i) {
        enrollment->enrollUAV(i, pufSeedBase + i, defaultPufNoise);
    }

    networkCredential = randomBytes(20);

    // Warmup: absorb first-call initialization overhead.
    {
        const std::vector<uint8_t> dummy(16, 0);
        phase2.warmupHash(dummy);
    }

    authSuccessSignal = registerSignal("authSuccess");
    commOverheadSignal = registerSignal("commOverhead");

    EV_INFO << "[GS] Enrollment complete for " << numUavs << " UAVs, hashMode=" << hashModeStr << "\n";
}

void GroundStation::handleMessage(cMessage* msg) {
    auto* protocolMsg = dynamic_cast<ProtocolMessage*>(msg);
    if (protocolMsg == nullptr) {
        delete msg;
        return;
    }

    switch (protocolMsg->type) {
        case MessageType::AUTH_REQUEST:
            onAuthRequest(protocolMsg);
            break;
        case MessageType::PUF_RESPONSE:
            onPufResponse(protocolMsg);
            break;
        default:
            break;
    }

    delete protocolMsg;
}

void GroundStation::finish() {
    const double successRate = totalAuthAttempts == 0
                                   ? 0.0
                                   : static_cast<double>(totalAuthSuccess) / static_cast<double>(totalAuthAttempts);
    const double phase2GsComputeMsMean =
        phase2GsComputeSamples == 0 ? 0.0 : phase2GsComputeMsTotal / static_cast<double>(phase2GsComputeSamples);

    recordScalar("hashMode", hashModeStr == "spongent" ? 1.0 : 0.0);
    recordScalar("totalAuthAttempts", totalAuthAttempts);
    recordScalar("totalAuthSuccess", totalAuthSuccess);
    recordScalar("authSuccessRate", successRate);
    recordScalar("phase2GsComputeMsTotal", phase2GsComputeMsTotal);
    recordScalar("phase2GsComputeMsMean", phase2GsComputeMsMean);
    recordScalar("phase2GsSha3MsTotal", phase2GsSha3MsTotal);
    recordScalar("phase2GsSpongentMsTotal", phase2GsSpongentMsTotal);

    for (const auto& [uavId, m] : phase2MetricsByUav) {
        const std::string prefix = "phase2Gs_uav_" + std::to_string(uavId) + "_";
        recordScalar((prefix + "m1_net_ms").c_str(), m.m1NetMs);
        recordScalar((prefix + "m1_gs_compute_ms").c_str(), m.m1GsComputeMs);
        recordScalar((prefix + "m3_net_ms").c_str(), m.m3NetMs);
        recordScalar((prefix + "m3_gs_compute_ms").c_str(), m.m3GsComputeMs);
        recordScalar((prefix + "bch_ms").c_str(), m.bchMs);
        recordScalar((prefix + "sha3_ms").c_str(), m.sha3Ms);
        recordScalar((prefix + "spongent_ms").c_str(), m.spongentMs);
        recordScalar((prefix + "success").c_str(), m.success ? 1 : 0);
    }
}

std::vector<uint8_t> GroundStation::randomBytes(size_t size) const {
    std::vector<uint8_t> out(size, 0);
    for (size_t i = 0; i < size; ++i) {
        out[i] = static_cast<uint8_t>(intrand(256));
    }
    return out;
}

uint32_t GroundStation::nowMillis() const {
    return static_cast<uint32_t>(simTime().dbl() * 1000.0);
}

uint64_t GroundStation::nowMicros() const {
    return static_cast<uint64_t>(simTime().dbl() * 1000000.0);
}

double GroundStation::elapsedMs(const std::chrono::steady_clock::time_point& start) {
    const auto now = std::chrono::steady_clock::now();
    const auto delta = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(now - start);
    return delta.count();
}

size_t GroundStation::estimateMessageBytes(const ProtocolMessage* msg) const {
    size_t bytes = 0;
    bytes += msg->tempId.size();
    bytes += sizeof(uint32_t);
    bytes += msg->field1.size();
    bytes += msg->field2.size();
    bytes += msg->field3.size();
    return bytes;
}

double GroundStation::getDisplayCoord(const cModule* module, int axis) {
    const char* value = module->getDisplayString().getTagArg("p", axis);
    if (value == nullptr || value[0] == '\0') {
        return 0.0;
    }
    try {
        return std::stod(value);
    } catch (...) {
        return 0.0;
    }
}

simtime_t GroundStation::computeLinkDelay(const cModule* destination, size_t payloadBytes) const {
    const double x1 = getDisplayCoord(this, 0);
    const double y1 = getDisplayCoord(this, 1);
    const double x2 = getDisplayCoord(destination, 0);
    const double y2 = getDisplayCoord(destination, 1);

    const double dx = x1 - x2;
    const double dy = y1 - y2;
    const double distanceMeters = std::sqrt(dx * dx + dy * dy);

    const double propDelay = propagationSpeedMps > 0.0 ? (distanceMeters / propagationSpeedMps) : 0.0;
    const double serDelay = linkBitrateBps > 0.0 ? (8.0 * static_cast<double>(payloadBytes) / linkBitrateBps) : 0.0;

    double jitter = 0.0;
    if (enableRandomJitter && queueJitterStddev > SIMTIME_ZERO) {
        jitter = std::max(0.0, normal(0.0, queueJitterStddev.dbl()));
    }

    const double proc = processingDelayMean > SIMTIME_ZERO ? processingDelayMean.dbl() : 0.0;

    return propDelay + serDelay + proc + jitter;
}

void GroundStation::onAuthRequest(const ProtocolMessage* msg) {
    const auto t0 = std::chrono::steady_clock::now();

    ++totalAuthAttempts;

    const uint32_t now = nowMillis();
    const uint32_t age = now >= msg->timestamp ? (now - msg->timestamp) : (msg->timestamp - now);
    double m1NetMs = 0.0;
    if (msg->sentAtUs > 0) {
        m1NetMs = static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0;
    }
    if (age > timestampWindowMs) {
        EV_WARN << "[GS] Rejecting stale auth request from tempId=" << msg->tempId << "\n";
        emit(authSuccessSignal, 0.0);
        return;
    }

    if (!enrollment->hasTempId(msg->tempId)) {
        EV_WARN << "[GS] Unknown tempId=" << msg->tempId << "\n";
        emit(authSuccessSignal, 0.0);
        return;
    }

    const bool hashOk =
        phase2.verifyAuthRequest(msg->tempId, msg->timestamp, msg->field1, msg->field2);
    if (!hashOk) {
        EV_WARN << "[GS] Invalid auth hash for tempId=" << msg->tempId << "\n";
        emit(authSuccessSignal, 0.0);
        return;
    }

    const int uavId = enrollment->resolveTempId(msg->tempId);
    const auto& crp = enrollment->getCurrentCRP(uavId);

    PendingAuthContext pending;
    pending.uavId = uavId;
    pending.tempId = msg->tempId;
    pending.timestamp = nowMillis();
    pending.nonceUav = msg->field1;
    pending.nonceGs = randomBytes(16);
    pending.expectedResponse = crp.response;
    pending.helperData = crp.helperData;
    pending.m1NetMs = m1NetMs;

    const std::vector<uint8_t> mac =
        phase2.computeChallengeMac(msg->tempId, crp.challenge, pending.nonceGs, pending.timestamp);
    pending.m1GsSha3Ms = 0.0;
    pending.m1GsSpongentMs = 0.0;

    auto* challenge = new ProtocolMessage("ChallengeIssuance", MessageType::CHALLENGE_ISSUANCE);
    challenge->senderId = -1;
    challenge->receiverId = uavId;
    challenge->tempId = msg->tempId;
    challenge->timestamp = pending.timestamp;
    challenge->sentAtUs = nowMicros();
    challenge->field1 = crp.challenge;
    challenge->field2 = pending.nonceGs;
    challenge->field3 = mac;

    pending.m1GsComputeMs = elapsedMs(t0);
    challenge->metricA = pending.m1NetMs;
    challenge->metricB = pending.m1GsComputeMs;

    pendingByUav[uavId] = pending;

    sendToUav(uavId, challenge);
    emitCommOverheadBytes(crp.challenge.size() + pending.nonceGs.size() + mac.size());

    phase2GsComputeMsTotal += elapsedMs(t0);
    ++phase2GsComputeSamples;
}

void GroundStation::onPufResponse(const ProtocolMessage* msg) {
    const auto t0 = std::chrono::steady_clock::now();

    const int uavId = msg->senderId;
    auto pendingIt = pendingByUav.find(uavId);
    if (pendingIt == pendingByUav.end()) {
        EV_WARN << "[GS] No pending auth context for UAV " << uavId << "\n";
        emit(authSuccessSignal, 0.0);
        return;
    }

    const PendingAuthContext& pending = pendingIt->second;

    double m3NetMs = 0.0;
    if (msg->sentAtUs > 0) {
        m3NetMs = static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0;
    }

    const std::vector<uint8_t> unmasked = phase2.unmaskResponse(msg->field1, pending.nonceGs);

    // Recover ECC parity: ecc = helperData XOR R_noisy (fuzzy extractor Gen/Rep scheme)
    std::vector<uint8_t> eccParity = pending.helperData;
    for (size_t b = 0; b < eccParity.size() && b < unmasked.size(); ++b) {
        eccParity[b] ^= unmasked[b];
    }

    const auto tBch = std::chrono::steady_clock::now();
    const std::vector<uint8_t> corrected = bchCodec.decode(unmasked, eccParity);
    const double bchMs = elapsedMs(tBch);

    const std::vector<uint8_t> sessionKey =
        phase2.deriveSessionKey(corrected, pending.nonceUav, pending.nonceGs, pending.timestamp);
    const bool tokenOk = phase2.verifyAuthToken(msg->field1, sessionKey, msg->field2);

    const int responseDistance = uavauth::crypto::PUFSimulator::hammingDistance(corrected, pending.expectedResponse);
    const bool responseOk = responseDistance <= responseDistanceThreshold;

    const bool success = tokenOk && responseOk;
    if (success) {
        ++totalAuthSuccess;
        enrollment->advanceCRP(uavId);
    }

    const double m3GsComputeMs = elapsedMs(t0);

    auto* confirmation = new ProtocolMessage("AuthConfirmation", MessageType::AUTH_CONFIRMATION);
    confirmation->senderId = -1;
    confirmation->receiverId = uavId;
    confirmation->timestamp = nowMillis();
    confirmation->sentAtUs = nowMicros();
    confirmation->success = success;
    confirmation->metricA = m3NetMs;
    confirmation->metricB = m3GsComputeMs;
    confirmation->metricC = bchMs;
    if (success) {
        confirmation->field1 = networkCredential;
    }

    sendToUav(uavId, confirmation);
    emitCommOverheadBytes(confirmation->field1.size() + 1);
    emit(authSuccessSignal, success ? 1.0 : 0.0);

    const double totalSha3Ms = 0.0;
    const double totalSpongentMs = 0.0;

    phase2MetricsByUav[uavId] = {
        pending.m1NetMs,
        pending.m1GsComputeMs,
        m3NetMs,
        m3GsComputeMs,
        bchMs,
        totalSha3Ms,
        totalSpongentMs,
        success,
    };

    pendingByUav.erase(pendingIt);

    phase2GsComputeMsTotal += pending.m1GsComputeMs + m3GsComputeMs;
    ++phase2GsComputeSamples;
}

void GroundStation::sendToUav(int uavId, ProtocolMessage* msg) {
    cModule* uav = getParentModule()->getSubmodule("uav", uavId);
    if (uav == nullptr) {
        delete msg;
        EV_WARN << "[GS] UAV " << uavId << " not found\n";
        return;
    }

    sendDirect(msg, computeLinkDelay(uav, estimateMessageBytes(msg)), SIMTIME_ZERO, uav, "in");
}

void GroundStation::emitCommOverheadBytes(size_t bytes) {
    emit(commOverheadSignal, static_cast<double>(bytes));
}
