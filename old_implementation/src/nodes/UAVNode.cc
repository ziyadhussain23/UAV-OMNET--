#include "UAVNode.h"

#include <algorithm>
#include <cmath>

using namespace omnetpp;
using uavauth::protocols::MessageType;
using uavauth::protocols::ProtocolMessage;

Define_Module(UAVNode);

UAVNode::UAVNode()
    : uavId(-1),
      pufSeed(0),
      peerTargetId(-1),
      pufNoiseLevel(0.03),
      hashModeStr("sha3"),
      hashMode(uavauth::crypto::HashMode::SHA3),
      authStartTime(SIMTIME_ZERO),
      peerAuthStartTime(SIMTIME_ZERO),
      linkBitrateBps(6e6),
      propagationSpeedMps(299792458.0),
      processingDelayMean(SIMTIME_ZERO),
      queueJitterStddev(SIMTIME_ZERO),
      enableRandomJitter(true),
      phase2Authenticated(false),
      puf(nullptr),
      phase2StartTs(SIMTIME_ZERO),
      phase2ComputeMs(0.0),
      phase2NetMs(0.0),
      phase2LatencyMs(0.0),
      phase2Success(false),
      phase2OverheadBytes(0),
      phase2Sha3ComputeMs(0.0),
      phase2SpongentComputeMs(0.0),
      m1UavComputeMs(0.0),
      m1GsComputeMs(0.0),
      m1NetMs(0.0),
      m2UavVerifyMs(0.0),
      m2NetMs(0.0),
      pufEvalMs(0.0),
      bchMs(0.0),
      m3CryptoMs(0.0),
      m3UavComputeMs(0.0),
      m3GsComputeMs(0.0),
      m3NetMs(0.0),
      m4UavComputeMs(0.0),
      m4NetMs(0.0),
      m1UavSha3Ms(0.0),
      m1UavSpongentMs(0.0),
      m3CryptoSha3Ms(0.0),
      m3CryptoSpongentMs(0.0),
      phase3ResponderPeerId(-1),
      responderP1P2JComputeMs(0.0),
      responderP3JComputeMs(0.0),
      responderP3NetMs(0.0) {}

UAVNode::~UAVNode() {
    delete puf;
    puf = nullptr;
}

void UAVNode::initialize() {
    uavId = par("uavId").intValue();
    pufSeed = par("pufSeed").intValue();
    pufNoiseLevel = par("pufNoiseLevel").doubleValue();
    tempId = par("tempId").stdstringValue();
    peerTargetId = par("peerTargetId").intValue();

    // Hash mode configuration (sha3 or spongent).
    hashModeStr = par("hashMode").stdstringValue();
    if (hashModeStr == "spongent") {
        hashMode = uavauth::crypto::HashMode::SPONGENT;
    } else {
        hashMode = uavauth::crypto::HashMode::SHA3;
    }
    phase2.setHashMode(hashMode);
    phase3.setHashMode(hashMode);

    authStartTime = par("authStartTime");
    peerAuthStartTime = par("peerAuthStartTime");

    linkBitrateBps = par("linkBitrateBps").doubleValue();
    propagationSpeedMps = par("propagationSpeedMps").doubleValue();
    processingDelayMean = par("processingDelayMean");
    queueJitterStddev = par("queueJitterStddev");
    enableRandomJitter = par("enableRandomJitter").boolValue();

    puf = new uavauth::crypto::PUFSimulator(pufSeed, pufNoiseLevel, 128, 128);

    authLatencySignal = registerSignal("authLatency");
    commOverheadSignal = registerSignal("commOverhead");
    peerAuthLatencySignal = registerSignal("peerAuthLatency");

    // Warmup: absorb first-call initialization overhead (OpenSSL EVP setup, SPONGENT
    // table init) so it does not skew the timing of UAV 0's first real auth.
    {
        const std::vector<uint8_t> dummy(16, 0);
        phase2.warmupHash(dummy);
        phase3.warmupHash(dummy);
    }

    scheduleAt(simTime() + authStartTime, new cMessage("phase2Start"));

    EV_INFO << "[UAV " << uavId << "] initialized with tempId=" << tempId
            << ", hashMode=" << hashModeStr << "\n";
}

void UAVNode::handleMessage(cMessage* msg) {
    if (msg->isSelfMessage()) {
        const std::string name = msg->getName();
        delete msg;

        if (name == "phase2Start") {
            startPhase2Authentication();
        } else if (name == "phase3Start") {
            startPhase3Authentication();
        }
        return;
    }

    auto* protocolMsg = dynamic_cast<ProtocolMessage*>(msg);
    if (protocolMsg == nullptr) {
        delete msg;
        return;
    }

    switch (protocolMsg->type) {
        case MessageType::CHALLENGE_ISSUANCE:
            onChallengeIssuance(protocolMsg);
            break;
        case MessageType::AUTH_CONFIRMATION:
            onAuthConfirmation(protocolMsg);
            break;
        case MessageType::PEER_AUTH_REQUEST:
            onPeerAuthRequest(protocolMsg);
            break;
        case MessageType::PEER_AUTH_RESPONSE:
            onPeerAuthResponse(protocolMsg);
            break;
        case MessageType::PEER_AUTH_COMPLETE:
            onPeerAuthComplete(protocolMsg);
            break;
        default:
            break;
    }

    delete protocolMsg;
}

void UAVNode::finish() {
    recordScalar("isPhase2Authenticated", phase2Authenticated ? 1 : 0);
    recordScalar("numPeerSessionKeys", static_cast<double>(peerSessionKeys.size()));
    recordScalar("hashMode", hashModeStr == "spongent" ? 1.0 : 0.0);

    recordScalar("phase2Success", phase2Success ? 1 : 0);
    recordScalar("phase2ComputeMs", phase2ComputeMs);
    recordScalar("phase2NetMs", phase2NetMs);
    recordScalar("phase2LatencyMs", phase2LatencyMs);
    recordScalar("phase2OverheadBytes", static_cast<double>(phase2OverheadBytes));

    // Dual-mode timing.
    recordScalar("phase2Sha3ComputeMs", phase2Sha3ComputeMs);
    recordScalar("phase2SpongentComputeMs", phase2SpongentComputeMs);

    recordScalar("m1_uav_compute_ms", m1UavComputeMs);
    recordScalar("m1_gs_compute_ms", m1GsComputeMs);
    recordScalar("m1_net_ms", m1NetMs);
    recordScalar("m2_uav_verify_ms", m2UavVerifyMs);
    recordScalar("m2_net_ms", m2NetMs);
    recordScalar("puf_eval_ms", pufEvalMs);
    recordScalar("bch_ms", bchMs);
    recordScalar("m3_crypto_ms", m3CryptoMs);
    recordScalar("m3_uav_compute_ms", m3UavComputeMs);
    recordScalar("m3_gs_compute_ms", m3GsComputeMs);
    recordScalar("m3_net_ms", m3NetMs);
    recordScalar("m4_uav_compute_ms", m4UavComputeMs);
    recordScalar("m4_net_ms", m4NetMs);

    // Dual-mode step metrics.
    recordScalar("m1_uav_sha3_ms", m1UavSha3Ms);
    recordScalar("m1_uav_spongent_ms", m1UavSpongentMs);
    recordScalar("m3_crypto_sha3_ms", m3CryptoSha3Ms);
    recordScalar("m3_crypto_spongent_ms", m3CryptoSpongentMs);

    // Phase 3: record per-peer metrics for all initiated pairs.
    int numPhase3Peers = 0;
    for (const auto& [peerId, computeMs] : phase3ComputeMsByPeer) {
        const std::string prefix = "phase3_peer_" + std::to_string(peerId) + "_";

        const bool success = phase3SuccessByPeer.count(peerId) ? phase3SuccessByPeer[peerId] : false;
        const double netMs = phase3NetMsByPeer.count(peerId) ? phase3NetMsByPeer[peerId] : 0.0;
        const double latencyMs = phase3LatencyMsByPeer.count(peerId) ? phase3LatencyMsByPeer[peerId] : 0.0;
        const double overheadBytes = phase3OverheadBytesByPeer.count(peerId)
                                         ? static_cast<double>(phase3OverheadBytesByPeer[peerId])
                                         : 0.0;

        recordScalar((prefix + "success").c_str(), success ? 1 : 0);
        recordScalar((prefix + "compute_ms").c_str(), computeMs);
        recordScalar((prefix + "net_ms").c_str(), netMs);
        recordScalar((prefix + "latency_ms").c_str(), latencyMs);
        recordScalar((prefix + "overhead_bytes").c_str(), overheadBytes);
        recordScalar((prefix + "sha3_ms").c_str(),
                     phase3Sha3MsByPeer.count(peerId) ? phase3Sha3MsByPeer[peerId] : 0.0);
        recordScalar((prefix + "spongent_ms").c_str(),
                     phase3SpongentMsByPeer.count(peerId) ? phase3SpongentMsByPeer[peerId] : 0.0);

        recordScalar((prefix + "p1_i_compute_ms").c_str(),
                     phase3P1IComputeMsByPeer.count(peerId) ? phase3P1IComputeMsByPeer[peerId] : 0.0);
        recordScalar((prefix + "p1_p2_j_compute_ms").c_str(),
                     phase3P1P2JComputeMsByPeer.count(peerId) ? phase3P1P2JComputeMsByPeer[peerId] : 0.0);
        recordScalar((prefix + "p1_net_ms").c_str(),
                     phase3P1NetMsByPeer.count(peerId) ? phase3P1NetMsByPeer[peerId] : 0.0);
        recordScalar((prefix + "p2_p3_i_compute_ms").c_str(),
                     phase3P2P3IComputeMsByPeer.count(peerId) ? phase3P2P3IComputeMsByPeer[peerId] : 0.0);
        recordScalar((prefix + "p2_net_ms").c_str(),
                     phase3P2NetMsByPeer.count(peerId) ? phase3P2NetMsByPeer[peerId] : 0.0);
        recordScalar((prefix + "p3_j_compute_ms").c_str(),
                     phase3P3JComputeMsByPeer.count(peerId) ? phase3P3JComputeMsByPeer[peerId] : 0.0);
        recordScalar((prefix + "p3_net_ms").c_str(),
                     phase3P3NetMsByPeer.count(peerId) ? phase3P3NetMsByPeer[peerId] : 0.0);

        if (success) ++numPhase3Peers;
    }

    // Phase 3: record responder-side per-peer metrics (where this UAV was responder).
    for (const auto& [requesterId, p3JMs] : phase3P3JComputeMsByPeer) {
        // Only record if this UAV was NOT the initiator for this peer (avoid double-recording).
        if (phase3ComputeMsByPeer.count(requesterId)) continue;
        const std::string prefix = "phase3_resp_" + std::to_string(requesterId) + "_";
        recordScalar((prefix + "p3_j_compute_ms").c_str(), p3JMs);
        recordScalar((prefix + "p3_net_ms").c_str(),
                     phase3P3NetMsByPeer.count(requesterId) ? phase3P3NetMsByPeer[requesterId] : 0.0);
        recordScalar((prefix + "sha3_ms").c_str(),
                     responderSha3MsByPeer.count(requesterId) ? responderSha3MsByPeer[requesterId] : 0.0);
        recordScalar((prefix + "spongent_ms").c_str(),
                     responderSpongentMsByPeer.count(requesterId) ? responderSpongentMsByPeer[requesterId] : 0.0);
    }

    // Also record backward-compatible single-peer scalars using first initiated peer.
    int primaryPeerId = -1;
    if (!phase3ComputeMsByPeer.empty()) {
        primaryPeerId = phase3ComputeMsByPeer.begin()->first;
    }

    double phase3ComputeMs = 0.0, phase3NetMs = 0.0, phase3LatencyMs = 0.0;
    double phase3OverheadBytes = 0.0;
    bool phase3Success = false;
    double p1IComputeMs = 0.0, p1P2JComputeMs = 0.0, p1NetMs = 0.0;
    double p2P3IComputeMs = 0.0, p2NetMs = 0.0, p3JComputeMs = 0.0, p3NetMs = 0.0;
    double primarySha3Ms = 0.0, primarySpongentMs = 0.0;

    if (primaryPeerId >= 0) {
        if (phase3ComputeMsByPeer.count(primaryPeerId)) phase3ComputeMs = phase3ComputeMsByPeer[primaryPeerId];
        if (phase3NetMsByPeer.count(primaryPeerId)) phase3NetMs = phase3NetMsByPeer[primaryPeerId];
        if (phase3LatencyMsByPeer.count(primaryPeerId)) phase3LatencyMs = phase3LatencyMsByPeer[primaryPeerId];
        if (phase3OverheadBytesByPeer.count(primaryPeerId)) phase3OverheadBytes = static_cast<double>(phase3OverheadBytesByPeer[primaryPeerId]);
        if (phase3SuccessByPeer.count(primaryPeerId)) phase3Success = phase3SuccessByPeer[primaryPeerId];
        if (phase3P1IComputeMsByPeer.count(primaryPeerId)) p1IComputeMs = phase3P1IComputeMsByPeer[primaryPeerId];
        if (phase3P1P2JComputeMsByPeer.count(primaryPeerId)) p1P2JComputeMs = phase3P1P2JComputeMsByPeer[primaryPeerId];
        if (phase3P1NetMsByPeer.count(primaryPeerId)) p1NetMs = phase3P1NetMsByPeer[primaryPeerId];
        if (phase3P2P3IComputeMsByPeer.count(primaryPeerId)) p2P3IComputeMs = phase3P2P3IComputeMsByPeer[primaryPeerId];
        if (phase3P2NetMsByPeer.count(primaryPeerId)) p2NetMs = phase3P2NetMsByPeer[primaryPeerId];
        if (phase3P3JComputeMsByPeer.count(primaryPeerId)) p3JComputeMs = phase3P3JComputeMsByPeer[primaryPeerId];
        if (phase3P3NetMsByPeer.count(primaryPeerId)) p3NetMs = phase3P3NetMsByPeer[primaryPeerId];
        if (phase3Sha3MsByPeer.count(primaryPeerId)) primarySha3Ms = phase3Sha3MsByPeer[primaryPeerId];
        if (phase3SpongentMsByPeer.count(primaryPeerId)) primarySpongentMs = phase3SpongentMsByPeer[primaryPeerId];
    }

    recordScalar("numPhase3Peers", static_cast<double>(numPhase3Peers));
    recordScalar("phase3PeerId", static_cast<double>(primaryPeerId));
    recordScalar("phase3Success", phase3Success ? 1 : 0);
    recordScalar("phase3ComputeMs", phase3ComputeMs);
    recordScalar("phase3NetMs", phase3NetMs);
    recordScalar("phase3LatencyMs", phase3LatencyMs);
    recordScalar("phase3OverheadBytes", phase3OverheadBytes);

    recordScalar("phase3Sha3ComputeMs", primarySha3Ms);
    recordScalar("phase3SpongentComputeMs", primarySpongentMs);

    recordScalar("p1_i_compute_ms", p1IComputeMs);
    recordScalar("p1_p2_j_compute_ms", p1P2JComputeMs);
    recordScalar("p1_net_ms", p1NetMs);
    recordScalar("p2_p3_i_compute_ms", p2P3IComputeMs);
    recordScalar("p2_net_ms", p2NetMs);
    recordScalar("p3_j_compute_ms", p3JComputeMs);
    recordScalar("p3_net_ms", p3NetMs);

    recordScalar("phase3ResponderPeerId", static_cast<double>(phase3ResponderPeerId));
    recordScalar("responder_p1_p2_j_compute_ms", responderP1P2JComputeMs);
    recordScalar("responder_p3_j_compute_ms", responderP3JComputeMs);
    recordScalar("responder_p3_net_ms", responderP3NetMs);

    // Backward-compatible single responder sha3/spongent (from first responder requester).
    double singleResponderSha3 = 0.0, singleResponderSpongent = 0.0;
    if (phase3ResponderPeerId >= 0) {
        if (responderSha3MsByPeer.count(phase3ResponderPeerId))
            singleResponderSha3 = responderSha3MsByPeer[phase3ResponderPeerId];
        if (responderSpongentMsByPeer.count(phase3ResponderPeerId))
            singleResponderSpongent = responderSpongentMsByPeer[phase3ResponderPeerId];
    }
    recordScalar("responder_sha3_ms", singleResponderSha3);
    recordScalar("responder_spongent_ms", singleResponderSpongent);
}

std::vector<uint8_t> UAVNode::randomBytes(size_t size) const {
    std::vector<uint8_t> out(size, 0);
    for (size_t i = 0; i < size; ++i) {
        out[i] = static_cast<uint8_t>(intrand(256));
    }
    return out;
}

uint32_t UAVNode::nowMillis() const {
    return static_cast<uint32_t>(simTime().dbl() * 1000.0);
}

uint64_t UAVNode::nowMicros() const {
    return static_cast<uint64_t>(simTime().dbl() * 1000000.0);
}

size_t UAVNode::estimateMessageBytes(const ProtocolMessage* msg) const {
    // Count only protocol-level payload bytes (matching Python implementation).
    // This excludes OMNeT++ simulation bookkeeping fields (senderId, receiverId,
    // sentAtUs, success flag) which are not part of the actual protocol.
    size_t bytes = 0;
    bytes += msg->tempId.size();        // TID (8 bytes when present)
    bytes += sizeof(uint32_t);          // timestamp (4 bytes)
    bytes += msg->field1.size();        // primary payload (nonce/challenge/masked response/token)
    bytes += msg->field2.size();        // secondary payload (hash/MAC/token)
    bytes += msg->field3.size();        // tertiary payload (MAC when present)
    return bytes;
}

double UAVNode::elapsedMs(const std::chrono::steady_clock::time_point& start) {
    const auto now = std::chrono::steady_clock::now();
    const auto delta = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(now - start);
    return delta.count();
}

double UAVNode::getDisplayCoord(const cModule* module, int axis) {
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

simtime_t UAVNode::computeLinkDelay(const cModule* destination, size_t payloadBytes) const {
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

void UAVNode::sendToGroundStation(ProtocolMessage* msg) {
    cModule* gs = getParentModule()->getSubmodule("groundStation");
    if (gs == nullptr) {
        throw cRuntimeError("groundStation submodule not found");
    }
    msg->sentAtUs = nowMicros();
    sendDirect(msg, computeLinkDelay(gs, estimateMessageBytes(msg)), SIMTIME_ZERO, gs, "in");
}

void UAVNode::sendToUav(int peerId, ProtocolMessage* msg) {
    cModule* peer = getParentModule()->getSubmodule("uav", peerId);
    if (peer == nullptr) {
        delete msg;
        EV_WARN << "[UAV " << uavId << "] peer UAV index " << peerId << " not found\n";
        return;
    }
    msg->sentAtUs = nowMicros();
    sendDirect(msg, computeLinkDelay(peer, estimateMessageBytes(msg)), SIMTIME_ZERO, peer, "in");
}

void UAVNode::resetPhase2Metrics() {
    phase2ComputeMs = 0.0;
    phase2NetMs = 0.0;
    phase2LatencyMs = 0.0;
    phase2Success = false;
    phase2OverheadBytes = 0;
    phase2Sha3ComputeMs = 0.0;
    phase2SpongentComputeMs = 0.0;

    m1UavComputeMs = 0.0;
    m1GsComputeMs = 0.0;
    m1NetMs = 0.0;
    m2UavVerifyMs = 0.0;
    m2NetMs = 0.0;
    pufEvalMs = 0.0;
    bchMs = 0.0;
    m3CryptoMs = 0.0;
    m3UavComputeMs = 0.0;
    m3GsComputeMs = 0.0;
    m3NetMs = 0.0;
    m4UavComputeMs = 0.0;
    m4NetMs = 0.0;

    m1UavSha3Ms = 0.0;
    m1UavSpongentMs = 0.0;
    m3CryptoSha3Ms = 0.0;
    m3CryptoSpongentMs = 0.0;

    phase2.resetTimingStats();
}

void UAVNode::startPhase2Authentication() {
    resetPhase2Metrics();

    const auto t0 = std::chrono::steady_clock::now();

    nonceUav = randomBytes(16);
    phase2StartTs = simTime();

    const uint32_t ts = nowMillis();
    const std::vector<uint8_t> authHash = phase2.computeAuthRequestHash(tempId, ts, nonceUav);

    auto* request = new ProtocolMessage("AuthRequest", MessageType::AUTH_REQUEST);
    request->senderId = uavId;
    request->receiverId = -1;
    request->tempId = tempId;
    request->timestamp = ts;
    request->field1 = nonceUav;
    request->field2 = authHash;

    m1UavComputeMs = elapsedMs(t0);
    phase2OverheadBytes += estimateMessageBytes(request);

    sendToGroundStation(request);
    emitCommOverheadBytes(estimateMessageBytes(request));

    EV_INFO << "[UAV " << uavId << "] Phase 2 request sent\n";
}

void UAVNode::onChallengeIssuance(const ProtocolMessage* msg) {
    if (msg->receiverId != -1 && msg->receiverId != uavId) {
        return;
    }

    phase2OverheadBytes += estimateMessageBytes(msg);

    if (msg->sentAtUs > 0) {
        m2NetMs = static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0;
    }

    m1NetMs = msg->metricA;
    m1GsComputeMs = msg->metricB;

    const auto tVerify = std::chrono::steady_clock::now();
    const std::vector<uint8_t>& challenge = msg->field1;
    const std::vector<uint8_t>& nonceGs = msg->field2;
    const std::vector<uint8_t>& challengeMac = msg->field3;

    const bool macOk = phase2.verifyChallengeMac(tempId, challenge, nonceGs, msg->timestamp, challengeMac);
    m2UavVerifyMs = elapsedMs(tVerify);
    if (!macOk) {
        EV_WARN << "[UAV " << uavId << "] invalid challenge MAC\n";
        return;
    }

    const auto tPuf = std::chrono::steady_clock::now();
    const std::vector<uint8_t> pufResponse = puf->evaluate(challenge);
    pufEvalMs = elapsedMs(tPuf);

    const auto tCrypto = std::chrono::steady_clock::now();
    const std::vector<uint8_t> maskedResponse = phase2.maskResponse(pufResponse, nonceGs);
    phase2SessionKey = phase2.deriveSessionKey(pufResponse, nonceUav, nonceGs, msg->timestamp);
    const std::vector<uint8_t> authToken = phase2.computeAuthToken(maskedResponse, phase2SessionKey);
    m3CryptoMs = elapsedMs(tCrypto);

    bchMs = 0.0;
    m3UavComputeMs = pufEvalMs + bchMs + m3CryptoMs;

    auto* response = new ProtocolMessage("PUFResponse", MessageType::PUF_RESPONSE);
    response->senderId = uavId;
    response->receiverId = -1;
    response->tempId = tempId;
    response->timestamp = msg->timestamp;
    response->field1 = maskedResponse;
    response->field2 = authToken;

    phase2OverheadBytes += estimateMessageBytes(response);

    sendToGroundStation(response);
    emitCommOverheadBytes(estimateMessageBytes(response));

    EV_INFO << "[UAV " << uavId << "] sent masked PUF response\n";
}

void UAVNode::onAuthConfirmation(const ProtocolMessage* msg) {
    if (msg->receiverId != -1 && msg->receiverId != uavId) {
        return;
    }

    phase2OverheadBytes += estimateMessageBytes(msg);

    if (msg->sentAtUs > 0) {
        m4NetMs = static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0;
    }

    m3NetMs = msg->metricA;
    m3GsComputeMs = msg->metricB;
    bchMs = msg->metricC;

    const auto tFinalize = std::chrono::steady_clock::now();

    if (!msg->success) {
        phase2Success = false;
        m4UavComputeMs = elapsedMs(tFinalize);
        phase2ComputeMs = m1UavComputeMs + m2UavVerifyMs + m3UavComputeMs + m4UavComputeMs;
        phase2NetMs = m1NetMs + m2NetMs + m3NetMs + m4NetMs;
        phase2LatencyMs = phase2ComputeMs + phase2NetMs;
        EV_WARN << "[UAV " << uavId << "] authentication failed at GS\n";
        return;
    }

    phase2Authenticated = true;
    phase2Success = true;
    networkCredential = msg->field1;

    m4UavComputeMs = elapsedMs(tFinalize);
    phase2ComputeMs = m1UavComputeMs + m2UavVerifyMs + m3UavComputeMs + m4UavComputeMs;
    phase2NetMs = m1NetMs + m2NetMs + m3NetMs + m4NetMs;
    phase2LatencyMs = phase2ComputeMs + phase2NetMs;

    // Accumulate hash timing from the wrapper (tracks per-mode time automatically).
    phase2Sha3ComputeMs = phase2.getHashSha3TimeMs();
    phase2SpongentComputeMs = phase2.getHashSpongentTimeMs();
    // Also populate step-level hash timing from wrapper.
    m1UavSha3Ms = phase2Sha3ComputeMs;  // Total UAV-side sha3 (wrapper tracks all calls)
    m1UavSpongentMs = phase2SpongentComputeMs;
    m3CryptoSha3Ms = phase2Sha3ComputeMs;
    m3CryptoSpongentMs = phase2SpongentComputeMs;

    emit(authLatencySignal, phase2LatencyMs);

    EV_INFO << "[UAV " << uavId << "] Phase 2 authenticated, latency="
            << phase2LatencyMs << " ms\n";

    if (peerAuthStartTime >= SIMTIME_ZERO) {
        scheduleAt(simTime() + peerAuthStartTime, new cMessage("phase3Start"));
    }
}

void UAVNode::startPhase3Authentication() {
    if (!phase2Authenticated) {
        return;
    }

    // Full mesh: initiate peer auth with all UAVs that have a higher ID.
    const int numUAVs = getParentModule()->par("numUAVs").intValue();
    for (int peerId = uavId + 1; peerId < numUAVs; ++peerId) {
        startPhase3WithPeer(peerId);
    }
}

void UAVNode::startPhase3WithPeer(int peerId) {
    if (!phase2Authenticated || peerId == uavId) {
        return;
    }

    const double sha3Before = phase3.getHashSha3TimeMs();
    const double spongentBefore = phase3.getHashSpongentTimeMs();
    const auto t0 = std::chrono::steady_clock::now();

    const std::vector<uint8_t> nonceA = randomBytes(16);
    const std::vector<uint8_t> tokenA = phase3.buildRequestToken(uavId, peerId, nonceA, networkCredential);

    initiatedNonceAByPeer[peerId] = nonceA;
    phase3StartTs[peerId] = simTime();

    auto* request = new ProtocolMessage("PeerAuthRequest", MessageType::PEER_AUTH_REQUEST);
    request->senderId = uavId;
    request->receiverId = peerId;
    request->timestamp = nowMillis();
    request->field1 = nonceA;
    request->field2 = tokenA;

    const double p1IComputeMs = elapsedMs(t0);

    phase3P1IComputeMsByPeer[peerId] = p1IComputeMs;
    phase3Sha3MsByPeer[peerId] = phase3.getHashSha3TimeMs() - sha3Before;
    phase3SpongentMsByPeer[peerId] = phase3.getHashSpongentTimeMs() - spongentBefore;
    phase3P1P2JComputeMsByPeer[peerId] = 0.0;
    phase3P1NetMsByPeer[peerId] = 0.0;
    phase3P2P3IComputeMsByPeer[peerId] = 0.0;
    phase3P2NetMsByPeer[peerId] = 0.0;
    phase3P3JComputeMsByPeer[peerId] = 0.0;
    phase3P3NetMsByPeer[peerId] = 0.0;

    phase3ComputeMsByPeer[peerId] = p1IComputeMs;
    phase3NetMsByPeer[peerId] = 0.0;
    phase3LatencyMsByPeer[peerId] = 0.0;
    phase3SuccessByPeer[peerId] = false;
    phase3OverheadBytesByPeer[peerId] = estimateMessageBytes(request);

    sendToUav(peerId, request);
    emitCommOverheadBytes(estimateMessageBytes(request));

    EV_INFO << "[UAV " << uavId << "] Phase 3 request sent to UAV " << peerId << "\n";
}

void UAVNode::onPeerAuthRequest(const ProtocolMessage* msg) {
    if (msg->receiverId != uavId || !phase2Authenticated) {
        return;
    }

    const int requesterId = msg->senderId;
    const std::vector<uint8_t>& nonceA = msg->field1;
    const std::vector<uint8_t>& tokenA = msg->field2;

    const double sha3Before = phase3.getHashSha3TimeMs();
    const double spongentBefore = phase3.getHashSpongentTimeMs();
    const auto t0 = std::chrono::steady_clock::now();

    const bool ok = phase3.verifyRequestToken(requesterId, uavId, nonceA, networkCredential, tokenA);
    if (!ok) {
        EV_WARN << "[UAV " << uavId << "] invalid peer request token from UAV " << requesterId << "\n";
        return;
    }

    const std::vector<uint8_t> nonceB = randomBytes(16);
    const std::vector<uint8_t> tokenB = phase3.buildResponseToken(uavId, requesterId, nonceA, nonceB, networkCredential);

    responderNonceAByPeer[requesterId] = nonceA;
    responderNonceBByPeer[requesterId] = nonceB;

    auto* response = new ProtocolMessage("PeerAuthResponse", MessageType::PEER_AUTH_RESPONSE);
    response->senderId = uavId;
    response->receiverId = requesterId;
    response->timestamp = nowMillis();
    response->field1 = nonceB;
    response->field2 = tokenB;

    const double p1P2JComputeMs = elapsedMs(t0);
    const double p1NetMs = msg->sentAtUs > 0 ? static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0 : 0.0;

    response->metricA = p1P2JComputeMs;
    response->metricB = p1NetMs;
    response->metricC = 0.0;
    response->metricD = 0.0;

    phase3ResponderPeerId = requesterId;
    responderP1P2JComputeMs = p1P2JComputeMs;

    // Responder hash timing for this requester.
    responderSha3MsByPeer[requesterId] = phase3.getHashSha3TimeMs() - sha3Before;
    responderSpongentMsByPeer[requesterId] = phase3.getHashSpongentTimeMs() - spongentBefore;

    sendToUav(requesterId, response);
    emitCommOverheadBytes(estimateMessageBytes(response));

    EV_INFO << "[UAV " << uavId << "] Phase 3 response sent to UAV " << requesterId << "\n";
}

void UAVNode::onPeerAuthResponse(const ProtocolMessage* msg) {
    if (msg->receiverId != uavId || !phase2Authenticated) {
        return;
    }

    const int responderId = msg->senderId;
    if (!initiatedNonceAByPeer.count(responderId)) {
        return;
    }

    const std::vector<uint8_t>& nonceA = initiatedNonceAByPeer[responderId];
    const std::vector<uint8_t>& nonceB = msg->field1;
    const std::vector<uint8_t>& tokenB = msg->field2;

    const double sha3Before = phase3.getHashSha3TimeMs();
    const double spongentBefore = phase3.getHashSpongentTimeMs();
    const auto t0 = std::chrono::steady_clock::now();

    const bool ok = phase3.verifyResponseToken(responderId, uavId, nonceA, nonceB, networkCredential, tokenB);
    if (!ok) {
        EV_WARN << "[UAV " << uavId << "] invalid peer response token from UAV " << responderId << "\n";
        return;
    }

    const std::vector<uint8_t> tokenC = phase3.buildCompletionToken(uavId, responderId, nonceB, networkCredential);

    peerSessionKeys[responderId] = phase3.derivePeerSessionKey(uavId, responderId, nonceA, nonceB, networkCredential);

    auto* complete = new ProtocolMessage("PeerAuthComplete", MessageType::PEER_AUTH_COMPLETE);
    complete->senderId = uavId;
    complete->receiverId = responderId;
    complete->timestamp = nowMillis();
    complete->field1 = tokenC;

    const double p2P3IComputeMs = elapsedMs(t0);
    const double p2NetMs = msg->sentAtUs > 0 ? static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0 : 0.0;
    const double p1P2JComputeMs = msg->metricA;
    const double p1NetMs = msg->metricB;

    phase3P1P2JComputeMsByPeer[responderId] = p1P2JComputeMs;
    phase3P1NetMsByPeer[responderId] = p1NetMs;
    phase3P2P3IComputeMsByPeer[responderId] = p2P3IComputeMs;
    phase3P2NetMsByPeer[responderId] = p2NetMs;

    phase3OverheadBytesByPeer[responderId] += estimateMessageBytes(msg);
    phase3OverheadBytesByPeer[responderId] += estimateMessageBytes(complete);

    sendToUav(responderId, complete);
    emitCommOverheadBytes(estimateMessageBytes(complete));

    // We don't have an explicit ACK in this 3-message protocol, so p3_j_compute and p3_net
    // are merged in the exporter from responder-side scalars.
    const double knownComputeMs = phase3P1IComputeMsByPeer[responderId] + p1P2JComputeMs + p2P3IComputeMs;
    const double knownNetMs = p1NetMs + p2NetMs;

    phase3ComputeMsByPeer[responderId] = knownComputeMs;
    phase3NetMsByPeer[responderId] = knownNetMs;
    phase3LatencyMsByPeer[responderId] = knownComputeMs + knownNetMs;
    phase3SuccessByPeer[responderId] = true;

    // Capture hash timing delta for this peer exchange.
    phase3Sha3MsByPeer[responderId] += phase3.getHashSha3TimeMs() - sha3Before;
    phase3SpongentMsByPeer[responderId] += phase3.getHashSpongentTimeMs() - spongentBefore;

    emit(peerAuthLatencySignal, phase3LatencyMsByPeer[responderId]);

    EV_INFO << "[UAV " << uavId << "] Phase 3 complete with UAV " << responderId << "\n";
}

void UAVNode::onPeerAuthComplete(const ProtocolMessage* msg) {
    if (msg->receiverId != uavId || !phase2Authenticated) {
        return;
    }

    const int requesterId = msg->senderId;
    if (!responderNonceAByPeer.count(requesterId) || !responderNonceBByPeer.count(requesterId)) {
        return;
    }

    const std::vector<uint8_t>& nonceA = responderNonceAByPeer[requesterId];
    const std::vector<uint8_t>& nonceB = responderNonceBByPeer[requesterId];

    const double sha3Before = phase3.getHashSha3TimeMs();
    const double spongentBefore = phase3.getHashSpongentTimeMs();
    const auto t0 = std::chrono::steady_clock::now();

    const bool ok = phase3.verifyCompletionToken(requesterId, uavId, nonceB, networkCredential, msg->field1);
    if (!ok) {
        EV_WARN << "[UAV " << uavId << "] invalid peer completion token from UAV " << requesterId << "\n";
        return;
    }

    peerSessionKeys[requesterId] = phase3.derivePeerSessionKey(requesterId, uavId, nonceA, nonceB, networkCredential);

    const double p3JComputeMs = elapsedMs(t0);
    const double p3NetMs = msg->sentAtUs > 0 ? static_cast<double>(nowMicros() - msg->sentAtUs) / 1000.0 : 0.0;

    phase3ResponderPeerId = requesterId;
    responderP3JComputeMs = p3JComputeMs;
    responderP3NetMs = p3NetMs;

    // Keep these keyed metrics too so this module can be used as source in merged exports.
    phase3P3JComputeMsByPeer[requesterId] = p3JComputeMs;
    phase3P3NetMsByPeer[requesterId] = p3NetMs;

    // Responder hash timing delta for the completion step.
    responderSha3MsByPeer[requesterId] += phase3.getHashSha3TimeMs() - sha3Before;
    responderSpongentMsByPeer[requesterId] += phase3.getHashSpongentTimeMs() - spongentBefore;

    responderNonceAByPeer.erase(requesterId);
    responderNonceBByPeer.erase(requesterId);

    EV_INFO << "[UAV " << uavId << "] peer session established with UAV " << requesterId << "\n";
}

void UAVNode::emitCommOverheadBytes(size_t bytes) {
    emit(commOverheadSignal, static_cast<double>(bytes));
}
