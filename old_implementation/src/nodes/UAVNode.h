#ifndef UAVAUTH_NODES_UAVNODE_H
#define UAVAUTH_NODES_UAVNODE_H

#include <omnetpp.h>

#include "../crypto/HashWrapper.h"
#include "../crypto/PUFSimulator.h"
#include "../protocols/Phase2Authentication.h"
#include "../protocols/Phase3PeerAuth.h"
#include "../protocols/ProtocolMessages.h"

#include <chrono>
#include <map>
#include <string>
#include <vector>

class UAVNode : public omnetpp::cSimpleModule {
  private:
    int uavId;
    int pufSeed;
    int peerTargetId;
    double pufNoiseLevel;

    std::string tempId;
    std::string hashModeStr;  // "sha3" or "spongent"
    uavauth::crypto::HashMode hashMode;

    omnetpp::simtime_t authStartTime;
    omnetpp::simtime_t peerAuthStartTime;

    // Link-delay model parameters.
    double linkBitrateBps;
    double propagationSpeedMps;
    omnetpp::simtime_t processingDelayMean;
    omnetpp::simtime_t queueJitterStddev;
    bool enableRandomJitter;

    bool phase2Authenticated;

    uavauth::crypto::PUFSimulator* puf;
    uavauth::protocols::Phase2Authentication phase2;
    uavauth::protocols::Phase3PeerAuth phase3;

    std::vector<uint8_t> nonceUav;
    std::vector<uint8_t> networkCredential;
    std::vector<uint8_t> phase2SessionKey;

    std::map<int, std::vector<uint8_t>> initiatedNonceAByPeer;
    std::map<int, std::vector<uint8_t>> responderNonceAByPeer;
    std::map<int, std::vector<uint8_t>> responderNonceBByPeer;
    std::map<int, std::vector<uint8_t>> peerSessionKeys;

    omnetpp::simtime_t phase2StartTs;
    std::map<int, omnetpp::simtime_t> phase3StartTs;

    // Phase 2 summary metrics.
    double phase2ComputeMs;
    double phase2NetMs;
    double phase2LatencyMs;
    bool phase2Success;
    size_t phase2OverheadBytes;

    // Phase 2 dual-mode timing metrics.
    double phase2Sha3ComputeMs;
    double phase2SpongentComputeMs;

    // Phase 2 detailed step metrics.
    double m1UavComputeMs;
    double m1GsComputeMs;
    double m1NetMs;
    double m2UavVerifyMs;
    double m2NetMs;
    double pufEvalMs;
    double bchMs;
    double m3CryptoMs;
    double m3UavComputeMs;
    double m3GsComputeMs;
    double m3NetMs;
    double m4UavComputeMs;
    double m4NetMs;

    // Phase 2 dual-mode step metrics.
    double m1UavSha3Ms;
    double m1UavSpongentMs;
    double m3CryptoSha3Ms;
    double m3CryptoSpongentMs;

    // Phase 3 initiator metrics keyed by peer UAV.
    std::map<int, double> phase3ComputeMsByPeer;
    std::map<int, double> phase3NetMsByPeer;
    std::map<int, double> phase3LatencyMsByPeer;
    std::map<int, bool> phase3SuccessByPeer;
    std::map<int, size_t> phase3OverheadBytesByPeer;

    std::map<int, double> phase3P1IComputeMsByPeer;
    std::map<int, double> phase3P1P2JComputeMsByPeer;
    std::map<int, double> phase3P1NetMsByPeer;
    std::map<int, double> phase3P2P3IComputeMsByPeer;
    std::map<int, double> phase3P2NetMsByPeer;
    std::map<int, double> phase3P3JComputeMsByPeer;
    std::map<int, double> phase3P3NetMsByPeer;

    // Phase 3 dual-mode timing by peer.
    std::map<int, double> phase3Sha3MsByPeer;
    std::map<int, double> phase3SpongentMsByPeer;

    // Phase 3 responder metrics (for the requester that targeted this UAV).
    int phase3ResponderPeerId;
    double responderP1P2JComputeMs;
    double responderP3JComputeMs;
    double responderP3NetMs;

    // Phase 3 responder dual-mode metrics keyed by requester.
    std::map<int, double> responderSha3MsByPeer;
    std::map<int, double> responderSpongentMsByPeer;

    omnetpp::simsignal_t authLatencySignal;
    omnetpp::simsignal_t commOverheadSignal;
    omnetpp::simsignal_t peerAuthLatencySignal;

    std::vector<uint8_t> randomBytes(size_t size) const;
    uint32_t nowMillis() const;
    uint64_t nowMicros() const;

    size_t estimateMessageBytes(const uavauth::protocols::ProtocolMessage* msg) const;
    static double elapsedMs(const std::chrono::steady_clock::time_point& start);

    static double getDisplayCoord(const omnetpp::cModule* module, int axis);
    omnetpp::simtime_t computeLinkDelay(const omnetpp::cModule* destination, size_t payloadBytes) const;

    void sendToGroundStation(uavauth::protocols::ProtocolMessage* msg);
    void sendToUav(int peerId, uavauth::protocols::ProtocolMessage* msg);

    void resetPhase2Metrics();

    void startPhase2Authentication();
    void startPhase3Authentication();
    void startPhase3WithPeer(int peerId);

    void onChallengeIssuance(const uavauth::protocols::ProtocolMessage* msg);
    void onAuthConfirmation(const uavauth::protocols::ProtocolMessage* msg);

    void onPeerAuthRequest(const uavauth::protocols::ProtocolMessage* msg);
    void onPeerAuthResponse(const uavauth::protocols::ProtocolMessage* msg);
    void onPeerAuthComplete(const uavauth::protocols::ProtocolMessage* msg);

    void emitCommOverheadBytes(size_t bytes);

  protected:
    virtual void initialize() override;
    virtual void handleMessage(omnetpp::cMessage* msg) override;
    virtual void finish() override;

  public:
    UAVNode();
    virtual ~UAVNode() override;
};

#endif
