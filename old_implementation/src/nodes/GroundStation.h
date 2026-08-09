#ifndef UAVAUTH_NODES_GROUNDSTATION_H
#define UAVAUTH_NODES_GROUNDSTATION_H

#include <omnetpp.h>

#include "../crypto/BCHCodec.h"
#include "../crypto/HashWrapper.h"
#include "../protocols/Phase1Enrollment.h"
#include "../protocols/Phase2Authentication.h"
#include "../protocols/ProtocolMessages.h"

#include <chrono>
#include <map>
#include <vector>

class GroundStation : public omnetpp::cSimpleModule {
  private:
    struct PendingAuthContext {
        int uavId;
        std::string tempId;
        uint32_t timestamp;
        std::vector<uint8_t> nonceUav;
        std::vector<uint8_t> nonceGs;
        std::vector<uint8_t> expectedResponse;
        std::vector<uint8_t> helperData;
        double m1NetMs = 0.0;
        double m1GsComputeMs = 0.0;
        double m1GsSha3Ms = 0.0;
        double m1GsSpongentMs = 0.0;
    };

  struct Phase2GsMetrics {
    double m1NetMs = 0.0;
    double m1GsComputeMs = 0.0;
    double m3NetMs = 0.0;
    double m3GsComputeMs = 0.0;
    double bchMs = 0.0;
    double sha3Ms = 0.0;
    double spongentMs = 0.0;
    bool success = false;
  };

    int numUavs;
    int numCrpsPerUav;
    int pufSeedBase;
    int responseDistanceThreshold;
    double defaultPufNoise;
    uint32_t timestampWindowMs;

    double linkBitrateBps;
    double propagationSpeedMps;
    omnetpp::simtime_t processingDelayMean;
    omnetpp::simtime_t queueJitterStddev;
    bool enableRandomJitter;

    std::string hashModeStr;
    uavauth::crypto::HashMode hashMode;

    int totalAuthAttempts;
    int totalAuthSuccess;

    double phase2GsComputeMsTotal;
    int phase2GsComputeSamples;
    double phase2GsSha3MsTotal;
    double phase2GsSpongentMsTotal;

    std::vector<uint8_t> networkCredential;

    uavauth::protocols::Phase1Enrollment* enrollment;
    uavauth::protocols::Phase2Authentication phase2;
    uavauth::crypto::BCHCodec bchCodec;

    std::map<int, PendingAuthContext> pendingByUav;
    std::map<int, Phase2GsMetrics> phase2MetricsByUav;

    omnetpp::simsignal_t authSuccessSignal;
    omnetpp::simsignal_t commOverheadSignal;

    std::vector<uint8_t> randomBytes(size_t size) const;
    uint32_t nowMillis() const;
    uint64_t nowMicros() const;
    static double elapsedMs(const std::chrono::steady_clock::time_point& start);
    size_t estimateMessageBytes(const uavauth::protocols::ProtocolMessage* msg) const;
    omnetpp::simtime_t computeLinkDelay(const omnetpp::cModule* destination, size_t payloadBytes) const;
    static double getDisplayCoord(const omnetpp::cModule* module, int axis);

    void onAuthRequest(const uavauth::protocols::ProtocolMessage* msg);
    void onPufResponse(const uavauth::protocols::ProtocolMessage* msg);

    void sendToUav(int uavId, uavauth::protocols::ProtocolMessage* msg);
    void emitCommOverheadBytes(size_t bytes);

  protected:
    virtual void initialize() override;
    virtual void handleMessage(omnetpp::cMessage* msg) override;
    virtual void finish() override;

  public:
    GroundStation();
    virtual ~GroundStation() override;
};

#endif
