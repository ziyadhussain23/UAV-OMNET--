#ifndef UAVAUTH_NODES_UAVNODE_H
#define UAVAUTH_NODES_UAVNODE_H

#include <omnetpp.h>

#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "fe/FuzzyExtractor.h"
#include "nodes/SimMessage.h"
#include "protocol/Protocol.h"
#include "puf/PufModel.h"

#include <map>
#include <memory>
#include <string>

namespace uavauth {
namespace nodes {

/// One UAV: runs Phase 2 against the ground station, then Phase 3 with peers.
class UavNode : public omnetpp::cSimpleModule {
  public:
    /// Called by the ground station during enrollment (init stage 1). The state
    /// handed over is entirely public -- challenge, helper data, identity.
    void provision(const protocol::DeviceState& state);

    /// The device's own PUF, created in init stage 0 so the ground station can
    /// interrogate the same instance during enrollment.
    puf::PufModel& devicePuf() { return *puf_; }

    struct Phase2Record {
        bool success = false;
        double walletLatencyMs = 0.0;   // simTime end-to-end
        double computeMs = 0.0, netMs = 0.0;
        double m1ComputeMs = 0.0, m2VerifyMs = 0.0, m3ComputeMs = 0.0, m4ComputeMs = 0.0;
        double m1NetMs = 0.0, m2NetMs = 0.0, m3NetMs = 0.0, m4NetMs = 0.0;
        double pufMs = 0.0, feMs = 0.0, macMs = 0.0, kdfMs = 0.0, dhMs = 0.0, aeadMs = 0.0;
        size_t bytesM1 = 0, bytesM2 = 0, bytesM3 = 0, bytesM4 = 0;
        size_t overheadBytes = 0;
        std::string abortReason = "none";
        bool ephemeralErased = false;
    };

    struct Phase3Record {
        bool success = false;
        bool initiator = false;
        double latencyMs = 0.0, computeMs = 0.0, netMs = 0.0;
        double p1ComputeMs = 0.0, p2ComputeMs = 0.0, p3ComputeMs = 0.0;
        double p1NetMs = 0.0, p2NetMs = 0.0, p3NetMs = 0.0;
        double macMs = 0.0, kdfMs = 0.0, dhMs = 0.0;
        size_t overheadBytes = 0;
        std::string abortReason = "none";
    };

    const Phase2Record& phase2Record() const { return phase2_; }
    const std::map<int, Phase3Record>& phase3Records() const { return phase3_; }

  protected:
    int numInitStages() const override { return 2; }
    void initialize(int stage) override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

  private:
    void sendToGs(const protocol::Message& payload, const protocol::StepTiming& t);
    void sendToPeer(int peerId, const protocol::Message& payload,
                    const protocol::StepTiming& t);
    void startPhase3Round();

    int uavId_ = -1;
    std::string suiteName_;
    std::string feProfile_;
    int numUavs_ = 0;
    bool fullMesh_ = true;

    std::unique_ptr<crypto::CryptoSuite> suite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<puf::PufModel> puf_;
    std::unique_ptr<protocol::UavProtocol> proto_;
    fe::FeParams feParams_;

    omnetpp::simtime_t phase2Start_ = 0;
    std::map<int, omnetpp::simtime_t> phase3Start_;

    Phase2Record phase2_;
    std::map<int, Phase3Record> phase3_;

    omnetpp::simsignal_t authLatencySignal_ = -1;
    omnetpp::simsignal_t peerAuthLatencySignal_ = -1;
    omnetpp::simsignal_t commOverheadSignal_ = -1;
};

} // namespace nodes
} // namespace uavauth

#endif
