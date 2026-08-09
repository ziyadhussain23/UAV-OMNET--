#ifndef UAVAUTH_NODES_GROUNDSTATIONNODE_H
#define UAVAUTH_NODES_GROUNDSTATIONNODE_H

#include <omnetpp.h>

#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "fe/FuzzyExtractor.h"
#include "nodes/SimMessage.h"
#include "protocol/Protocol.h"
#include "puf/PufModel.h"

#include <map>
#include <memory>
#include <vector>

namespace uavauth {
namespace nodes {

/// Ground station: enrollment authority and Phase-2 peer.
class GroundStationNode : public omnetpp::cSimpleModule {
  public:
    /// Per-UAV Phase-2 record, written to the results at finish().
    struct GsPhase2Record {
        bool success = false;
        double m1NetMs = 0.0, m1ComputeMs = 0.0;
        double m3NetMs = 0.0, m3ComputeMs = 0.0;
        double macMs = 0.0, kdfMs = 0.0, dhMs = 0.0, aeadMs = 0.0;
        size_t bytesM2 = 0, bytesM4 = 0;
        std::string abortReason = "none";
    };

    /// Enrollment cost per UAV.
    struct GsPhase1Record {
        double pufMs = 0.0, feMs = 0.0, totalMs = 0.0;
        size_t helperBytes = 0, challengeBytes = 0;
        bool success = false;
    };

    const std::map<int, GsPhase2Record>& phase2Records() const { return phase2_; }
    const std::map<int, GsPhase1Record>& phase1Records() const { return phase1_; }
    protocol::GroundStationProtocol& proto() { return *proto_; }
    const crypto::CryptoSuite& suite() const { return *suite_; }

  protected:
    int numInitStages() const override { return 2; }
    void initialize(int stage) override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

  private:
    void enrollAll();
    void send(protocol::Message&& payload, int destUavId,
              const protocol::StepTiming& timing);

    std::unique_ptr<crypto::CryptoSuite> suite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<protocol::GroundStationProtocol> proto_;

    fe::FeParams feParams_;
    int numUavs_ = 0;
    std::string suiteName_;
    std::string feProfile_;
    uint32_t timestampWindowMs_ = 5000;

    std::map<int, GsPhase2Record> phase2_;
    std::map<int, GsPhase1Record> phase1_;

    int authAttempts_ = 0;
    int authSuccesses_ = 0;

    omnetpp::simsignal_t authSuccessSignal_ = -1;
    omnetpp::simsignal_t commOverheadSignal_ = -1;
};

} // namespace nodes
} // namespace uavauth

#endif
