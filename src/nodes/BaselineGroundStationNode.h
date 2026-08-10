#ifndef UAVAUTH_NODES_BASELINEGROUNDSTATIONNODE_H
#define UAVAUTH_NODES_BASELINEGROUNDSTATIONNODE_H

#include <omnetpp.h>

#include "crypto/Sha3Suite.h"
#include "crypto/SignatureSuite.h"
#include "nodes/SimMessage.h"
#include "protocol/BaselineSigAuth.h"

#include <map>
#include <memory>
#include <string>

namespace uavauth {
namespace nodes {

/// Ground station for the RSA/ECDSA baseline. See BaselineGroundStationNode.ned.
class BaselineGroundStationNode : public omnetpp::cSimpleModule {
  public:
    struct Record {
        bool success = false;
        double m1ComputeMs = 0.0, m3ComputeMs = 0.0;
        double m1NetMs = 0.0, m3NetMs = 0.0;
        double signMs = 0.0, verifyMs = 0.0, macMs = 0.0, kdfMs = 0.0, dhMs = 0.0;
        size_t bytesM2 = 0, bytesM4 = 0;
        std::string abortReason = "none";
    };

  protected:
    int numInitStages() const override { return 2; }
    void initialize(int stage) override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

  private:
    void enrollAll();
    void send(const protocol::Message& payload, int destUavId, const protocol::StepTiming& t);

    int numUavs_ = 0;
    std::string sigSuiteName_;

    crypto::Sha3Suite symSuite_;
    std::unique_ptr<crypto::SignatureSuite> sigSuite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<protocol::BaselineGroundStationProtocol> proto_;

    std::map<int, Record> records_;
    int authAttempts_ = 0;
    int authSuccesses_ = 0;

    omnetpp::simsignal_t authSuccessSignal_ = -1;
    omnetpp::simsignal_t commOverheadSignal_ = -1;
};

} // namespace nodes
} // namespace uavauth

#endif
