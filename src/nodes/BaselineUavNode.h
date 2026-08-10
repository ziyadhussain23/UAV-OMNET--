#ifndef UAVAUTH_NODES_BASELINEUAVNODE_H
#define UAVAUTH_NODES_BASELINEUAVNODE_H

#include <omnetpp.h>

#include "crypto/Sha3Suite.h"
#include "crypto/SignatureSuite.h"
#include "nodes/SimMessage.h"
#include "protocol/BaselineSigAuth.h"

#include <memory>
#include <string>

namespace uavauth {
namespace nodes {

/// One UAV running the RSA/ECDSA baseline handshake. See BaselineUavNode.ned.
class BaselineUavNode : public omnetpp::cSimpleModule {
  public:
    struct Record {
        bool success = false;
        double wallLatencyMs = 0.0;
        double computeMs = 0.0, netMs = 0.0;
        double m1ComputeMs = 0.0, m2VerifyMs = 0.0, m3ComputeMs = 0.0, m4ComputeMs = 0.0;
        double m1NetMs = 0.0, m2NetMs = 0.0, m3NetMs = 0.0, m4NetMs = 0.0;
        double signMs = 0.0, verifyMs = 0.0, macMs = 0.0, kdfMs = 0.0, dhMs = 0.0;
        size_t bytesM1 = 0, bytesM2 = 0, bytesM3 = 0, bytesM4 = 0;
        size_t overheadBytes = 0;
        std::string abortReason = "none";
        bool ephemeralErased = false;
    };

    crypto::SignatureSuite& signatureSuite() { return *sigSuite_; }
    core::Bytes publicKeyBytes() const { return proto_->publicKeyBytes(); }
    void provisionGsPublicKey(const core::Bytes& gsSpki) { proto_->provisionGsPublicKey(gsSpki); }
    void ensureOwnKeypair() { proto_->ensureOwnKeypair(); }

  protected:
    int numInitStages() const override { return 2; }
    void initialize(int stage) override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

  private:
    void send(const protocol::Message& payload, const protocol::StepTiming& t);

    int uavId_ = -1;
    std::string sigSuiteName_;

    crypto::Sha3Suite symSuite_;
    std::unique_ptr<crypto::SignatureSuite> sigSuite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<protocol::BaselineUavProtocol> proto_;

    omnetpp::simtime_t phase2Start_ = 0;
    Record rec_;

    omnetpp::simsignal_t authLatencySignal_ = -1;
    omnetpp::simsignal_t commOverheadSignal_ = -1;
};

} // namespace nodes
} // namespace uavauth

#endif
