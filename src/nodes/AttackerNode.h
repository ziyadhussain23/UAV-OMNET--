#ifndef UAVAUTH_NODES_ATTACKERNODE_H
#define UAVAUTH_NODES_ATTACKERNODE_H

#include <omnetpp.h>

#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "nodes/SimMessage.h"

#include <map>
#include <set>
#include <memory>
#include <string>
#include <vector>

namespace uavauth {
namespace nodes {

/// Adversary against the running protocol.
///
/// Turns the security theorems into measurements. Each attack declares what it
/// expects to happen, and the run records what actually happened, so a claim of
/// "the attack fails" is backed by a counter rather than by prose.
///
/// The legacy control arm matters as much as the attacks themselves: run against
/// `protocolVariant = "legacy"` the same attacker code must SUCCEED. Without that
/// arm, "every attack failed" is unfalsifiable -- it could equally mean the
/// attacker is broken.
class AttackerNode : public omnetpp::cSimpleModule {
  public:
    struct AttackStat {
        long attempts = 0;
        long accepted = 0;            // victim acted on the injected message
        long rejected = 0;
        long repliesElicited = 0;     // the oracle signal: victim answered at all
        long credentialsExposed = 0;  // per-pair secrets recovered in the clear
        long responsesLeaked = 0;     // PUF responses recovered
    };

  protected:
    void initialize() override;
    void handleMessage(omnetpp::cMessage* msg) override;
    void finish() override;

  private:
    void observe(SimMessage* msg);
    void attemptCredentialRecovery(SimMessage* msg);
    void injectForgedM2(int victimUav, const SimMessage& observedM1);
    void injectReplay(const SimMessage& captured);
    void forwardTampered(SimMessage* msg);

    std::string attackMode_ = "none";
    int targetUav_ = 0;
    long maxAttempts_ = 100;
    bool expectSuccess_ = false;   // true only for the legacy control arm

    std::unique_ptr<crypto::CryptoSuite> suite_;
    std::unique_ptr<crypto::Drbg> rng_;

    std::map<std::string, AttackStat> stats_;
    std::map<int, SimMessage*> capturedM1_;    // victim -> its M1
    /// Victims for which a GENUINE M2 has already been delivered. An M3 after
    /// that point is the victim answering the real ground station, not us, so
    /// counting it would fabricate an oracle hit.
    std::set<int> genuineM2Seen_;
    long observedMessages_ = 0;
    long observedM4_ = 0;
    long plaintextCredentialBytes_ = 0;
};

} // namespace nodes
} // namespace uavauth

#endif
