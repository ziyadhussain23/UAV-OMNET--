#include "nodes/AttackerNode.h"

#include "nodes/WirelessMedium.h"

#include <string>

namespace uavauth {
namespace nodes {

using namespace omnetpp;
using core::Bytes;
using core::FieldId;
using core::fromString;

Define_Module(AttackerNode);

void AttackerNode::initialize() {
    attackMode_ = par("attackMode").stdstringValue();
    targetUav_ = par("targetUav").intValue();
    maxAttempts_ = par("maxAttempts").intValue();
    expectSuccess_ = par("expectSuccess").boolValue();

    suite_ = crypto::makeCryptoSuite(par("suite").stdstringValue());

    Bytes seed(32);
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<uint8_t>(intrand(256));
    rng_ = std::make_unique<crypto::Drbg>(seed);

    // Register with the medium so it starts routing copies (or interceptions)
    // here. Without this the medium's fast path applies and the run behaves
    // exactly like an unattacked one.
    WirelessMedium::get(this)->registerAttacker(this);

    EV_INFO << "attacker active: mode=" << attackMode_ << " target=uav[" << targetUav_
            << "] expectSuccess=" << (expectSuccess_ ? "yes" : "no") << endl;
}

void AttackerNode::handleMessage(cMessage* raw) {
    auto* msg = dynamic_cast<SimMessage*>(raw);
    if (msg == nullptr) { delete raw; return; }

    observe(msg);

    if (attackMode_ == "gsimpersonate" &&
        msg->payload.type == protocol::MessageType::P2_M1_AUTH_REQUEST) {
        // We hold the only copy: the ground station never receives it. Answer with
        // a forged M2 and see whether the victim performs PUF-dependent work for us.
        delete msg;
        return;
    }

    if (attackMode_ == "tamper" || attackMode_ == "mitm") {
        // The medium handed us the message instead of the victim, so we own
        // delivery: corrupt one field and pass it on.
        forwardTampered(msg);
        return;   // ownership transferred
    }

    delete msg;
}

void AttackerNode::observe(SimMessage* msg) {
    ++observedMessages_;
    const auto type = msg->payload.type;

    // Every wire field is visible to a passive adversary. What matters is whether
    // any of it is secret -- which is what the credential recovery below tests.
    if (type == protocol::MessageType::P2_M4_GS_CONFIRM) {
        ++observedM4_;
        attemptCredentialRecovery(msg);
    }

    // Capture an M1 so it can be replayed later, and use it to mount the
    // ground-station impersonation.
    if (type == protocol::MessageType::P2_M1_AUTH_REQUEST) {
        const int victim = msg->payload.senderId;
        if (capturedM1_.find(victim) == capturedM1_.end()) {
            capturedM1_[victim] = msg->dup();
            if (attackMode_ == "gsimpersonate" && victim == targetUav_)
                injectForgedM2(victim, *msg);
            if (attackMode_ == "replay" && victim == targetUav_)
                injectReplay(*msg);
        }
    }

    // Track genuine ground-station traffic so a legitimate reply is never
    // mistaken for an oracle hit.
    if (type == protocol::MessageType::P2_M2_GS_RESPONSE && !msg->injectedByAttacker)
        genuineM2Seen_.insert(msg->payload.receiverId);

    // The oracle signal. If the victim emits M3 while the only M2 it has seen is
    // one we forged, it has performed a PUF-dependent computation on our behalf --
    // the read-out oracle the audited protocol permitted. Requiring that no
    // genuine M2 has arrived yet is what makes this a real measurement rather
    // than a count of the victim answering the real ground station.
    if (type == protocol::MessageType::P2_M3_UAV_CONFIRM &&
        attackMode_ == "gsimpersonate" && msg->payload.senderId == targetUav_) {
        AttackStat& s = stats_["gsimpersonate"];
        if (s.attempts > 0 && genuineM2Seen_.find(targetUav_) == genuineM2Seen_.end()) {
            ++s.repliesElicited;
            ++s.accepted;
            EV_WARN << "ORACLE HIT: uav[" << targetUav_
                    << "] answered a forged M2" << endl;
        }
    }
}

void AttackerNode::attemptCredentialRecovery(SimMessage* msg) {
    AttackStat& s = stats_["credsniff"];
    ++s.attempts;

    if (!msg->payload.has(FieldId::CRED_PKG)) {
        ++s.rejected;
        return;
    }
    const Bytes& blob = msg->payload.get(FieldId::CRED_PKG);

    // A per-pair credential is 32 bytes of high-entropy key material. If the
    // package were plaintext -- as it was in the audited protocol -- the count
    // and length prefixes would be directly parseable here. Test that by trying
    // to read the plaintext framing: u16 count followed by plausible lengths.
    bool looksPlaintext = false;
    if (blob.size() > 4) {
        const uint16_t count = core::readU16be(blob, 0);
        if (count > 0 && count < 64) {
            const uint16_t firstLen = core::readU16be(blob, 4);
            if (firstLen == suite_->keyLen()) looksPlaintext = true;
        }
    }

    if (looksPlaintext) {
        ++s.accepted;
        ++s.credentialsExposed;
        plaintextCredentialBytes_ += static_cast<long>(blob.size());
        EV_WARN << "credential package appears to be plaintext" << endl;
    } else {
        ++s.rejected;
    }
}

void AttackerNode::injectForgedM2(int victimUav, const SimMessage& observedM1) {
    AttackStat& s = stats_["gsimpersonate"];
    if (s.attempts >= maxAttempts_) return;

    cModule* victim = getParentModule()->getSubmodule("uav", victimUav);
    if (victim == nullptr) return;

    // Forge M2 with an attacker-chosen nonce, an attacker-chosen ephemeral share
    // and a random tag. Under the hardened protocol the UAV verifies the tag
    // before doing anything, so this must produce no reply at all.
    for (int i = 0; i < 8 && s.attempts < maxAttempts_; ++i) {
        auto* forged = new SimMessage("forged-M2");
        forged->payload.type = protocol::MessageType::P2_M2_GS_RESPONSE;
        forged->payload.suiteId = static_cast<uint8_t>(suite_->id());
        forged->payload.senderId = -1;             // pretend to be the ground station
        forged->payload.receiverId = victimUav;
        forged->payload.set(FieldId::NONCE_2, rng_->bytes(16));
        forged->payload.set(FieldId::TIMESTAMP,
                            protocol::encodeTimestamp(
                                static_cast<uint32_t>(simTime().dbl() * 1000.0)));
        forged->payload.set(FieldId::EPK_B, rng_->bytes(32));
        forged->payload.set(FieldId::MAC_TAG, rng_->bytes(suite_->macLen()));
        forged->injectedByAttacker = true;
        forged->setKind(static_cast<short>(forged->payload.type));

        ++s.attempts;
        WirelessMedium::get(this)->transmit(forged, this, victim);
    }
    (void)observedM1;
}

void AttackerNode::injectReplay(const SimMessage& captured) {
    AttackStat& s = stats_["replay"];
    if (s.attempts >= maxAttempts_) return;

    cModule* gs = getParentModule()->getSubmodule("groundStation");
    if (gs == nullptr) return;

    // Re-send the captured M1 verbatim. The timestamp is still inside its window,
    // so only the nonce cache can stop this.
    auto* copy = captured.dup();
    copy->injectedByAttacker = true;
    ++s.attempts;
    WirelessMedium::get(this)->transmit(copy, this, gs);
}

void AttackerNode::forwardTampered(SimMessage* msg) {
    AttackStat& s = stats_["tamper"];

    // Flip one bit of the authenticator if present, otherwise of any payload
    // field, then deliver it. A correct implementation must reject every one.
    FieldId victimField = FieldId::MAC_TAG;
    if (!msg->payload.has(victimField)) {
        if (msg->payload.fields.empty()) {
            delete msg;
            return;
        }
        victimField = msg->payload.fields.begin()->first;
    }
    Bytes v = msg->payload.get(victimField);
    if (!v.empty()) {
        v[rng_->uniform(static_cast<uint32_t>(v.size()))] ^= 0x01;
        msg->payload.set(victimField, v);
        msg->tampered = true;
        ++s.attempts;
    }

    cModule* dest = (msg->payload.receiverId < 0)
                        ? getParentModule()->getSubmodule("groundStation")
                        : getParentModule()->getSubmodule("uav", msg->payload.receiverId);
    if (dest == nullptr) {
        delete msg;
        return;
    }
    WirelessMedium::get(this)->transmit(msg, this, dest);
}

void AttackerNode::finish() {
    recordScalar("attack_observed_messages", static_cast<double>(observedMessages_));
    recordScalar("attack_observed_m4", static_cast<double>(observedM4_));
    recordScalar("attack_plaintext_credential_bytes",
                 static_cast<double>(plaintextCredentialBytes_));
    recordScalar("attack_expect_success", expectSuccess_ ? 1.0 : 0.0);

    for (const auto& entry : stats_) {
        const std::string p = "atk_" + entry.first + "_";
        const AttackStat& s = entry.second;
        recordScalar((p + "attempts").c_str(), static_cast<double>(s.attempts));
        recordScalar((p + "accepted").c_str(), static_cast<double>(s.accepted));
        recordScalar((p + "rejected").c_str(), static_cast<double>(s.rejected));
        recordScalar((p + "replies_elicited").c_str(),
                     static_cast<double>(s.repliesElicited));
        recordScalar((p + "credentials_exposed").c_str(),
                     static_cast<double>(s.credentialsExposed));
        recordScalar((p + "responses_leaked").c_str(),
                     static_cast<double>(s.responsesLeaked));
        recordScalar((p + "success_rate").c_str(),
                     s.attempts > 0 ? static_cast<double>(s.accepted) / s.attempts : 0.0);

        // An attack that succeeds where the theory says it must not -- or fails
        // where the legacy control arm says it should succeed -- is the signal
        // worth surfacing.
        const bool succeeded = (s.accepted > 0) || (s.repliesElicited > 0) ||
                               (s.credentialsExposed > 0);
        // expectSuccess describes the configured attack only. The legacy control
        // arm disables ground-station authentication and nothing else, so the
        // other attack types are still expected to fail there.
        const bool expected = (entry.first == attackMode_) ? expectSuccess_ : false;
        recordScalar((p + "expected_success").c_str(), expected ? 1.0 : 0.0);
        recordScalar((p + "outcome_matches_expectation").c_str(),
                     (succeeded == expected) ? 1.0 : 0.0);
    }

    for (auto& entry : capturedM1_) delete entry.second;
    capturedM1_.clear();
}

} // namespace nodes
} // namespace uavauth
