#ifndef UAVAUTH_PROTOCOL_PROTOCOL_H
#define UAVAUTH_PROTOCOL_PROTOCOL_H

#include "core/Bytes.h"
#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "crypto/X25519.h"
#include "fe/FuzzyExtractor.h"
#include "protocol/Wire.h"
#include "puf/PufModel.h"

#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace uavauth {
namespace protocol {

using core::Bytes;

/// Per-message timing breakdown, carried alongside a result so a node can report
/// where the cost went without the protocol code carrying timing statements.
struct StepTiming {
    double computeMs = 0.0;
    double pufMs = 0.0;
    double feMs = 0.0;
    double macMs = 0.0;
    double kdfMs = 0.0;
    double dhMs = 0.0;
    double aeadMs = 0.0;
};

/// Outcome of handling one protocol message.
struct StepResult {
    bool ok = false;
    AbortReason abort = AbortReason::None;
    bool hasReply = false;
    Message reply;
    StepTiming timing;
};

/// Bounded replay cache: rejects a nonce already seen inside the freshness
/// window. Without it the timestamp window alone would let a captured message be
/// re-sent verbatim for up to deltaT.
class ReplayCache {
  public:
    explicit ReplayCache(size_t capacity = 4096) : capacity_(capacity) {}
    /// Returns true if the nonce is fresh (and records it); false if replayed.
    bool offer(const Bytes& nonce);
    size_t hits() const { return hits_; }
    void clear();

  private:
    size_t capacity_;
    size_t hits_ = 0;
    std::set<Bytes> seen_;
    std::deque<Bytes> order_;
};

// ---------------------------------------------------------------------------
// Phase 1: enrollment authority (ground station side)
// ---------------------------------------------------------------------------

/// What the ground station keeps for one enrolled UAV.
struct DeviceRecord {
    int uavId = -1;
    Bytes tid;                 // current temporary identity
    Bytes pendingTid;          // set once M4 is sent, committed on next M1
    Bytes challenge;           // the PUF challenge fixed at enrollment
    fe::HelperData helper;     // public helper data (also held by the UAV)
    Bytes mk;                  // device master key -- the only long-term secret
    bool enrolled = false;
};

/// What the UAV stores. Every field here is public: capturing the device yields
/// no key material, because mk is regenerated from the PUF on demand.
struct DeviceState {
    int uavId = -1;
    Bytes tid;
    Bytes challenge;
    fe::HelperData helper;
    bool provisioned = false;
};

// ---------------------------------------------------------------------------
// Session state
// ---------------------------------------------------------------------------

struct Phase2UavSession {
    Bytes mk;
    Bytes authKey;
    Bytes n1;
    Bytes n2;              // recorded when M2 verifies; needed as M4's AAD
    Bytes tidAtRequest;    // TID used in M1/M3, kept because M4 rotates it
    uint32_t t1 = 0;
    crypto::X25519KeyPair ephemeral;
    Bytes transcript;
    Bytes sessionKey;
    bool established = false;
    bool ephemeralErased = false;
    std::map<int, Bytes> peerCredentials;   // peerId -> Cred_ij
    std::map<int, Bytes> peerTids;
};

struct Phase2GsSession {
    int uavId = -1;
    Bytes authKey;
    Bytes n1, n2;
    uint32_t t1 = 0, t2 = 0;
    Bytes epkA, epkB;
    crypto::X25519KeyPair ephemeral;
    Bytes transcript;
    Bytes sessionKey;
    bool m3Verified = false;
    bool ephemeralErased = false;
};

struct Phase3Session {
    int localId = -1;
    int peerId = -1;
    bool initiator = false;
    Bytes authKey;
    Bytes nonceLocal, nonceRemote;
    crypto::X25519KeyPair ephemeral;
    Bytes epkLocal, epkRemote;
    Bytes p1Encoded, p2Encoded;
    Bytes sessionKey;
    bool established = false;
    bool ephemeralErased = false;
};

// ---------------------------------------------------------------------------
// Ground station
// ---------------------------------------------------------------------------

class GroundStationProtocol {
  public:
    GroundStationProtocol(const crypto::CryptoSuite& suite, const fe::FeParams& feParams,
                          crypto::Drbg& rng, uint32_t timestampWindowMs = 5000);

    /// Phase 1. Enrolls a device over the trusted channel: evaluates its PUF,
    /// runs the fuzzy extractor, and stores (challenge, helper, mk).
    bool enroll(int uavId, puf::PufModel& devicePuf, DeviceRecord& recordOut,
                DeviceState& deviceStateOut, StepTiming& timing);

    /// Phase 2 handlers.
    StepResult handleM1(const Message& m1, uint32_t nowMs);
    StepResult handleM3(const Message& m3, uint32_t nowMs);

    const DeviceRecord* findByTid(const Bytes& tid) const;
    const DeviceRecord* record(int uavId) const;
    bool sessionKeyFor(int uavId, Bytes& out) const;

    /// Per-pair credential, derived from the GS master key. Distinct inputs per
    /// pair mean a captured credential says nothing about any other pair.
    Bytes pairCredential(int a, int b) const;

    size_t replayHits() const { return replay_.hits(); }
    void setNumUavs(int n) { numUavs_ = n; }
    int numUavs() const { return numUavs_; }

  private:
    const crypto::CryptoSuite& suite_;
    fe::FeParams feParams_;
    crypto::Drbg& rng_;
    uint32_t windowMs_;
    int numUavs_ = 0;

    Bytes gsMasterKey_;
    std::map<int, DeviceRecord> devices_;
    std::map<int, Phase2GsSession> sessions_;
    ReplayCache replay_;
};

// ---------------------------------------------------------------------------
// UAV
// ---------------------------------------------------------------------------

class UavProtocol {
  public:
    UavProtocol(int uavId, const crypto::CryptoSuite& suite, const fe::FeParams& feParams,
                puf::PufModel& devicePuf, crypto::Drbg& rng,
                uint32_t timestampWindowMs = 5000);

    void provision(const DeviceState& state) { state_ = state; }
    const DeviceState& state() const { return state_; }

    /// Phase 2, UAV side.
    ///
    /// Note the ordering: sigma1 is keyed by K_auth = KDF(mk), so the UAV must
    /// regenerate mk from its PUF BEFORE it can send M1. (The specification text
    /// derives mk at M3, which is not workable; recorded in docs/spec-deviations.md.)
    /// This does not weaken the verify-before-respond property, because the
    /// challenge is fixed at enrollment and held locally -- a fraudulent ground
    /// station cannot choose it.
    StepResult startPhase2(uint32_t nowMs);
    StepResult handleM2(const Message& m2, uint32_t nowMs);
    StepResult handleM4(const Message& m4, uint32_t nowMs);

    /// Phase 3.
    StepResult startPhase3(int peerId, uint32_t nowMs);
    StepResult handleP1(const Message& p1, uint32_t nowMs);
    StepResult handleP2(const Message& p2, uint32_t nowMs);
    StepResult handleP3(const Message& p3, uint32_t nowMs);

    bool phase2Established() const { return phase2_.established; }
    const Bytes& phase2SessionKey() const { return phase2_.sessionKey; }
    bool peerSessionKey(int peerId, Bytes& out) const;
    size_t peerCredentialCount() const { return phase2_.peerCredentials.size(); }
    bool hasPeerCredential(int peerId) const;
    /// Injected directly in the capture-attack scenario, bypassing Phase 2.
    void injectPeerCredential(int peerId, const Bytes& cred, const Bytes& peerTid);
    bool ephemeralErased() const { return phase2_.ephemeralErased; }

    /// Control arm for the security evaluation. In legacy mode the UAV does NOT
    /// verify the ground station's authenticator on M2, reproducing the flaw the
    /// audit found in the original protocol. Its only purpose is to show that the
    /// attack harness can actually detect a successful attack -- without it,
    /// "every attack failed" could equally mean the attacker is broken.
    void setLegacyNoGsAuth(bool enabled) { legacyNoGsAuth_ = enabled; }
    bool legacyNoGsAuth() const { return legacyNoGsAuth_; }
    size_t replayHits() const { return replay_.hits(); }
    int id() const { return uavId_; }

  private:
    /// Regenerate the master key from the PUF and the public helper data.
    bool regenerateMasterKey(Bytes& mkOut, StepTiming& timing);

    int uavId_;
    const crypto::CryptoSuite& suite_;
    fe::FeParams feParams_;
    puf::PufModel& puf_;
    crypto::Drbg& rng_;
    uint32_t windowMs_;

    bool legacyNoGsAuth_ = false;
    DeviceState state_;
    Phase2UavSession phase2_;
    std::map<int, Phase3Session> peers_;
    ReplayCache replay_;
};

} // namespace protocol
} // namespace uavauth

#endif
