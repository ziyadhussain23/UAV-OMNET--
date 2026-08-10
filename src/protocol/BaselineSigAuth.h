#ifndef UAVAUTH_PROTOCOL_BASELINESIGAUTH_H
#define UAVAUTH_PROTOCOL_BASELINESIGAUTH_H

#include "core/Bytes.h"
#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "crypto/SignatureSuite.h"
#include "crypto/X25519.h"
#include "protocol/Protocol.h"   // StepResult/StepTiming/ReplayCache
#include "protocol/Wire.h"

#include <map>
#include <memory>

namespace uavauth {
namespace protocol {

using core::Bytes;

/// A real, fully implemented RSA/ECDSA-signed ephemeral-DH mutual-authentication
/// handshake, built to the same StepResult/Message contract and the same
/// four-message shape as UavProtocol/GroundStationProtocol's Phase 2
/// (src/protocol/Protocol.h), for a genuine same-platform, same-implementation
/// latency comparison -- not a bare primitive benchmark and not a literature
/// figure.
///
/// Message shape (B1-B4, MessageType band 400, see Wire.h):
///   B1 (UAV->GS): {senderId, N1, T1, epkA, Sig_UAV(senderId||N1||T1||epkA)}
///   B2 (GS->UAV): verify B1's signature under the UAV's long-term public key
///                 (never do work in response to an invalid signature -- the
///                 same verify-before-respond discipline as Protocol.h's own
///                 Phase 2, applied here for the same reason: never let a
///                 forged message trigger asymmetric compute).
///                 {N2, T2, epkB, Sig_GS(senderId||N1||N2||T1||T2||epkA||epkB)}
///   B3 (UAV->GS): verify B2's signature under the GS's long-term public key;
///                 derive the ephemeral shared secret and session key; reply
///                 with a symmetric MAC confirmation (not a second signature)
///                 keyed by that session key -- the same design TLS 1.3's
///                 Finished message uses, and the same shape as Protocol.h's
///                 own M3/M4, which confirm with a cheap MAC rather than a
///                 second expensive asymmetric operation.
///                 {MAC_sessionKey(transcript)}
///   B4 (GS->UAV): verify B3's confirmation MAC; reply with the GS's own
///                 confirmation MAC. {MAC_sessionKey(transcript || "confirm")}
///
/// Long-term signature keypairs and the peer's public key are provisioned
/// once, out of band, exactly as this project's own PUF challenge/helper data
/// are provisioned once in Phase 1 -- not part of the timed handshake, and
/// public keys are not retransmitted on the wire in B1-B4 (Wire.h's PUBKEY/
/// CERT fields exist for wire-format generality but are unused by this
/// protocol; see PUBKEY's own comment in core/Encoding.h).
///
/// KDF and MAC for session-key derivation/confirmation use a CryptoSuite
/// (this work's own sha3 suite), paired with whichever SignatureSuite (RSA or
/// ECDSA) authenticates the exchange -- mirroring how a real ECDHE-RSA/
/// ECDHE-ECDSA handshake also layers a fast symmetric KDF/MAC under whichever
/// asymmetric scheme proves identity.

struct BaselineGsSession {
    int uavId = -1;
    Bytes n1, n2;
    uint32_t t1 = 0, t2 = 0;
    Bytes epkA, epkB;
    crypto::X25519KeyPair ephemeral;
    Bytes transcript;
    Bytes sessionKey;
    bool ephemeralErased = false;
};

struct BaselineUavSession {
    Bytes n1, n2;
    uint32_t t1 = 0;
    crypto::X25519KeyPair ephemeral;
    Bytes transcript;
    Bytes sessionKey;
    bool established = false;
    bool ephemeralErased = false;
};

class BaselineGroundStationProtocol {
  public:
    BaselineGroundStationProtocol(const crypto::SignatureSuite& sigSuite,
                                  const crypto::CryptoSuite& symSuite, crypto::Drbg& rng,
                                  uint32_t timestampWindowMs = 5000);

    /// One-time enrollment: generate this GS's own long-term keypair (if not
    /// already done) and register one UAV's public key. Not charged to any
    /// per-handshake timing.
    void ensureOwnKeypair();
    void enrollUav(int uavId, const Bytes& uavPublicKeySpki);
    Bytes publicKeyBytes() const;

    StepResult handleM1(const Message& m1, uint32_t nowMs);
    StepResult handleM3(const Message& m3, uint32_t nowMs);

    size_t replayHits() const { return replay_.hits(); }

  private:
    const crypto::SignatureSuite& sigSuite_;
    const crypto::CryptoSuite& symSuite_;
    crypto::Drbg& rng_;
    uint32_t windowMs_;

    crypto::SignatureKeyPair keypair_;
    std::map<int, std::unique_ptr<crypto::SignatureKeyPair>> uavPublicKeys_;
    std::map<int, BaselineGsSession> sessions_;
    ReplayCache replay_;
};

class BaselineUavProtocol {
  public:
    BaselineUavProtocol(int uavId, const crypto::SignatureSuite& sigSuite,
                        const crypto::CryptoSuite& symSuite, crypto::Drbg& rng,
                        uint32_t timestampWindowMs = 5000);

    /// One-time enrollment: generate this UAV's own long-term keypair (if not
    /// already done) and learn the GS's public key. Not charged to any
    /// per-handshake timing.
    void ensureOwnKeypair();
    void provisionGsPublicKey(const Bytes& gsPublicKeySpki);
    Bytes publicKeyBytes() const;

    StepResult startPhase2(uint32_t nowMs);
    StepResult handleM2(const Message& m2, uint32_t nowMs);
    StepResult handleM4(const Message& m4, uint32_t nowMs);

    bool established() const { return session_.established; }
    size_t replayHits() const { return replay_.hits(); }

  private:
    int uavId_;
    const crypto::SignatureSuite& sigSuite_;
    const crypto::CryptoSuite& symSuite_;
    crypto::Drbg& rng_;
    uint32_t windowMs_;

    crypto::SignatureKeyPair keypair_;
    std::unique_ptr<crypto::SignatureKeyPair> gsPublicKey_;
    BaselineUavSession session_;
    ReplayCache replay_;
};

} // namespace protocol
} // namespace uavauth

#endif
