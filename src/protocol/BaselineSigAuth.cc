#include "protocol/BaselineSigAuth.h"

#include "core/Encoding.h"

namespace uavauth {
namespace protocol {

using core::append;
using core::Bytes;
using core::FieldId;
using core::FieldMap;
using crypto::monotonicNs;

namespace {

constexpr size_t kNonceLen = 16;

double msSince(int64_t startNs) {
    return static_cast<double>(monotonicNs() - startNs) / 1.0e6;
}

bool timestampFresh(uint32_t nowMs, uint32_t msgMs, uint32_t windowMs) {
    const uint32_t diff = (nowMs >= msgMs) ? (nowMs - msgMs) : (msgMs - nowMs);
    return diff <= windowMs;
}

StepResult fail(AbortReason reason, const StepTiming& timing = StepTiming{}) {
    StepResult r;
    r.ok = false;
    r.abort = reason;
    r.timing = timing;
    return r;
}

} // namespace

// ---------------------------------------------------------------------------
// BaselineGroundStationProtocol
// ---------------------------------------------------------------------------

BaselineGroundStationProtocol::BaselineGroundStationProtocol(
    const crypto::SignatureSuite& sigSuite, const crypto::CryptoSuite& symSuite,
    crypto::Drbg& rng, uint32_t timestampWindowMs)
    : sigSuite_(sigSuite), symSuite_(symSuite), rng_(rng), windowMs_(timestampWindowMs) {}

void BaselineGroundStationProtocol::ensureOwnKeypair() {
    if (!keypair_.valid()) keypair_ = sigSuite_.generateKeypair();
}

void BaselineGroundStationProtocol::enrollUav(int uavId, const Bytes& uavPublicKeySpki) {
    uavPublicKeys_[uavId] = sigSuite_.keyFromPublicBytes(uavPublicKeySpki);
}

Bytes BaselineGroundStationProtocol::publicKeyBytes() const {
    return sigSuite_.publicKeyBytes(keypair_);
}

StepResult BaselineGroundStationProtocol::handleM1(const Message& m1, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (m1.type != MessageType::B1_M1_AUTH_REQUEST) return fail(AbortReason::UnexpectedMessage);
    if (!m1.has(FieldId::SENDER_ID) || !m1.has(FieldId::NONCE_1) ||
        !m1.has(FieldId::TIMESTAMP) || !m1.has(FieldId::EPK_A) || !m1.has(FieldId::SIGNATURE))
        return fail(AbortReason::MissingField);

    const int uavId = decodeId(m1.get(FieldId::SENDER_ID));
    const Bytes n1 = m1.get(FieldId::NONCE_1);
    const Bytes epkA = m1.get(FieldId::EPK_A);
    if (n1.size() != kNonceLen || epkA.size() != crypto::kX25519KeyLen)
        return fail(AbortReason::MalformedField);

    uint32_t t1 = 0;
    try {
        t1 = decodeTimestamp(m1.get(FieldId::TIMESTAMP));
    } catch (const std::exception&) {
        return fail(AbortReason::MalformedField);
    }
    if (!timestampFresh(nowMs, t1, windowMs_)) return fail(AbortReason::StaleTimestamp);
    if (!replay_.offer(n1)) return fail(AbortReason::ReplayedNonce);

    const auto keyIt = uavPublicKeys_.find(uavId);
    if (keyIt == uavPublicKeys_.end() || keyIt->second == nullptr)
        return fail(AbortReason::UnknownIdentity);

    // Verify BEFORE doing anything else, including the ephemeral keygen below:
    // an invalid signature must never trigger asymmetric compute on our side,
    // the same verify-before-respond discipline Protocol.h's own Phase 2 uses.
    FieldMap signed1{{FieldId::SENDER_ID, m1.get(FieldId::SENDER_ID)},
                     {FieldId::NONCE_1, n1},
                     {FieldId::TIMESTAMP, m1.get(FieldId::TIMESTAMP)},
                     {FieldId::EPK_A, epkA}};
    const Bytes input1 = macInput(m1.suiteId, MessageType::B1_M1_AUTH_REQUEST, signed1);

    const int64_t tv = monotonicNs();
    const bool sigOk = sigSuite_.verify(*keyIt->second, input1, m1.get(FieldId::SIGNATURE));
    timing.verifyMs += msSince(tv);
    if (!sigOk) return fail(AbortReason::MacVerifyFailed, timing);

    BaselineGsSession session;
    session.uavId = uavId;
    session.n1 = n1;
    session.t1 = t1;
    session.epkA = epkA;
    session.n2 = rng_.bytes(kNonceLen);
    session.t2 = nowMs;

    const int64_t td = monotonicNs();
    session.ephemeral = crypto::x25519Generate(rng_.bytes(32), symSuite_.counters());
    timing.dhMs += msSince(td);
    session.epkB = session.ephemeral.publicKey;

    Message m2;
    m2.type = MessageType::B1_M2_GS_RESPONSE;
    m2.suiteId = m1.suiteId;
    m2.senderId = -1;
    m2.receiverId = uavId;
    m2.set(FieldId::NONCE_2, session.n2);
    m2.set(FieldId::TIMESTAMP, encodeTimestamp(session.t2));
    m2.set(FieldId::EPK_B, session.epkB);

    FieldMap signed2{{FieldId::SENDER_ID, m1.get(FieldId::SENDER_ID)},
                     {FieldId::NONCE_1, n1},
                     {FieldId::NONCE_2, session.n2},
                     {FieldId::TIMESTAMP, encodeTimestamp(session.t2)},
                     {FieldId::EPK_A, epkA},
                     {FieldId::EPK_B, session.epkB}};
    const Bytes input2 = macInput(m2.suiteId, MessageType::B1_M2_GS_RESPONSE, signed2);

    const int64_t ts = monotonicNs();
    m2.set(FieldId::SIGNATURE, sigSuite_.sign(keypair_, input2));
    timing.signMs += msSince(ts);

    session.transcript = input1;
    append(session.transcript, input2);
    sessions_[uavId] = session;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m2;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult BaselineGroundStationProtocol::handleM3(const Message& m3, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();
    (void)nowMs;

    if (m3.type != MessageType::B1_M3_UAV_CONFIRM) return fail(AbortReason::UnexpectedMessage);
    if (!m3.has(FieldId::MAC_TAG)) return fail(AbortReason::MissingField);

    const auto sit = sessions_.find(m3.senderId);
    if (sit == sessions_.end()) return fail(AbortReason::UnexpectedMessage);
    BaselineGsSession& session = sit->second;

    // Complete the key exchange so the confirmation MAC can be checked.
    const int64_t td = monotonicNs();
    Bytes shared;
    const bool dhOk = crypto::x25519Derive(session.ephemeral.secret, session.epkA, shared,
                                           symSuite_.counters());
    timing.dhMs += msSince(td);
    if (!dhOk) return fail(AbortReason::DhFailed, timing);

    const int64_t tk = monotonicNs();
    session.sessionKey = symSuite_.kdf(shared, session.transcript, crypto::label::kP2Sess,
                                       Bytes{}, symSuite_.keyLen());
    timing.kdfMs += msSince(tk);

    session.ephemeral.erase();
    session.ephemeralErased = true;
    core::secureZero(shared);

    const int64_t tm = monotonicNs();
    const bool macOk =
        symSuite_.macVerify(session.sessionKey, session.transcript, m3.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed, timing);

    Bytes confirmInput = session.transcript;
    append(confirmInput, core::fromString("confirm"));

    Message m4;
    m4.type = MessageType::B1_M4_GS_CONFIRM;
    m4.suiteId = m3.suiteId;
    m4.senderId = -1;
    m4.receiverId = session.uavId;

    const int64_t tm4 = monotonicNs();
    m4.set(FieldId::MAC_TAG, symSuite_.mac(session.sessionKey, confirmInput));
    timing.macMs += msSince(tm4);

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m4;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

// ---------------------------------------------------------------------------
// BaselineUavProtocol
// ---------------------------------------------------------------------------

BaselineUavProtocol::BaselineUavProtocol(int uavId, const crypto::SignatureSuite& sigSuite,
                                         const crypto::CryptoSuite& symSuite, crypto::Drbg& rng,
                                         uint32_t timestampWindowMs)
    : uavId_(uavId), sigSuite_(sigSuite), symSuite_(symSuite), rng_(rng),
      windowMs_(timestampWindowMs) {}

void BaselineUavProtocol::ensureOwnKeypair() {
    if (!keypair_.valid()) keypair_ = sigSuite_.generateKeypair();
}

void BaselineUavProtocol::provisionGsPublicKey(const Bytes& gsPublicKeySpki) {
    gsPublicKey_ = sigSuite_.keyFromPublicBytes(gsPublicKeySpki);
}

Bytes BaselineUavProtocol::publicKeyBytes() const { return sigSuite_.publicKeyBytes(keypair_); }

StepResult BaselineUavProtocol::startPhase2(uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (gsPublicKey_ == nullptr) return fail(AbortReason::NotAuthenticated);

    session_ = BaselineUavSession{};
    session_.n1 = rng_.bytes(kNonceLen);
    session_.t1 = nowMs;

    const int64_t td = monotonicNs();
    session_.ephemeral = crypto::x25519Generate(rng_.bytes(32), symSuite_.counters());
    timing.dhMs += msSince(td);

    Message m1;
    m1.type = MessageType::B1_M1_AUTH_REQUEST;
    m1.suiteId = 0;   // no CryptoSuite domain applies; the signature suite has no SuiteId
    m1.senderId = uavId_;
    m1.receiverId = -1;
    m1.set(FieldId::SENDER_ID, encodeId(uavId_));
    m1.set(FieldId::NONCE_1, session_.n1);
    m1.set(FieldId::TIMESTAMP, encodeTimestamp(session_.t1));
    m1.set(FieldId::EPK_A, session_.ephemeral.publicKey);

    FieldMap signed1{{FieldId::SENDER_ID, encodeId(uavId_)},
                     {FieldId::NONCE_1, session_.n1},
                     {FieldId::TIMESTAMP, encodeTimestamp(session_.t1)},
                     {FieldId::EPK_A, session_.ephemeral.publicKey}};
    const Bytes input1 = macInput(m1.suiteId, MessageType::B1_M1_AUTH_REQUEST, signed1);

    const int64_t ts = monotonicNs();
    m1.set(FieldId::SIGNATURE, sigSuite_.sign(keypair_, input1));
    timing.signMs += msSince(ts);

    session_.transcript = input1;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m1;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult BaselineUavProtocol::handleM2(const Message& m2, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (m2.type != MessageType::B1_M2_GS_RESPONSE) return fail(AbortReason::UnexpectedMessage);
    if (session_.transcript.empty()) return fail(AbortReason::UnexpectedMessage);
    if (!m2.has(FieldId::NONCE_2) || !m2.has(FieldId::TIMESTAMP) || !m2.has(FieldId::EPK_B) ||
        !m2.has(FieldId::SIGNATURE))
        return fail(AbortReason::MissingField);

    const Bytes n2 = m2.get(FieldId::NONCE_2);
    const Bytes epkB = m2.get(FieldId::EPK_B);
    if (n2.size() != kNonceLen || epkB.size() != crypto::kX25519KeyLen)
        return fail(AbortReason::MalformedField);

    uint32_t t2 = 0;
    try {
        t2 = decodeTimestamp(m2.get(FieldId::TIMESTAMP));
    } catch (const std::exception&) {
        return fail(AbortReason::MalformedField);
    }
    if (!timestampFresh(nowMs, t2, windowMs_)) return fail(AbortReason::StaleTimestamp);
    if (!replay_.offer(n2)) return fail(AbortReason::ReplayedNonce);

    // Verify-before-respond: an invalid GS signature produces no reply.
    FieldMap signed2{{FieldId::SENDER_ID, encodeId(uavId_)},
                     {FieldId::NONCE_1, session_.n1},
                     {FieldId::NONCE_2, n2},
                     {FieldId::TIMESTAMP, m2.get(FieldId::TIMESTAMP)},
                     {FieldId::EPK_A, session_.ephemeral.publicKey},
                     {FieldId::EPK_B, epkB}};
    const Bytes input2 = macInput(m2.suiteId, MessageType::B1_M2_GS_RESPONSE, signed2);

    const int64_t tv = monotonicNs();
    const bool sigOk = sigSuite_.verify(*gsPublicKey_, input2, m2.get(FieldId::SIGNATURE));
    timing.verifyMs += msSince(tv);
    if (!sigOk) return fail(AbortReason::MacVerifyFailed, timing);

    session_.n2 = n2;
    append(session_.transcript, input2);

    const int64_t td = monotonicNs();
    Bytes shared;
    const bool dhOk =
        crypto::x25519Derive(session_.ephemeral.secret, epkB, shared, symSuite_.counters());
    timing.dhMs += msSince(td);
    if (!dhOk) return fail(AbortReason::DhFailed, timing);

    const int64_t tk = monotonicNs();
    session_.sessionKey = symSuite_.kdf(shared, session_.transcript, crypto::label::kP2Sess,
                                        Bytes{}, symSuite_.keyLen());
    timing.kdfMs += msSince(tk);

    session_.ephemeral.erase();
    session_.ephemeralErased = true;
    core::secureZero(shared);

    Message m3;
    m3.type = MessageType::B1_M3_UAV_CONFIRM;
    m3.suiteId = m2.suiteId;
    m3.senderId = uavId_;
    m3.receiverId = -1;

    const int64_t tm = monotonicNs();
    m3.set(FieldId::MAC_TAG, symSuite_.mac(session_.sessionKey, session_.transcript));
    timing.macMs += msSince(tm);

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m3;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult BaselineUavProtocol::handleM4(const Message& m4, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();
    (void)nowMs;

    if (m4.type != MessageType::B1_M4_GS_CONFIRM) return fail(AbortReason::UnexpectedMessage);
    if (session_.sessionKey.empty()) return fail(AbortReason::UnexpectedMessage);
    if (!m4.has(FieldId::MAC_TAG)) return fail(AbortReason::MissingField);

    Bytes confirmInput = session_.transcript;
    append(confirmInput, core::fromString("confirm"));

    const int64_t tm = monotonicNs();
    const bool macOk =
        symSuite_.macVerify(session_.sessionKey, confirmInput, m4.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed, timing);

    session_.established = true;

    StepResult r;
    r.ok = true;
    r.hasReply = false;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

} // namespace protocol
} // namespace uavauth
