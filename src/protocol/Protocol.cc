#include "protocol/Protocol.h"

#include "core/Encoding.h"

#include <algorithm>
#include <cmath>

namespace uavauth {
namespace protocol {

using core::append;
using core::Bytes;
using core::FieldId;
using core::FieldMap;
using crypto::monotonicNs;

namespace {

constexpr size_t kNonceLen = 16;
constexpr size_t kTidLen = 16;

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

/// Serialise the credential package delivered in M4:
///   u16(count) || [ u16(peerId) || u16(credLen) || cred || u16(tidLen) || tid ]*
///   || u16(tidNewLen) || tidNew
/// TID_new travels INSIDE the AEAD. The specification places it outside, where an
/// attacker could flip it and desynchronise identities.
Bytes packCredentials(const std::map<int, Bytes>& creds,
                      const std::map<int, Bytes>& tids, const Bytes& tidNew) {
    Bytes out = core::u16be(static_cast<uint16_t>(creds.size()));
    for (const auto& entry : creds) {
        append(out, core::u16be(static_cast<uint16_t>(entry.first)));
        append(out, core::lengthPrefixed(entry.second));
        const auto tidIt = tids.find(entry.first);
        append(out, core::lengthPrefixed(tidIt == tids.end() ? Bytes{} : tidIt->second));
    }
    append(out, core::lengthPrefixed(tidNew));
    return out;
}

bool unpackCredentials(const Bytes& blob, std::map<int, Bytes>& credsOut,
                       std::map<int, Bytes>& tidsOut, Bytes& tidNewOut) {
    try {
        size_t off = 0;
        const uint16_t count = core::readU16be(blob, off);
        off += 2;
        for (uint16_t i = 0; i < count; ++i) {
            const int peerId = static_cast<int>(core::readU16be(blob, off));
            off += 2;
            const uint16_t credLen = core::readU16be(blob, off);
            off += 2;
            if (off + credLen > blob.size()) return false;
            credsOut[peerId] = Bytes(blob.begin() + static_cast<long>(off),
                                     blob.begin() + static_cast<long>(off + credLen));
            off += credLen;
            const uint16_t tidLen = core::readU16be(blob, off);
            off += 2;
            if (off + tidLen > blob.size()) return false;
            tidsOut[peerId] = Bytes(blob.begin() + static_cast<long>(off),
                                    blob.begin() + static_cast<long>(off + tidLen));
            off += tidLen;
        }
        const uint16_t tidLen = core::readU16be(blob, off);
        off += 2;
        if (off + tidLen != blob.size()) return false;
        tidNewOut = Bytes(blob.begin() + static_cast<long>(off), blob.end());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace

// ---------------------------------------------------------------------------
// ReplayCache
// ---------------------------------------------------------------------------

bool ReplayCache::offer(const Bytes& nonce) {
    if (seen_.find(nonce) != seen_.end()) {
        ++hits_;
        return false;
    }
    seen_.insert(nonce);
    order_.push_back(nonce);
    if (order_.size() > capacity_) {
        seen_.erase(order_.front());
        order_.pop_front();
    }
    return true;
}

void ReplayCache::clear() {
    seen_.clear();
    order_.clear();
    hits_ = 0;
}

// ---------------------------------------------------------------------------
// GroundStationProtocol
// ---------------------------------------------------------------------------

GroundStationProtocol::GroundStationProtocol(const crypto::CryptoSuite& suite,
                                             const fe::FeParams& feParams,
                                             crypto::Drbg& rng, uint32_t timestampWindowMs)
    : suite_(suite), feParams_(feParams), rng_(rng), windowMs_(timestampWindowMs) {
    // The GS master key never leaves the ground station; every per-pair
    // credential is derived from it.
    gsMasterKey_ = rng_.bytes(suite_.keyLen());
}

Bytes GroundStationProtocol::pairCredential(int a, int b) const {
    const int lo = std::min(a, b);
    const int hi = std::max(a, b);
    Bytes info = core::u16be(static_cast<uint16_t>(lo));
    append(info, core::u16be(static_cast<uint16_t>(hi)));
    return suite_.kdf(gsMasterKey_, Bytes{}, crypto::label::kPairCred, info,
                      suite_.keyLen());
}

bool GroundStationProtocol::enroll(int uavId, puf::PufModel& devicePuf,
                                   DeviceRecord& recordOut, DeviceState& deviceStateOut,
                                   StepTiming& timing) {
    const int64_t t0 = monotonicNs();
    fe::FuzzyExtractor extractor(feParams_, suite_);

    DeviceRecord rec;
    rec.uavId = uavId;
    rec.challenge = rng_.bytes(16);

    const int64_t tp = monotonicNs();
    const Bytes response = devicePuf.evaluateIdeal(rec.challenge, extractor.requiredPufBits());
    timing.pufMs = msSince(tp);

    const int64_t tf = monotonicNs();
    const fe::GenResult gen = extractor.gen(response, rng_.bytes(static_cast<size_t>(feParams_.seedBytes)));
    timing.feMs = msSince(tf);
    if (!gen.ok) return false;

    rec.helper = gen.helper;
    rec.mk = gen.mk;
    rec.tid = suite_.kdf(gen.mk, Bytes{}, crypto::label::kTidRotate,
                         core::u16be(static_cast<uint16_t>(uavId)), kTidLen);
    rec.enrolled = true;

    devices_[uavId] = rec;
    recordOut = rec;

    deviceStateOut.uavId = uavId;
    deviceStateOut.tid = rec.tid;
    deviceStateOut.challenge = rec.challenge;
    deviceStateOut.helper = rec.helper;   // public
    deviceStateOut.provisioned = true;

    timing.computeMs = msSince(t0);
    return true;
}

const DeviceRecord* GroundStationProtocol::findByTid(const Bytes& tid) const {
    for (const auto& entry : devices_) {
        // Accept the pending identity too: if M4 was lost the UAV still holds the
        // old TID, and rejecting it would strand the device permanently.
        if (entry.second.tid == tid ||
            (!entry.second.pendingTid.empty() && entry.second.pendingTid == tid))
            return &entry.second;
    }
    return nullptr;
}

const DeviceRecord* GroundStationProtocol::record(int uavId) const {
    const auto it = devices_.find(uavId);
    return it == devices_.end() ? nullptr : &it->second;
}

bool GroundStationProtocol::sessionKeyFor(int uavId, Bytes& out) const {
    const auto it = sessions_.find(uavId);
    if (it == sessions_.end() || it->second.sessionKey.empty()) return false;
    out = it->second.sessionKey;
    return true;
}

StepResult GroundStationProtocol::handleM1(const Message& m1, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (m1.type != MessageType::P2_M1_AUTH_REQUEST) return fail(AbortReason::UnexpectedMessage);
    if (!m1.has(FieldId::TID) || !m1.has(FieldId::NONCE_1) || !m1.has(FieldId::TIMESTAMP) ||
        !m1.has(FieldId::EPK_A) || !m1.has(FieldId::MAC_TAG))
        return fail(AbortReason::MissingField);

    const Bytes tid = m1.get(FieldId::TID);
    const Bytes n1 = m1.get(FieldId::NONCE_1);
    const Bytes epkA = m1.get(FieldId::EPK_A);
    if (epkA.size() != crypto::kX25519KeyLen || n1.size() != kNonceLen)
        return fail(AbortReason::MalformedField);

    uint32_t t1 = 0;
    try {
        t1 = decodeTimestamp(m1.get(FieldId::TIMESTAMP));
    } catch (const std::exception&) {
        return fail(AbortReason::MalformedField);
    }
    if (!timestampFresh(nowMs, t1, windowMs_)) return fail(AbortReason::StaleTimestamp);
    if (!replay_.offer(n1)) return fail(AbortReason::ReplayedNonce);

    const DeviceRecord* rec = findByTid(tid);
    if (rec == nullptr) return fail(AbortReason::UnknownIdentity);

    // Verify sigma1 under a key only the genuine device (via its PUF) or this
    // ground station (via its database) can compute.
    const int64_t tk = monotonicNs();
    const Bytes authKey =
        suite_.kdf(rec->mk, Bytes{}, crypto::label::kP2Auth, Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    FieldMap signed1{{FieldId::TID, tid},
                     {FieldId::NONCE_1, n1},
                     {FieldId::TIMESTAMP, m1.get(FieldId::TIMESTAMP)},
                     {FieldId::EPK_A, epkA}};
    const Bytes input1 = macInput(m1.suiteId, MessageType::P2_M1_AUTH_REQUEST, signed1);

    const int64_t tm = monotonicNs();
    const bool macOk = suite_.macVerify(authKey, input1, m1.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed);

    // Authenticated. Build M2 with a fresh nonce and ephemeral share.
    Phase2GsSession session;
    session.uavId = rec->uavId;
    session.authKey = authKey;
    session.n1 = n1;
    session.t1 = t1;
    session.epkA = epkA;
    session.n2 = rng_.bytes(kNonceLen);
    session.t2 = nowMs;

    const int64_t td = monotonicNs();
    session.ephemeral = crypto::x25519Generate(rng_.bytes(32), suite_.counters());
    timing.dhMs += msSince(td);
    session.epkB = session.ephemeral.publicKey;

    Message m2;
    m2.type = MessageType::P2_M2_GS_RESPONSE;
    m2.suiteId = m1.suiteId;
    m2.senderId = -1;
    m2.receiverId = rec->uavId;
    m2.set(FieldId::NONCE_2, session.n2);
    m2.set(FieldId::TIMESTAMP, encodeTimestamp(session.t2));
    m2.set(FieldId::EPK_B, session.epkB);

    // sigma2 binds both nonces and both ephemeral shares, and implicitly the TID
    // and N1 (present in the MAC input without being retransmitted).
    FieldMap signed2{{FieldId::TID, tid},
                     {FieldId::NONCE_1, n1},
                     {FieldId::NONCE_2, session.n2},
                     {FieldId::TIMESTAMP, encodeTimestamp(session.t2)},
                     {FieldId::EPK_A, epkA},
                     {FieldId::EPK_B, session.epkB}};
    const Bytes input2 = macInput(m2.suiteId, MessageType::P2_M2_GS_RESPONSE, signed2);

    const int64_t tm2 = monotonicNs();
    m2.set(FieldId::MAC_TAG, suite_.mac(authKey, input2));
    timing.macMs += msSince(tm2);

    session.transcript = input1;
    append(session.transcript, input2);
    sessions_[rec->uavId] = session;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m2;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult GroundStationProtocol::handleM3(const Message& m3, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (m3.type != MessageType::P2_M3_UAV_CONFIRM) return fail(AbortReason::UnexpectedMessage);
    if (!m3.has(FieldId::TID) || !m3.has(FieldId::MAC_TAG))
        return fail(AbortReason::MissingField);

    const DeviceRecord* rec = findByTid(m3.get(FieldId::TID));
    if (rec == nullptr) return fail(AbortReason::UnknownIdentity);
    auto sit = sessions_.find(rec->uavId);
    if (sit == sessions_.end()) return fail(AbortReason::UnexpectedMessage);
    Phase2GsSession& session = sit->second;

    FieldMap signed3{{FieldId::TID, m3.get(FieldId::TID)}};
    Bytes input3 = macInput(m3.suiteId, MessageType::P2_M3_UAV_CONFIRM, signed3);
    append(input3, session.transcript);

    const int64_t tm = monotonicNs();
    const bool macOk = suite_.macVerify(session.authKey, input3, m3.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed);
    session.m3Verified = true;

    // Complete the key exchange.
    const int64_t td = monotonicNs();
    Bytes shared;
    const bool dhOk =
        crypto::x25519Derive(session.ephemeral.secret, session.epkA, shared, suite_.counters());
    timing.dhMs += msSince(td);
    if (!dhOk) return fail(AbortReason::DhFailed);

    const DeviceRecord* mutableRec = rec;
    Bytes ikm = mutableRec->mk;
    append(ikm, shared);

    const int64_t tk = monotonicNs();
    session.sessionKey = suite_.kdf(ikm, session.transcript, crypto::label::kP2Sess,
                                    Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    // Erase the ephemeral scalar: forward secrecy holds only if it is gone.
    session.ephemeral.erase();
    session.ephemeralErased = true;
    core::secureZero(shared);

    // Build M4: per-pair credentials and the rotated identity, all inside the AEAD.
    std::map<int, Bytes> creds;
    std::map<int, Bytes> tids;
    for (const auto& entry : devices_) {
        if (entry.first == rec->uavId) continue;
        creds[entry.first] = pairCredential(rec->uavId, entry.first);
        tids[entry.first] = entry.second.tid;
    }

    DeviceRecord& stored = devices_[rec->uavId];
    Bytes rotateInfo = session.n1;
    append(rotateInfo, session.n2);
    const Bytes tidNew =
        suite_.kdf(stored.mk, stored.tid, crypto::label::kTidRotate, rotateInfo, kTidLen);
    stored.pendingTid = tidNew;

    const Bytes plaintext = packCredentials(creds, tids, tidNew);

    const Bytes aeadKeyNonce =
        suite_.kdf(session.sessionKey, Bytes{}, crypto::label::kP2Aead, Bytes{},
                   suite_.aeadKeyLen() + suite_.aeadNonceLen());
    const Bytes aeadKey(aeadKeyNonce.begin(),
                        aeadKeyNonce.begin() + static_cast<long>(suite_.aeadKeyLen()));
    const Bytes aeadNonce(aeadKeyNonce.begin() + static_cast<long>(suite_.aeadKeyLen()),
                          aeadKeyNonce.end());

    FieldMap aadFields{{FieldId::TID, m3.get(FieldId::TID)},
                       {FieldId::NONCE_1, session.n1},
                       {FieldId::NONCE_2, session.n2}};
    const Bytes aad = macInput(m3.suiteId, MessageType::P2_M4_GS_CONFIRM, aadFields);

    Bytes ciphertext;
    const int64_t ta = monotonicNs();
    const bool sealOk = suite_.aeadSeal(aeadKey, aeadNonce, aad, plaintext, ciphertext);
    timing.aeadMs += msSince(ta);
    if (!sealOk) return fail(AbortReason::AeadOpenFailed);

    Message m4;
    m4.type = MessageType::P2_M4_GS_CONFIRM;
    m4.suiteId = m3.suiteId;
    m4.senderId = -1;
    m4.receiverId = rec->uavId;
    m4.set(FieldId::AEAD_NONCE, aeadNonce);
    m4.set(FieldId::CRED_PKG, ciphertext);

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m4;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

// ---------------------------------------------------------------------------
// UavProtocol
// ---------------------------------------------------------------------------

UavProtocol::UavProtocol(int uavId, const crypto::CryptoSuite& suite,
                         const fe::FeParams& feParams, puf::PufModel& devicePuf,
                         crypto::Drbg& rng, uint32_t timestampWindowMs)
    : uavId_(uavId), suite_(suite), feParams_(feParams), puf_(devicePuf), rng_(rng),
      windowMs_(timestampWindowMs) {}

bool UavProtocol::regenerateMasterKey(Bytes& mkOut, StepTiming& timing) {
    fe::FuzzyExtractor extractor(feParams_, suite_);

    const int64_t tp = monotonicNs();
    const Bytes noisy = puf_.evaluateNoisy(state_.challenge, extractor.requiredPufBits(), rng_);
    timing.pufMs += msSince(tp);

    const int64_t tf = monotonicNs();
    const fe::RepResult rep = extractor.rep(noisy, state_.helper);
    timing.feMs += msSince(tf);

    if (!rep.ok) return false;
    mkOut = rep.mk;
    return true;
}

StepResult UavProtocol::startPhase2(uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (!state_.provisioned) return fail(AbortReason::NotAuthenticated);

    // Regenerate mk from the PUF: sigma1 is keyed by it, so this must happen
    // before M1 can be built. The raw response is consumed here and never
    // transmitted, so there is nothing on the wire for an attacker to harvest.
    Bytes mk;
    if (!regenerateMasterKey(mk, timing)) return fail(AbortReason::FuzzyExtractorFailed, timing);

    phase2_ = Phase2UavSession{};
    phase2_.mk = mk;

    const int64_t tk = monotonicNs();
    phase2_.authKey = suite_.kdf(mk, Bytes{}, crypto::label::kP2Auth, Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    phase2_.n1 = rng_.bytes(kNonceLen);
    phase2_.t1 = nowMs;
    phase2_.tidAtRequest = state_.tid;

    const int64_t td = monotonicNs();
    phase2_.ephemeral = crypto::x25519Generate(rng_.bytes(32), suite_.counters());
    timing.dhMs += msSince(td);

    Message m1;
    m1.type = MessageType::P2_M1_AUTH_REQUEST;
    m1.suiteId = static_cast<uint8_t>(suite_.id());
    m1.senderId = uavId_;
    m1.receiverId = -1;
    m1.set(FieldId::TID, state_.tid);
    m1.set(FieldId::NONCE_1, phase2_.n1);
    m1.set(FieldId::TIMESTAMP, encodeTimestamp(phase2_.t1));
    m1.set(FieldId::EPK_A, phase2_.ephemeral.publicKey);

    FieldMap signed1{{FieldId::TID, state_.tid},
                     {FieldId::NONCE_1, phase2_.n1},
                     {FieldId::TIMESTAMP, encodeTimestamp(phase2_.t1)},
                     {FieldId::EPK_A, phase2_.ephemeral.publicKey}};
    const Bytes input1 = macInput(m1.suiteId, MessageType::P2_M1_AUTH_REQUEST, signed1);

    const int64_t tm = monotonicNs();
    m1.set(FieldId::MAC_TAG, suite_.mac(phase2_.authKey, input1));
    timing.macMs += msSince(tm);

    phase2_.transcript = input1;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m1;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult UavProtocol::handleM2(const Message& m2, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (m2.type != MessageType::P2_M2_GS_RESPONSE) return fail(AbortReason::UnexpectedMessage);
    if (phase2_.authKey.empty()) return fail(AbortReason::UnexpectedMessage);
    if (!m2.has(FieldId::NONCE_2) || !m2.has(FieldId::TIMESTAMP) || !m2.has(FieldId::EPK_B) ||
        !m2.has(FieldId::MAC_TAG))
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

    // Verify the ground station BEFORE doing anything else or emitting anything.
    // A forged M2 produces no reply at all, so there is no oracle to query.
    FieldMap signed2{{FieldId::TID, state_.tid},
                     {FieldId::NONCE_1, phase2_.n1},
                     {FieldId::NONCE_2, n2},
                     {FieldId::TIMESTAMP, m2.get(FieldId::TIMESTAMP)},
                     {FieldId::EPK_A, phase2_.ephemeral.publicKey},
                     {FieldId::EPK_B, epkB}};
    const Bytes input2 = macInput(m2.suiteId, MessageType::P2_M2_GS_RESPONSE, signed2);

    const int64_t tm = monotonicNs();
    const bool macOk = suite_.macVerify(phase2_.authKey, input2, m2.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed, timing);

    phase2_.n2 = n2;
    append(phase2_.transcript, input2);

    Message m3;
    m3.type = MessageType::P2_M3_UAV_CONFIRM;
    m3.suiteId = m2.suiteId;
    m3.senderId = uavId_;
    m3.receiverId = -1;
    m3.set(FieldId::TID, state_.tid);

    FieldMap signed3{{FieldId::TID, state_.tid}};
    Bytes input3 = macInput(m3.suiteId, MessageType::P2_M3_UAV_CONFIRM, signed3);
    append(input3, phase2_.transcript);

    const int64_t tm3 = monotonicNs();
    m3.set(FieldId::MAC_TAG, suite_.mac(phase2_.authKey, input3));
    timing.macMs += msSince(tm3);

    // Derive the forward-secret session key and erase the scalar.
    const int64_t td = monotonicNs();
    Bytes shared;
    const bool dhOk =
        crypto::x25519Derive(phase2_.ephemeral.secret, epkB, shared, suite_.counters());
    timing.dhMs += msSince(td);
    if (!dhOk) return fail(AbortReason::DhFailed, timing);

    Bytes ikm = phase2_.mk;
    append(ikm, shared);

    const int64_t tk = monotonicNs();
    phase2_.sessionKey = suite_.kdf(ikm, phase2_.transcript, crypto::label::kP2Sess,
                                    Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    phase2_.ephemeral.erase();
    phase2_.ephemeralErased = true;
    core::secureZero(shared);

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = m3;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult UavProtocol::handleM4(const Message& m4, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (m4.type != MessageType::P2_M4_GS_CONFIRM) return fail(AbortReason::UnexpectedMessage);
    if (phase2_.sessionKey.empty()) return fail(AbortReason::UnexpectedMessage);
    if (!m4.has(FieldId::AEAD_NONCE) || !m4.has(FieldId::CRED_PKG))
        return fail(AbortReason::MissingField);

    const Bytes aeadKeyNonce =
        suite_.kdf(phase2_.sessionKey, Bytes{}, crypto::label::kP2Aead, Bytes{},
                   suite_.aeadKeyLen() + suite_.aeadNonceLen());
    const Bytes aeadKey(aeadKeyNonce.begin(),
                        aeadKeyNonce.begin() + static_cast<long>(suite_.aeadKeyLen()));
    const Bytes aeadNonce(aeadKeyNonce.begin() + static_cast<long>(suite_.aeadKeyLen()),
                          aeadKeyNonce.end());

    // M4 does not retransmit the TID or either nonce; the AAD is rebuilt from
    // session state, so an attacker cannot substitute a package from a different
    // session even though those fields are absent from the wire.
    FieldMap aadFields{{FieldId::TID, phase2_.tidAtRequest},
                       {FieldId::NONCE_1, phase2_.n1},
                       {FieldId::NONCE_2, phase2_.n2}};
    const Bytes aad = macInput(m4.suiteId, MessageType::P2_M4_GS_CONFIRM, aadFields);

    Bytes plaintext;
    const int64_t ta = monotonicNs();
    const bool openOk =
        suite_.aeadOpen(aeadKey, aeadNonce, aad, m4.get(FieldId::CRED_PKG), plaintext);
    timing.aeadMs += msSince(ta);
    if (!openOk) return fail(AbortReason::AeadOpenFailed, timing);

    std::map<int, Bytes> creds, tids;
    Bytes tidNew;
    if (!unpackCredentials(plaintext, creds, tids, tidNew))
        return fail(AbortReason::MalformedField, timing);

    phase2_.peerCredentials = creds;
    phase2_.peerTids = tids;
    if (!tidNew.empty()) state_.tid = tidNew;
    phase2_.established = true;

    StepResult r;
    r.ok = true;
    r.hasReply = false;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

bool UavProtocol::hasPeerCredential(int peerId) const {
    return phase2_.peerCredentials.find(peerId) != phase2_.peerCredentials.end();
}

void UavProtocol::injectPeerCredential(int peerId, const Bytes& cred, const Bytes& peerTid) {
    phase2_.peerCredentials[peerId] = cred;
    phase2_.peerTids[peerId] = peerTid;
}

bool UavProtocol::peerSessionKey(int peerId, Bytes& out) const {
    const auto it = peers_.find(peerId);
    if (it == peers_.end() || !it->second.established) return false;
    out = it->second.sessionKey;
    return true;
}

StepResult UavProtocol::startPhase3(int peerId, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    const auto credIt = phase2_.peerCredentials.find(peerId);
    if (credIt == phase2_.peerCredentials.end()) return fail(AbortReason::NoSuchPeer);

    Phase3Session session;
    session.localId = uavId_;
    session.peerId = peerId;
    session.initiator = true;

    const int64_t tk = monotonicNs();
    session.authKey = suite_.kdf(credIt->second, Bytes{}, crypto::label::kPeerAuth, Bytes{},
                                 suite_.keyLen());
    timing.kdfMs += msSince(tk);

    session.nonceLocal = rng_.bytes(kNonceLen);
    const int64_t td = monotonicNs();
    session.ephemeral = crypto::x25519Generate(rng_.bytes(32), suite_.counters());
    timing.dhMs += msSince(td);
    session.epkLocal = session.ephemeral.publicKey;

    Message p1;
    p1.type = MessageType::P3_P1_PEER_REQUEST;
    p1.suiteId = static_cast<uint8_t>(suite_.id());
    p1.senderId = uavId_;
    p1.receiverId = peerId;
    p1.set(FieldId::SENDER_ID, encodeId(uavId_));
    p1.set(FieldId::RECEIVER_ID, encodeId(peerId));
    p1.set(FieldId::NONCE_1, session.nonceLocal);
    p1.set(FieldId::TIMESTAMP, encodeTimestamp(nowMs));
    p1.set(FieldId::EPK_A, session.epkLocal);

    FieldMap signedP1{{FieldId::SENDER_ID, encodeId(uavId_)},
                      {FieldId::RECEIVER_ID, encodeId(peerId)},
                      {FieldId::NONCE_1, session.nonceLocal},
                      {FieldId::TIMESTAMP, encodeTimestamp(nowMs)},
                      {FieldId::EPK_A, session.epkLocal}};
    const Bytes inputP1 = macInput(p1.suiteId, MessageType::P3_P1_PEER_REQUEST, signedP1);

    const int64_t tm = monotonicNs();
    p1.set(FieldId::MAC_TAG, suite_.mac(session.authKey, inputP1));
    timing.macMs += msSince(tm);

    session.p1Encoded = inputP1;
    peers_[peerId] = session;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = p1;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult UavProtocol::handleP1(const Message& p1, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (p1.type != MessageType::P3_P1_PEER_REQUEST) return fail(AbortReason::UnexpectedMessage);
    for (FieldId f : {FieldId::SENDER_ID, FieldId::RECEIVER_ID, FieldId::NONCE_1,
                      FieldId::TIMESTAMP, FieldId::EPK_A, FieldId::MAC_TAG})
        if (!p1.has(f)) return fail(AbortReason::MissingField);

    int initiatorId = -1;
    uint32_t tstamp = 0;
    try {
        initiatorId = decodeId(p1.get(FieldId::SENDER_ID));
        tstamp = decodeTimestamp(p1.get(FieldId::TIMESTAMP));
    } catch (const std::exception&) {
        return fail(AbortReason::MalformedField);
    }
    if (!timestampFresh(nowMs, tstamp, windowMs_)) return fail(AbortReason::StaleTimestamp);

    const Bytes nonceRemote = p1.get(FieldId::NONCE_1);
    if (!replay_.offer(nonceRemote)) return fail(AbortReason::ReplayedNonce);

    const auto credIt = phase2_.peerCredentials.find(initiatorId);
    if (credIt == phase2_.peerCredentials.end()) return fail(AbortReason::NoSuchPeer);

    const int64_t tk = monotonicNs();
    const Bytes authKey = suite_.kdf(credIt->second, Bytes{}, crypto::label::kPeerAuth,
                                     Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    FieldMap signedP1{{FieldId::SENDER_ID, p1.get(FieldId::SENDER_ID)},
                      {FieldId::RECEIVER_ID, p1.get(FieldId::RECEIVER_ID)},
                      {FieldId::NONCE_1, nonceRemote},
                      {FieldId::TIMESTAMP, p1.get(FieldId::TIMESTAMP)},
                      {FieldId::EPK_A, p1.get(FieldId::EPK_A)}};
    const Bytes inputP1 = macInput(p1.suiteId, MessageType::P3_P1_PEER_REQUEST, signedP1);

    const int64_t tm = monotonicNs();
    const bool macOk = suite_.macVerify(authKey, inputP1, p1.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed, timing);

    Phase3Session session;
    session.localId = uavId_;
    session.peerId = initiatorId;
    session.initiator = false;
    session.authKey = authKey;
    session.nonceRemote = nonceRemote;
    session.epkRemote = p1.get(FieldId::EPK_A);
    session.nonceLocal = rng_.bytes(kNonceLen);

    const int64_t td = monotonicNs();
    session.ephemeral = crypto::x25519Generate(rng_.bytes(32), suite_.counters());
    timing.dhMs += msSince(td);
    session.epkLocal = session.ephemeral.publicKey;

    Message p2;
    p2.type = MessageType::P3_P2_PEER_RESPONSE;
    p2.suiteId = p1.suiteId;
    p2.senderId = uavId_;
    p2.receiverId = initiatorId;
    p2.set(FieldId::NONCE_2, session.nonceLocal);
    p2.set(FieldId::EPK_B, session.epkLocal);

    FieldMap signedP2{{FieldId::SENDER_ID, encodeId(initiatorId)},
                      {FieldId::RECEIVER_ID, encodeId(uavId_)},
                      {FieldId::NONCE_1, session.nonceRemote},
                      {FieldId::NONCE_2, session.nonceLocal},
                      {FieldId::EPK_A, session.epkRemote},
                      {FieldId::EPK_B, session.epkLocal}};
    const Bytes inputP2 = macInput(p2.suiteId, MessageType::P3_P2_PEER_RESPONSE, signedP2);

    const int64_t tm2 = monotonicNs();
    p2.set(FieldId::MAC_TAG, suite_.mac(authKey, inputP2));
    timing.macMs += msSince(tm2);

    session.p1Encoded = inputP1;
    session.p2Encoded = inputP2;
    peers_[initiatorId] = session;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = p2;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult UavProtocol::handleP2(const Message& p2, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (p2.type != MessageType::P3_P2_PEER_RESPONSE) return fail(AbortReason::UnexpectedMessage);
    if (!p2.has(FieldId::NONCE_2) || !p2.has(FieldId::EPK_B) || !p2.has(FieldId::MAC_TAG))
        return fail(AbortReason::MissingField);

    auto it = peers_.find(p2.senderId);
    if (it == peers_.end() || !it->second.initiator) return fail(AbortReason::UnexpectedMessage);
    Phase3Session& session = it->second;

    session.nonceRemote = p2.get(FieldId::NONCE_2);
    session.epkRemote = p2.get(FieldId::EPK_B);
    if (session.epkRemote.size() != crypto::kX25519KeyLen)
        return fail(AbortReason::MalformedField);

    FieldMap signedP2{{FieldId::SENDER_ID, encodeId(session.localId)},
                      {FieldId::RECEIVER_ID, encodeId(session.peerId)},
                      {FieldId::NONCE_1, session.nonceLocal},
                      {FieldId::NONCE_2, session.nonceRemote},
                      {FieldId::EPK_A, session.epkLocal},
                      {FieldId::EPK_B, session.epkRemote}};
    const Bytes inputP2 = macInput(p2.suiteId, MessageType::P3_P2_PEER_RESPONSE, signedP2);

    const int64_t tm = monotonicNs();
    const bool macOk = suite_.macVerify(session.authKey, inputP2, p2.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed, timing);

    session.p2Encoded = inputP2;

    Message p3;
    p3.type = MessageType::P3_P3_PEER_COMPLETE;
    p3.suiteId = p2.suiteId;
    p3.senderId = session.localId;
    p3.receiverId = session.peerId;

    Bytes inputP3 = macInput(p3.suiteId, MessageType::P3_P3_PEER_COMPLETE, FieldMap{});
    append(inputP3, session.p1Encoded);
    append(inputP3, session.p2Encoded);

    const int64_t tm3 = monotonicNs();
    p3.set(FieldId::MAC_TAG, suite_.mac(session.authKey, inputP3));
    timing.macMs += msSince(tm3);

    const int64_t td = monotonicNs();
    Bytes shared;
    const bool dhOk =
        crypto::x25519Derive(session.ephemeral.secret, session.epkRemote, shared,
                             suite_.counters());
    timing.dhMs += msSince(td);
    if (!dhOk) return fail(AbortReason::DhFailed, timing);

    Bytes transcript = session.p1Encoded;
    append(transcript, session.p2Encoded);

    Bytes ikm = phase2_.peerCredentials[session.peerId];
    append(ikm, shared);

    const int64_t tk = monotonicNs();
    session.sessionKey =
        suite_.kdf(ikm, transcript, crypto::label::kPeerSess, Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    session.ephemeral.erase();
    session.ephemeralErased = true;
    core::secureZero(shared);
    session.established = true;

    StepResult r;
    r.ok = true;
    r.hasReply = true;
    r.reply = p3;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

StepResult UavProtocol::handleP3(const Message& p3, uint32_t nowMs) {
    StepTiming timing;
    const int64_t t0 = monotonicNs();

    if (p3.type != MessageType::P3_P3_PEER_COMPLETE) return fail(AbortReason::UnexpectedMessage);
    if (!p3.has(FieldId::MAC_TAG)) return fail(AbortReason::MissingField);

    auto it = peers_.find(p3.senderId);
    if (it == peers_.end() || it->second.initiator) return fail(AbortReason::UnexpectedMessage);
    Phase3Session& session = it->second;

    Bytes inputP3 = macInput(p3.suiteId, MessageType::P3_P3_PEER_COMPLETE, FieldMap{});
    append(inputP3, session.p1Encoded);
    append(inputP3, session.p2Encoded);

    const int64_t tm = monotonicNs();
    const bool macOk = suite_.macVerify(session.authKey, inputP3, p3.get(FieldId::MAC_TAG));
    timing.macMs += msSince(tm);
    if (!macOk) return fail(AbortReason::MacVerifyFailed, timing);

    const int64_t td = monotonicNs();
    Bytes shared;
    const bool dhOk =
        crypto::x25519Derive(session.ephemeral.secret, session.epkRemote, shared,
                             suite_.counters());
    timing.dhMs += msSince(td);
    if (!dhOk) return fail(AbortReason::DhFailed, timing);

    Bytes transcript = session.p1Encoded;
    append(transcript, session.p2Encoded);

    Bytes ikm = phase2_.peerCredentials[session.peerId];
    append(ikm, shared);

    const int64_t tk = monotonicNs();
    session.sessionKey =
        suite_.kdf(ikm, transcript, crypto::label::kPeerSess, Bytes{}, suite_.keyLen());
    timing.kdfMs += msSince(tk);

    session.ephemeral.erase();
    session.ephemeralErased = true;
    core::secureZero(shared);
    session.established = true;

    StepResult r;
    r.ok = true;
    r.hasReply = false;
    timing.computeMs = msSince(t0);
    r.timing = timing;
    return r;
}

} // namespace protocol
} // namespace uavauth
