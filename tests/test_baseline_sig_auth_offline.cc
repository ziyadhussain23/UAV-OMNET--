// The RSA/ECDSA baseline handshake, driven over a fake transport, before any
// simulation wiring exists -- same rationale as test_protocol_offline.cc:
// catch protocol bugs before they hide behind OMNeT++ plumbing.
//
// DEPS: core/Bytes.cc core/Encoding.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/Sha3Suite.cc crypto/Drbg.cc crypto/X25519.cc crypto/SignatureSuite.cc crypto/RsaSuite.cc crypto/EcdsaSuite.cc fe/BchCodec.cc fe/FuzzyExtractor.cc protocol/Wire.cc protocol/Protocol.cc protocol/BaselineSigAuth.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/EcdsaSuite.h"
#include "crypto/RsaSuite.h"
#include "crypto/Sha3Suite.h"
#include "protocol/BaselineSigAuth.h"
#include "tests/TestUtil.h"

using namespace uavauth::core;
using namespace uavauth::crypto;
using namespace uavauth::protocol;

namespace {

constexpr uint32_t kNow = 1'000'000;

struct Pair {
    Sha3Suite symSuite;
    std::unique_ptr<SignatureSuite> sigSuite;
    std::unique_ptr<Drbg> gsRng, uavRng;
    std::unique_ptr<BaselineGroundStationProtocol> gs;
    std::unique_ptr<BaselineUavProtocol> uav;

    explicit Pair(const char* sigSuiteName, int uavId = 0) {
        sigSuite = makeSignatureSuite(sigSuiteName);
        gsRng = std::make_unique<Drbg>(fromString("baseline-gs"));
        uavRng = std::make_unique<Drbg>(fromString("baseline-uav-" + std::to_string(uavId)));
        gs = std::make_unique<BaselineGroundStationProtocol>(*sigSuite, symSuite, *gsRng);
        uav = std::make_unique<BaselineUavProtocol>(uavId, *sigSuite, symSuite, *uavRng);

        gs->ensureOwnKeypair();
        uav->ensureOwnKeypair();
        gs->enrollUav(uavId, uav->publicKeyBytes());
        uav->provisionGsPublicKey(gs->publicKeyBytes());
    }
};

void testHappyPath(const char* sigSuiteName) {
    Pair p(sigSuiteName);

    const StepResult r1 = p.uav->startPhase2(kNow);
    CHECK_MSG(r1.ok, std::string(sigSuiteName) + ": B1 build failed");
    CHECK(r1.hasReply);

    const StepResult r2 = p.gs->handleM1(r1.reply, kNow);
    CHECK_MSG(r2.ok, std::string(sigSuiteName) + ": GS rejected a genuine B1");
    CHECK(r2.hasReply);

    const StepResult r3 = p.uav->handleM2(r2.reply, kNow);
    CHECK_MSG(r3.ok, std::string(sigSuiteName) + ": UAV rejected a genuine B2");
    CHECK(r3.hasReply);

    const StepResult r4 = p.gs->handleM3(r3.reply, kNow);
    CHECK_MSG(r4.ok, std::string(sigSuiteName) + ": GS rejected a genuine B3");
    CHECK(r4.hasReply);

    const StepResult r5 = p.uav->handleM4(r4.reply, kNow);
    CHECK_MSG(r5.ok, std::string(sigSuiteName) + ": UAV rejected a genuine B4");
    CHECK(p.uav->established());

    // Every step actually charged the primitive it claims to.
    CHECK(r1.timing.signMs > 0.0);      // UAV signs B1
    CHECK(r2.timing.verifyMs > 0.0);    // GS verifies B1
    CHECK(r2.timing.signMs > 0.0);      // GS signs B2
    CHECK(r3.timing.verifyMs > 0.0);    // UAV verifies B2
    CHECK(r1.timing.dhMs > 0.0 && r2.timing.dhMs > 0.0);   // ephemeral keygen both sides
    CHECK(r3.timing.dhMs > 0.0 && r4.timing.dhMs > 0.0);   // ephemeral derive both sides
}

void testForgedB1Rejected(const char* sigSuiteName) {
    Pair p(sigSuiteName);
    const StepResult r1 = p.uav->startPhase2(kNow);

    // Flip one bit of the signature.
    Message forged = r1.reply;
    Bytes sig = forged.get(FieldId::SIGNATURE);
    sig[sig.size() / 2] ^= 0x01;
    forged.set(FieldId::SIGNATURE, sig);

    const StepResult r2 = p.gs->handleM1(forged, kNow);
    CHECK_MSG(!r2.ok, std::string(sigSuiteName) + ": GS accepted a tampered B1 signature");
    CHECK_MSG(!r2.hasReply, std::string(sigSuiteName) + ": GS replied to a forged B1 -- oracle");
}

void testForgedB2Rejected(const char* sigSuiteName) {
    Pair p(sigSuiteName);
    const StepResult r1 = p.uav->startPhase2(kNow);
    const StepResult r2 = p.gs->handleM1(r1.reply, kNow);

    Message forged = r2.reply;
    Bytes sig = forged.get(FieldId::SIGNATURE);
    sig[0] ^= 0x01;
    forged.set(FieldId::SIGNATURE, sig);

    const StepResult r3 = p.uav->handleM2(forged, kNow);
    CHECK_MSG(!r3.ok, std::string(sigSuiteName) + ": UAV accepted a tampered B2 signature");
    CHECK_MSG(!r3.hasReply, std::string(sigSuiteName) + ": UAV replied to a forged B2");
}

void testReplayOfB1Rejected(const char* sigSuiteName) {
    Pair p(sigSuiteName);
    const StepResult r1 = p.uav->startPhase2(kNow);
    const StepResult first = p.gs->handleM1(r1.reply, kNow);
    CHECK(first.ok);

    const StepResult replayed = p.gs->handleM1(r1.reply, kNow);
    CHECK_MSG(!replayed.ok, std::string(sigSuiteName) + ": GS accepted a replayed B1");
    CHECK_EQ(static_cast<int>(replayed.abort), static_cast<int>(AbortReason::ReplayedNonce));
}

void testStaleTimestampRejected(const char* sigSuiteName) {
    Pair p(sigSuiteName);
    const StepResult r1 = p.uav->startPhase2(kNow);
    const StepResult r2 = p.gs->handleM1(r1.reply, kNow + 60'000);   // 60s later, default window 5s
    CHECK_MSG(!r2.ok, std::string(sigSuiteName) + ": GS accepted a stale-timestamp B1");
    CHECK_EQ(static_cast<int>(r2.abort), static_cast<int>(AbortReason::StaleTimestamp));
}

void testUnknownUavRejected(const char* sigSuiteName) {
    Pair p(sigSuiteName, /*uavId=*/7);
    // A different UAV, never enrolled with this GS.
    Sha3Suite sym;
    auto sig = makeSignatureSuite(sigSuiteName);
    Drbg rng(fromString("stranger"));
    BaselineUavProtocol stranger(99, *sig, sym, rng);
    stranger.ensureOwnKeypair();
    stranger.provisionGsPublicKey(p.gs->publicKeyBytes());

    const StepResult r1 = stranger.startPhase2(kNow);
    const StepResult r2 = p.gs->handleM1(r1.reply, kNow);
    CHECK_MSG(!r2.ok, std::string(sigSuiteName) + ": GS accepted an unenrolled UAV");
    CHECK_EQ(static_cast<int>(r2.abort), static_cast<int>(AbortReason::UnknownIdentity));
}

void testSessionKeysMatch(const char* sigSuiteName) {
    // Not exposed as a public accessor (this baseline has no peer-auth phase
    // that needs it), so this is verified indirectly: B4's confirmation MAC
    // only verifies if the GS derived the identical session key the UAV did.
    Pair p(sigSuiteName);
    const StepResult r1 = p.uav->startPhase2(kNow);
    const StepResult r2 = p.gs->handleM1(r1.reply, kNow);
    const StepResult r3 = p.uav->handleM2(r2.reply, kNow);
    const StepResult r4 = p.gs->handleM3(r3.reply, kNow);
    const StepResult r5 = p.uav->handleM4(r4.reply, kNow);
    CHECK_MSG(r5.ok, std::string(sigSuiteName) + ": session keys diverged (B4 confirmation failed)");
}

} // namespace

int main() {
    for (const char* suite : {"rsa2048", "ecdsa-p256"}) {
        testHappyPath(suite);
        testForgedB1Rejected(suite);
        testForgedB2Rejected(suite);
        testReplayOfB1Rejected(suite);
        testStaleTimestampRejected(suite);
        testUnknownUavRejected(suite);
        testSessionKeysMatch(suite);
    }
    return uavauth::test::summarise("baseline-sig-auth-offline");
}
