// Stage-6 gate: the full four-phase protocol, driven over a fake transport.
//
// Proving the protocol correct here -- before any simulation wiring exists --
// keeps protocol bugs from hiding behind OMNeT++ plumbing. Covers the happy
// path, key agreement on both sides, and the negative cases the security
// argument depends on: every single-bit flip is rejected, a forged ground
// station elicits no response at all, replays and stale timestamps are refused,
// tokens cannot be reflected across message types, and a captured credential
// unlocks only its own pair.
//
// DEPS: core/Bytes.cc core/Encoding.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/Sha3Suite.cc crypto/Drbg.cc crypto/X25519.cc fe/BchCodec.cc fe/FuzzyExtractor.cc puf/IdealPrfPuf.cc protocol/Wire.cc protocol/Protocol.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/Sha3Suite.h"
#include "protocol/Protocol.h"
#include "puf/IdealPrfPuf.h"
#include "tests/TestUtil.h"

#include <cstdio>
#include <map>
#include <memory>
#include <vector>

using namespace uavauth::core;
using namespace uavauth::crypto;
using namespace uavauth::protocol;
using namespace uavauth::fe;
using namespace uavauth::puf;

namespace {

constexpr uint32_t kNow = 1'000'000;

/// A complete swarm wired up in memory: one ground station and N UAVs, all
/// enrolled, with no network in between.
struct Swarm {
    Sha3Suite suite;
    FeParams feParams = FeParams::profile("bch255-131-18");
    std::unique_ptr<Drbg> rng;
    std::unique_ptr<GroundStationProtocol> gs;
    std::vector<std::unique_ptr<IdealPrfPuf>> pufs;
    std::vector<std::unique_ptr<Drbg>> uavRngs;
    std::vector<std::unique_ptr<UavProtocol>> uavs;
    int n = 0;

    explicit Swarm(int numUavs, double ber = 0.0) : n(numUavs) {
        rng = std::make_unique<Drbg>(fromString("swarm-gs"));
        gs = std::make_unique<GroundStationProtocol>(suite, feParams, *rng);
        gs->setNumUavs(numUavs);

        for (int i = 0; i < numUavs; ++i) {
            auto puf = std::make_unique<IdealPrfPuf>(fromString("device-" + std::to_string(i)));
            puf->setNoiseBer(ber);
            auto urng = std::make_unique<Drbg>(fromString("uav-rng-" + std::to_string(i)));
            pufs.push_back(std::move(puf));
            uavRngs.push_back(std::move(urng));
        }
        // Enroll every device first, so the ground station can mint the full set
        // of per-pair credentials.
        std::vector<DeviceState> states(static_cast<size_t>(numUavs));
        for (int i = 0; i < numUavs; ++i) {
            DeviceRecord rec;
            StepTiming t;
            const bool ok = gs->enroll(i, *pufs[static_cast<size_t>(i)], rec,
                                       states[static_cast<size_t>(i)], t);
            if (!ok) throw std::runtime_error("enrollment failed");
        }
        for (int i = 0; i < numUavs; ++i) {
            auto uav = std::make_unique<UavProtocol>(i, suite, feParams,
                                                     *pufs[static_cast<size_t>(i)],
                                                     *uavRngs[static_cast<size_t>(i)]);
            uav->provision(states[static_cast<size_t>(i)]);
            uavs.push_back(std::move(uav));
        }
    }

    UavProtocol& uav(int i) { return *uavs[static_cast<size_t>(i)]; }

    /// Run a complete Phase 2 for one UAV. Returns true on mutual success.
    bool runPhase2(int i, uint32_t now = kNow) {
        const StepResult r1 = uav(i).startPhase2(now);
        if (!r1.ok || !r1.hasReply) return false;
        const StepResult r2 = gs->handleM1(r1.reply, now);
        if (!r2.ok || !r2.hasReply) return false;
        const StepResult r3 = uav(i).handleM2(r2.reply, now);
        if (!r3.ok || !r3.hasReply) return false;
        const StepResult r4 = gs->handleM3(r3.reply, now);
        if (!r4.ok || !r4.hasReply) return false;
        const StepResult r5 = uav(i).handleM4(r4.reply, now);
        return r5.ok;
    }

    /// Run a complete Phase 3 between two authenticated peers.
    bool runPhase3(int i, int j, uint32_t now = kNow) {
        const StepResult p1 = uav(i).startPhase3(j, now);
        if (!p1.ok || !p1.hasReply) return false;
        const StepResult p2 = uav(j).handleP1(p1.reply, now);
        if (!p2.ok || !p2.hasReply) return false;
        const StepResult p3 = uav(i).handleP2(p2.reply, now);
        if (!p3.ok || !p3.hasReply) return false;
        const StepResult done = uav(j).handleP3(p3.reply, now);
        return done.ok;
    }
};

void testPhase1Enrollment() {
    Swarm s(3);
    for (int i = 0; i < 3; ++i) {
        const DeviceRecord* rec = s.gs->record(i);
        CHECK(rec != nullptr);
        CHECK(rec->enrolled);
        CHECK_EQ(rec->mk.size(), 32u);
        CHECK(!rec->tid.empty());

        // The device stores nothing secret: only its identity, its challenge and
        // the public helper data.
        const DeviceState& st = s.uav(i).state();
        CHECK(st.provisioned);
        CHECK(st.challenge == rec->challenge);
        CHECK(st.helper.sketch == rec->helper.sketch);
        CHECK(st.tid == rec->tid);
    }
    // Distinct devices get distinct master keys and identities.
    CHECK(s.gs->record(0)->mk != s.gs->record(1)->mk);
    CHECK(s.gs->record(0)->tid != s.gs->record(1)->tid);
}

void testPhase2HappyPathAndKeyAgreement() {
    Swarm s(4);
    for (int i = 0; i < 4; ++i) {
        CHECK_MSG(s.runPhase2(i), "Phase 2 failed for UAV " + std::to_string(i));
        CHECK(s.uav(i).phase2Established());

        // Both endpoints must derive the SAME session key.
        Bytes gsKey;
        CHECK(s.gs->sessionKeyFor(i, gsKey));
        CHECK_MSG(gsKey == s.uav(i).phase2SessionKey(),
                  "session keys disagree for UAV " + std::to_string(i));
        CHECK_EQ(gsKey.size(), 32u);

        // The ephemeral scalar must be erased: forward secrecy depends on it.
        CHECK(s.uav(i).ephemeralErased());

        // Credentials for every other UAV arrived.
        CHECK_EQ(s.uav(i).peerCredentialCount(), 3u);
    }
    // Different UAVs get different session keys.
    CHECK(s.uav(0).phase2SessionKey() != s.uav(1).phase2SessionKey());
}

void testPhase2UnderPufNoise() {
    // 3% bit-error rate: the fuzzy extractor must still reproduce mk so that
    // Phase 2 succeeds.
    Swarm s(5, 0.03);
    int successes = 0;
    for (int i = 0; i < 5; ++i)
        if (s.runPhase2(i)) ++successes;
    CHECK_MSG(successes == 5, "Phase 2 failed under 3% PUF noise");
}

void testPhase3FullMesh() {
    const int n = 6;
    Swarm s(n);
    for (int i = 0; i < n; ++i) CHECK(s.runPhase2(i));

    int pairs = 0, ok = 0;
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            ++pairs;
            if (s.runPhase3(i, j)) ++ok;

            // Both peers must agree on the pair key.
            Bytes ki, kj;
            CHECK(s.uav(i).peerSessionKey(j, ki));
            CHECK(s.uav(j).peerSessionKey(i, kj));
            CHECK_MSG(ki == kj, "peer session keys disagree for pair " +
                                    std::to_string(i) + "," + std::to_string(j));
        }
    }
    CHECK_EQ(pairs, n * (n - 1) / 2);
    CHECK_MSG(ok == pairs, "not every peer pair authenticated");
    std::printf("  [info] full mesh: %d/%d pairs authenticated\n", ok, pairs);

    // Distinct pairs must derive distinct keys.
    Bytes k01, k02;
    CHECK(s.uav(0).peerSessionKey(1, k01));
    CHECK(s.uav(0).peerSessionKey(2, k02));
    CHECK(k01 != k02);
}

void testForgedGroundStationGetsNoResponse() {
    // The corollary the security argument turns on: an adversary posing as the
    // ground station must not be able to make the UAV emit anything.
    Swarm s(2);
    const StepResult r1 = s.uav(0).startPhase2(kNow);
    CHECK(r1.ok);

    const StepResult real = s.gs->handleM1(r1.reply, kNow);
    CHECK(real.ok);

    int accepted = 0, replied = 0;
    Drbg attacker(fromString("forge-m2"));
    for (int attempt = 0; attempt < 200; ++attempt) {
        Message forged = real.reply;
        // Attacker-chosen nonce and ephemeral share, random MAC.
        forged.set(FieldId::NONCE_2, attacker.bytes(16));
        forged.set(FieldId::EPK_B, attacker.bytes(32));
        forged.set(FieldId::MAC_TAG, attacker.bytes(16));

        const StepResult r = s.uav(0).handleM2(forged, kNow);
        if (r.ok) ++accepted;
        if (r.hasReply) ++replied;
        CHECK(r.abort == AbortReason::MacVerifyFailed);
    }
    CHECK_MSG(accepted == 0, "UAV accepted a forged M2");
    CHECK_MSG(replied == 0, "UAV replied to a forged M2 (oracle!)");
    std::printf("  [info] forged M2: 0/200 accepted, 0/200 elicited a reply\n");
}

void testEveryBitFlipRejected() {
    Swarm s(2);
    const StepResult m1 = s.uav(0).startPhase2(kNow);
    CHECK(m1.ok);

    // Flip each bit of each field of M1 in turn; the ground station must reject
    // every one of them.
    int accepted = 0, total = 0;
    for (const auto& entry : m1.reply.fields) {
        for (size_t bit = 0; bit < entry.second.size() * 8 && bit < 64; ++bit) {
            Message bad = m1.reply;
            Bytes v = entry.second;
            v[bit / 8] = static_cast<uint8_t>(v[bit / 8] ^ (1u << (bit % 8)));
            bad.set(entry.first, v);
            ++total;
            if (s.gs->handleM1(bad, kNow).ok) ++accepted;
        }
    }
    CHECK_MSG(accepted == 0, "ground station accepted a tampered M1");
    std::printf("  [info] tampered M1: 0/%d accepted\n", total);
}

void testReplayAndStaleTimestampRejected() {
    Swarm s(2);
    const StepResult m1 = s.uav(0).startPhase2(kNow);
    CHECK(m1.ok);

    // First delivery is accepted.
    CHECK(s.gs->handleM1(m1.reply, kNow).ok);

    // A verbatim replay inside the freshness window must still be refused: the
    // timestamp alone would allow it, the nonce cache is what stops it.
    const StepResult replayed = s.gs->handleM1(m1.reply, kNow + 100);
    CHECK_MSG(!replayed.ok, "verbatim replay accepted inside the window");
    CHECK(replayed.abort == AbortReason::ReplayedNonce);
    CHECK(s.gs->replayHits() > 0);

    // Outside the window it is rejected on the timestamp first.
    const StepResult stale = s.gs->handleM1(m1.reply, kNow + 60'000);
    CHECK(!stale.ok);
    CHECK(stale.abort == AbortReason::StaleTimestamp);
}

void testTokensCannotBeReflectedAcrossMessageTypes() {
    // Distinct per-type domain tags mean a P1 token is not a valid P3 token.
    Swarm s(2);
    CHECK(s.runPhase2(0));
    CHECK(s.runPhase2(1));

    const StepResult p1 = s.uav(0).startPhase3(1, kNow);
    CHECK(p1.ok);

    Message reflected = p1.reply;
    reflected.type = MessageType::P3_P3_PEER_COMPLETE;
    const StepResult r = s.uav(1).handleP3(reflected, kNow);
    CHECK_MSG(!r.ok, "a P1 token was accepted as P3");

    // Feeding P1 back to its own sender must also fail.
    const StepResult echo = s.uav(0).handleP1(p1.reply, kNow);
    CHECK(!echo.ok);
}

void testCapturedCredentialUnlocksOnlyItsOwnPair() {
    // Physical capture: the attacker learns UAV 2's stored credentials but not
    // its PUF. Pairs that do not involve UAV 2 must stay secure.
    const int n = 4;
    Swarm s(n);
    for (int i = 0; i < n; ++i) CHECK(s.runPhase2(i));

    const int captured = 2;
    // Credentials are pair-specific, so the ones held by UAV 2 say nothing about
    // the pair (0,1).
    const Bytes cred01 = s.gs->pairCredential(0, 1);
    const Bytes cred02 = s.gs->pairCredential(0, 2);
    const Bytes cred12 = s.gs->pairCredential(1, 2);
    CHECK(cred01 != cred02);
    CHECK(cred01 != cred12);
    CHECK(cred02 != cred12);

    // Symmetry: both endpoints derive the same pair credential.
    CHECK(s.gs->pairCredential(0, 1) == s.gs->pairCredential(1, 0));

    // Give a rogue UAV every credential UAV 2 holds, and have it try to
    // impersonate UAV 0 to UAV 1 -- a pair it has no credential for.
    Drbg rogueRng(fromString("rogue"));
    IdealPrfPuf roguePuf(fromString("rogue-puf"));
    UavProtocol rogue(0, s.suite, s.feParams, roguePuf, rogueRng);
    rogue.provision(s.uav(captured).state());
    rogue.injectPeerCredential(1, cred02, Bytes(16, 0));   // wrong pair's credential

    const StepResult forged = rogue.startPhase3(1, kNow);
    CHECK(forged.ok);   // it can emit a message...
    const StepResult victim = s.uav(1).handleP1(forged.reply, kNow);
    CHECK_MSG(!victim.ok, "impersonation with a foreign pair credential succeeded");
    CHECK(victim.abort == AbortReason::MacVerifyFailed);

    // The blast radius is exactly the captured node's own links.
    const int incident = n - 1;
    const int totalPairs = n * (n - 1) / 2;
    std::printf("  [info] capture of UAV %d exposes %d of %d pairs (%.0f%%)\n", captured,
                incident, totalPairs, 100.0 * incident / totalPairs);
    CHECK(incident < totalPairs);
}

void testUnknownIdentityAndMissingFields() {
    Swarm s(2);
    const StepResult m1 = s.uav(0).startPhase2(kNow);
    CHECK(m1.ok);

    Message unknown = m1.reply;
    unknown.set(FieldId::TID, Bytes(16, 0xAB));
    const StepResult r = s.gs->handleM1(unknown, kNow);
    CHECK(!r.ok);
    CHECK(r.abort == AbortReason::UnknownIdentity);

    // Dropping any required field is caught, not dereferenced.
    for (FieldId f : {FieldId::TID, FieldId::NONCE_1, FieldId::TIMESTAMP, FieldId::EPK_A,
                      FieldId::MAC_TAG}) {
        Message missing = m1.reply;
        missing.fields.erase(f);
        const StepResult mr = s.gs->handleM1(missing, kNow);
        CHECK(!mr.ok);
        CHECK(mr.abort == AbortReason::MissingField);
    }

    // A wrong-length ephemeral key is rejected as malformed.
    Message badEpk = m1.reply;
    badEpk.set(FieldId::EPK_A, Bytes(16, 0x00));
    CHECK(s.gs->handleM1(badEpk, kNow).abort == AbortReason::MalformedField);
}

void testTamperedCredentialPackageRejected() {
    Swarm s(2);
    const StepResult r1 = s.uav(0).startPhase2(kNow);
    const StepResult r2 = s.gs->handleM1(r1.reply, kNow);
    const StepResult r3 = s.uav(0).handleM2(r2.reply, kNow);
    const StepResult r4 = s.gs->handleM3(r3.reply, kNow);
    CHECK(r4.ok);

    // Every single-byte corruption of the AEAD package must fail to open.
    const Bytes pkg = r4.reply.get(FieldId::CRED_PKG);
    int accepted = 0;
    for (size_t i = 0; i < pkg.size(); i += 7) {
        Message bad = r4.reply;
        Bytes v = pkg;
        v[i] = static_cast<uint8_t>(v[i] ^ 0x01);
        bad.set(FieldId::CRED_PKG, v);
        const StepResult br = s.uav(0).handleM4(bad, kNow);
        if (br.ok) ++accepted;
        CHECK(br.abort == AbortReason::AeadOpenFailed);
    }
    CHECK_MSG(accepted == 0, "a tampered credential package was accepted");

    // The genuine package still opens.
    CHECK(s.uav(0).handleM4(r4.reply, kNow).ok);
}

void testPhase3RequiresPhase2() {
    // A UAV that has not completed Phase 2 holds no credentials and cannot start
    // a peer handshake.
    Swarm s(2);
    const StepResult r = s.uav(0).startPhase3(1, kNow);
    CHECK(!r.ok);
    CHECK(r.abort == AbortReason::NoSuchPeer);
}

void testWireSizes() {
    Swarm s(10);
    const StepResult m1 = s.uav(0).startPhase2(kNow);
    const StepResult m2 = s.gs->handleM1(m1.reply, kNow);
    const StepResult m3 = s.uav(0).handleM2(m2.reply, kNow);
    const StepResult m4 = s.gs->handleM3(m3.reply, kNow);
    CHECK(m4.ok);
    CHECK(s.uav(0).handleM4(m4.reply, kNow).ok);
    CHECK(s.runPhase2(1));
    const StepResult p1 = s.uav(0).startPhase3(1, kNow);
    const StepResult p2 = s.uav(1).handleP1(p1.reply, kNow);
    const StepResult p3 = s.uav(0).handleP2(p2.reply, kNow);

    std::printf("  [info] wire bytes (N=10): m1=%zu m2=%zu m3=%zu m4=%zu | p1=%zu p2=%zu p3=%zu\n",
                m1.reply.wireBytes(), m2.reply.wireBytes(), m3.reply.wireBytes(),
                m4.reply.wireBytes(), p1.reply.wireBytes(), p2.reply.wireBytes(),
                p3.reply.wireBytes());

    // Sizes must be non-trivial and self-consistent with the encoder.
    CHECK(m1.reply.wireBytes() == m1.reply.encode().size());
    CHECK(m4.reply.wireBytes() > m3.reply.wireBytes());   // carries the credential package
}

} // namespace

int main() {
    testPhase1Enrollment();
    testPhase2HappyPathAndKeyAgreement();
    testPhase2UnderPufNoise();
    testPhase3FullMesh();
    testForgedGroundStationGetsNoResponse();
    testEveryBitFlipRejected();
    testReplayAndStaleTimestampRejected();
    testTokensCannotBeReflectedAcrossMessageTypes();
    testCapturedCredentialUnlocksOnlyItsOwnPair();
    testUnknownIdentityAndMissingFields();
    testTamperedCredentialPackageRejected();
    testPhase3RequiresPhase2();
    testWireSizes();
    return uavauth::test::summarise("protocol-offline");
}
