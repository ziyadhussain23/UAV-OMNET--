// Stage-3 gate: the PUF models and the min-entropy measurement.
//
// The model this replaces called itself a "128-stage arbiter PUF" but was an
// FNV-seeded mt19937 whose real delay-model functions were never called, and its
// noise flipped a *fixed* number of positions chosen with replacement -- so the
// flip count had zero variance and every bit was equally unreliable. Both
// defects are what the checks below are aimed at:
//
//   * evaluateIdeal/evaluateNoisy are separate, and the noise enters the delay
//     difference rather than the output bit, so reliability is bit-dependent
//     (testNoiseIsBitDependent measures exactly that, against the Bernoulli
//     reference);
//   * a target BER is reached by calibrating the delay-noise sigma, not by
//     asserting it (testReliabilityArbiter);
//   * min-entropy is measured rather than assumed, and the arbiter figure is
//     reported without being asserted to be high, because it should not be.
//
// DEPS: core/Bytes.cc crypto/Drbg.cc crypto/OsslCommon.cc crypto/PrimitiveCounters.cc puf/IdealPrfPuf.cc puf/ArbiterPuf.cc puf/XorArbiterPuf.cc puf/MinEntropy.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "puf/ArbiterPuf.h"
#include "puf/IdealPrfPuf.h"
#include "puf/MinEntropy.h"
#include "puf/PufModel.h"
#include "puf/XorArbiterPuf.h"
#include "tests/TestUtil.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <cmath>
#include <cstdio>
#include <functional>
#include <set>
#include <string>
#include <vector>

using namespace uavauth::core;
using namespace uavauth::crypto;
using namespace uavauth::puf;

namespace {

constexpr size_t kResponseBits = 255;   // the fuzzy extractor's block length

/// SHA3-256 and HMAC-SHA3-256 computed from scratch, with a fresh context every
/// call. The models keep long-lived contexts for speed; recomputing the
/// reference the slow way is what makes the structural checks below meaningful.
Bytes refSha3(const Bytes& input) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    if (!input.empty()) EVP_DigestUpdate(ctx, input.data(), input.size());
    EVP_DigestFinal_ex(ctx, out, &outLen);
    EVP_MD_CTX_free(ctx);
    return Bytes(out, out + outLen);
}

/// HMAC-SHA3-256, fresh fetch and context per call: the slow reference the
/// model's own response stream is checked against.
Bytes refHmac(const Bytes& key, const Bytes& msg) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    char digest[] = "SHA3-256";
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_end()};
    unsigned char tag[EVP_MAX_MD_SIZE];
    size_t tagLen = 0;
    EVP_MAC_init(ctx, key.data(), key.size(), params);
    if (!msg.empty()) EVP_MAC_update(ctx, msg.data(), msg.size());
    EVP_MAC_final(ctx, tag, &tagLen, sizeof(tag));
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return Bytes(tag, tag + tagLen);
}

Bytes seedOf(const std::string& tag, int index) {
    return fromString(tag + "/" + std::to_string(index));
}

double mean(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double s = 0.0;
    for (double x : v) s += x;
    return s / static_cast<double>(v.size());
}

double variance(const std::vector<double>& v) {
    if (v.size() < 2) return 0.0;
    const double m = mean(v);
    double acc = 0.0;
    for (double x : v) acc += (x - m) * (x - m);
    return acc / static_cast<double>(v.size() - 1);
}

// ---------------------------------------------------------------------------

void testSubChallenge() {
    const Bytes c = fromString("challenge-0");

    // Deterministic.
    CHECK(deriveSubChallenge(c, 7) == deriveSubChallenge(c, 7));
    CHECK_EQ(deriveSubChallenge(c, 7).size(), 16u);

    // Distinct per index: 512 indices, no collisions.
    std::set<std::string> seen;
    for (uint16_t j = 0; j < 512; ++j) seen.insert(toHex(deriveSubChallenge(c, j)));
    CHECK_EQ(seen.size(), 512u);

    // Distinct per challenge, and the index really is appended big-endian
    // (SHA3-256(C || u16be(j)) -- so C="ab", j=0x6364 must equal C="abcd", j=0
    // only if the encoding were ambiguous; check that it is not).
    CHECK(deriveSubChallenge(fromString("challenge-1"), 7) != deriveSubChallenge(c, 7));
    CHECK(deriveSubChallenge(fromString("ab"), 0x6364) !=
          deriveSubChallenge(fromString("abcd"), 0));

    // Empty challenge is legal.
    CHECK_EQ(deriveSubChallenge(Bytes{}, 0).size(), 16u);

    // Pin the convention: first 16 bytes of SHA3-256(C || u16be(j)).
    for (uint16_t j : {uint16_t(0), uint16_t(1), uint16_t(254), uint16_t(4097)}) {
        Bytes input = c;
        const Bytes index = u16be(j);
        input.insert(input.end(), index.begin(), index.end());
        Bytes expected = refSha3(input);
        expected.resize(16);
        CHECK(deriveSubChallenge(c, j) == expected);
    }

    // The streamed form the hot paths use: one squeeze, 16 bytes per bit,
    // deterministic, distinct per index and per challenge.
    const Bytes stream = subStream(c, 512);
    CHECK_EQ(stream.size(), 512u * 16u);
    CHECK(subStream(c, 0).empty());
    CHECK(subStream(c, 4) == subStream(c, 4));
    CHECK(subStream(fromString("challenge-1"), 4) != subStream(c, 4));
    seen.clear();
    for (size_t j = 0; j < 512; ++j)
        seen.insert(toHex(Bytes(stream.begin() + static_cast<long>(16 * j),
                                stream.begin() + static_cast<long>(16 * (j + 1)))));
    CHECK_EQ(seen.size(), 512u);
}

/// The models are defined by a formula, not by whatever their code happens to
/// compute. Both formulas are recomputed here from scratch.
void testModelDefinitions() {
    const Bytes seed = fromString("definition-seed");
    const Bytes challenge = fromString("definition-challenge");
    const size_t bits = 64;

    // IdealPrfPuf: the whole response is a counter-mode HMAC-SHA3-256 stream,
    //   block_ctr = HMAC(key, label || challenge || u16be(ctr)),
    // concatenated and truncated, with label "uavauth/v1/puf/ideal-prf-response"
    // and key = SHA3-256("uavauth/v1/puf/ideal-prf-key" || seed). Recomputed
    // here the slow way, fresh fetch and context per block, so the check is
    // against the definition and not against the model's own code path.
    Bytes keyInput = fromString("uavauth/v1/puf/ideal-prf-key");
    keyInput.insert(keyInput.end(), seed.begin(), seed.end());
    const Bytes key = refSha3(keyInput);

    IdealPrfPuf prf(seed);
    const Bytes prfResponse = prf.evaluateIdeal(challenge, bits);
    Bytes prfExpected;
    const Bytes respLabel = fromString("uavauth/v1/puf/ideal-prf-response");
    for (uint16_t ctr = 0; prfExpected.size() < bytesForBits(bits); ++ctr) {
        Bytes msg = respLabel;
        msg.insert(msg.end(), challenge.begin(), challenge.end());
        const Bytes cbuf = u16be(ctr);
        msg.insert(msg.end(), cbuf.begin(), cbuf.end());
        const Bytes block = refHmac(key, msg);
        prfExpected.insert(prfExpected.end(), block.begin(), block.end());
    }
    prfExpected.resize(bytesForBits(bits));
    if ((bits & 7) != 0)
        prfExpected.back() = static_cast<unsigned char>(prfExpected.back() & (0xFFu << (8 - (bits & 7))));
    CHECK_MSG(prfResponse == prfExpected,
              "ideal-prf response is not the counter-mode HMAC-SHA3-256 stream");

    // ArbiterPuf: Delta = sum_i w[i]*phi[i] + w[128] with
    // phi[i] = prod_{k=i..127}(1-2c[k]), response bit = (Delta > 0). The
    // previous implementation shipped these formulas but never called them, so
    // recompute the parity vector independently and compare.
    ArbiterPuf arb(seed);
    const std::vector<double>& w = arb.weights();
    const Bytes arbResponse = arb.evaluateIdeal(challenge, bits);
    const Bytes subs = subStream(challenge, bits);
    int arbMismatch = 0;
    double maxDeltaError = 0.0;
    for (size_t j = 0; j < bits; ++j) {
        const Bytes sub(subs.begin() + static_cast<long>(16 * j),
                        subs.begin() + static_cast<long>(16 * (j + 1)));
        std::vector<double> phi(ArbiterPuf::kStages + 1, 1.0);
        for (size_t i = 0; i < ArbiterPuf::kStages; ++i) {
            double product = 1.0;
            for (size_t k = i; k < ArbiterPuf::kStages; ++k)
                product *= getBit(sub, k) ? -1.0 : 1.0;
            phi[i] = product;
        }
        double delta = 0.0;
        for (size_t i = 0; i <= ArbiterPuf::kStages; ++i) delta += w[i] * phi[i];
        maxDeltaError = std::max(maxDeltaError, std::fabs(delta - arb.deltaForSubChallenge(sub)));
        if (getBit(arbResponse, j) != (delta > 0.0)) ++arbMismatch;
    }
    CHECK_MSG(arbMismatch == 0, "arbiter response bit is not sign(Delta) of the delay model");
    CHECK_MSG(maxDeltaError < 1e-9, "arbiter Delta disagrees with the parity-vector definition");

    // The weights are the device: N(0,1) per stage, 129 of them.
    double sum = 0.0, sumSq = 0.0;
    for (double x : w) {
        sum += x;
        sumSq += x * x;
    }
    const double m = sum / static_cast<double>(w.size());
    const double var = sumSq / static_cast<double>(w.size()) - m * m;
    CHECK_MSG(std::fabs(m) < 0.35, "arbiter stage weights are not centred");
    CHECK_MSG(var > 0.6 && var < 1.6, "arbiter stage weight variance far from 1");

    // XOR of one chain is that chain; XOR of k is the XOR of the k chains.
    XorArbiterPuf xorDevice(seed, 4);
    const Bytes xorResponse = xorDevice.evaluateIdeal(challenge, bits);
    int xorMismatch = 0;
    for (size_t j = 0; j < bits; ++j) {
        const Bytes sub(subs.begin() + static_cast<long>(16 * j),
                        subs.begin() + static_cast<long>(16 * (j + 1)));
        bool bit = false;
        for (int c = 0; c < xorDevice.chains(); ++c)
            bit ^= (xorDevice.chain(c).deltaForSubChallenge(sub) > 0.0);
        if (getBit(xorResponse, j) != bit) ++xorMismatch;
    }
    CHECK_MSG(xorMismatch == 0, "xor-arbiter response is not the XOR of its chains");
}

void testDeterminism() {
    const Bytes challenge = fromString("determinism-challenge");

    IdealPrfPuf prf(seedOf("dev", 1));
    ArbiterPuf arb(seedOf("dev", 1));
    prf.setNoiseBer(0.05);
    arb.setNoiseSigma(2.0);

    // evaluateIdeal is stable across calls and consumes no randomness.
    const Bytes prfIdeal = prf.evaluateIdeal(challenge, kResponseBits);
    const Bytes arbIdeal = arb.evaluateIdeal(challenge, kResponseBits);
    CHECK(prfIdeal == prf.evaluateIdeal(challenge, kResponseBits));
    CHECK(arbIdeal == arb.evaluateIdeal(challenge, kResponseBits));
    CHECK_EQ(prfIdeal.size(), bytesForBits(kResponseBits));

    // Distinct device seeds give distinct responses.
    IdealPrfPuf prfOther(seedOf("dev", 2));
    ArbiterPuf arbOther(seedOf("dev", 2));
    CHECK(prfOther.evaluateIdeal(challenge, kResponseBits) != prfIdeal);
    CHECK(arbOther.evaluateIdeal(challenge, kResponseBits) != arbIdeal);

    // Same device, distinct challenge.
    CHECK(prf.evaluateIdeal(fromString("other"), kResponseBits) != prfIdeal);
    CHECK(arb.evaluateIdeal(fromString("other"), kResponseBits) != arbIdeal);

    // The same DRBG seed reproduces the same noisy response; a different one
    // does not.
    Drbg r1(fromString("noise-seed"));
    Drbg r2(fromString("noise-seed"));
    Drbg r3(fromString("noise-seed-2"));
    const Bytes n1 = prf.evaluateNoisy(challenge, kResponseBits, r1);
    CHECK(n1 == prf.evaluateNoisy(challenge, kResponseBits, r2));
    CHECK(n1 != prf.evaluateNoisy(challenge, kResponseBits, r3));
    CHECK(n1 != prfIdeal);

    Drbg a1(fromString("noise-seed"));
    Drbg a2(fromString("noise-seed"));
    const Bytes m1 = arb.evaluateNoisy(challenge, kResponseBits, a1);
    CHECK(m1 == arb.evaluateNoisy(challenge, kResponseBits, a2));

    // Zero noise reproduces the ideal response exactly, for both models...
    IdealPrfPuf quiet(seedOf("dev", 1));
    ArbiterPuf quietArb(seedOf("dev", 1));
    Drbg q(fromString("quiet"));
    CHECK(quiet.evaluateNoisy(challenge, kResponseBits, q) == prfIdeal);
    CHECK(quietArb.evaluateNoisy(challenge, kResponseBits, q) == arbIdeal);

    // ...and the DRBG consumption of a field evaluation does not depend on the
    // noise setting, so a run stays reproducible when the noise level changes.
    Drbg cA(fromString("count"));
    Drbg cB(fromString("count"));
    quiet.evaluateNoisy(challenge, kResponseBits, cA);
    prf.evaluateNoisy(challenge, kResponseBits, cB);
    CHECK_EQ(cA.bytesDrawn(), cB.bytesDrawn());
    Drbg cC(fromString("count"));
    Drbg cD(fromString("count"));
    quietArb.evaluateNoisy(challenge, kResponseBits, cC);
    arb.evaluateNoisy(challenge, kResponseBits, cD);
    CHECK_EQ(cC.bytesDrawn(), cD.bytesDrawn());

    // Cost was charged to the PUF counter.
    CHECK(prf.counters().get(Primitive::PufEval).calls > 0);
    CHECK(arb.counters().get(Primitive::PufEval).calls > 0);
    CHECK(arb.counters().get(Primitive::PufEval).inputBytes > 0);

    // A response longer than the uint16_t sub-challenge index must be rejected,
    // not silently wrapped into repeating bits.
    Drbg big(fromString("big"));
    CHECK_THROWS(prf.evaluateIdeal(challenge, kMaxResponseBits + 1));
    CHECK_THROWS(arb.evaluateIdeal(challenge, kMaxResponseBits + 1));
    CHECK_THROWS(arb.evaluateNoisy(challenge, kMaxResponseBits + 1, big));
    CHECK_THROWS(XorArbiterPuf(seedOf("dev", 1), 2).evaluateIdeal(challenge, kMaxResponseBits + 1));
    CHECK_THROWS(arb.measureBer(challenge, kMaxResponseBits + 1, big, 1));
    // A sub-challenge too short for 128 stages is rejected as well.
    CHECK_THROWS(arb.deltaForSubChallenge(Bytes(8, 0x5a)));

    // Zero-length requests are legal and produce nothing.
    CHECK(prf.evaluateIdeal(challenge, 0).empty());
    CHECK_EQ(arb.measureBer(challenge, 0, big, 10), 0.0);
    CHECK_EQ(arb.measureBer(challenge, 16, big, 0), 0.0);

    // Weight vector: 129 entries (128 stages + the constant term), and it is a
    // deterministic function of the device seed.
    CHECK_EQ(arb.weights().size(), ArbiterPuf::kStages + 1);
    CHECK(arb.weights() == ArbiterPuf(seedOf("dev", 1)).weights());
    CHECK(arb.weights() != arbOther.weights());
}

// Mean fractional inter-device Hamming distance over all device pairs.
double uniqueness(const std::function<Bytes(int)>& responseOf, int devices,
                  double* minOut, double* maxOut) {
    std::vector<Bytes> r;
    r.reserve(static_cast<size_t>(devices));
    for (int d = 0; d < devices; ++d) r.push_back(responseOf(d));

    double sum = 0.0;
    double lo = 1.0, hi = 0.0;
    int pairs = 0;
    for (int i = 0; i < devices; ++i)
        for (int j = i + 1; j < devices; ++j) {
            const double hd = static_cast<double>(hammingDistance(r[i], r[j])) /
                              static_cast<double>(kResponseBits);
            sum += hd;
            lo = std::min(lo, hd);
            hi = std::max(hi, hd);
            ++pairs;
        }
    CHECK_MSG(pairs >= 100, "uniqueness needs at least 100 device pairs");
    if (minOut != nullptr) *minOut = lo;
    if (maxOut != nullptr) *maxOut = hi;
    return sum / static_cast<double>(pairs);
}

void testUniqueness() {
    const Bytes challenge = fromString("uniqueness-challenge");
    const int devices = 24;   // 276 pairs

    double lo = 0.0, hi = 0.0;
    const double prfHd = uniqueness(
        [&](int d) { return IdealPrfPuf(seedOf("uniq", d)).evaluateIdeal(challenge, kResponseBits); },
        devices, &lo, &hi);
    std::printf("  [info] uniqueness ideal-prf   mean=%.4f min=%.4f max=%.4f\n", prfHd, lo, hi);
    CHECK_MSG(prfHd >= 0.45 && prfHd <= 0.55, "ideal-prf inter-device HD outside [45%,55%]");
    CHECK(lo > 0.25 && hi < 0.75);

    const double arbHd = uniqueness(
        [&](int d) { return ArbiterPuf(seedOf("uniq", d)).evaluateIdeal(challenge, kResponseBits); },
        devices, &lo, &hi);
    std::printf("  [info] uniqueness arbiter-128 mean=%.4f min=%.4f max=%.4f\n", arbHd, lo, hi);
    CHECK_MSG(arbHd >= 0.45 && arbHd <= 0.55, "arbiter inter-device HD outside [45%,55%]");
    CHECK(lo > 0.25 && hi < 0.75);

    const double xorHd = uniqueness(
        [&](int d) { return XorArbiterPuf(seedOf("uniq", d), 4).evaluateIdeal(challenge, kResponseBits); },
        devices, &lo, &hi);
    std::printf("  [info] uniqueness xor-arb-4   mean=%.4f min=%.4f max=%.4f\n", xorHd, lo, hi);
    CHECK_MSG(xorHd >= 0.45 && xorHd <= 0.55, "xor-arbiter inter-device HD outside [45%,55%]");
}

void testReliabilityIdeal() {
    // Bernoulli(p) is set, not calibrated, so the only error here is binomial.
    const double targets[] = {0.01, 0.03, 0.05, 0.10};
    IdealPrfPuf prf(seedOf("rel", 1));
    Drbg rng(fromString("rel-ideal"));

    for (double target : targets) {
        prf.setNoiseBer(target);
        CHECK_EQ(prf.noiseBer(), target);
        const int trials = 160;
        const double measured =
            prf.measureBer(fromString("rel-challenge"), kResponseBits, rng, trials);
        const double sd = std::sqrt(target * (1.0 - target) /
                                    (static_cast<double>(trials) * kResponseBits));
        std::printf("  [info] BER ideal-prf   target=%.3f measured=%.4f (%.1f sigma)\n",
                    target, measured, (measured - target) / sd);
        CHECK_MSG(std::fabs(measured - target) <= 0.005,
                  "ideal-prf BER off target by more than 0.5 points");
        CHECK_MSG(std::fabs(measured - target) <= 5.0 * sd, "ideal-prf BER outside 5 sigma");
    }
}

void testReliabilityArbiter() {
    // sigma has no natural unit, so it is calibrated to each target BER and the
    // result is then measured on challenges the calibration never saw.
    const double targets[] = {0.01, 0.03, 0.05, 0.10};
    ArbiterPuf arb(seedOf("rel", 2));
    Drbg calRng(fromString("rel-arb-calibrate"));
    Drbg measRng(fromString("rel-arb-measure"));

    for (double target : targets) {
        const double sigma = arb.sigmaForTargetBer(target, calRng, 20000);
        arb.setNoiseSigma(sigma);
        CHECK_EQ(arb.noiseSigma(), sigma);

        // Average over many challenges rather than over many repetitions of one.
        // A single challenge's BER is a mean over only 255 draws of |Delta|, and
        // that Delta-sampling error -- not the noise-sampling error -- dominates:
        // repeating one challenge 1000 times converges to the wrong number.
        const int challenges = 40;
        const int trials = 14;
        double sum = 0.0;
        for (int c = 0; c < challenges; ++c)
            sum += arb.measureBer(fromString("rel-arb-" + std::to_string(c)), kResponseBits,
                                  measRng, trials);
        const double measured = sum / challenges;
        std::printf("  [info] BER arbiter-128 target=%.3f sigma=%.4f measured=%.4f\n",
                    target, sigma, measured);
        CHECK_MSG(std::fabs(measured - target) <= 0.005,
                  "arbiter BER off target by more than 0.5 points after calibration");
    }

    // sigma is monotone in the requested BER, and zero BER means zero noise.
    Drbg r(fromString("mono"));
    CHECK_EQ(arb.sigmaForTargetBer(0.0, r, 2000), 0.0);
    const double s1 = arb.sigmaForTargetBer(0.01, r, 4000);
    const double s10 = arb.sigmaForTargetBer(0.10, r, 4000);
    CHECK(s1 > 0.0 && s10 > s1);
}

void testNoiseIsBitDependent() {
    // The defining property of a delay-model PUF: because the noise is added to
    // Delta and not to the output bit, reliability varies enormously across bit
    // positions -- metastable bits (|Delta| ~ 0) flip constantly, confident bits
    // essentially never do. A Bernoulli channel, by construction, cannot show
    // this: every position has the same flip probability.
    const size_t bits = 128;
    const int trials = 600;
    const double targetBer = 0.05;
    const Bytes challenge = fromString("noise-profile-challenge");

    ArbiterPuf arb(seedOf("noise", 1));
    Drbg calRng(fromString("noise-cal"));
    arb.setNoiseSigma(arb.sigmaForTargetBer(targetBer, calRng, 20000));

    IdealPrfPuf prf(seedOf("noise", 1));
    prf.setNoiseBer(targetBer);

    const auto profile = [&](const PufModel& model, const char* seed) {
        Drbg rng(fromString(seed));
        const Bytes ideal = model.evaluateIdeal(challenge, bits);
        std::vector<size_t> flips(bits, 0);
        for (int t = 0; t < trials; ++t) {
            const Bytes noisy = model.evaluateNoisy(challenge, bits, rng);
            for (size_t j = 0; j < bits; ++j)
                if (getBit(noisy, j) != getBit(ideal, j)) ++flips[j];
        }
        std::vector<double> rate(bits);
        for (size_t j = 0; j < bits; ++j)
            rate[j] = static_cast<double>(flips[j]) / trials;
        return rate;
    };

    const std::vector<double> arbRate = profile(arb, "noise-run");
    const std::vector<double> prfRate = profile(prf, "noise-run");

    const double arbVar = variance(arbRate);
    const double prfVar = variance(prfRate);
    // A Bernoulli channel's per-bit rates scatter only by sampling error,
    // p(1-p)/trials; anything close to that is a uniform channel.
    const double binomialVar = targetBer * (1.0 - targetBer) / trials;

    int arbNearZero = 0, arbHigh = 0, prfNearZero = 0, prfHigh = 0;
    for (double x : arbRate) {
        if (x < 0.002) ++arbNearZero;
        if (x > 0.25) ++arbHigh;
    }
    for (double x : prfRate) {
        if (x < 0.002) ++prfNearZero;
        if (x > 0.25) ++prfHigh;
    }

    std::printf("  [info] per-bit flip rate: arbiter mean=%.4f var=%.3e | "
                "ideal-prf mean=%.4f var=%.3e | binomial var=%.3e\n",
                mean(arbRate), arbVar, mean(prfRate), prfVar, binomialVar);
    std::printf("  [info] per-bit flip rate: arbiter %d/%zu bits <0.2%% and %d/%zu >25%%; "
                "ideal-prf %d and %d\n",
                arbNearZero, bits, arbHigh, bits, prfNearZero, prfHigh);

    CHECK_MSG(arbVar > 10.0 * prfVar,
              "arbiter per-bit flip rates are not materially more dispersed than Bernoulli");
    CHECK_MSG(prfVar < 4.0 * binomialVar,
              "ideal-prf per-bit flip rates scatter by more than sampling error");
    CHECK_MSG(arbNearZero > 0 && arbHigh > 0,
              "arbiter shows neither highly reliable nor metastable bits");
    CHECK_MSG(prfHigh == 0, "Bernoulli channel produced a bit flipping over 25% of the time");

    // The fast measurePerBitFlipRate path must be the same model, not an
    // approximation of it: same DRBG seed, same draw order, identical answer.
    Drbg viaApi(fromString("equivalence"));
    const Bytes ideal = arb.evaluateIdeal(challenge, bits);
    std::vector<size_t> flips(bits, 0);
    for (int t = 0; t < 25; ++t) {
        const Bytes noisy = arb.evaluateNoisy(challenge, bits, viaApi);
        for (size_t j = 0; j < bits; ++j)
            if (getBit(noisy, j) != getBit(ideal, j)) ++flips[j];
    }
    Drbg viaFast(fromString("equivalence"));
    const std::vector<double> fast = arb.measurePerBitFlipRate(challenge, bits, viaFast, 25);
    bool identical = true;
    for (size_t j = 0; j < bits; ++j)
        if (std::fabs(fast[j] - static_cast<double>(flips[j]) / 25.0) > 1e-12) identical = false;
    CHECK_MSG(identical, "measurePerBitFlipRate disagrees with evaluateNoisy");
}

void testXorTradeoff() {
    // XOR-ing chains buys modelling resistance and pays for it in reliability.
    const double perChainBer = 0.03;
    const Bytes challenge = fromString("xor-challenge");
    const int ks[] = {1, 4, 8};

    // The same challenge set is used for the device and for its chains, so the
    // challenge-sampling error is common to both and cancels in the comparison.
    std::vector<Bytes> challenges;
    for (int c = 0; c < 16; ++c) challenges.push_back(fromString("xor-c-" + std::to_string(c)));
    const int trials = 8;

    double previous = -1.0;
    for (int k : ks) {
        XorArbiterPuf device(seedOf("xor", 1), k);
        CHECK_EQ(device.chains(), k);
        CHECK_EQ(std::string(device.name()), "xor-arbiter-" + std::to_string(k));

        Drbg calRng(fromString("xor-cal"));
        const double sigma = device.setChainSigmaForTargetBer(perChainBer, calRng, 20000);
        CHECK(sigma > 0.0);
        CHECK_EQ(device.chain(0).noiseSigma(), sigma);

        Drbg measRng(fromString("xor-measure"));
        double sum = 0.0;
        for (const Bytes& ch : challenges)
            sum += device.measureBer(ch, kResponseBits, measRng, trials);
        const double measured = sum / static_cast<double>(challenges.size());

        // Predict from the chains' own measured BERs rather than from the
        // nominal 3%. A shared sigma does not give every chain the same error
        // rate -- a chain's reliability scales with the norm of its weight
        // vector, which varies by ~6% across chains -- and at k=8 the XOR
        // amplifies a per-chain error by dBER/dp = k(1-2p)^(k-1) ~ 5.
        double product = 1.0;
        double chainSum = 0.0;
        for (int c = 0; c < k; ++c) {
            Drbg chainRng(fromString("xor-chain-measure"));
            double chainSumBer = 0.0;
            for (const Bytes& ch : challenges)
                chainSumBer += device.chain(c).measureBer(ch, kResponseBits, chainRng, trials);
            const double chainBer = chainSumBer / static_cast<double>(challenges.size());
            chainSum += chainBer;
            product *= (1.0 - 2.0 * chainBer);
        }
        const double predicted = 0.5 * (1.0 - product);

        std::printf("  [info] xor-arbiter k=%d  BER measured=%.4f predicted=%.4f "
                    "(mean per-chain %.4f, nominal-p prediction %.4f)\n",
                    k, measured, predicted, chainSum / k,
                    XorArbiterPuf::predictedBer(perChainBer, k));

        CHECK_MSG(measured > previous, "XOR BER did not increase with k");
        CHECK_MSG(std::fabs(measured - predicted) <= 0.01,
                  "XOR BER departs from (1 - prod_c(1-2p_c))/2");
        previous = measured;
    }

    // The chains really are independent devices, not k copies of one.
    XorArbiterPuf device(seedOf("xor", 1), 4);
    CHECK(device.chain(0).weights() != device.chain(1).weights());
    CHECK(device.chain(0).weights() != device.chain(2).weights());

    // A 1-XOR device is a plain arbiter PUF: same ideal response shape, and its
    // noiseless output must be reproducible.
    XorArbiterPuf one(seedOf("xor", 2), 1);
    CHECK(one.evaluateIdeal(challenge, kResponseBits) ==
          one.evaluateIdeal(challenge, kResponseBits));
    CHECK_THROWS(XorArbiterPuf(seedOf("xor", 3), 0));
}

// Collect one response per device.
std::vector<Bytes> population(int devices, size_t blockBits,
                              const std::function<Bytes(const Bytes&, size_t)>& evalOf,
                              const char* seedTag) {
    Drbg seedRng(fromString(seedTag));
    std::vector<Bytes> out;
    out.reserve(static_cast<size_t>(devices));
    for (int d = 0; d < devices; ++d) out.push_back(evalOf(seedRng.bytes(16), blockBits));
    return out;
}

void reportEstimate(const char* label, const EntropyEstimate& e) {
    std::printf("  [info] min-entropy %-22s D=%-6zu n=%-4zu mcv=%.4f (raw %.4f) "
                "pred=%.4f (ctx=%d) min=%.1f bits/block maxbias=%.4f\n",
                label, e.devices, e.blockBits, e.mcvRatePerBit, e.mcvRateUncorrectedPerBit,
                e.compressionBitsPerBlock / static_cast<double>(e.blockBits), e.contextBits,
                e.minOfEstimates, e.maxPositionBias);
}

void testMinEntropy() {
    const Bytes challenge = fromString("entropy-challenge");

    const auto idealPrfEval = [&](const Bytes& seed, size_t bits) {
        return IdealPrfPuf(seed).evaluateIdeal(challenge, bits);
    };
    const auto arbiterEval = [&](const Bytes& seed, size_t bits) {
        return ArbiterPuf(seed).evaluateIdeal(challenge, bits);
    };

    // --- Fuzzy-extractor-shaped population: 255-bit blocks, 1000 devices -----
    const int devicesA = 1000;

    Drbg uniformRng(fromString("uniform-reference"));
    std::vector<Bytes> uniformA;
    for (int d = 0; d < devicesA; ++d) uniformA.push_back(uniformRng.bytes(bytesForBits(kResponseBits)));

    const EntropyEstimate refA = estimateMinEntropy(uniformA, kResponseBits);
    const EntropyEstimate prfA =
        estimateMinEntropy(population(devicesA, kResponseBits, idealPrfEval, "ent-prf"), kResponseBits);
    const EntropyEstimate arbA =
        estimateMinEntropy(population(devicesA, kResponseBits, arbiterEval, "ent-arb"), kResponseBits);

    reportEstimate("uniform-reference", refA);
    reportEstimate("ideal-prf", prfA);
    reportEstimate("arbiter-128", arbA);

    CHECK_EQ(prfA.devices, static_cast<size_t>(devicesA));
    CHECK_EQ(prfA.blockBits, kResponseBits);
    CHECK(std::fabs(prfA.mcvBitsPerBlock -
                    prfA.mcvRatePerBit * static_cast<double>(kResponseBits)) < 1e-9);
    CHECK(prfA.minOfEstimates <= prfA.mcvBitsPerBlock);
    CHECK(prfA.minOfEstimates <= prfA.compressionBitsPerBlock);

    // The PRF source must be indistinguishable from a uniform source of the same
    // shape under both estimators. Comparing against the reference rather than
    // against 1.0 is what makes this independent of the sample size: at D=1000
    // the 99% upper bound alone caps *any* source at ~0.85 bit/bit.
    CHECK_MSG(prfA.mcvRatePerBit >= refA.mcvRatePerBit - 0.01,
              "ideal-prf MCV rate below the uniform reference");
    CHECK_MSG(prfA.compressionBitsPerBlock >= refA.compressionBitsPerBlock - 2.0,
              "ideal-prf predictability estimate below the uniform reference");
    CHECK_MSG(prfA.mcvRatePerBit > 0.84, "ideal-prf MCV rate below the D=1000 floor");
    CHECK_MSG(prfA.maxPositionBias < 0.10, "ideal-prf has a strongly biased bit position");

    // --- Large population: the rate the source actually converges to ---------
    // 40000 devices of 16-bit blocks is 640k bits, which is what it takes for the
    // uncorrected MCV rate of an unbiased source to clear 0.99.
    const int devicesB = 40000;
    const size_t blockBitsB = 16;

    Drbg uniformRngB(fromString("uniform-reference-b"));
    std::vector<Bytes> uniformB;
    for (int d = 0; d < devicesB; ++d) uniformB.push_back(uniformRngB.bytes(bytesForBits(blockBitsB)));

    const EntropyEstimate refB = estimateMinEntropy(uniformB, blockBitsB);
    const EntropyEstimate prfB =
        estimateMinEntropy(population(devicesB, blockBitsB, idealPrfEval, "ent-prf-b"), blockBitsB);
    const EntropyEstimate arbB =
        estimateMinEntropy(population(devicesB, blockBitsB, arbiterEval, "ent-arb-b"), blockBitsB);

    reportEstimate("uniform-reference/40k", refB);
    reportEstimate("ideal-prf/40k", prfB);
    reportEstimate("arbiter-128/40k", arbB);

    CHECK_MSG(prfB.mcvRateUncorrectedPerBit >= 0.99,
              "ideal-prf MCV rate below 0.99 at 40000 devices");
    CHECK_MSG(prfB.mcvRatePerBit >= refB.mcvRatePerBit - 0.01,
              "ideal-prf 99%-bounded MCV rate below the uniform reference at 40000 devices");
    CHECK_MSG(prfB.maxPositionBias < 0.02, "ideal-prf positional bias too large at 40000 devices");

    // The arbiter rate is reported, not asserted. Its response bits are all
    // linear functions of 129 stage weights, so the honest expectation is that a
    // bit-level estimator cannot see the dependence at all -- the arbiter PUF's
    // weakness is a modelling attack on the challenge-response map, which needs
    // the challenges to detect. Asserting a high rate here would be asserting
    // that the estimator is blind, which is not a security property.
    std::printf("  [info] arbiter-128 rate is informational: bit-level estimators cannot "
                "see the 129-weight linear structure that makes it modelable\n");

    // --- Regression guards --------------------------------------------------
    // A source with a stuck bit position must lose exactly that position's bit.
    std::vector<Bytes> stuck = uniformA;
    for (Bytes& r : stuck) setBit(r, 3, true);
    const EntropyEstimate stuckEst = estimateMinEntropy(stuck, kResponseBits);
    CHECK_MSG(stuckEst.mcvBitsPerBlock < refA.mcvBitsPerBlock - 0.5,
              "a stuck bit position did not reduce the MCV estimate");
    CHECK(stuckEst.maxPositionBias > 0.49);

    // A source whose every bit repeats the previous one has one bit per block of
    // entropy at most, and the predictability estimate must catch it even though
    // the per-position MCV sees perfectly balanced bits.
    std::vector<Bytes> repeated;
    Drbg repRng(fromString("repeat"));
    for (int d = 0; d < devicesA; ++d) {
        Bytes r(bytesForBits(kResponseBits), 0);
        const bool bit = (repRng.uniform(2) == 1);
        for (size_t i = 0; i < kResponseBits; ++i) setBit(r, i, bit);
        repeated.push_back(r);
    }
    const EntropyEstimate repEst = estimateMinEntropy(repeated, kResponseBits);
    std::printf("  [info] all-constant source: mcv=%.1f pred=%.1f min=%.1f bits/block\n",
                repEst.mcvBitsPerBlock, repEst.compressionBitsPerBlock, repEst.minOfEstimates);
    CHECK_MSG(repEst.compressionBitsPerBlock < 1.0,
              "predictability estimate missed a perfectly predictable source");
    CHECK(repEst.minOfEstimates < 1.0);
    CHECK(repEst.mcvBitsPerBlock > repEst.compressionBitsPerBlock);

    // Degenerate inputs.
    CHECK_EQ(estimateMinEntropy({}, kResponseBits).minOfEstimates, 0.0);
    CHECK_EQ(estimateMinEntropy(uniformA, 0).minOfEstimates, 0.0);
    CHECK_THROWS(estimateMinEntropy({Bytes(4, 0)}, kResponseBits));
}

} // namespace

int main() {
    testSubChallenge();
    testModelDefinitions();
    testDeterminism();
    testUniqueness();
    testReliabilityIdeal();
    testReliabilityArbiter();
    testNoiseIsBitDependent();
    testXorTradeoff();
    testMinEntropy();
    return uavauth::test::summarise("puf");
}
