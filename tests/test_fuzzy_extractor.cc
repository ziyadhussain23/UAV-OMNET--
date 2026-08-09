// Stage-5 gate: the fuzzy extractor.
//
// Checks the properties the protocol depends on: a noisy response reproduces the
// enrolled key exactly, a too-noisy or foreign response fails CLOSED (no key at
// all, rather than a partial or uncorrected one), the measured failure rate
// tracks the binomial prediction, and an under-provisioned entropy budget is
// rejected at construction instead of silently yielding a weak key.
//
// DEPS: core/Bytes.cc core/Encoding.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/Sha3Suite.cc crypto/Drbg.cc fe/BchCodec.cc fe/FuzzyExtractor.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/Sha3Suite.h"
#include "fe/FuzzyExtractor.h"
#include "tests/TestUtil.h"

#include <cmath>
#include <cstdio>
#include <string>

using namespace uavauth::core;
using namespace uavauth::crypto;
using namespace uavauth::fe;

namespace {

Sha3Suite suite;

/// Flip each bit independently with probability p (a true Bernoulli channel,
/// not a fixed-count flip).
Bytes applyBernoulliNoise(const Bytes& bits, size_t bitCount, double p, Drbg& rng) {
    Bytes out = bits;
    for (size_t i = 0; i < bitCount; ++i)
        if (rng.uniformDouble() < p) setBit(out, i, !getBit(out, i));
    return out;
}

/// P(Binomial(n,p) > t): the analytic per-block failure probability.
double binomialTailAbove(int n, double p, int t) {
    double logP = 0.0;
    double tail = 0.0;
    // Sum k = t+1 .. n of C(n,k) p^k (1-p)^(n-k), computed in log space.
    for (int k = 0; k <= n; ++k) {
        if (k > 0) logP += std::log(static_cast<double>(n - k + 1)) - std::log(static_cast<double>(k));
        const double term = logP + k * std::log(p) + (n - k) * std::log1p(-p);
        if (k > t) tail += std::exp(term);
    }
    return tail;
}

void testEntropyBudget() {
    // The default profile must satisfy its own budget.
    FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    CHECK_EQ(p.numBlocks, 4);
    CHECK(fe.residualEntropyBits() >= fe.requiredEntropyBits());
    std::printf("  [info] bch255-131-18: residual %.1f bits >= required %.1f bits\n",
                fe.residualEntropyBits(), fe.requiredEntropyBits());

    // 255-bit blocks are required: a 128-bit block leaks 124 of its own bits and
    // contributes essentially nothing, so the budget must reject it.
    FeParams tooSmall = p;
    tooSmall.numBlocks = 1;
    CHECK_THROWS(FuzzyExtractor(tooSmall, suite));

    // A pessimistic entropy rate must also be rejected rather than warned about.
    FeParams lowRate = p;
    lowRate.assumedMinEntropyRate = 0.5;
    CHECK_THROWS(FuzzyExtractor(lowRate, suite));

    // ... but can be compensated with more blocks.
    FeParams compensated = lowRate;
    compensated.numBlocks = 200;
    FuzzyExtractor big(compensated, suite);
    CHECK(big.residualEntropyBits() >= big.requiredEntropyBits());

    // Disabling the check is possible but must be explicit.
    FeParams unchecked = tooSmall;
    unchecked.checkBudget = false;
    FuzzyExtractor loose(unchecked, suite);
    CHECK(loose.residualEntropyBits() < loose.requiredEntropyBits());

    // Leak accounting.
    HelperData hd;
    hd.params = p;
    CHECK_EQ(hd.leakBits(), static_cast<size_t>(4 * 124));
}

void testAllProfilesConstructAndRoundTrip() {
    for (const std::string& name :
         {std::string("bch255-131-18"), std::string("bch255-91-25"),
          std::string("rep3-bch255-131-18")}) {
        const FeParams p = FeParams::profile(name);
        FuzzyExtractor fe(p, suite);
        Drbg rng(fromString("profile-" + name));

        const Bytes response = rng.bytes(bytesForBits(fe.requiredPufBits()));
        const Bytes seed = rng.bytes(static_cast<size_t>(p.seedBytes));

        const GenResult g = fe.gen(response, seed);
        CHECK(g.ok);
        CHECK_EQ(g.mk.size(), 32u);
        CHECK_EQ(g.helper.sketch.size(), static_cast<size_t>(p.numBlocks));

        const RepResult r = fe.rep(response, g.helper);
        CHECK_MSG(r.ok, "noise-free Rep failed for profile " + name);
        CHECK_MSG(r.mk == g.mk, "noise-free Rep produced a different key for " + name);

        std::printf("  [info] %-20s L=%d rep=%d pufBits=%zu leak=%zu residual=%.1f\n",
                    name.c_str(), p.numBlocks, p.repFactor, fe.requiredPufBits(),
                    g.helper.leakBits(), fe.residualEntropyBits());
    }
    CHECK_THROWS(FeParams::profile("no-such-profile"));
}

void testReproductionUnderNoise() {
    const FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    Drbg rng(fromString("noise-repro"));

    const size_t pufBits = fe.requiredPufBits();
    const Bytes response = rng.bytes(bytesForBits(pufBits));
    const Bytes seed = rng.bytes(32);
    const GenResult g = fe.gen(response, seed);
    CHECK(g.ok);

    // At 3% BER the extractor should nearly always reproduce the key.
    const int trials = 300;
    int successes = 0, keyMatches = 0;
    for (int i = 0; i < trials; ++i) {
        const Bytes noisy = applyBernoulliNoise(response, pufBits, 0.03, rng);
        const RepResult r = fe.rep(noisy, g.helper);
        if (r.ok) {
            ++successes;
            if (r.mk == g.mk) ++keyMatches;
        } else {
            // Fail closed: no key material on failure.
            CHECK(r.mk.empty());
        }
    }
    // Whenever Rep succeeds the key MUST be the enrolled one -- a success with a
    // different key would mean silent miscorrection.
    CHECK_MSG(successes == keyMatches,
              "Rep reported success but produced the wrong key");
    std::printf("  [info] BER 3%%: %d/%d reproductions succeeded (FRR %.4f)\n",
                successes, trials, 1.0 - static_cast<double>(successes) / trials);
    CHECK_MSG(successes >= trials - 5, "unexpectedly high failure rate at 3% BER");
}

void testFrrTracksBinomialPrediction() {
    // At 5% BER the per-block failure probability is large enough to measure.
    const FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    Drbg rng(fromString("frr-prediction"));

    const double ber = 0.05;
    const double perBlock = binomialTailAbove(255, ber, 18);
    const double predictedFrr = 1.0 - std::pow(1.0 - perBlock, p.numBlocks);

    const size_t pufBits = fe.requiredPufBits();
    const Bytes response = rng.bytes(bytesForBits(pufBits));
    const GenResult g = fe.gen(response, rng.bytes(32));

    const int trials = 400;
    int failures = 0;
    for (int i = 0; i < trials; ++i) {
        const Bytes noisy = applyBernoulliNoise(response, pufBits, ber, rng);
        if (!fe.rep(noisy, g.helper).ok) ++failures;
    }
    const double measured = static_cast<double>(failures) / trials;
    const double se = std::sqrt(predictedFrr * (1.0 - predictedFrr) / trials);
    std::printf("  [info] BER 5%%: measured FRR %.3f, binomial prediction %.3f "
                "(per-block %.4f, +/- %.3f s.e.)\n",
                measured, predictedFrr, perBlock, se);
    CHECK_MSG(std::fabs(measured - predictedFrr) < 5.0 * se + 0.02,
              "measured FRR is inconsistent with the binomial prediction");
}

void testFailsClosedBeyondCorrectionRadius() {
    const FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    Drbg rng(fromString("fail-closed"));

    const size_t pufBits = fe.requiredPufBits();
    const Bytes response = rng.bytes(bytesForBits(pufBits));
    const GenResult g = fe.gen(response, rng.bytes(32));

    // Corrupt one block far beyond t = 18 errors.
    Bytes broken = response;
    for (int i = 0; i < 60; ++i) setBit(broken, static_cast<size_t>(i * 3), !getBit(broken, static_cast<size_t>(i * 3)));

    const RepResult r = fe.rep(broken, g.helper);
    CHECK_MSG(!r.ok, "Rep succeeded despite errors far beyond the correction radius");
    CHECK_MSG(r.mk.empty(), "failed Rep still returned key material");
    CHECK(r.stats.blocksFailed > 0);
}

void testForeignResponseNeverYieldsEnrolledKey() {
    // Protocol-level false accept: a different device's response must never
    // reproduce the enrolled key.
    const FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    Drbg rng(fromString("foreign"));

    const size_t pufBits = fe.requiredPufBits();
    const Bytes response = rng.bytes(bytesForBits(pufBits));
    const GenResult g = fe.gen(response, rng.bytes(32));

    int decoderAccepts = 0, keyMatches = 0;
    const int trials = 500;
    for (int i = 0; i < trials; ++i) {
        const Bytes foreign = rng.bytes(bytesForBits(pufBits));
        const RepResult r = fe.rep(foreign, g.helper);
        if (r.ok) {
            ++decoderAccepts;
            if (r.mk == g.mk) ++keyMatches;
        }
    }
    CHECK_MSG(keyMatches == 0, "a foreign response reproduced the enrolled key");
    std::printf("  [info] cross-device: %d/%d decoder accepts, %d key matches "
                "(protocol-level FAR must be 0)\n",
                decoderAccepts, trials, keyMatches);
}

void testDeterminismAndIsolation() {
    const FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    Drbg rng(fromString("determinism"));

    const Bytes response = rng.bytes(bytesForBits(fe.requiredPufBits()));
    const Bytes seed = rng.bytes(32);

    // Gen is deterministic in (response, seed).
    const GenResult g1 = fe.gen(response, seed);
    const GenResult g2 = fe.gen(response, seed);
    CHECK(g1.mk == g2.mk);
    CHECK(g1.helper.sketch == g2.helper.sketch);

    // Rep is deterministic and repeatable.
    const RepResult r1 = fe.rep(response, g1.helper);
    const RepResult r2 = fe.rep(response, g1.helper);
    CHECK(r1.mk == r2.mk);
    CHECK(r1.ok && r2.ok);

    // A different seed gives an independent key from the same response, so
    // re-enrollment rotates the key.
    const Bytes otherSeed = rng.bytes(32);
    const GenResult g3 = fe.gen(response, otherSeed);
    CHECK(g3.mk != g1.mk);

    // Helper data from one enrollment must not unlock another.
    const RepResult mismatched = fe.rep(response, g3.helper);
    CHECK(mismatched.ok);              // it decodes, being a valid sketch...
    CHECK(mismatched.mk != g1.mk);     // ...but yields a different key

    // Malformed inputs are rejected rather than misinterpreted.
    CHECK_THROWS(fe.gen(Bytes(10, 0), seed));
    CHECK_THROWS(fe.gen(response, Bytes(8, 0)));
    CHECK(!fe.rep(Bytes(10, 0), g1.helper).ok);
}

void testHelperDataCarriesNoKey() {
    // The helper data is public: it must not contain the key.
    const FeParams p = FeParams::profile("bch255-131-18");
    FuzzyExtractor fe(p, suite);
    Drbg rng(fromString("helper-public"));
    const Bytes response = rng.bytes(bytesForBits(fe.requiredPufBits()));
    const GenResult g = fe.gen(response, rng.bytes(32));

    for (const Bytes& s : g.helper.sketch) {
        CHECK_EQ(s.size(), bytesForBits(255));
        // The key must not appear verbatim inside any sketch block.
        bool found = false;
        if (s.size() >= g.mk.size()) {
            for (size_t off = 0; off + g.mk.size() <= s.size(); ++off)
                if (std::equal(g.mk.begin(), g.mk.end(), s.begin() + static_cast<long>(off)))
                    found = true;
        }
        CHECK(!found);
    }
}

} // namespace

int main() {
    testEntropyBudget();
    testAllProfilesConstructAndRoundTrip();
    testReproductionUnderNoise();
    testFrrTracksBinomialPrediction();
    testFailsClosedBeyondCorrectionRadius();
    testForeignResponseNeverYieldsEnrolledKey();
    testDeterminismAndIsolation();
    testHelperDataCarriesNoKey();
    return uavauth::test::summarise("fuzzy-extractor");
}
