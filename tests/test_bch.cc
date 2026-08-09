// Stage-5 gate: the BCH codec.
//
// This is the most important correctness gate in the project. The previous
// implementation set the parity length to m*t = 144 instead of deg(g) = 124,
// giving k = 111 < 128 so the tail of every PUF response went unprotected, and
// its decoder returned the uncorrected input on failure, which made the whole
// fuzzy extractor a no-op that a loose Hamming threshold then hid. Every one of
// those failure modes is tested for here.
//
// DEPS: core/Bytes.cc fe/BchCodec.cc

#include "core/Bytes.h"
#include "fe/BchCodec.h"
#include "tests/TestUtil.h"

#include <cstdio>
#include <random>
#include <set>
#include <vector>

using namespace uavauth::core;
using namespace uavauth::fe;

namespace {

std::mt19937 rng(0xB0BAFE77u);

Bytes randomDataBits(int k) {
    Bytes data(bytesForBits(static_cast<size_t>(k)), 0);
    for (int i = 0; i < k; ++i) setBit(data, static_cast<size_t>(i), (rng() & 1u) != 0);
    return data;
}

/// Flip exactly `w` distinct bit positions in the first n bits.
Bytes injectErrors(const Bytes& word, int n, int w, std::vector<int>* positionsOut = nullptr) {
    std::set<int> chosen;
    while (static_cast<int>(chosen.size()) < w) chosen.insert(static_cast<int>(rng() % static_cast<unsigned>(n)));
    Bytes bad = word;
    for (int p : chosen) setBit(bad, static_cast<size_t>(p), !getBit(bad, static_cast<size_t>(p)));
    if (positionsOut != nullptr) positionsOut->assign(chosen.begin(), chosen.end());
    return bad;
}

void testGeneratorParameters() {
    // The three parameter sets the fuzzy-extractor profiles use. deg(g) for
    // t=18 was independently confirmed to be 124 (124 conjugate roots).
    const BchCodec c18(18);
    CHECK_EQ(c18.n(), 255);
    CHECK_MSG(c18.parityBits() == 124, "deg(g) for t=18 must be 124, not m*t=144");
    CHECK_MSG(c18.k() == 131, "k for t=18 must be 131 (>= 128 response bits)");
    CHECK(c18.k() >= 128);

    const BchCodec c22(22);
    CHECK_EQ(c22.n(), 255);
    CHECK(c22.parityBits() == 255 - c22.k());
    std::printf("  [info] t=22 -> parity=%d k=%d\n", c22.parityBits(), c22.k());

    const BchCodec c25(25);
    CHECK(c25.parityBits() == 255 - c25.k());
    std::printf("  [info] t=25 -> parity=%d k=%d\n", c25.parityBits(), c25.k());

    // Generator coefficients must be binary; a non-binary coefficient means the
    // conjugate closure was incomplete (the original bug).
    for (uint8_t coeff : c18.generator()) CHECK(coeff == 0 || coeff == 1);
    CHECK_EQ(c18.generator().size(), static_cast<size_t>(c18.parityBits() + 1));
    CHECK_EQ(c18.generator().front(), 1);   // non-zero constant term
    CHECK_EQ(c18.generator().back(), 1);    // monic

    // Larger t must cost more parity.
    CHECK(c22.parityBits() > c18.parityBits());
    CHECK(c25.parityBits() > c22.parityBits());
}

void testGeneratorDividesXnPlus1() {
    // A structural check of the generator: g(x) must divide x^255 + 1, since
    // every BCH generator divides x^n - 1.
    const BchCodec codec(18);
    const std::vector<uint8_t>& g = codec.generator();
    const int degG = codec.parityBits();

    // Polynomial long division of x^255 + 1 by g over GF(2).
    std::vector<uint8_t> remainder(256, 0);
    remainder[255] = 1;
    remainder[0] = 1;

    for (int i = 255; i >= degG; --i) {
        if (remainder[static_cast<size_t>(i)] == 0) continue;
        for (int j = 0; j <= degG; ++j) {
            remainder[static_cast<size_t>(i - degG + j)] = static_cast<uint8_t>(
                remainder[static_cast<size_t>(i - degG + j)] ^ g[static_cast<size_t>(j)]);
        }
    }
    bool zero = true;
    for (uint8_t v : remainder)
        if (v != 0) { zero = false; break; }
    CHECK_MSG(zero, "g(x) does not divide x^255 + 1");
}

void testEncodeIsSystematicAndValid() {
    const BchCodec codec(18);
    for (int trial = 0; trial < 2000; ++trial) {
        const Bytes data = randomDataBits(codec.k());
        const Bytes word = codec.encodeCodeword(data);
        CHECK_EQ(word.size(), bytesForBits(255));

        // Systematic: the first k bits are the message.
        for (int i = 0; i < codec.k(); ++i)
            CHECK(getBit(word, static_cast<size_t>(i)) == getBit(data, static_cast<size_t>(i)));

        // And the result is a genuine codeword (all syndromes zero).
        CHECK(codec.isCodeword(word));
    }

    // Wrong-size input is rejected rather than silently padded.
    CHECK_THROWS(codec.encodeParity(Bytes(4, 0x00)));
}

void testZeroErrorRoundTrip() {
    const BchCodec codec(18);
    for (int trial = 0; trial < 10000; ++trial) {
        const Bytes word = codec.encodeCodeword(randomDataBits(codec.k()));
        Bytes corrected;
        int errors = -1;
        CHECK(codec.decodeCodeword(word, corrected, errors));
        CHECK_EQ(errors, 0);
        CHECK(corrected == word);
    }
}

void testCorrectsUpToT() {
    // For every weight 1..t, exactly recover the original codeword.
    const BchCodec codec(18);
    const int trialsPerWeight = 1000;
    int totalFailures = 0;

    for (int w = 1; w <= codec.t(); ++w) {
        int failures = 0;
        for (int trial = 0; trial < trialsPerWeight; ++trial) {
            const Bytes word = codec.encodeCodeword(randomDataBits(codec.k()));
            const Bytes received = injectErrors(word, codec.n(), w);

            Bytes corrected;
            int errors = -1;
            const bool ok = codec.decodeCodeword(received, corrected, errors);
            if (!ok || corrected != word || errors != w) ++failures;
        }
        if (failures != 0) {
            std::printf("  [FAIL] weight %d: %d/%d failures\n", w, failures, trialsPerWeight);
            totalFailures += failures;
        }
    }
    CHECK_MSG(totalFailures == 0,
              "decoder failed to correct some error patterns within t");
    std::printf("  [info] corrected all %d trials across weights 1..%d\n",
                trialsPerWeight * codec.t(), codec.t());
}

void testBeyondTNeverSilentlyLies() {
    // Past the correction radius the decoder may fail or may miscorrect to a
    // different codeword, but it must NEVER report success while returning
    // something that is not a codeword, and must never return the received word
    // unchanged while claiming success.
    const BchCodec codec(18);
    int reportedSuccess = 0;
    int notACodeword = 0;
    int returnedInputUnchanged = 0;
    int miscorrected = 0;
    const int trials = 3000;

    for (int trial = 0; trial < trials; ++trial) {
        const int w = codec.t() + 1 + static_cast<int>(rng() % 12);
        const Bytes word = codec.encodeCodeword(randomDataBits(codec.k()));
        const Bytes received = injectErrors(word, codec.n(), w);

        Bytes corrected;
        int errors = -1;
        if (codec.decodeCodeword(received, corrected, errors)) {
            ++reportedSuccess;
            if (!codec.isCodeword(corrected)) ++notACodeword;
            if (corrected == received) ++returnedInputUnchanged;
            if (corrected != word) ++miscorrected;
        }
    }

    CHECK_MSG(notACodeword == 0,
              "decoder reported success for a non-codeword result");
    CHECK_MSG(returnedInputUnchanged == 0,
              "decoder returned the uncorrected input while reporting success");
    std::printf("  [info] weight>t: %d/%d reported success, %d of those miscorrected "
                "to a different codeword (expected: rare but non-zero)\n",
                reportedSuccess, trials, miscorrected);
}

void testDecodeRejectsMalformedInput() {
    const BchCodec codec(18);
    Bytes corrected;
    int errors = 0;
    CHECK(!codec.decodeCodeword(Bytes(10, 0x00), corrected, errors));
    CHECK(!codec.decodeCodeword(Bytes{}, corrected, errors));
    CHECK_EQ(errors, -1);
}

void testAllZeroAndAllOnePatterns() {
    const BchCodec codec(18);

    // The all-zero word is a codeword.
    const Bytes zeroData(bytesForBits(static_cast<size_t>(codec.k())), 0);
    const Bytes zeroWord = codec.encodeCodeword(zeroData);
    CHECK(codec.isCodeword(zeroWord));
    CHECK_EQ(popcount(zeroWord), 0u);

    // Single-error correction on the all-zero codeword, at every position.
    int failures = 0;
    for (int pos = 0; pos < codec.n(); ++pos) {
        Bytes received = zeroWord;
        setBit(received, static_cast<size_t>(pos), true);
        Bytes corrected;
        int errors = -1;
        if (!codec.decodeCodeword(received, corrected, errors) || corrected != zeroWord ||
            errors != 1)
            ++failures;
    }
    CHECK_MSG(failures == 0, "single-bit correction failed at some position");
}

void testConstructionValidation() {
    CHECK_THROWS(BchCodec(0));
    CHECK_THROWS(BchCodec(-1));
    CHECK_THROWS(BchCodec(100));
}

} // namespace

int main() {
    testGeneratorParameters();
    testGeneratorDividesXnPlus1();
    testEncodeIsSystematicAndValid();
    testZeroErrorRoundTrip();
    testCorrectsUpToT();
    testBeyondTNeverSilentlyLies();
    testDecodeRejectsMalformedInput();
    testAllZeroAndAllOnePatterns();
    testConstructionValidation();
    return uavauth::test::summarise("bch");
}
