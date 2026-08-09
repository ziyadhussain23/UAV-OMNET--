#include "fe/FuzzyExtractor.h"

#include "core/Encoding.h"
#include "crypto/PrimitiveCounters.h"

#include <cmath>
#include <stdexcept>

namespace uavauth {
namespace fe {

using core::append;
using core::bytesForBits;
using core::getBit;
using core::setBit;
using crypto::monotonicNs;

FeParams FeParams::profile(const std::string& name) {
    FeParams p;
    p.profileName = name;
    if (name == "bch255-131-18") {
        p.bchT = 18;
        p.numBlocks = 4;
        p.repFactor = 1;
    } else if (name == "bch255-91-25") {
        p.bchT = 25;
        p.numBlocks = 5;
        p.repFactor = 1;
        // Parity is 164 bits here, so each block contributes
        // 0.95*255 - 164 = 78.25 bits; five blocks give 391 >= 384.
    } else if (name == "rep3-bch255-131-18") {
        p.bchT = 18;
        p.numBlocks = 5;
        p.repFactor = 3;
    } else {
        throw std::invalid_argument("FeParams::profile: unknown profile '" + name + "'");
    }
    return p;
}

size_t HelperData::leakBits() const {
    // Each sketch discloses at most n-k bits. With a repetition inner code the
    // majority-vote structure leaks the within-group parities as well, which is
    // accounted for as (repFactor-1) bits per outer bit.
    const BchCodec probe(params.bchT);
    const size_t outerLeak =
        static_cast<size_t>(params.numBlocks) * static_cast<size_t>(probe.parityBits());
    const size_t innerLeak = static_cast<size_t>(params.numBlocks) *
                             static_cast<size_t>(params.blockBits) *
                             static_cast<size_t>(params.repFactor - 1);
    return outerLeak + innerLeak;
}

FuzzyExtractor::FuzzyExtractor(const FeParams& params, const crypto::CryptoSuite& suite)
    : params_(params), suite_(suite) {
    if (params_.repFactor != 1 && params_.repFactor != 3)
        throw std::invalid_argument("FuzzyExtractor: repFactor must be 1 or 3");
    if (params_.numBlocks < 1)
        throw std::invalid_argument("FuzzyExtractor: numBlocks must be >= 1");
    if (params_.seedBytes < 16)
        throw std::invalid_argument("FuzzyExtractor: seed must be at least 16 bytes");

    codec_ = std::make_unique<BchCodec>(params_.bchT);
    if (codec_->n() != params_.blockBits)
        throw std::invalid_argument("FuzzyExtractor: blockBits must equal the BCH block length");

    if (params_.checkBudget && residualEntropyBits() < requiredEntropyBits()) {
        throw std::runtime_error(
            "FuzzyExtractor: entropy budget not met -- residual " +
            std::to_string(residualEntropyBits()) + " bits < required " +
            std::to_string(requiredEntropyBits()) +
            " bits; increase numBlocks or the measured min-entropy rate");
    }
}

double FuzzyExtractor::residualEntropyBits() const {
    // Only the outer sketch leak is subtracted here. The repetition inner code
    // consumes extra PUF bits rather than extra entropy from the outer word.
    const double perBlock = params_.assumedMinEntropyRate *
                                static_cast<double>(params_.blockBits) -
                            static_cast<double>(codec_->parityBits());
    return static_cast<double>(params_.numBlocks) * perBlock;
}

double FuzzyExtractor::requiredEntropyBits() const {
    return static_cast<double>(params_.keyBits) + 2.0 * static_cast<double>(params_.epsLog2);
}

size_t FuzzyExtractor::requiredPufBits() const {
    return static_cast<size_t>(params_.numBlocks) * static_cast<size_t>(params_.blockBits) *
           static_cast<size_t>(params_.repFactor);
}

Bytes FuzzyExtractor::extractBlock(const Bytes& all, int index, int bits) const {
    Bytes out(bytesForBits(static_cast<size_t>(bits)), 0);
    const size_t base = static_cast<size_t>(index) * static_cast<size_t>(bits);
    for (int i = 0; i < bits; ++i)
        setBit(out, static_cast<size_t>(i), getBit(all, base + static_cast<size_t>(i)));
    return out;
}

namespace {

/// Majority vote over groups of `rep` consecutive bits.
Bytes repetitionDecode(const Bytes& expanded, int outerBits, int rep) {
    Bytes out(bytesForBits(static_cast<size_t>(outerBits)), 0);
    for (int i = 0; i < outerBits; ++i) {
        int ones = 0;
        for (int r = 0; r < rep; ++r)
            if (getBit(expanded, static_cast<size_t>(i * rep + r))) ++ones;
        setBit(out, static_cast<size_t>(i), ones * 2 > rep);
    }
    return out;
}

} // namespace

GenResult FuzzyExtractor::gen(const Bytes& responseBits, const Bytes& seed) const {
    GenResult result;
    const int64_t t0 = monotonicNs();

    if (seed.size() != static_cast<size_t>(params_.seedBytes))
        throw std::invalid_argument("FuzzyExtractor::gen: wrong seed length");
    if (responseBits.size() != bytesForBits(requiredPufBits()))
        throw std::invalid_argument("FuzzyExtractor::gen: wrong response length");

    result.helper.seed = seed;
    result.helper.params = params_;
    result.stats.blocksTotal = params_.numBlocks;

    // Collapse the repetition inner code first, if configured.
    const int outerBitsTotal = params_.numBlocks * params_.blockBits;
    const Bytes outer = (params_.repFactor == 1)
                            ? responseBits
                            : repetitionDecode(responseBits, outerBitsTotal, params_.repFactor);

    Bytes recovered;
    recovered.reserve(bytesForBits(static_cast<size_t>(outerBitsTotal)));

    for (int b = 0; b < params_.numBlocks; ++b) {
        const Bytes block = extractBlock(outer, b, params_.blockBits);

        // The random codeword is derived deterministically from the seed and the
        // block index, so enrollment is reproducible for a given (response, seed).
        const Bytes rBits = suite_.kdf(seed, Bytes{}, "uavauth/v1/fe-codeword",
                                       core::u16be(static_cast<uint16_t>(b)),
                                       bytesForBits(static_cast<size_t>(codec_->k())));
        // Zero the padding bits beyond k so encodeCodeword sees a clean message.
        Bytes data = rBits;
        for (int i = codec_->k(); i < static_cast<int>(data.size() * 8); ++i)
            setBit(data, static_cast<size_t>(i), false);

        const int64_t tb = monotonicNs();
        const Bytes codeword = codec_->encodeCodeword(data);
        result.stats.bchMs += static_cast<double>(monotonicNs() - tb) / 1.0e6;

        result.helper.sketch.push_back(core::xorBytes(block, codeword));
        append(recovered, block);
    }

    const int64_t te = monotonicNs();
    Bytes key = suite_.extract(seed, recovered);
    result.stats.extractMs = static_cast<double>(monotonicNs() - te) / 1.0e6;

    const size_t keyBytes = static_cast<size_t>(params_.keyBits) / 8;
    if (key.size() < keyBytes)
        key = suite_.kdf(key, seed, crypto::label::kFeRoot, Bytes{}, keyBytes);
    key.resize(keyBytes);

    result.mk = key;
    result.ok = true;
    result.stats.totalMs = static_cast<double>(monotonicNs() - t0) / 1.0e6;
    return result;
}

RepResult FuzzyExtractor::rep(const Bytes& noisyResponseBits,
                              const HelperData& helper) const {
    RepResult result;
    const int64_t t0 = monotonicNs();
    result.stats.blocksTotal = params_.numBlocks;

    if (noisyResponseBits.size() != bytesForBits(requiredPufBits()) ||
        helper.sketch.size() != static_cast<size_t>(params_.numBlocks) ||
        helper.seed.size() != static_cast<size_t>(params_.seedBytes)) {
        result.ok = false;
        result.stats.totalMs = static_cast<double>(monotonicNs() - t0) / 1.0e6;
        return result;
    }

    const int outerBitsTotal = params_.numBlocks * params_.blockBits;
    const Bytes outer =
        (params_.repFactor == 1)
            ? noisyResponseBits
            : repetitionDecode(noisyResponseBits, outerBitsTotal, params_.repFactor);

    Bytes recovered;
    bool allOk = true;

    for (int b = 0; b < params_.numBlocks; ++b) {
        const Bytes block = extractBlock(outer, b, params_.blockBits);
        const Bytes& sketch = helper.sketch[static_cast<size_t>(b)];
        if (sketch.size() != block.size()) { allOk = false; break; }

        // w = R' XOR s = c XOR e: the noise now sits on a codeword.
        const Bytes noisyCodeword = core::xorBytes(block, sketch);

        Bytes corrected;
        int errors = -1;
        const int64_t tb = monotonicNs();
        const bool ok = codec_->decodeCodeword(noisyCodeword, corrected, errors);
        result.stats.bchMs += static_cast<double>(monotonicNs() - tb) / 1.0e6;

        if (!ok) {
            ++result.stats.blocksFailed;
            allOk = false;
            continue;   // keep counting failures for the diagnostics
        }
        result.stats.errorsCorrectedTotal += errors;
        if (errors > result.stats.errorsPerBlockMax) result.stats.errorsPerBlockMax = errors;

        // Recover the enrolled response block: R = s XOR c.
        append(recovered, core::xorBytes(sketch, corrected));
    }

    if (!allOk) {
        // Fail closed. A partially recovered response must never be turned into
        // a key, and the caller must not receive anything it could mistake for one.
        result.ok = false;
        result.mk.clear();
        result.stats.totalMs = static_cast<double>(monotonicNs() - t0) / 1.0e6;
        return result;
    }

    const int64_t te = monotonicNs();
    Bytes key = suite_.extract(helper.seed, recovered);
    result.stats.extractMs = static_cast<double>(monotonicNs() - te) / 1.0e6;

    const size_t keyBytes = static_cast<size_t>(params_.keyBits) / 8;
    if (key.size() < keyBytes)
        key = suite_.kdf(key, helper.seed, crypto::label::kFeRoot, Bytes{}, keyBytes);
    key.resize(keyBytes);

    result.mk = key;
    result.ok = true;
    result.stats.totalMs = static_cast<double>(monotonicNs() - t0) / 1.0e6;
    return result;
}

} // namespace fe
} // namespace uavauth
