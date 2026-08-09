#ifndef UAVAUTH_FE_FUZZYEXTRACTOR_H
#define UAVAUTH_FE_FUZZYEXTRACTOR_H

#include "core/Bytes.h"
#include "crypto/CryptoSuite.h"
#include "fe/BchCodec.h"

#include <memory>
#include <string>
#include <vector>

namespace uavauth {
namespace fe {

using core::Bytes;

/// Parameters of the code-offset fuzzy extractor.
///
/// Entropy budget. A code-offset sketch is a bounded-leakage primitive: it
/// discloses at most n-k bits of the response. So the design constraint is
///
///     numBlocks * (rate*blockBits - (n-k))  >=  keyBits + 2*epsLog2
///
/// With blockBits = 255, t = 18 (parity 124) and a measured min-entropy rate of
/// 0.95, each block contributes 242.25 - 124 = 118.25 bits, so four blocks give
/// 473 >= 256 + 128. This inequality is enforced at construction, not merely
/// documented: an under-provisioned extractor yields a weak key silently.
///
/// Using 255-bit blocks rather than 128-bit ones is forced by the same
/// inequality -- a 128-bit block leaks 124 of its own bits and contributes
/// almost nothing.
struct FeParams {
    int blockBits = 255;                  // must equal the BCH block length n
    int bchT = 18;
    int numBlocks = 4;                    // L
    int repFactor = 1;                    // 1 = none, 3 = [3,1,3] inner code
    int keyBits = 256;                    // ell
    int epsLog2 = 64;                     // eps = 2^-epsLog2
    int seedBytes = 32;
    double assumedMinEntropyRate = 0.95;  // measured, not assumed away
    bool checkBudget = true;
    std::string profileName = "bch255-131-18";

    /// Named profiles.
    ///   "bch255-131-18"        paper parameters; FRR ~1.2e-3 at 3% BER
    ///   "bch255-91-25"         stronger outer code; FRR ~4e-7 at 3% BER
    ///   "rep3-bch255-131-18"   repetition inner code; FRR < 1e-15, 3x PUF cost
    static FeParams profile(const std::string& name);
};

/// Public helper data. Contains no secret: it may be stored on the device and
/// transmitted in the clear.
struct HelperData {
    std::vector<Bytes> sketch;   // one n-bit offset per block
    Bytes seed;                  // extractor salt
    FeParams params;

    size_t leakBits() const;
};

struct FeStats {
    int blocksTotal = 0;
    int blocksFailed = 0;
    int errorsCorrectedTotal = 0;
    int errorsPerBlockMax = 0;
    double bchMs = 0.0;
    double extractMs = 0.0;
    double totalMs = 0.0;
};

struct GenResult {
    HelperData helper;
    Bytes mk;
    bool ok = false;
    FeStats stats;
};

struct RepResult {
    Bytes mk;
    bool ok = false;
    FeStats stats;
};

/// Code-offset fuzzy extractor composed with the suite's strong extractor.
class FuzzyExtractor {
  public:
    FuzzyExtractor(const FeParams& params, const crypto::CryptoSuite& suite);

    /// Enrollment. `seed` must be seedBytes long and is published as part of the
    /// helper data; `gen` is deterministic given (response, seed).
    GenResult gen(const Bytes& responseBits, const Bytes& seed) const;

    /// Field reproduction. Deterministic and side-effect free: it consumes no
    /// randomness, so the same noisy response always gives the same answer.
    ///
    /// If ANY block fails to decode, the whole operation fails and `mk` is left
    /// empty. Returning a partially-recovered or uncorrected value would defeat
    /// the point of the extractor.
    RepResult rep(const Bytes& noisyResponseBits, const HelperData& helper) const;

    /// Total PUF bits the caller must supply: numBlocks * blockBits * repFactor.
    size_t requiredPufBits() const;

    /// Residual min-entropy implied by the configured rate, in bits.
    double residualEntropyBits() const;

    /// Budget requirement: keyBits + 2*epsLog2.
    double requiredEntropyBits() const;

    const FeParams& params() const { return params_; }
    const BchCodec& codec() const { return *codec_; }

  private:
    Bytes extractBlock(const Bytes& all, int index, int bits) const;

    FeParams params_;
    const crypto::CryptoSuite& suite_;
    std::unique_ptr<BchCodec> codec_;
};

} // namespace fe
} // namespace uavauth

#endif
