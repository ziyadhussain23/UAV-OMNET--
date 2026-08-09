#ifndef UAVAUTH_FE_BCHCODEC_H
#define UAVAUTH_FE_BCHCODEC_H

#include "core/Bytes.h"

#include <vector>

namespace uavauth {
namespace fe {

using core::Bytes;

/// Binary BCH code over GF(2^8), block length n = 255.
///
/// The generator polynomial is the product of the minimal polynomials of
/// alpha^1 .. alpha^2t, taken over the FULL conjugate closure of each root. A
/// previous implementation multiplied in only one representative per cyclotomic
/// coset and then hard-coded the parity length as m*t = 144; the true degree for
/// t = 18 is 124, so that version silently produced k = 111 < 128 and left the
/// tail of every response unprotected. This class computes deg(g) and asserts
/// the coefficients are binary at construction, so that class of error cannot
/// recur unnoticed.
///
/// Verified parameter sets (deg(g) confirmed by independent computation):
///     t = 18  ->  parity 124, k = 131
///     t = 22  ->  parity 155, k = 100
///     t = 25  ->  parity 171, k =  84
///
/// All bit vectors are packed MSB-first, matching core::getBit / core::setBit.
class BchCodec {
  public:
    explicit BchCodec(int t, int primitivePoly = 0x11D);

    int n() const { return n_; }
    int k() const { return k_; }
    int t() const { return t_; }
    int parityBits() const { return parityBits_; }

    /// Systematic encoding: returns the parityBits() parity bits for a k-bit
    /// message. Throws if `dataBits` is not exactly k bits' worth of bytes.
    Bytes encodeParity(const Bytes& dataBits) const;

    /// Full systematic codeword: k message bits followed by parityBits() parity
    /// bits, n bits total.
    Bytes encodeCodeword(const Bytes& dataBits) const;

    /// Decode an n-bit received word.
    ///
    /// Returns true only if the corrected word is a genuine codeword (all
    /// syndromes zero). On failure it returns false and does NOT write
    /// `correctedOut` -- returning the uncorrected input on failure is exactly
    /// the defect that made an earlier fuzzy extractor a no-op.
    bool decodeCodeword(const Bytes& receivedNBits, Bytes& correctedOut,
                        int& errorsCorrected) const;

    /// True if every syndrome of the given n-bit word is zero.
    bool isCodeword(const Bytes& wordNBits) const;

    /// Generator polynomial coefficients, lowest degree first, one entry per
    /// bit. Exposed for the structural tests.
    const std::vector<uint8_t>& generator() const { return generator_; }

  private:
    int gfMul(int a, int b) const;
    int gfInv(int a) const;
    int gfPow(int a, int e) const;
    std::vector<int> computeSyndromes(const Bytes& word) const;

    int t_;
    int n_ = 255;
    int k_ = 0;
    int parityBits_ = 0;
    int primPoly_;

    std::vector<int> expTable_;   // alpha^i, length 512 for wrap-free indexing
    std::vector<int> logTable_;   // log_alpha(x), length 256
    std::vector<uint8_t> generator_;
};

} // namespace fe
} // namespace uavauth

#endif
