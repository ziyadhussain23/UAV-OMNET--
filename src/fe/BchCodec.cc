#include "fe/BchCodec.h"

#include <set>
#include <stdexcept>
#include <string>

namespace uavauth {
namespace fe {

using core::getBit;
using core::setBit;

BchCodec::BchCodec(int t, int primitivePoly) : t_(t), primPoly_(primitivePoly) {
    if (t < 1 || t > 30) throw std::invalid_argument("BchCodec: t out of range");

    // GF(2^8) log/antilog tables.
    expTable_.assign(512, 0);
    logTable_.assign(256, 0);
    int x = 1;
    for (int i = 0; i < 255; ++i) {
        expTable_[static_cast<size_t>(i)] = x;
        logTable_[static_cast<size_t>(x)] = i;
        x <<= 1;
        if (x & 0x100) x ^= primPoly_;
    }
    for (int i = 255; i < 512; ++i) expTable_[static_cast<size_t>(i)] = expTable_[static_cast<size_t>(i - 255)];

    // Collect the conjugate closure of {alpha^1 .. alpha^2t}. Taking the closure
    // (rather than one representative per coset) is what makes the generator's
    // coefficients binary and its degree correct.
    std::set<int> roots;
    for (int i = 1; i <= 2 * t_; ++i) {
        int c = i % 255;
        while (roots.insert(c).second) c = (c * 2) % 255;
    }

    // g(x) = prod over roots r of (x - alpha^r), computed over GF(2^8).
    std::vector<int> g{1};
    for (int r : roots) {
        const int ar = expTable_[static_cast<size_t>(r)];
        std::vector<int> next(g.size() + 1, 0);
        for (size_t i = 0; i < g.size(); ++i) {
            next[i] ^= gfMul(g[i], ar);   // coefficient * alpha^r
            next[i + 1] ^= g[i];          // coefficient * x
        }
        g.swap(next);
    }

    // The product over a full conjugate closure must land back in GF(2).
    for (int coeff : g) {
        if (coeff != 0 && coeff != 1)
            throw std::runtime_error(
                "BchCodec: generator has non-binary coefficients (conjugate "
                "closure incomplete)");
    }

    parityBits_ = static_cast<int>(g.size()) - 1;
    k_ = n_ - parityBits_;
    if (k_ <= 0)
        throw std::runtime_error("BchCodec: t too large for n=255 (k would be <= 0)");

    generator_.assign(g.size(), 0);
    for (size_t i = 0; i < g.size(); ++i)
        generator_[i] = static_cast<uint8_t>(g[i] & 1);
}

int BchCodec::gfMul(int a, int b) const {
    if (a == 0 || b == 0) return 0;
    return expTable_[static_cast<size_t>(logTable_[static_cast<size_t>(a)] +
                                         logTable_[static_cast<size_t>(b)])];
}

int BchCodec::gfInv(int a) const {
    if (a == 0) throw std::invalid_argument("BchCodec: inverse of zero");
    return expTable_[static_cast<size_t>(255 - logTable_[static_cast<size_t>(a)]) % 255];
}

int BchCodec::gfPow(int a, int e) const {
    if (a == 0) return 0;
    int ex = (logTable_[static_cast<size_t>(a)] * e) % 255;
    if (ex < 0) ex += 255;
    return expTable_[static_cast<size_t>(ex)];
}

Bytes BchCodec::encodeParity(const Bytes& dataBits) const {
    const size_t needed = core::bytesForBits(static_cast<size_t>(k_));
    if (dataBits.size() != needed)
        throw std::invalid_argument("BchCodec::encodeParity: expected " +
                                    std::to_string(needed) + " bytes for k=" +
                                    std::to_string(k_) + " bits");

    // Systematic remainder: r(x) = m(x) * x^(n-k) mod g(x), computed with an
    // LFSR. Index convention throughout: remainder[j] and generator_[j] are both
    // the coefficient of x^j, so the two arrays cannot drift apart.
    const size_t degG = static_cast<size_t>(parityBits_);
    std::vector<uint8_t> remainder(degG, 0);

    for (int i = 0; i < k_; ++i) {   // message bits, highest degree first
        const uint8_t bit = getBit(dataBits, static_cast<size_t>(i)) ? 1u : 0u;
        const uint8_t feedback = static_cast<uint8_t>(bit ^ remainder[degG - 1]);

        // Multiply the register by x.
        for (size_t j = degG - 1; j > 0; --j) remainder[j] = remainder[j - 1];
        remainder[0] = 0;

        // Reduce by g(x); its leading term is consumed by the feedback tap.
        if (feedback) {
            for (size_t j = 0; j < degG; ++j)
                remainder[j] = static_cast<uint8_t>(remainder[j] ^ generator_[j]);
        }
    }

    // Pack the parity. Codeword packed bit (k + p) holds degree
    // n-1-(k+p) = degG-1-p, so parity bit p is remainder[degG-1-p].
    Bytes parity(core::bytesForBits(degG), 0);
    for (size_t p = 0; p < degG; ++p)
        setBit(parity, p, remainder[degG - 1 - p] != 0);
    return parity;
}

Bytes BchCodec::encodeCodeword(const Bytes& dataBits) const {
    const Bytes parity = encodeParity(dataBits);
    Bytes word(core::bytesForBits(static_cast<size_t>(n_)), 0);
    for (int i = 0; i < k_; ++i)
        setBit(word, static_cast<size_t>(i), getBit(dataBits, static_cast<size_t>(i)));
    for (int i = 0; i < parityBits_; ++i)
        setBit(word, static_cast<size_t>(k_ + i), getBit(parity, static_cast<size_t>(i)));
    return word;
}

std::vector<int> BchCodec::computeSyndromes(const Bytes& word) const {
    // S_j = sum_i c_i * (alpha^j)^i, with bit i of the packed word being the
    // coefficient of x^(n-1-i).
    std::vector<int> syn(static_cast<size_t>(2 * t_), 0);
    for (int j = 1; j <= 2 * t_; ++j) {
        int acc = 0;
        for (int i = 0; i < n_; ++i) {
            if (getBit(word, static_cast<size_t>(i))) {
                const int power = (n_ - 1 - i);
                acc ^= gfPow(expTable_[static_cast<size_t>(j % 255)], power);
            }
        }
        syn[static_cast<size_t>(j - 1)] = acc;
    }
    return syn;
}

bool BchCodec::isCodeword(const Bytes& wordNBits) const {
    const std::vector<int> syn = computeSyndromes(wordNBits);
    for (int s : syn)
        if (s != 0) return false;
    return true;
}

bool BchCodec::decodeCodeword(const Bytes& receivedNBits, Bytes& correctedOut,
                              int& errorsCorrected) const {
    errorsCorrected = -1;
    const size_t needed = core::bytesForBits(static_cast<size_t>(n_));
    if (receivedNBits.size() != needed) return false;

    const std::vector<int> syn = computeSyndromes(receivedNBits);

    bool allZero = true;
    for (int s : syn)
        if (s != 0) { allZero = false; break; }
    if (allZero) {
        correctedOut = receivedNBits;
        errorsCorrected = 0;
        return true;
    }

    // Berlekamp-Massey over GF(2^8).
    std::vector<int> lambda{1};
    std::vector<int> prev{1};
    int L = 0;
    int m = 1;
    int b = 1;

    for (int r = 0; r < 2 * t_; ++r) {
        int delta = syn[static_cast<size_t>(r)];
        for (int i = 1; i <= L && i < static_cast<int>(lambda.size()); ++i) {
            if (r - i >= 0)
                delta ^= gfMul(lambda[static_cast<size_t>(i)], syn[static_cast<size_t>(r - i)]);
        }

        if (delta == 0) {
            ++m;
        } else if (2 * L <= r) {
            const std::vector<int> temp = lambda;
            const int coeff = gfMul(delta, gfInv(b));
            if (lambda.size() < prev.size() + static_cast<size_t>(m))
                lambda.resize(prev.size() + static_cast<size_t>(m), 0);
            for (size_t i = 0; i < prev.size(); ++i)
                lambda[i + static_cast<size_t>(m)] ^= gfMul(coeff, prev[i]);
            L = r + 1 - L;
            prev = temp;
            b = delta;
            m = 1;
        } else {
            const int coeff = gfMul(delta, gfInv(b));
            if (lambda.size() < prev.size() + static_cast<size_t>(m))
                lambda.resize(prev.size() + static_cast<size_t>(m), 0);
            for (size_t i = 0; i < prev.size(); ++i)
                lambda[i + static_cast<size_t>(m)] ^= gfMul(coeff, prev[i]);
            ++m;
        }
    }

    if (L > t_) return false;   // more errors than the code can correct

    // Chien search: root alpha^-i of lambda means position i is in error.
    std::vector<int> errorPositions;
    for (int i = 0; i < n_; ++i) {
        // Evaluate lambda at alpha^(-i).
        int sum = 0;
        for (size_t j = 0; j < lambda.size(); ++j) {
            if (lambda[j] == 0) continue;
            int exponent = (-static_cast<int>(j) * i) % 255;
            if (exponent < 0) exponent += 255;
            sum ^= gfMul(lambda[j], expTable_[static_cast<size_t>(exponent)]);
        }
        if (sum == 0) {
            // Position i corresponds to the coefficient of x^i, i.e. packed bit
            // (n-1-i).
            const int bitIndex = n_ - 1 - i;
            if (bitIndex < 0 || bitIndex >= n_) return false;
            errorPositions.push_back(bitIndex);
        }
    }

    if (errorPositions.empty() || static_cast<int>(errorPositions.size()) != L)
        return false;   // lambda did not split into distinct roots: uncorrectable

    Bytes corrected = receivedNBits;
    for (int pos : errorPositions)
        setBit(corrected, static_cast<size_t>(pos), !getBit(corrected, static_cast<size_t>(pos)));

    // Final verification. Without this a miscorrection would be reported as
    // success, which is precisely how a broken decoder hides.
    if (!isCodeword(corrected)) return false;

    correctedOut = corrected;
    errorsCorrected = static_cast<int>(errorPositions.size());
    return true;
}

} // namespace fe
} // namespace uavauth
