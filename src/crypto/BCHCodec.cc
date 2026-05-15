#include "BCHCodec.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace uavauth {
namespace crypto {

BCHCodec::BCHCodec(int errorCorrection, int primitivePolynomial)
    : m(8),
      n(255),
      t(errorCorrection),
      lastErrorCount(0) {

    // For BCH(255, k, t), k = 255 - m*t approximately
    // With t=18 and m=8, eccBits = 18*8 = 144, so k = 255 - 144 = 111 approximately
    // We use 128 bits (16 bytes) of data which fits within this
    eccBits = m * t;
    eccBytes = (eccBits + 7) / 8;
    k = n - eccBits;
    dataBytes = 16;  // 128 bits for PUF response

    initGaloisField(primitivePolynomial);
    generateBCHPoly();
}

BCHCodec::BCHCodec(size_t blockLengthBits, size_t dataLengthBits, size_t minDistanceBits)
    : BCHCodec(static_cast<int>(minDistanceBits), 0x11d) {
    // Legacy constructor - convert parameters
    (void)blockLengthBits;
    (void)dataLengthBits;
}

void BCHCodec::initGaloisField(int primitivePolynomial) {
    const int fieldSize = 1 << m;  // 256 for m=8

    alphaTo.resize(fieldSize);
    indexOf.resize(fieldSize);

    // Initialize tables
    int mask = 1;
    alphaTo[m] = 0;

    for (int i = 0; i < m; ++i) {
        alphaTo[i] = mask;
        indexOf[alphaTo[i]] = i;
        if ((primitivePolynomial >> i) & 1) {
            alphaTo[m] ^= mask;
        }
        mask <<= 1;
    }

    indexOf[alphaTo[m]] = m;
    mask >>= 1;

    for (int i = m + 1; i < n; ++i) {
        if (alphaTo[i - 1] >= mask) {
            alphaTo[i] = alphaTo[m] ^ ((alphaTo[i - 1] ^ mask) << 1);
        } else {
            alphaTo[i] = alphaTo[i - 1] << 1;
        }
        indexOf[alphaTo[i]] = i;
    }

    indexOf[0] = -1;  // log(0) is undefined
}

void BCHCodec::generateBCHPoly() {
    // Generate BCH generator polynomial g(x) as LCM of minimal polynomials
    // For t-error correcting BCH, g(x) has roots alpha^1, alpha^3, ..., alpha^(2t-1)

    std::vector<int> zeros(2 * t + 1, 0);
    std::vector<bool> used(n + 1, false);

    // Find all zeros (conjugate classes)
    int numZeros = 0;
    for (int i = 1; i <= 2 * t; ++i) {
        if (!used[i]) {
            zeros[numZeros++] = i;
            // Mark conjugates
            int coset = i;
            do {
                used[coset] = true;
                coset = (coset * 2) % n;
            } while (coset != i);
        }
    }

    // Build generator polynomial
    genPoly.assign(1, 1);  // Start with g(x) = 1

    for (int i = 0; i < numZeros; ++i) {
        // Multiply by (x - alpha^zeros[i])
        std::vector<int> factor = {1, alphaTo[zeros[i]]};

        std::vector<int> newPoly(genPoly.size() + 1, 0);
        for (size_t j = 0; j < genPoly.size(); ++j) {
            for (size_t k = 0; k < factor.size(); ++k) {
                newPoly[j + k] ^= gfMul(genPoly[j], factor[k]);
            }
        }
        genPoly = std::move(newPoly);
    }
}

int BCHCodec::gfMul(int a, int b) const {
    if (a == 0 || b == 0) return 0;
    int logA = indexOf[a];
    int logB = indexOf[b];
    return alphaTo[(logA + logB) % n];
}

int BCHCodec::gfPow(int a, int power) const {
    if (a == 0) return 0;
    int logA = indexOf[a];
    return alphaTo[(logA * power) % n];
}

int BCHCodec::gfInv(int a) const {
    if (a == 0) throw std::invalid_argument("Cannot invert 0 in GF");
    return alphaTo[(n - indexOf[a]) % n];
}

std::vector<uint8_t> BCHCodec::encode(const std::vector<uint8_t>& data) {
    // Convert data bytes to bit array
    std::vector<int> dataBits(n, 0);
    for (size_t i = 0; i < data.size() && i < static_cast<size_t>(dataBytes); ++i) {
        for (int b = 0; b < 8; ++b) {
            if (i * 8 + b < static_cast<size_t>(k)) {
                dataBits[i * 8 + b] = (data[i] >> (7 - b)) & 1;
            }
        }
    }

    // Shift data to make room for parity (systematic encoding)
    std::vector<int> shiftedData(n, 0);
    for (int i = 0; i < k; ++i) {
        shiftedData[i + eccBits] = dataBits[i];
    }

    // Divide by generator polynomial to get remainder (parity)
    std::vector<int> remainder = shiftedData;
    for (int i = n - 1; i >= eccBits; --i) {
        if (remainder[i]) {
            for (size_t j = 0; j < genPoly.size(); ++j) {
                remainder[i - j] ^= genPoly[genPoly.size() - 1 - j];
            }
        }
    }

    // Extract parity bits and convert to bytes
    std::vector<uint8_t> ecc(eccBytes, 0);
    for (int i = 0; i < eccBits && i < eccBytes * 8; ++i) {
        if (remainder[i]) {
            ecc[i / 8] |= (1 << (7 - (i % 8)));
        }
    }

    return ecc;
}

std::vector<int> BCHCodec::computeSyndromes(const std::vector<int>& codeword) const {
    std::vector<int> syndromes(2 * t + 1, 0);

    for (int i = 1; i <= 2 * t; ++i) {
        syndromes[i] = 0;
        for (int j = 0; j < n; ++j) {
            if (codeword[j]) {
                syndromes[i] ^= gfPow(alphaTo[j], i);
            }
        }
    }

    return syndromes;
}

std::vector<int> BCHCodec::berlekampMassey(const std::vector<int>& syndromes) const {
    std::vector<int> sigma(2 * t + 1, 0);  // Error locator polynomial
    std::vector<int> b(2 * t + 1, 0);      // Previous polynomial
    sigma[0] = 1;
    b[0] = 1;

    int L = 0;  // Current number of errors
    int m_bm = 1;  // Step since last update
    int b_coeff = 1;

    for (int r = 1; r <= 2 * t; ++r) {
        // Compute discrepancy
        int delta = syndromes[r];
        for (int i = 1; i <= L; ++i) {
            delta ^= gfMul(sigma[i], syndromes[r - i]);
        }

        if (delta == 0) {
            ++m_bm;
        } else {
            std::vector<int> tau(2 * t + 1, 0);

            // tau = sigma - delta * b_coeff^{-1} * x^m * b
            int factor = gfMul(delta, gfInv(b_coeff));
            for (int i = 0; i <= 2 * t - m_bm; ++i) {
                tau[i + m_bm] = gfMul(factor, b[i]);
            }
            for (int i = 0; i <= 2 * t; ++i) {
                tau[i] ^= sigma[i];
            }

            if (2 * L <= r - 1) {
                b = sigma;
                L = r - L;
                b_coeff = delta;
                m_bm = 1;
            } else {
                ++m_bm;
            }

            sigma = tau;
        }
    }

    // Trim polynomial
    sigma.resize(L + 1);
    return sigma;
}

std::vector<int> BCHCodec::chienSearch(const std::vector<int>& errorLocator) const {
    std::vector<int> errorPositions;

    for (int i = 0; i < n; ++i) {
        int sum = 0;
        for (size_t j = 0; j < errorLocator.size(); ++j) {
            sum ^= gfMul(errorLocator[j], gfPow(alphaTo[i], static_cast<int>(j)));
        }
        if (sum == 0) {
            // Found root alpha^i, error at position n - i
            int pos = (n - i) % n;
            errorPositions.push_back(pos);
        }
    }

    return errorPositions;
}

std::vector<uint8_t> BCHCodec::decode(const std::vector<uint8_t>& received,
                                       const std::vector<uint8_t>& ecc) {
    lastErrorCount = 0;

    // Reconstruct codeword from data + ecc
    std::vector<int> codeword(n, 0);

    // ECC bits first (systematic encoding places parity at start)
    for (size_t i = 0; i < ecc.size() && i < static_cast<size_t>(eccBytes); ++i) {
        for (int b = 0; b < 8; ++b) {
            if (i * 8 + b < static_cast<size_t>(eccBits)) {
                codeword[i * 8 + b] = (ecc[i] >> (7 - b)) & 1;
            }
        }
    }

    // Data bits
    for (size_t i = 0; i < received.size() && i < static_cast<size_t>(dataBytes); ++i) {
        for (int b = 0; b < 8; ++b) {
            int pos = eccBits + i * 8 + b;
            if (pos < n) {
                codeword[pos] = (received[i] >> (7 - b)) & 1;
            }
        }
    }

    // Compute syndromes
    std::vector<int> syndromes = computeSyndromes(codeword);

    // Check if all syndromes are zero (no errors)
    bool hasErrors = false;
    for (int i = 1; i <= 2 * t; ++i) {
        if (syndromes[i] != 0) {
            hasErrors = true;
            break;
        }
    }

    if (!hasErrors) {
        lastErrorCount = 0;
        return received;  // No errors to correct
    }

    // Find error locator polynomial using Berlekamp-Massey
    std::vector<int> errorLocator = berlekampMassey(syndromes);

    // Find error positions using Chien search
    std::vector<int> errorPositions = chienSearch(errorLocator);

    // Validate
    if (errorPositions.size() != errorLocator.size() - 1) {
        lastErrorCount = -1;  // Decoding failed
        return received;
    }

    // Correct errors
    for (int pos : errorPositions) {
        if (pos < n) {
            codeword[pos] ^= 1;
        }
    }

    lastErrorCount = static_cast<int>(errorPositions.size());

    // Extract corrected data
    std::vector<uint8_t> corrected(dataBytes, 0);
    for (int i = 0; i < dataBytes * 8 && eccBits + i < n; ++i) {
        if (codeword[eccBits + i]) {
            corrected[i / 8] |= (1 << (7 - (i % 8)));
        }
    }

    return corrected;
}

} // namespace crypto
} // namespace uavauth
