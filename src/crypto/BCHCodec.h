#ifndef UAVAUTH_CRYPTO_BCHCODEC_H
#define UAVAUTH_CRYPTO_BCHCODEC_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace uavauth {
namespace crypto {

/**
 * Software BCH error correction codec.
 * Implements BCH(255, k, t) where t is the error correction capability.
 * Used for fuzzy extractor to correct PUF response noise.
 *
 * Default: BCH(255, 131, 18) - correct up to 18 bit errors in 16-byte (128-bit) data
 * This matches the Python bchlib.BCH(18, 8219) configuration.
 */
class BCHCodec {
  private:
    int m;              // GF(2^m) field order (m=8 for BCH-255)
    int n;              // Codeword length (2^m - 1 = 255)
    int k;              // Data length in bits
    int t;              // Error correction capability
    int eccBits;        // ECC bits = n - k
    int eccBytes;       // ECC bytes
    int dataBytes;      // Data bytes

    // Galois field tables
    std::vector<int> alphaTo;   // Power -> polynomial
    std::vector<int> indexOf;   // Polynomial -> power
    std::vector<int> genPoly;   // Generator polynomial coefficients

    int lastErrorCount;

    // Initialize GF(2^m) tables
    void initGaloisField(int primitivePolynomial);

    // Generate BCH generator polynomial for t errors
    void generateBCHPoly();

    // GF arithmetic
    int gfMul(int a, int b) const;
    int gfPow(int a, int power) const;
    int gfInv(int a) const;

    // Syndrome calculation
    std::vector<int> computeSyndromes(const std::vector<int>& codeword) const;

    // Berlekamp-Massey algorithm for error locator polynomial
    std::vector<int> berlekampMassey(const std::vector<int>& syndromes) const;

    // Chien search for error locations
    std::vector<int> chienSearch(const std::vector<int>& errorLocator) const;

  public:
    /**
     * Create BCH codec.
     * @param t Error correction capability (number of bit errors to correct)
     * @param primitivePolynomial GF(2^8) primitive polynomial (default: 0x11d = x^8+x^4+x^3+x^2+1)
     */
    explicit BCHCodec(int errorCorrection = 18, int primitivePolynomial = 0x11d);

    // Legacy constructor for compatibility
    BCHCodec(size_t blockLengthBits, size_t dataLengthBits, size_t minDistanceBits);

    ~BCHCodec() = default;

    /**
     * Encode data and return ECC parity bytes.
     * @param data Input data (up to k/8 bytes)
     * @return ECC parity bytes
     */
    std::vector<uint8_t> encode(const std::vector<uint8_t>& data);

    /**
     * Decode and correct errors in received data.
     * @param received Noisy received data
     * @param ecc ECC parity bytes from enrollment
     * @return Corrected data
     */
    std::vector<uint8_t> decode(const std::vector<uint8_t>& received,
                                const std::vector<uint8_t>& ecc);

    /**
     * Get number of errors corrected in last decode operation.
     * Returns -1 if decoding failed (too many errors).
     */
    int getErrorCount() const { return lastErrorCount; }

    /**
     * Get ECC size in bytes.
     */
    int getEccBytes() const { return eccBytes; }
};

} // namespace crypto
} // namespace uavauth

#endif
