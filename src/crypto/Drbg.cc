#include "crypto/Drbg.h"

#include "crypto/OsslCommon.h"

#include <openssl/evp.h>

#include <cmath>
#include <stdexcept>

namespace uavauth {
namespace crypto {

namespace {

Bytes sha3_256(const Bytes& input) {
    const OsslCommon& ossl = OsslCommon::instance();
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throwOsslError("Drbg: EVP_MD_CTX_new");

    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    const bool ok = EVP_DigestInit_ex(ctx, ossl.sha3_256(), nullptr) == 1 &&
                    (input.empty() ||
                     EVP_DigestUpdate(ctx, input.data(), input.size()) == 1) &&
                    EVP_DigestFinal_ex(ctx, out, &outLen) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throwOsslError("Drbg: SHA3-256");
    return Bytes(out, out + outLen);
}

} // namespace

Drbg::Drbg(const Bytes& seed) { reseed(seed); }

void Drbg::reseed(const Bytes& seed) {
    key_ = sha3_256(seed);
    buffer_.clear();
    offset_ = 0;
    counter_ = 0;
    drawn_ = 0;
    haveSpareNormal_ = false;
    spareNormal_ = 0.0;
}

void Drbg::refill() {
    // block_i = SHA3-256(key || counter_i)
    Bytes input = key_;
    for (int shift = 56; shift >= 0; shift -= 8)
        input.push_back(static_cast<uint8_t>((counter_ >> shift) & 0xFF));
    buffer_ = sha3_256(input);
    offset_ = 0;
    ++counter_;
}

Bytes Drbg::bytes(size_t n) {
    Bytes out;
    out.reserve(n);
    while (out.size() < n) {
        if (offset_ >= buffer_.size()) refill();
        const size_t take = std::min(n - out.size(), buffer_.size() - offset_);
        out.insert(out.end(), buffer_.begin() + static_cast<long>(offset_),
                   buffer_.begin() + static_cast<long>(offset_ + take));
        offset_ += take;
    }
    drawn_ += n;
    return out;
}

uint32_t Drbg::uniform(uint32_t bound) {
    if (bound == 0) return 0;

    // Rejection sampling: discard the tail of the 32-bit range that would make
    // the modulo non-uniform.
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % bound);
    for (;;) {
        const Bytes b = bytes(4);
        const uint32_t v = (static_cast<uint32_t>(b[0]) << 24) |
                           (static_cast<uint32_t>(b[1]) << 16) |
                           (static_cast<uint32_t>(b[2]) << 8) |
                           static_cast<uint32_t>(b[3]);
        if (v < limit) return v % bound;
    }
}

double Drbg::uniformDouble() {
    // 53 significant bits, matching the double mantissa.
    const Bytes b = bytes(8);
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | b[static_cast<size_t>(i)];
    return static_cast<double>(v >> 11) * (1.0 / 9007199254740992.0);
}

double Drbg::normal() {
    if (haveSpareNormal_) {
        haveSpareNormal_ = false;
        return spareNormal_;
    }
    // Box-Muller. u1 is bounded away from zero so log() stays finite.
    double u1 = uniformDouble();
    if (u1 < 1e-300) u1 = 1e-300;
    const double u2 = uniformDouble();
    const double r = std::sqrt(-2.0 * std::log(u1));
    const double theta = 2.0 * M_PI * u2;
    spareNormal_ = r * std::sin(theta);
    haveSpareNormal_ = true;
    return r * std::cos(theta);
}

} // namespace crypto
} // namespace uavauth
