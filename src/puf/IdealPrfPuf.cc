#include "puf/IdealPrfPuf.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

#include <algorithm>
#include <stdexcept>

namespace uavauth {
namespace puf {

using core::bytesForBits;
using core::fromString;
using core::setBit;
using crypto::OsslCommon;
using crypto::Primitive;
using crypto::ScopedTimer;

namespace {

/// Domain separator, so a device seed reused elsewhere in the simulation cannot
/// produce a colliding PUF key.
const char* kKeyLabel = "uavauth/v1/puf/ideal-prf-key";

Bytes sha3_256(const Bytes& input) {
    static thread_local detail::MdCtxHolder holder;
    EVP_MD_CTX* ctx = holder.ctx;
    if (ctx == nullptr) crypto::throwOsslError("IdealPrfPuf: EVP_MD_CTX_new");
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    const bool ok =
        EVP_DigestInit_ex(ctx, OsslCommon::instance().sha3_256(), nullptr) == 1 &&
        (input.empty() || EVP_DigestUpdate(ctx, input.data(), input.size()) == 1) &&
        EVP_DigestFinal_ex(ctx, out, &outLen) == 1;
    if (!ok) crypto::throwOsslError("IdealPrfPuf: SHA3-256");
    return Bytes(out, out + outLen);
}

} // namespace

IdealPrfPuf::IdealPrfPuf(const Bytes& deviceSeed) {
    Bytes input = fromString(kKeyLabel);
    input.insert(input.end(), deviceSeed.begin(), deviceSeed.end());
    deviceKey_ = sha3_256(input);

    macCtx_ = EVP_MAC_CTX_new(OsslCommon::instance().hmac());
    if (macCtx_ == nullptr) crypto::throwOsslError("IdealPrfPuf: EVP_MAC_CTX_new");

    char digest[] = "SHA3-256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
    params[1] = OSSL_PARAM_construct_end();

    // Key once. Subsequent calls re-initialise with a NULL key, which OpenSSL
    // documents as "reuse the key already set" -- that skips the HMAC key
    // schedule, which would otherwise be half the cost of a one-bit evaluation.
    if (EVP_MAC_init(macCtx_, deviceKey_.data(), deviceKey_.size(), params) != 1)
        crypto::throwOsslError("IdealPrfPuf: EVP_MAC_init");
}

IdealPrfPuf::~IdealPrfPuf() {
    if (macCtx_ != nullptr) EVP_MAC_CTX_free(macCtx_);
}

void IdealPrfPuf::setNoiseBer(double ber) {
    ber_ = std::min(1.0, std::max(0.0, ber));
}

bool IdealPrfPuf::prfBit(const Bytes& subChallenge) const {
    if (EVP_MAC_init(macCtx_, nullptr, 0, nullptr) != 1)
        crypto::throwOsslError("IdealPrfPuf: EVP_MAC_init (reuse)");
    unsigned char tag[EVP_MAX_MD_SIZE];
    size_t tagLen = 0;
    const bool ok =
        EVP_MAC_update(macCtx_, subChallenge.data(), subChallenge.size()) == 1 &&
        EVP_MAC_final(macCtx_, tag, &tagLen, sizeof(tag)) == 1;
    if (!ok) crypto::throwOsslError("IdealPrfPuf: HMAC-SHA3-256");
    if (tagLen == 0) throw std::runtime_error("IdealPrfPuf: empty MAC tag");
    return (tag[0] & 0x80u) != 0;   // MSB-first, matching core::getBit
}

Bytes IdealPrfPuf::evaluateIdeal(const Bytes& challenge, size_t bitCount) const {
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out(bytesForBits(bitCount), 0);
    for (size_t j = 0; j < bitCount; ++j) {
        const Bytes sub = deriveSubChallenge(challenge, static_cast<uint16_t>(j));
        setBit(out, j, prfBit(sub));
    }
    return out;
}

Bytes IdealPrfPuf::evaluateNoisy(const Bytes& challenge, size_t bitCount,
                                 crypto::Drbg& rng) const {
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out(bytesForBits(bitCount), 0);
    for (size_t j = 0; j < bitCount; ++j) {
        const Bytes sub = deriveSubChallenge(challenge, static_cast<uint16_t>(j));
        const bool ideal = prfBit(sub);
        // One draw per bit whatever ber_ is, so the DRBG stream position after
        // an evaluation does not depend on the noise configuration.
        const bool flip = rng.uniformDouble() < ber_;
        setBit(out, j, ideal != flip);
    }
    return out;
}

double IdealPrfPuf::measureBer(const Bytes& challenge, size_t bitCount,
                               crypto::Drbg& rng, int trials) const {
    if (bitCount == 0 || trials <= 0) return 0.0;
    const Bytes ideal = evaluateIdeal(challenge, bitCount);
    size_t flips = 0;
    for (int t = 0; t < trials; ++t)
        flips += core::hammingDistance(ideal, evaluateNoisy(challenge, bitCount, rng));
    return static_cast<double>(flips) /
           (static_cast<double>(trials) * static_cast<double>(bitCount));
}

} // namespace puf
} // namespace uavauth
