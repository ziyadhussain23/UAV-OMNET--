#include "puf/IdealPrfPuf.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>

namespace uavauth {
namespace puf {

using core::bytesForBits;
using core::fromString;
using crypto::OsslCommon;
using crypto::Primitive;
using crypto::ScopedTimer;

namespace {

/// Domain separator, so a device seed reused elsewhere in the simulation cannot
/// produce a colliding PUF key.
const char* kKeyLabel = "uavauth/v1/puf/ideal-prf-key";

/// Domain separator on the response stream, so it is a distinct function from
/// every other keyed use of the same device key.
const char* kRespLabel = "uavauth/v1/puf/ideal-prf-response";

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

/// One HMAC-SHA3-256 over a fixed framing, on a cached context. The context is
/// keyed once at first use and re-initialised per call with a NULL key, which
/// OpenSSL documents as "reuse the key already set": that skips the key schedule,
/// which would otherwise be most of the cost of a 32-byte output.
Bytes hmacKeyed(EVP_MAC_CTX* ctx, const Bytes& label, const Bytes& challenge,
                uint16_t counter) {
    unsigned char cbuf[2] = {static_cast<unsigned char>(counter >> 8),
                             static_cast<unsigned char>(counter & 0xFF)};
    unsigned char tag[EVP_MAX_MD_SIZE];
    size_t tagLen = 0;
    const bool ok =
        EVP_MAC_init(ctx, nullptr, 0, nullptr) == 1 &&
        EVP_MAC_update(ctx, label.data(), label.size()) == 1 &&
        (challenge.empty() || EVP_MAC_update(ctx, challenge.data(), challenge.size()) == 1) &&
        EVP_MAC_update(ctx, cbuf, sizeof(cbuf)) == 1 &&
        EVP_MAC_final(ctx, tag, &tagLen, sizeof(tag)) == 1;
    if (!ok) crypto::throwOsslError("IdealPrfPuf: HMAC-SHA3-256");
    return Bytes(tag, tag + tagLen);
}

/// The whole response as a counter-mode stream:
///   block_ctr = HMAC-SHA3-256(deviceKey, label || challenge || u16be(ctr)),
/// concatenated and truncated to `bits` bits. ceil(1020/256) = 4 calls cover a
/// full default response, which is where the earlier one-HMAC-per-bit loop used
/// to spend essentially all of its time.
Bytes responseStream(const Bytes& key, const Bytes& challenge, size_t bits) {
    // One context per thread, re-keyed only when the device key changes. The
    // re-keying path pays the HMAC key schedule once per device instead of once
    // per 32-byte block.
    static thread_local EVP_MAC_CTX* ctx = nullptr;
    static thread_local Bytes keyedFor;
    if (ctx == nullptr) {
        ctx = EVP_MAC_CTX_new(OsslCommon::instance().hmac());
        if (ctx == nullptr) crypto::throwOsslError("IdealPrfPuf: EVP_MAC_CTX_new");
    }
    if (keyedFor != key) {
        char digest[] = "SHA3-256";
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_MAC_init(ctx, key.data(), key.size(), params) != 1)
            crypto::throwOsslError("IdealPrfPuf: EVP_MAC_init");
        keyedFor = key;
    }

    const size_t outLen = bytesForBits(bits);
    Bytes out;
    out.reserve(outLen);
    const Bytes label = fromString(kRespLabel);
    for (uint16_t ctr = 0; out.size() < outLen; ++ctr) {
        Bytes block = hmacKeyed(ctx, label, challenge, ctr);
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(outLen);

    // Bits past `bits` in the final byte are never read, but zero them anyway
    // so two responses compare equal iff their used bits do.
    const size_t rem = bits & 7;
    if (rem != 0 && !out.empty())
        out.back() = static_cast<unsigned char>(out.back() & (0xFFu << (8 - rem)));
    return out;
}

} // namespace

IdealPrfPuf::IdealPrfPuf(const Bytes& deviceSeed) {
    Bytes input = fromString(kKeyLabel);
    input.insert(input.end(), deviceSeed.begin(), deviceSeed.end());
    deviceKey_ = sha3_256(input);
}

void IdealPrfPuf::setNoiseBer(double ber) {
    ber_ = std::min(1.0, std::max(0.0, ber));
}

Bytes IdealPrfPuf::evaluateIdeal(const Bytes& challenge, size_t bitCount) const {
    requireValidBitCount(bitCount);
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    return responseStream(deviceKey_, challenge, bitCount);
}

Bytes IdealPrfPuf::evaluateNoisy(const Bytes& challenge, size_t bitCount,
                                 crypto::Drbg& rng) const {
    requireValidBitCount(bitCount);
    ScopedTimer timer(counters_, Primitive::PufEval, challenge.size());
    Bytes out = responseStream(deviceKey_, challenge, bitCount);

    // Bernoulli(ber) per bit via a 16-bit threshold. Two DRBG bytes per bit
    // whatever ber is, so the DRBG stream position after an evaluation does not
    // depend on the noise setting.
    const Bytes mask = rng.bytes(2 * bitCount);
    const uint32_t thr = static_cast<uint32_t>(std::llround(ber_ * 65536.0));
    if (thr == 0) return out;
    for (size_t j = 0; j < bitCount; ++j) {
        const uint32_t v = static_cast<uint32_t>(mask[2 * j]) |
                           (static_cast<uint32_t>(mask[2 * j + 1]) << 8);
        if (v < thr)
            out[j >> 3] = static_cast<unsigned char>(out[j >> 3] ^ (0x80u >> (j & 7)));
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
