#ifndef UAVAUTH_PUF_PUFMODEL_H
#define UAVAUTH_PUF_PUFMODEL_H

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/OsslCommon.h"
#include "crypto/PrimitiveCounters.h"

#include <openssl/evp.h>

#include <cstdint>
#include <stdexcept>

namespace uavauth {
namespace puf {

using core::Bytes;

/// Abstract PUF model.
///
/// Two things separate this interface from the previous implementation, both of
/// which were the source of misleading results:
///
///  1. The noise-free and the field evaluation are *different methods*. A model
///     must therefore state explicitly what its deterministic answer is, and the
///     noise process cannot quietly become part of the "ideal" response.
///
///  2. `evaluateNoisy` takes an explicit DRBG. Every bit of randomness a device
///     consumes comes from a seeded, reproducible stream, so a run can be
///     replayed exactly. Models must never call rand(), mt19937 or RAND_bytes.
///
/// Implementations charge their evaluation cost to `counters()` under
/// `Primitive::PufEval`, so the reported PUF latency comes from the same
/// measurement path as every other primitive.
class PufModel {
  public:
    virtual ~PufModel() = default;

    virtual const char* name() const = 0;

    /// Width of the per-response-bit sub-challenge the model consumes, in bits.
    /// The *outer* challenge handed to evaluate*() may be any length: it is
    /// compressed to a fixed-width sub-challenge per response bit by
    /// deriveSubChallenge().
    virtual size_t challengeBits() const = 0;

    /// Deterministic noise-free response, bitCount bits packed MSB-first.
    virtual Bytes evaluateIdeal(const Bytes& challenge, size_t bitCount) const = 0;

    /// Field evaluation: ideal response perturbed by the device's noise process.
    ///
    /// Implementations consume a fixed amount of randomness per response bit,
    /// independent of the configured noise magnitude, so that two devices
    /// configured differently still walk the DRBG stream identically.
    virtual Bytes evaluateNoisy(const Bytes& challenge, size_t bitCount,
                                crypto::Drbg& rng) const = 0;

    /// Per-primitive cost accumulator for this device.
    const crypto::PrimitiveCounters& counters() const { return counters_; }
    crypto::PrimitiveCounters& counters() { return counters_; }

  protected:
    /// Mutable so that the const evaluate methods can still be timed; a counter
    /// update is not part of the model's logical state.
    mutable crypto::PrimitiveCounters counters_;
};

namespace detail {

/// Reusable digest context. Fetching a context per call would dominate the
/// measured cost of a sub-challenge derivation, which is a single Keccak
/// permutation.
struct MdCtxHolder {
    EVP_MD_CTX* ctx = nullptr;
    MdCtxHolder() : ctx(EVP_MD_CTX_new()) {}
    ~MdCtxHolder() {
        if (ctx != nullptr) EVP_MD_CTX_free(ctx);
    }
    MdCtxHolder(const MdCtxHolder&) = delete;
    MdCtxHolder& operator=(const MdCtxHolder&) = delete;
};

} // namespace detail

/// Sub-challenge for response bit j: the first 16 bytes of
/// SHA3-256(C || u16be(j)).
///
/// Fixed convention shared by every model, for two reasons. It lets a challenge
/// of any length drive an arbitrary number of response bits, and -- because the
/// derivation depends only on (C, j) and not on the device -- two devices
/// answering the same challenge are compared on exactly the same input, which is
/// what makes an inter-device Hamming distance meaningful.
///
/// 16 bytes is not an arbitrary truncation: it is exactly the 128-stage arbiter
/// challenge width.
inline Bytes deriveSubChallenge(const Bytes& challenge, uint16_t j) {
    static thread_local detail::MdCtxHolder holder;
    EVP_MD_CTX* ctx = holder.ctx;
    if (ctx == nullptr) crypto::throwOsslError("PUF: EVP_MD_CTX_new");

    const unsigned char index[2] = {static_cast<unsigned char>(j >> 8),
                                    static_cast<unsigned char>(j & 0xFF)};
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    const bool ok =
        EVP_DigestInit_ex(ctx, crypto::OsslCommon::instance().sha3_256(), nullptr) == 1 &&
        (challenge.empty() ||
         EVP_DigestUpdate(ctx, challenge.data(), challenge.size()) == 1) &&
        EVP_DigestUpdate(ctx, index, sizeof(index)) == 1 &&
        EVP_DigestFinal_ex(ctx, out, &outLen) == 1;
    if (!ok) crypto::throwOsslError("PUF: sub-challenge SHA3-256");
    if (outLen < 16) throw std::runtime_error("PUF: short SHA3-256 output");
    return Bytes(out, out + 16);
}

/// Width of a sub-challenge, in bits. Equals the arbiter stage count.
constexpr size_t kSubChallengeBits = 128;

/// Largest response length any model will produce. The sub-challenge index is a
/// uint16_t, so a longer response would silently wrap and start repeating bits;
/// fail loudly instead. The fuzzy extractor's largest profile needs 3825 bits.
constexpr size_t kMaxResponseBits = 65536;

inline void requireValidBitCount(size_t bitCount) {
    if (bitCount > kMaxResponseBits)
        throw std::invalid_argument("PUF: response length exceeds 65536 bits");
}

} // namespace puf
} // namespace uavauth

#endif
