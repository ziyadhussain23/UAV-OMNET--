#ifndef UAVAUTH_CRYPTO_PRIMITIVECOUNTERS_H
#define UAVAUTH_CRYPTO_PRIMITIVECOUNTERS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace uavauth {
namespace crypto {

/// Every primitive whose cost is reported separately in omnet_primitive_costs.csv.
enum class Primitive {
    Hash160 = 0,
    Mac,
    MacVerify,
    Kdf,
    Extract,
    AeadSeal,
    AeadOpen,
    DhKeygen,
    DhDerive,
    PufEval,
    FeGen,
    FeRep,
    BchEncode,
    BchDecode,
    Rng,
    Sign,     // RSA/ECDSA baseline (src/crypto/SignatureSuite.h)
    Verify,   // long-term keypair generation is a one-time enrollment cost,
              // like the PUF's own manufacturing, so no per-handshake
              // "keygen" primitive is charged here -- only sign/verify are.
    COUNT
};

const char* primitiveName(Primitive p);

/// Per-primitive cost accumulator.
///
/// Individual samples are retained (up to a cap) so the exporter can report a
/// median and p95 rather than only a mean. That matters because a single
/// steady_clock read costs 20-50 ns while a short SHA3 call costs ~1 us, so
/// per-call timing carries a systematic bias that a mean alone would hide.
struct PrimitiveStat {
    uint64_t calls = 0;
    uint64_t inputBytes = 0;
    double totalNs = 0.0;
    double maxNs = 0.0;
    std::vector<double> samplesNs;   // reservoir, capped

    void add(double ns, size_t inBytes);
    double meanNs() const;
    double medianNs() const;
    double percentileNs(double q) const;
    double sdNs() const;
};

class PrimitiveCounters {
  public:
    void add(Primitive p, double ns, size_t inputBytes);
    const PrimitiveStat& get(Primitive p) const;
    PrimitiveStat& get(Primitive p);
    void reset();

    /// Total wall-clock time attributed to every primitive, in milliseconds.
    double totalMs() const;

    static constexpr size_t kMaxSamples = 4096;

  private:
    PrimitiveStat stats_[static_cast<size_t>(Primitive::COUNT)];
};

/// RAII timer that charges its lifetime to a primitive counter.
class ScopedTimer {
  public:
    ScopedTimer(PrimitiveCounters& counters, Primitive p, size_t inputBytes = 0);
    ~ScopedTimer();
    ScopedTimer(const ScopedTimer&) = delete;
    ScopedTimer& operator=(const ScopedTimer&) = delete;

    /// Elapsed time so far, without ending the measurement.
    double elapsedMs() const;

  private:
    PrimitiveCounters& counters_;
    Primitive primitive_;
    size_t inputBytes_;
    int64_t startNs_;
};

/// Monotonic clock reading in nanoseconds; shared so every measurement in the
/// project uses one clock source.
int64_t monotonicNs();

} // namespace crypto
} // namespace uavauth

#endif
