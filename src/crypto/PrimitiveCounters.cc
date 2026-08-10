#include "crypto/PrimitiveCounters.h"

#include <algorithm>
#include <chrono>
#include <cmath>

namespace uavauth {
namespace crypto {

const char* primitiveName(Primitive p) {
    switch (p) {
        case Primitive::Hash160:   return "hash160";
        case Primitive::Mac:       return "mac";
        case Primitive::MacVerify: return "mac_verify";
        case Primitive::Kdf:       return "kdf";
        case Primitive::Extract:   return "extract";
        case Primitive::AeadSeal:  return "aead_seal";
        case Primitive::AeadOpen:  return "aead_open";
        case Primitive::DhKeygen:  return "dh_keygen";
        case Primitive::DhDerive:  return "dh_derive";
        case Primitive::PufEval:   return "puf_eval";
        case Primitive::FeGen:     return "fe_gen";
        case Primitive::FeRep:     return "fe_rep";
        case Primitive::BchEncode: return "bch_encode";
        case Primitive::BchDecode: return "bch_decode";
        case Primitive::Rng:       return "rng";
        case Primitive::Sign:      return "sign";
        case Primitive::Verify:    return "verify";
        case Primitive::COUNT:     break;
    }
    return "unknown";
}

int64_t monotonicNs() {
    using clock = std::chrono::steady_clock;
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock::now().time_since_epoch())
        .count();
}

void PrimitiveStat::add(double ns, size_t inBytes) {
    ++calls;
    inputBytes += inBytes;
    totalNs += ns;
    if (ns > maxNs) maxNs = ns;
    if (samplesNs.size() < PrimitiveCounters::kMaxSamples) samplesNs.push_back(ns);
}

double PrimitiveStat::meanNs() const {
    return calls == 0 ? 0.0 : totalNs / static_cast<double>(calls);
}

double PrimitiveStat::percentileNs(double q) const {
    if (samplesNs.empty()) return 0.0;
    std::vector<double> sorted = samplesNs;
    std::sort(sorted.begin(), sorted.end());
    if (q <= 0.0) return sorted.front();
    if (q >= 1.0) return sorted.back();
    const double pos = q * static_cast<double>(sorted.size() - 1);
    const size_t lo = static_cast<size_t>(pos);
    const size_t hi = std::min(lo + 1, sorted.size() - 1);
    const double frac = pos - static_cast<double>(lo);
    return sorted[lo] * (1.0 - frac) + sorted[hi] * frac;
}

double PrimitiveStat::medianNs() const { return percentileNs(0.5); }

double PrimitiveStat::sdNs() const {
    if (samplesNs.size() < 2) return 0.0;
    double sum = 0.0;
    for (double v : samplesNs) sum += v;
    const double mean = sum / static_cast<double>(samplesNs.size());
    double acc = 0.0;
    for (double v : samplesNs) acc += (v - mean) * (v - mean);
    return std::sqrt(acc / static_cast<double>(samplesNs.size() - 1));
}

void PrimitiveCounters::add(Primitive p, double ns, size_t inputBytes) {
    stats_[static_cast<size_t>(p)].add(ns, inputBytes);
}

const PrimitiveStat& PrimitiveCounters::get(Primitive p) const {
    return stats_[static_cast<size_t>(p)];
}

PrimitiveStat& PrimitiveCounters::get(Primitive p) {
    return stats_[static_cast<size_t>(p)];
}

void PrimitiveCounters::reset() {
    for (size_t i = 0; i < static_cast<size_t>(Primitive::COUNT); ++i)
        stats_[i] = PrimitiveStat{};
}

double PrimitiveCounters::totalMs() const {
    double ns = 0.0;
    for (size_t i = 0; i < static_cast<size_t>(Primitive::COUNT); ++i)
        ns += stats_[i].totalNs;
    return ns / 1.0e6;
}

ScopedTimer::ScopedTimer(PrimitiveCounters& counters, Primitive p, size_t inputBytes)
    : counters_(counters), primitive_(p), inputBytes_(inputBytes), startNs_(monotonicNs()) {}

ScopedTimer::~ScopedTimer() {
    counters_.add(primitive_, static_cast<double>(monotonicNs() - startNs_), inputBytes_);
}

double ScopedTimer::elapsedMs() const {
    return static_cast<double>(monotonicNs() - startNs_) / 1.0e6;
}

} // namespace crypto
} // namespace uavauth
