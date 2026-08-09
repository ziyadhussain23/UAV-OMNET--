// Same-platform PKI baselines.
//
// The previous comparison table put this work's x86-64 timings against RSA/ECC
// figures cited from ARM Cortex-A72 and Raspberry Pi papers, which conflates
// protocol efficiency with a hardware-class advantage. It also quoted "8-15 ms"
// for RSA-2048 *verification*, which is implausible by two orders of magnitude --
// verification with a small public exponent is tens of microseconds.
//
// This benchmark measures RSA-2048, ECDSA P-256, ECDH P-256 and X25519 with the
// same OpenSSL build, on the same host, using the same clock as the protocol
// itself, so the comparison is apples to apples. It also measures this protocol's
// own per-primitive costs for reference.
//
// Timing method: each operation is measured over many iterations and the MEDIAN
// is reported alongside the mean. A single steady_clock read costs 20-50 ns while
// a short hash costs ~1 us, so per-call bracketing carries a systematic bias that
// a mean alone would hide.
//
// Output: CSV on stdout, so it can be redirected into the results directory.
//
// DEPS: core/Bytes.cc core/Encoding.cc crypto/PrimitiveCounters.cc crypto/OsslCommon.cc crypto/Sha3Suite.cc crypto/Drbg.cc crypto/X25519.cc

#include "core/Bytes.h"
#include "crypto/Drbg.h"
#include "crypto/OsslCommon.h"
#include "crypto/PrimitiveCounters.h"
#include "crypto/Sha3Suite.h"
#include "crypto/X25519.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

using namespace uavauth::core;
using namespace uavauth::crypto;

namespace {

struct Sample {
    std::string scheme, operation;
    int keyBits = 0;
    std::string curve;
    int iterations = 0;
    std::vector<double> us;
};

double median(std::vector<double> v) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return (n % 2) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

double mean(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double s = 0.0;
    for (double x : v) s += x;
    return s / static_cast<double>(v.size());
}

double sd(const std::vector<double>& v) {
    if (v.size() < 2) return 0.0;
    const double m = mean(v);
    double a = 0.0;
    for (double x : v) a += (x - m) * (x - m);
    return std::sqrt(a / static_cast<double>(v.size() - 1));
}

double pct(std::vector<double> v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double pos = q * static_cast<double>(v.size() - 1);
    const size_t lo = static_cast<size_t>(pos);
    const size_t hi = std::min(lo + 1, v.size() - 1);
    return v[lo] + (pos - static_cast<double>(lo)) * (v[hi] - v[lo]);
}

void emit(const Sample& s) {
    std::printf("%s,%s,%d,%s,%d,%.3f,%.3f,%.3f,%.3f,%.3f\n", s.scheme.c_str(),
                s.operation.c_str(), s.keyBits, s.curve.c_str(), s.iterations,
                mean(s.us), sd(s.us), median(s.us), pct(s.us, 0.05), pct(s.us, 0.95));
}

/// Time `fn` over `iters` iterations in batches, recording per-batch mean cost.
template <typename Fn>
std::vector<double> timeBatched(Fn fn, int iters, int batch = 50) {
    std::vector<double> out;
    for (int i = 0; i < iters; i += batch) {
        const int n = std::min(batch, iters - i);
        const int64_t t0 = monotonicNs();
        for (int k = 0; k < n; ++k) fn();
        const double perCallUs =
            static_cast<double>(monotonicNs() - t0) / 1000.0 / static_cast<double>(n);
        out.push_back(perCallUs);
    }
    return out;
}

EVP_PKEY* genRsa(int bits) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* key = nullptr;
    if (ctx && EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) == 1)
        EVP_PKEY_keygen(ctx, &key);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return key;
}

EVP_PKEY* genEc(int nid) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* key = nullptr;
    if (ctx && EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) == 1)
        EVP_PKEY_keygen(ctx, &key);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return key;
}

bool signOnce(EVP_PKEY* key, const Bytes& msg, Bytes& sigOut) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    size_t len = 0;
    bool ok = EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
              EVP_DigestSign(ctx, nullptr, &len, msg.data(), msg.size()) == 1;
    if (ok) {
        sigOut.resize(len);
        ok = EVP_DigestSign(ctx, sigOut.data(), &len, msg.data(), msg.size()) == 1;
        sigOut.resize(len);
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool verifyOnce(EVP_PKEY* key, const Bytes& msg, const Bytes& sig) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    const bool ok = EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1 &&
                    EVP_DigestVerify(ctx, sig.data(), sig.size(), msg.data(), msg.size()) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

} // namespace

int main() {
    std::printf("scheme,operation,key_bits,curve,iterations,mean_us,sd_us,median_us,p05_us,p95_us\n");

    const Bytes msg = fromString("UAV authentication handshake transcript");
    Drbg rng(fromString("pki-baseline"));

    // ---- RSA-2048 ----
    if (EVP_PKEY* rsa = genRsa(2048)) {
        Bytes sig;
        if (signOnce(rsa, msg, sig)) {
            emit({"rsa2048", "sign", 2048, "", 200,
                  timeBatched([&] { Bytes s; signOnce(rsa, msg, s); }, 200, 10)});
            emit({"rsa2048", "verify", 2048, "", 2000,
                  timeBatched([&] { verifyOnce(rsa, msg, sig); }, 2000, 100)});
            std::fprintf(stderr, "rsa2048 signature: %zu bytes\n", sig.size());
        }
        EVP_PKEY_free(rsa);
    }

    // ---- ECDSA P-256 ----
    if (EVP_PKEY* ec = genEc(NID_X9_62_prime256v1)) {
        Bytes sig;
        if (signOnce(ec, msg, sig)) {
            emit({"ecdsa-p256", "sign", 256, "P-256", 2000,
                  timeBatched([&] { Bytes s; signOnce(ec, msg, s); }, 2000, 100)});
            emit({"ecdsa-p256", "verify", 256, "P-256", 2000,
                  timeBatched([&] { verifyOnce(ec, msg, sig); }, 2000, 100)});
            std::fprintf(stderr, "ecdsa-p256 signature: %zu bytes\n", sig.size());
        }
        EVP_PKEY_free(ec);
    }

    // ---- ECDH P-256 ----
    {
        EVP_PKEY* a = genEc(NID_X9_62_prime256v1);
        EVP_PKEY* b = genEc(NID_X9_62_prime256v1);
        if (a && b) {
            auto derive = [&] {
                EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(a, nullptr);
                size_t len = 0;
                if (ctx && EVP_PKEY_derive_init(ctx) == 1 &&
                    EVP_PKEY_derive_set_peer(ctx, b) == 1 &&
                    EVP_PKEY_derive(ctx, nullptr, &len) == 1) {
                    std::vector<unsigned char> out(len);
                    EVP_PKEY_derive(ctx, out.data(), &len);
                }
                if (ctx) EVP_PKEY_CTX_free(ctx);
            };
            emit({"ecdh-p256", "derive", 256, "P-256", 2000, timeBatched(derive, 2000, 100)});
        }
        if (a) EVP_PKEY_free(a);
        if (b) EVP_PKEY_free(b);
    }

    // ---- X25519: what this protocol actually uses ----
    {
        PrimitiveCounters c;
        const Bytes seedA = rng.bytes(32);
        const Bytes seedB = rng.bytes(32);
        const X25519KeyPair ka = x25519Generate(seedA, c);
        const X25519KeyPair kb = x25519Generate(seedB, c);
        emit({"x25519", "keygen", 256, "Curve25519", 2000,
              timeBatched([&] { x25519Generate(seedA, c); }, 2000, 100)});
        emit({"x25519", "derive", 256, "Curve25519", 2000,
              timeBatched([&] { Bytes s; x25519Derive(ka.secret, kb.publicKey, s, c); },
                          2000, 100)});
    }

    // ---- This protocol's own symmetric primitives, same host and clock ----
    {
        Sha3Suite suite;
        const Bytes key(32, 0x5a);
        emit({"ours-sha3", "hash160", 0, "", 5000,
              timeBatched([&] { suite.hash160(msg); }, 5000, 200)});
        emit({"ours-sha3", "mac", 0, "", 5000,
              timeBatched([&] { suite.mac(key, msg); }, 5000, 200)});
        emit({"ours-sha3", "kdf", 0, "", 5000,
              timeBatched([&] { suite.kdf(key, Bytes{}, label::kP2Sess, Bytes{}, 32); },
                          5000, 200)});
        const Bytes nonce(suite.aeadNonceLen(), 0x01);
        Bytes ct;
        emit({"ours-sha3", "aead_seal", 0, "", 5000,
              timeBatched([&] { Bytes o; suite.aeadSeal(key, nonce, Bytes{}, msg, o); },
                          5000, 200)});
    }

    std::fprintf(stderr, "openssl: %s\n", OsslCommon::instance().versionString().c_str());
    return 0;
}
