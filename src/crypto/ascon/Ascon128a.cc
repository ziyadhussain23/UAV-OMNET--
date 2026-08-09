#include "crypto/ascon/Ascon128a.h"

#include <openssl/crypto.h>

#include <cstring>

namespace uavauth {
namespace crypto {

namespace {

constexpr uint64_t kIv = 0x80800c0800000000ULL;   // k=128, r=128, a=12, b=8
constexpr int kRoundsA = 12;                      // initialisation / finalisation
constexpr int kRoundsB = 8;                       // data processing

/// Round constants of the Ascon permutation. p^b uses the *last* b of them, so
/// p^8 starts at index 4 -- that is what makes p^12 and p^8 different functions
/// rather than one being a prefix of the other.
constexpr uint64_t kRoundConstants[kRoundsA] = {
    0xf0ULL, 0xe1ULL, 0xd2ULL, 0xc3ULL, 0xb4ULL, 0xa5ULL,
    0x96ULL, 0x87ULL, 0x78ULL, 0x69ULL, 0x5aULL, 0x4bULL};

struct State {
    uint64_t x[5];
};

inline uint64_t rotr(uint64_t v, int n) {
    return (v >> n) | (v << (64 - n));
}

inline uint64_t load64be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[i];
    return v;
}

inline void store64be(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        p[i] = static_cast<uint8_t>(v & 0xFFu);
        v >>= 8;
    }
}

/// One round: constant addition, the 5-bit S-box in its standard bitwise form
/// (all five outputs computed from the pre-round values before any write-back),
/// then the linear diffusion layer.
inline void asconRound(State& s, uint64_t constant) {
    uint64_t x0 = s.x[0], x1 = s.x[1], x2 = s.x[2], x3 = s.x[3], x4 = s.x[4];

    x2 ^= constant;

    // Substitution layer.
    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;
    const uint64_t t0 = ~x0 & x1;
    const uint64_t t1 = ~x1 & x2;
    const uint64_t t2 = ~x2 & x3;
    const uint64_t t3 = ~x3 & x4;
    const uint64_t t4 = ~x4 & x0;
    x0 ^= t1;
    x1 ^= t2;
    x2 ^= t3;
    x3 ^= t4;
    x4 ^= t0;
    x1 ^= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 = ~x2;

    // Linear diffusion layer.
    s.x[0] = x0 ^ rotr(x0, 19) ^ rotr(x0, 28);
    s.x[1] = x1 ^ rotr(x1, 61) ^ rotr(x1, 39);
    s.x[2] = x2 ^ rotr(x2, 1) ^ rotr(x2, 6);
    s.x[3] = x3 ^ rotr(x3, 10) ^ rotr(x3, 17);
    s.x[4] = x4 ^ rotr(x4, 7) ^ rotr(x4, 41);
}

inline void permute(State& s, int rounds) {
    for (int i = kRoundsA - rounds; i < kRoundsA; ++i) asconRound(s, kRoundConstants[i]);
}

/// S <- p^a(IV || K || N), then S ^= (0* || K).
void initialise(State& s, const Bytes& key, const Bytes& nonce) {
    const uint64_t k0 = load64be(key.data());
    const uint64_t k1 = load64be(key.data() + 8);
    s.x[0] = kIv;
    s.x[1] = k0;
    s.x[2] = k1;
    s.x[3] = load64be(nonce.data());
    s.x[4] = load64be(nonce.data() + 8);
    permute(s, kRoundsA);
    s.x[3] ^= k0;
    s.x[4] ^= k1;
}

/// Absorbs the associated data, then applies the domain-separation bit. Note
/// that empty associated data absorbs *no* block at all (not even a padding
/// one), while non-empty data is always 10*-padded, so |A| = 16 still costs a
/// second, all-padding block. The trailing S ^= 1 is what keeps AD and
/// plaintext from being confusable.
void absorbAssociatedData(State& s, const Bytes& ad) {
    if (!ad.empty()) {
        size_t offset = 0;
        for (; offset + kAsconRateBytes <= ad.size(); offset += kAsconRateBytes) {
            s.x[0] ^= load64be(ad.data() + offset);
            s.x[1] ^= load64be(ad.data() + offset + 8);
            permute(s, kRoundsB);
        }
        uint8_t block[kAsconRateBytes];
        std::memset(block, 0, sizeof(block));
        const size_t remaining = ad.size() - offset;
        if (remaining > 0) std::memcpy(block, ad.data() + offset, remaining);
        block[remaining] = 0x80;
        s.x[0] ^= load64be(block);
        s.x[1] ^= load64be(block + 8);
        permute(s, kRoundsB);
    }
    s.x[4] ^= 1ULL;
}

/// S <- p^a(S ^ (0^r || K || 0*)), T = last 128 bits of S, XORed with K.
void finalise(State& s, const Bytes& key, uint8_t tag[kAsconTagBytes]) {
    const uint64_t k0 = load64be(key.data());
    const uint64_t k1 = load64be(key.data() + 8);
    s.x[2] ^= k0;
    s.x[3] ^= k1;
    permute(s, kRoundsA);
    store64be(tag, s.x[3] ^ k0);
    store64be(tag + 8, s.x[4] ^ k1);
}

void wipe(State& s) {
    volatile uint64_t* v = s.x;
    for (int i = 0; i < 5; ++i) v[i] = 0;
}

void wipe(uint8_t* p, size_t n) {
    volatile uint8_t* v = p;
    for (size_t i = 0; i < n; ++i) v[i] = 0;
}

} // namespace

const char* asconVerificationStatus() {
    return "Ascon-128a v1.2 (k=128, r=128, a=12, b=8, IV=0x80800c0800000000), vendored. "
           "VERIFIED: reproduces all 1089 vectors of the official known-answer-test file "
           "crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt from the designers' "
           "reference repository github.com/ascon/ascon-c at tag v1.2.8 (plaintext and "
           "associated data of 0..32 bytes), checked as twelve explicit vectors plus a "
           "SHA3-256 digest over the concatenation of all 1089 ciphertexts; plus "
           "round-trip, rejection of every single-byte corruption of ciphertext and of "
           "associated data, wrong key, wrong nonce, and truncated input. NOT VERIFIED: "
           "no constant-time or side-channel analysis -- tags are compared with "
           "CRYPTO_memcmp and no branch depends on secret data, but nothing stronger is "
           "claimed. The KAT file was retrieved from the designers' repository rather "
           "than regenerated from the NIST LWC submission package.";
}

bool ascon128aEncrypt(const Bytes& key16, const Bytes& nonce16, const Bytes& ad,
                      const Bytes& pt, Bytes& ctOut) {
    ctOut.clear();
    if (key16.size() != kAsconKeyBytes || nonce16.size() != kAsconNonceBytes) return false;

    State s;
    initialise(s, key16, nonce16);
    absorbAssociatedData(s, ad);

    Bytes ct;
    ct.reserve(pt.size() + kAsconTagBytes);

    uint8_t block[kAsconRateBytes];
    size_t offset = 0;
    for (; offset + kAsconRateBytes <= pt.size(); offset += kAsconRateBytes) {
        s.x[0] ^= load64be(pt.data() + offset);
        s.x[1] ^= load64be(pt.data() + offset + 8);
        store64be(block, s.x[0]);
        store64be(block + 8, s.x[1]);
        ct.insert(ct.end(), block, block + kAsconRateBytes);
        permute(s, kRoundsB);
    }

    // Final block: 10*-padded, absorbed but not permuted, and the ciphertext is
    // truncated back to the length of the real plaintext remainder.
    const size_t remaining = pt.size() - offset;
    std::memset(block, 0, sizeof(block));
    if (remaining > 0) std::memcpy(block, pt.data() + offset, remaining);
    block[remaining] = 0x80;
    s.x[0] ^= load64be(block);
    s.x[1] ^= load64be(block + 8);
    uint8_t rate[kAsconRateBytes];
    store64be(rate, s.x[0]);
    store64be(rate + 8, s.x[1]);
    ct.insert(ct.end(), rate, rate + remaining);

    uint8_t tag[kAsconTagBytes];
    finalise(s, key16, tag);
    ct.insert(ct.end(), tag, tag + kAsconTagBytes);

    wipe(s);
    wipe(block, sizeof(block));
    wipe(rate, sizeof(rate));
    ctOut = ct;
    return true;
}

bool ascon128aDecrypt(const Bytes& key16, const Bytes& nonce16, const Bytes& ad,
                      const Bytes& ct, Bytes& ptOut) {
    ptOut.clear();
    if (key16.size() != kAsconKeyBytes || nonce16.size() != kAsconNonceBytes) return false;
    if (ct.size() < kAsconTagBytes) return false;   // no tag => nothing to verify
    const size_t bodyLen = ct.size() - kAsconTagBytes;

    State s;
    initialise(s, key16, nonce16);
    absorbAssociatedData(s, ad);

    Bytes pt(bodyLen);
    size_t offset = 0;
    for (; offset + kAsconRateBytes <= bodyLen; offset += kAsconRateBytes) {
        const uint64_t c0 = load64be(ct.data() + offset);
        const uint64_t c1 = load64be(ct.data() + offset + 8);
        store64be(pt.data() + offset, s.x[0] ^ c0);
        store64be(pt.data() + offset + 8, s.x[1] ^ c1);
        s.x[0] = c0;   // the rate is *replaced* by the ciphertext, not XORed
        s.x[1] = c1;
        permute(s, kRoundsB);
    }

    // Final partial block: recover the plaintext, then rebuild the rate as
    // C_t || (remaining state bytes with the padding bit flipped back in), which
    // is what makes decryption reach the same state encryption did.
    const size_t remaining = bodyLen - offset;
    uint8_t rate[kAsconRateBytes];
    store64be(rate, s.x[0]);
    store64be(rate + 8, s.x[1]);
    for (size_t i = 0; i < remaining; ++i)
        pt[offset + i] = static_cast<uint8_t>(rate[i] ^ ct[offset + i]);
    for (size_t i = 0; i < remaining; ++i) rate[i] = ct[offset + i];
    rate[remaining] = static_cast<uint8_t>(rate[remaining] ^ 0x80u);
    s.x[0] = load64be(rate);
    s.x[1] = load64be(rate + 8);

    uint8_t tag[kAsconTagBytes];
    finalise(s, key16, tag);

    // The INT-CTXT check. Constant-time, and on failure the recovered plaintext
    // is destroyed rather than returned.
    const bool authentic =
        CRYPTO_memcmp(tag, ct.data() + bodyLen, kAsconTagBytes) == 0;

    wipe(s);
    wipe(rate, sizeof(rate));
    wipe(tag, sizeof(tag));

    if (!authentic) {
        if (!pt.empty()) wipe(pt.data(), pt.size());
        ptOut.clear();
        return false;
    }
    ptOut = pt;
    return true;
}

} // namespace crypto
} // namespace uavauth
