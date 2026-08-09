#include "crypto/SpongentSuite.h"

#include "core/Encoding.h"
#include "crypto/ascon/Ascon128a.h"

#include <openssl/crypto.h>

#include <stdexcept>

namespace uavauth {
namespace crypto {

using core::append;
using core::kDomainHash;
using core::kDomainKdf;
using core::kDomainMac;
using core::lengthPrefixed;
using core::u16be;

std::string SpongentSuite::implTag(Primitive p) const {
    switch (p) {
        case Primitive::Hash160:
            return "spongent160-176-16/vendored";
        case Primitive::Mac:
        case Primitive::MacVerify:
            return "keyed-sponge-spongent160/vendored";
        case Primitive::Kdf:
        case Primitive::Extract:
            return "sponge-kdf-spongent160/vendored";
        case Primitive::AeadSeal:
        case Primitive::AeadOpen:
            return "ascon128a-v12/vendored";
        default:
            return std::string(primitiveName(p)) + "/vendored";
    }
}

Bytes SpongentSuite::hash160(const Bytes& message) const {
    ScopedTimer timer(counters_, Primitive::Hash160, message.size());
    // Domain byte plus length prefix, exactly as in Sha3Suite: the protocol hash
    // h(.) is a different function from the bare primitive, so that a raw
    // SPONGENT digest computed elsewhere can never be passed off as an h(.)
    // value. The digest is already 160 bits wide, so unlike the sha3 profile
    // there is no truncation step here.
    Bytes input;
    input.push_back(kDomainHash);
    append(input, lengthPrefixed(message));
    return sponge_.hash(input);
}

Bytes SpongentSuite::macRaw(const Bytes& key, const Bytes& message) const {
    // Prefix keyed sponge; see the header for why HMAC is not applicable and for
    // the role of each element of the absorbed string.
    Bytes input;
    input.push_back(kDomainMac);
    input.push_back(kSuiteVersion);
    append(input, lengthPrefixed(key));
    append(input, message);
    return sponge_.spongeAbsorbSqueeze(input, macLen());
}

Bytes SpongentSuite::mac(const Bytes& key, const Bytes& message) const {
    ScopedTimer timer(counters_, Primitive::Mac, message.size());
    return macRaw(key, message);
}

bool SpongentSuite::macVerify(const Bytes& key, const Bytes& message,
                              const Bytes& tag) const {
    ScopedTimer timer(counters_, Primitive::MacVerify, message.size());
    if (tag.size() != macLen()) return false;
    const Bytes expected = macRaw(key, message);
    // Constant-time, as in Sha3Suite: no early return on the first differing
    // byte, or the comparison itself would leak the correct tag one byte at a
    // time.
    return CRYPTO_memcmp(expected.data(), tag.data(), macLen()) == 0;
}

Bytes SpongentSuite::kdfRaw(const Bytes& ikm, const Bytes& salt, const std::string& label,
                            const Bytes& info, size_t outLen) const {
    // One pass, no extract-then-expand split: a sponge can absorb all the inputs
    // and then emit outLen bytes directly, so HKDF's two-step structure would buy
    // nothing here.
    //
    // Every field is length-prefixed, which makes the absorbed string an
    // injective encoding of (ikm, salt, label, info, outLen) -- two different
    // derivations can therefore never absorb the same bytes.
    //
    // Binding outLen into the *input* is the load-bearing detail. Squeezing is a
    // stream, so without it a 16-byte key would be the exact prefix of the
    // 32-byte key derived from the same material, and a protocol that used both
    // lengths for different purposes would be handing out related keys.
    // test_spongent.cc asserts the non-prefix property.
    //
    // The length is absorbed as a u16be, so a request beyond 65535 bytes is
    // refused rather than silently wrapped -- a wrapped length would make two
    // different requests absorb identical bytes and quietly reintroduce the
    // related-key problem this field exists to prevent.
    if (outLen > 0xFFFFu)
        throw std::invalid_argument("SpongentSuite::kdf: outLen exceeds 65535 bytes");

    Bytes input;
    input.push_back(kDomainKdf);
    input.push_back(kSuiteVersion);
    append(input, lengthPrefixed(ikm));
    append(input, lengthPrefixed(salt));
    append(input, lengthPrefixed(label));
    append(input, lengthPrefixed(info));
    append(input, u16be(static_cast<uint16_t>(outLen)));
    return sponge_.spongeAbsorbSqueeze(input, outLen);
}

Bytes SpongentSuite::kdf(const Bytes& ikm, const Bytes& salt, const std::string& label,
                         const Bytes& info, size_t outLen) const {
    ScopedTimer timer(counters_, Primitive::Kdf, ikm.size());
    return kdfRaw(ikm, salt, label, info, outLen);
}

Bytes SpongentSuite::extract(const Bytes& salt, const Bytes& source) const {
    ScopedTimer timer(counters_, Primitive::Extract, source.size());
    // The fuzzy extractor's strong extractor: the noisy PUF response is the key
    // material and the helper seed is the salt. It is the KDF under its own
    // label, so an extractor output can never coincide with a session key
    // derived from the same response.
    return kdfRaw(source, salt, label::kFeExtract, Bytes{}, keyLen());
}

bool SpongentSuite::aeadSeal(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                             const Bytes& plaintext, Bytes& ciphertextOut) const {
    ScopedTimer timer(counters_, Primitive::AeadSeal, plaintext.size());
    if (key.size() != aeadKeyLen() || nonce.size() != aeadNonceLen()) {
        ciphertextOut.clear();
        return false;
    }
    return ascon128aEncrypt(key, nonce, aad, plaintext, ciphertextOut);
}

bool SpongentSuite::aeadOpen(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                             const Bytes& ciphertext, Bytes& plaintextOut) const {
    ScopedTimer timer(counters_, Primitive::AeadOpen, ciphertext.size());
    if (key.size() != aeadKeyLen() || nonce.size() != aeadNonceLen()) {
        plaintextOut.clear();
        return false;
    }
    return ascon128aDecrypt(key, nonce, aad, ciphertext, plaintextOut);
}

// makeCryptoSuite() is deliberately NOT defined here: crypto/CryptoSuiteFactory.cc
// owns it and picks this suite up through its own include of SpongentSuite.h.

} // namespace crypto
} // namespace uavauth
