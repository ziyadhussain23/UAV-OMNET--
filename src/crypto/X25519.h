#ifndef UAVAUTH_CRYPTO_X25519_H
#define UAVAUTH_CRYPTO_X25519_H

#include "core/Bytes.h"
#include "crypto/PrimitiveCounters.h"

namespace uavauth {
namespace crypto {

using core::Bytes;

constexpr size_t kX25519KeyLen = 32;

/// Ephemeral X25519 key pair.
///
/// The secret scalar must be erased once the shared secret has been derived:
/// forward secrecy holds only if the scalar is genuinely gone, so `erase()` is
/// part of the protocol, not housekeeping.
struct X25519KeyPair {
    Bytes secret;      // 32 bytes; cleared by erase()
    Bytes publicKey;   // 32 bytes
    bool erased = false;

    void erase();
};

/// Derive a key pair deterministically from 32 caller-supplied seed bytes.
///
/// The seed comes from the simulation's DRBG rather than from EVP_PKEY_keygen,
/// so an entire run -- including all ephemeral keys -- is reproducible from the
/// OMNeT++ seed set. Throws std::invalid_argument if the seed is not 32 bytes.
X25519KeyPair x25519Generate(const Bytes& seed32, PrimitiveCounters& counters);

/// Compute the shared secret. Returns false (and clears `sharedOut`) if OpenSSL
/// rejects the peer key, which is how low-order points that would yield an
/// all-zero secret are caught. Callers must treat false as a protocol abort and
/// must never fall through to a derived key.
bool x25519Derive(const Bytes& secret32, const Bytes& peerPublic32, Bytes& sharedOut,
                  PrimitiveCounters& counters);

} // namespace crypto
} // namespace uavauth

#endif
