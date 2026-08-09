#ifndef UAVAUTH_CRYPTO_ASCON_ASCON128A_H
#define UAVAUTH_CRYPTO_ASCON_ASCON128A_H

#include "core/Bytes.h"

#include <cstddef>
#include <cstdint>

namespace uavauth {
namespace crypto {

using core::Bytes;

/// Ascon-128a v1.2 -- the AEAD of the constrained-hardware suite.
///
/// Parameters (Dobraunig, Eichlseder, Mendel, Schlaeffer, "Ascon v1.2", NIST LWC
/// / CAESAR final portfolio):
///
///   key 128 bits, nonce 128 bits, tag 128 bits, rate r = 128 bits,
///   a = 12 initialisation/finalisation rounds, b = 8 intermediate rounds,
///   IV = 0x80800c0800000000, 320-bit state held as five 64-bit words.
///
/// This is the "a" (fast) member of the family: twice the rate of Ascon-128 at
/// the cost of a smaller capacity, still at the 128-bit security level. It
/// replaces ChaCha20-Poly1305 in the spongent profile because it is the AEAD a
/// constrained UAV would actually ship, and because measuring ChaCha against a
/// SPONGENT hash would mix the two hardware profiles the experiment separates.
///
/// -------------------------------------------------------------------------
/// VERIFICATION STATUS -- unlike SPONGENT, Ascon does have an official KAT.
///
/// tests/test_ascon.cc reproduces every one of the 1089 vectors in
/// crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt from the designers'
/// reference repository github.com/ascon/ascon-c (tag v1.2.8): twelve vectors are
/// written out in full in tests/kat/ascon128a_kat.h, and the whole set is covered
/// by regenerating every input and hashing the concatenated ciphertexts.
///
/// Not verified: constant-time behaviour. The implementation is branch-free over
/// secret data and compares tags with CRYPTO_memcmp, but no timing or
/// side-channel analysis was performed, and the compiler is free to do as it
/// likes with the 64-bit words.
/// -------------------------------------------------------------------------

constexpr size_t kAsconKeyBytes   = 16;
constexpr size_t kAsconNonceBytes = 16;
constexpr size_t kAsconTagBytes   = 16;
constexpr size_t kAsconRateBytes  = 16;

/// Seals `pt` under (`key16`, `nonce16`) with `ad` authenticated but not
/// encrypted. On success `ctOut` is ciphertext || tag, i.e. |pt| + 16 bytes.
/// Returns false only for a malformed key or nonce length; `ctOut` is cleared
/// first either way, so a failed call cannot leave a stale buffer behind.
///
/// The caller owns nonce uniqueness. Ascon, like every nonce-based AEAD, loses
/// all confidentiality guarantees if a (key, nonce) pair is ever repeated.
bool ascon128aEncrypt(const Bytes& key16, const Bytes& nonce16, const Bytes& ad,
                      const Bytes& pt, Bytes& ctOut);

/// Opens `ct` (ciphertext || tag). Returns false on a bad key/nonce length, on
/// input shorter than the tag, and -- the case that matters -- on tag mismatch.
/// `ptOut` is cleared on every failure path: unauthenticated plaintext is never
/// handed back, since releasing it would break the INT-CTXT argument the
/// protocol's abort logic relies on.
bool ascon128aDecrypt(const Bytes& key16, const Bytes& nonce16, const Bytes& ad,
                      const Bytes& ct, Bytes& ptOut);

/// Exactly what has and has not been checked about this implementation.
/// (A free function, not a class member -- Ascon has no object state here.)
const char* asconVerificationStatus();

} // namespace crypto
} // namespace uavauth

#endif
