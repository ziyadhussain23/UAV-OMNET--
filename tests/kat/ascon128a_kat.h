#ifndef UAVAUTH_TESTS_KAT_ASCON128A_KAT_H
#define UAVAUTH_TESTS_KAT_ASCON128A_KAT_H

// Official known-answer tests for Ascon-128a v1.2.
//
// Source: crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt from the designers'
// reference repository https://github.com/ascon/ascon-c at tag v1.2.8 (the NIST
// lightweight-crypto submission KAT format). Copied here verbatim -- lower-cased
// -- so the test suite is self-contained and never touches the network.
//
// The full file holds 1089 vectors, one for every (|PT|, |AD|) pair with both
// lengths in 0..32, ordered as
//
//     Count = 33 * |PT| + |AD| + 1
//
// and every vector shares the same fixed key and nonce, with
//
//     Key   = Nonce = 00 01 02 ... 0f
//     PT    = the first |PT| bytes of 00 01 02 ... 1f
//     AD    = the first |AD| bytes of 00 01 02 ... 1f
//     CT    = ciphertext || 16-byte tag
//
// That regularity was checked against the file for all 1089 records, which is
// what lets tests/test_ascon.cc regenerate every input locally and compare the
// whole set against one committed digest (kAllCiphertextsSha3_256) instead of
// carrying 35 KB of hex. The twelve vectors written out below are a readable
// spot-check spanning the interesting boundaries: empty plaintext, empty
// associated data, associated data of exactly one and one-and-a-bit rate blocks,
// plaintext of exactly one and two rate blocks, and both fields at full length.

#include <cstddef>

namespace uavauth {
namespace test {
namespace kat {

struct Ascon128aVector {
    int count;            // Count field in the source file, for traceability
    const char* adHex;
    const char* ptHex;
    const char* ctHex;    // ciphertext || tag
};

// Key and nonce are constant across the whole KAT file.
constexpr const char* kAscon128aKeyHex   = "000102030405060708090a0b0c0d0e0f";
constexpr const char* kAscon128aNonceHex = "000102030405060708090a0b0c0d0e0f";

constexpr Ascon128aVector kAscon128aVectors[] = {
    {   1, "", "",
     "7a834e6f09210957067b10fd831f0078"},
    {   2, "00", "",
     "af3031b07b129ec84153373ddcaba528"},
    {  17, "000102030405060708090a0b0c0d0e0f", "",
     "56c15eb024de91ca0165362a49b31ebd"},
    {  18, "000102030405060708090a0b0c0d0e0f10", "",
     "917d530f34157158cf8ca49d01af44f0"},
    {  33, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "",
     "2fdee642b4c31c2f205dcc8b3dad4542"},
    {  34, "", "00",
     "6e652b55bfdc8cad2ec43815b1666b1a3a"},
    { 300, "0001", "000102030405060708",
     "abe4e02c2714c0ba4a16d4655a2825d7ef4e289e6bdf94e443"},
    { 545, "000102030405060708090a0b0c0d0e0f", "000102030405060708090a0b0c0d0e0f",
     "52499ac9c84323a4ae24eaeccf45c137316d7ab17724ba67a85ecd3c0457c459"},
    { 546, "000102030405060708090a0b0c0d0e0f10", "000102030405060708090a0b0c0d0e0f",
     "bc26a071c86e16ad251fd2ad8d3139f440cdb729f8bcbbbcdf377e2d38d3ef15"},
    { 579, "000102030405060708090a0b0c0d0e0f10", "000102030405060708090a0b0c0d0e0f10",
     "bc26a071c86e16ad251fd2ad8d3139f43b1d71c0094e2b77150642b91fdb91fcb2"},
    {1057, "", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "6e490cfed5b3546767350cd83c4acfbd4cfb4bd07abf5bc24d4b104645717c1e"
     "513abfd1335acfd296c49a35e0d54b73"},
    {1089, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
           "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "a55236ac020dbda74ce6ccd10c68c4d8514450a382bc87c68946d86a921dd88e"
     "2adddfbbe77d4112830e01960b9d38d5"},
};

constexpr size_t kAscon128aVectorCount =
    sizeof(kAscon128aVectors) / sizeof(kAscon128aVectors[0]);

// Number of records in the source file, and the maximum plaintext / associated
// data length it covers.
constexpr int kAscon128aFullKatCount = 1089;
constexpr int kAscon128aFullKatMaxLen = 32;

// SHA3-256 over the concatenation of the CT fields of all 1089 records, in Count
// order (34848 bytes in total). Reproducible from the source file with the
// following Python (no line continuations, so it stays inside this comment):
//
//   import re, hashlib
//   ct = re.findall("CT = ([0-9A-Fa-f]*)", open("LWC_AEAD_KAT_128_128.txt").read())
//   print(hashlib.sha3_256(b"".join(bytes.fromhex(x) for x in ct)).hexdigest())
constexpr const char* kAscon128aAllCiphertextsSha3_256 =
    "96a472a01a88394109e16f33044f164ca5d05cdbd93ff043f733ccce7e2109e5";

} // namespace kat
} // namespace test
} // namespace uavauth

#endif
