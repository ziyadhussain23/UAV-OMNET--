// Build/link smoke check.
//
// Exercises the core encoding layer and OpenSSL from inside the simulation
// binary, so that environment problems (missing -lcrypto, header search paths,
// OMNeT++ kernel linkage) surface at Stage 0 rather than during protocol work.
// Replaced by the real node modules; kept because it is a fast end-to-end
// sanity check that the toolchain is intact.

#include <omnetpp.h>

#include <openssl/evp.h>

#include "core/Bytes.h"
#include "core/Encoding.h"

using namespace omnetpp;
using namespace uavauth::core;

class SmokeNode : public cSimpleModule {
  protected:
    void initialize() override {
        // Canonical encoding round-trip.
        FieldMap fields;
        fields[FieldId::TID] = fromHex("00112233445566778899aabbccddeeff");
        fields[FieldId::NONCE_1] = fromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
        const Bytes encoded = encodeFields(0x01, 0x11, fields);
        const DecodedFields decoded = decodeFields(encoded);
        if (decoded.fields != fields)
            throw cRuntimeError("smoke: TLV round-trip mismatch");

        // OpenSSL reachable and correct: SHA3-256("abc") known-answer.
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) throw cRuntimeError("smoke: EVP_MD_CTX_new failed");
        const bool ok = EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) == 1 &&
                        EVP_DigestUpdate(ctx, "abc", 3) == 1 &&
                        EVP_DigestFinal_ex(ctx, digest, &digestLen) == 1;
        EVP_MD_CTX_free(ctx);
        if (!ok) throw cRuntimeError("smoke: SHA3-256 evaluation failed");

        const Bytes got(digest, digest + digestLen);
        const std::string want =
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
        if (toHex(got) != want)
            throw cRuntimeError("smoke: SHA3-256(\"abc\") mismatch: %s", toHex(got).c_str());

        EV_INFO << "smoke: TLV encoding and OpenSSL SHA3-256 verified ("
                << encoded.size() << " encoded bytes)" << endl;
    }
};

Define_Module(SmokeNode);
