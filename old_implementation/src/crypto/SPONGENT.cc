#include "SPONGENT.h"

#include <algorithm>

namespace uavauth {
namespace crypto {

const uint8_t SPONGENT::SBOX[16] = {
    0xC, 0x5, 0x6, 0xB,
    0x9, 0x0, 0xA, 0xD,
    0x3, 0xE, 0xF, 0x8,
    0x4, 0x7, 0x1, 0x2
};

SPONGENT::SPONGENT(int outBits)
    : rateBits(16), capacityBits(144), outputBits(outBits), state(static_cast<size_t>((16 + 144) / 8), 0) {}

std::vector<uint8_t> SPONGENT::hash(const std::vector<uint8_t>& message) const {
    std::fill(state.begin(), state.end(), 0);

    std::vector<uint8_t> padded = message;
    padded.push_back(0x80);
    while ((padded.size() * 8) % static_cast<size_t>(rateBits) != 0U) {
        padded.push_back(0x00);
    }

    absorb(padded);
    return squeeze();
}

std::vector<uint8_t> SPONGENT::hashMultiple(const std::vector<std::vector<uint8_t>>& inputs) const {
    std::vector<uint8_t> concatenated;
    for (const auto& chunk : inputs) {
        concatenated.insert(concatenated.end(), chunk.begin(), chunk.end());
    }
    return hash(concatenated);
}

void SPONGENT::absorb(const std::vector<uint8_t>& input) const {
    const size_t blockBytes = static_cast<size_t>(rateBits / 8);

    for (size_t i = 0; i < input.size(); i += blockBytes) {
        for (size_t j = 0; j < blockBytes && (i + j) < input.size(); ++j) {
            state[j] ^= input[i + j];
        }
        permutation();
    }
}

std::vector<uint8_t> SPONGENT::squeeze() const {
    const size_t outBytesNeeded = static_cast<size_t>(outputBits / 8);
    const size_t rateBytes = static_cast<size_t>(rateBits / 8);

    std::vector<uint8_t> output;
    output.reserve(outBytesNeeded);

    while (output.size() < outBytesNeeded) {
        for (size_t i = 0; i < rateBytes && output.size() < outBytesNeeded; ++i) {
            output.push_back(state[i]);
        }
        if (output.size() < outBytesNeeded) {
            permutation();
        }
    }

    return output;
}

void SPONGENT::permutation() const {
    // SPONGENT-160 uses 80 rounds.
    for (int round = 0; round < 80; ++round) {
        sBoxLayer();
        pLayer();

        // Round constant injection (compact form for simulation purposes).
        state[0] ^= static_cast<uint8_t>(round & 0xFF);
        state[state.size() - 1] ^= static_cast<uint8_t>((round * 0x9E) & 0xFF);
    }
}

void SPONGENT::sBoxLayer() const {
    for (uint8_t& byte : state) {
        const uint8_t high = SBOX[(byte >> 4U) & 0x0FU];
        const uint8_t low = SBOX[byte & 0x0FU];
        byte = static_cast<uint8_t>((high << 4U) | low);
    }
}

void SPONGENT::pLayer() const {
    std::vector<uint8_t> original = state;
    std::fill(state.begin(), state.end(), 0);

    const int nBits = static_cast<int>(original.size() * 8);
    for (int i = 0; i < nBits; ++i) {
        const int srcByte = i / 8;
        const int srcBit = i % 8;
        const bool bitSet = ((original[static_cast<size_t>(srcByte)] >> srcBit) & 0x1U) != 0U;

        int target = 0;
        if (i == nBits - 1) {
            target = nBits - 1;
        } else {
            target = (i * 40) % (nBits - 1);
        }

        const int dstByte = target / 8;
        const int dstBit = target % 8;
        if (bitSet) {
            state[static_cast<size_t>(dstByte)] |= static_cast<uint8_t>(1U << dstBit);
        }
    }
}

} // namespace crypto
} // namespace uavauth
