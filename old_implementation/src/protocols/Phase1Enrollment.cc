#include "Phase1Enrollment.h"

#include "../crypto/PUFSimulator.h"

#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace uavauth {
namespace protocols {

Phase1Enrollment::Phase1Enrollment(int numCrps)
    : bchCodec(255, 131, 18), numCrpsPerUav(numCrps) {}

std::string Phase1Enrollment::generateTempId(int uavId) const {
    std::ostringstream oss;
    oss << "UAV_" << uavId;
    return oss.str();
}

void Phase1Enrollment::enrollUAV(int uavId, int pufSeed, double pufNoiseLevel) {
    uavauth::crypto::PUFSimulator puf(pufSeed, pufNoiseLevel, 128, 128);

    std::vector<CRPRecord> records;
    records.reserve(static_cast<size_t>(numCrpsPerUav));

    std::mt19937 challengeRng(static_cast<uint32_t>(100000 + uavId));
    std::uniform_int_distribution<int> byteDist(0, 255);

    for (int i = 0; i < numCrpsPerUav; ++i) {
        CRPRecord record;
        record.challenge.resize(16);
        for (uint8_t& b : record.challenge) {
            b = static_cast<uint8_t>(byteDist(challengeRng));
        }

        record.response = puf.evaluate(record.challenge);

        // Helper data: h_i = BCH_encode(R_i) XOR R_i (per protocol theory)
        std::vector<uint8_t> encoded = bchCodec.encode(record.response);
        for (size_t b = 0; b < encoded.size() && b < record.response.size(); ++b) {
            encoded[b] ^= record.response[b];
        }
        record.helperData = encoded;

        records.push_back(record);
    }

    const std::string tempId = generateTempId(uavId);

    crpDatabase[uavId] = records;
    uavToTempId[uavId] = tempId;
    tempIdToUav[tempId] = uavId;
    nextCrpIndex[uavId] = 0;
}

bool Phase1Enrollment::hasUAV(int uavId) const {
    return crpDatabase.find(uavId) != crpDatabase.end();
}

bool Phase1Enrollment::hasTempId(const std::string& tempId) const {
    return tempIdToUav.find(tempId) != tempIdToUav.end();
}

int Phase1Enrollment::resolveTempId(const std::string& tempId) const {
    const auto it = tempIdToUav.find(tempId);
    if (it == tempIdToUav.end()) {
        throw std::runtime_error("Unknown temporary UAV identity");
    }
    return it->second;
}

std::string Phase1Enrollment::getTempId(int uavId) const {
    const auto it = uavToTempId.find(uavId);
    if (it == uavToTempId.end()) {
        throw std::runtime_error("UAV not enrolled");
    }
    return it->second;
}

const CRPRecord& Phase1Enrollment::getCurrentCRP(int uavId) const {
    const auto dbIt = crpDatabase.find(uavId);
    if (dbIt == crpDatabase.end()) {
        throw std::runtime_error("UAV not enrolled");
    }

    const auto idxIt = nextCrpIndex.find(uavId);
    if (idxIt == nextCrpIndex.end()) {
        throw std::runtime_error("CRP index state missing");
    }

    const size_t index = idxIt->second % dbIt->second.size();
    return dbIt->second[index];
}

size_t Phase1Enrollment::getCurrentCRPIndex(int uavId) const {
    const auto it = nextCrpIndex.find(uavId);
    if (it == nextCrpIndex.end()) {
        throw std::runtime_error("CRP index state missing");
    }
    return it->second;
}

void Phase1Enrollment::advanceCRP(int uavId) {
    auto dbIt = crpDatabase.find(uavId);
    auto idxIt = nextCrpIndex.find(uavId);
    if (dbIt == crpDatabase.end() || idxIt == nextCrpIndex.end()) {
        throw std::runtime_error("UAV not enrolled");
    }

    const size_t total = dbIt->second.size();
    idxIt->second = (idxIt->second + 1U) % total;
}

int Phase1Enrollment::getNumCrpsPerUav() const {
    return numCrpsPerUav;
}

} // namespace protocols
} // namespace uavauth
