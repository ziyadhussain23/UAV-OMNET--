#ifndef UAVAUTH_PROTOCOLS_PHASE1ENROLLMENT_H
#define UAVAUTH_PROTOCOLS_PHASE1ENROLLMENT_H

#include "../crypto/BCHCodec.h"

#include <cstddef>
#include <map>
#include <string>
#include <vector>

namespace uavauth {
namespace protocols {

struct CRPRecord {
    std::vector<uint8_t> challenge;
    std::vector<uint8_t> response;
    std::vector<uint8_t> helperData;
};

class Phase1Enrollment {
  private:
    std::map<int, std::vector<CRPRecord>> crpDatabase;
    std::map<int, std::string> uavToTempId;
    std::map<std::string, int> tempIdToUav;
    std::map<int, size_t> nextCrpIndex;

    uavauth::crypto::BCHCodec bchCodec;
    int numCrpsPerUav;

    std::string generateTempId(int uavId) const;

  public:
    explicit Phase1Enrollment(int numCrps = 12);

    void enrollUAV(int uavId, int pufSeed, double pufNoiseLevel);

    bool hasUAV(int uavId) const;
    bool hasTempId(const std::string& tempId) const;

    int resolveTempId(const std::string& tempId) const;
    std::string getTempId(int uavId) const;

    const CRPRecord& getCurrentCRP(int uavId) const;
    size_t getCurrentCRPIndex(int uavId) const;
    void advanceCRP(int uavId);

    int getNumCrpsPerUav() const;
};

} // namespace protocols
} // namespace uavauth

#endif
