#ifndef UAVAUTH_INETAPPS_GROUNDSTATIONNODEINETAPP_H
#define UAVAUTH_INETAPPS_GROUNDSTATIONNODEINETAPP_H

#include "inet/applications/base/ApplicationBase.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "protocol/Protocol.h"

#include <memory>
#include <string>

namespace uavauth {
namespace inet_apps {

/// Ground station, Phase 2 side, transported over a real INET UDP/802.11
/// stack. See GroundStationNodeInetApp.ned for scope.
class GroundStationNodeInetApp : public inet::ApplicationBase, public inet::UdpSocket::ICallback {
  public:
    GroundStationNodeInetApp() = default;
    ~GroundStationNodeInetApp() override { cancelAndDelete(enrollTimer_); }

  protected:
    void initialize(int stage) override;
    void handleMessageWhenUp(omnetpp::cMessage* msg) override;
    void finish() override;
    void refreshDisplay() const override {}

    void handleStartOperation(inet::LifecycleOperation* operation) override;
    void handleStopOperation(inet::LifecycleOperation* operation) override;
    void handleCrashOperation(inet::LifecycleOperation* operation) override;

    void socketDataArrived(inet::UdpSocket* socket, inet::Packet* packet) override;
    void socketErrorArrived(inet::UdpSocket* socket, inet::Indication* indication) override;
    void socketClosed(inet::UdpSocket* socket) override;

  private:
    void enrollAll();
    void sendMessage(const protocol::Message& msg, const inet::L3Address& destAddr, int destPort);

    int numUavs_ = 0;
    int localPort_ = 9200;
    std::string suiteName_;

    std::unique_ptr<crypto::CryptoSuite> suite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<protocol::GroundStationProtocol> proto_;

    inet::UdpSocket socket_;
    omnetpp::cMessage* enrollTimer_ = nullptr;

    long attemptsM1_ = 0;
    long successesM4_ = 0;
    double gsComputeMs_ = 0.0;
};

} // namespace inet_apps
} // namespace uavauth

#endif
