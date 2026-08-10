#ifndef UAVAUTH_INETAPPS_UAVNODEINETAPP_H
#define UAVAUTH_INETAPPS_UAVNODEINETAPP_H

#include "inet/applications/base/ApplicationBase.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "protocol/Protocol.h"
#include "puf/PufModel.h"

#include <memory>
#include <string>

namespace uavauth {
namespace inet_apps {

/// One UAV, Phase 2 side, transported over a real INET UDP/802.11 stack
/// instead of WirelessMedium. See UavNodeInetApp.ned for scope.
class UavNodeInetApp : public inet::ApplicationBase, public inet::UdpSocket::ICallback {
  public:
    UavNodeInetApp() = default;
    ~UavNodeInetApp() override { cancelAndDelete(startTimer_); }

    /// Called by the ground station app during enrollment, exactly as
    /// GroundStationNode::enrollAll() does on the non-INET track: a direct
    /// C++ call over the (unmodelled) trusted enrollment channel.
    void provision(const protocol::DeviceState& state) { proto_->provision(state); }
    puf::PufModel& devicePuf() { return *puf_; }
    int uavId() const { return uavId_; }

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
    void startPhase2();
    void sendMessage(const protocol::Message& msg, const inet::L3Address& destAddr, int destPort);

    int uavId_ = -1;
    std::string suiteName_;
    std::string feProfile_;
    int localPort_ = 9300;
    int gsPort_ = 9200;

    std::unique_ptr<crypto::CryptoSuite> suite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<puf::PufModel> puf_;
    std::unique_ptr<protocol::UavProtocol> proto_;
    fe::FeParams feParams_;

    inet::UdpSocket socket_;
    inet::L3Address gsAddr_;
    omnetpp::cMessage* startTimer_ = nullptr;

    omnetpp::simtime_t phase2Start_ = 0;
    bool phase2Success_ = false;
    double wallLatencyMs_ = 0.0;
    size_t bytesSent_ = 0, bytesReceived_ = 0;
};

} // namespace inet_apps
} // namespace uavauth

#endif
