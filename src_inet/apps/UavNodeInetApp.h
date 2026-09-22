#ifndef UAVAUTH_INETAPPS_UAVNODEINETAPP_H
#define UAVAUTH_INETAPPS_UAVNODEINETAPP_H

#include "inet/applications/base/ApplicationBase.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

#include "crypto/CryptoSuite.h"
#include "crypto/Drbg.h"
#include "protocol/Protocol.h"
#include "puf/PufModel.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace uavauth {
namespace inet_apps {

/// One UAV, Phases 2 and 3, transported over a real INET UDP/802.11 stack
/// instead of WirelessMedium. See UavNodeInetApp.ned for scope.
///
/// Two clocks, resolved differently here than on the idealised track. INET
/// drives everything from the simulation clock, so a message's wall time
/// (received - sent) is real end-to-end time including CSMA/CA backoff,
/// queueing and propagation. Compute is measured on the host clock by the
/// protocol's own ScopedTimers. On this track they live on the same timeline,
/// so net = wall - compute is a legitimate decomposition (and is reported as
/// derived, never as an independent measurement).
class UavNodeInetApp : public inet::ApplicationBase, public inet::UdpSocket::ICallback {
  public:
    UavNodeInetApp() = default;
    ~UavNodeInetApp() override {
        cancelAndDelete(startTimer_);
        cancelAndDelete(peerTimer_);
    }

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

    /// Resolve every peer's L3 address once, at the first real event.
    ///
    /// Peer IDENTITY is not recovered from the address, though. A host inside
    /// INET can hold several L3 addresses and the one a routed packet carries as
    /// its source is not necessarily the one L3AddressResolver hands back, so an
    /// address comparison silently resolves some senders to "unknown" and every
    /// P2 is dropped. Each UAV instead binds its OWN port (peerBasePort + id) and
    /// peers reply to the source port they were written from, so the source port
    /// of any incoming datagram names its sender exactly -- port-based demux,
    /// the way a real peer-to-peer service would do it.
    void buildPeerTable();
    void startPhase3Round();
    int peerByPort(int srcPort) const;

    /// One peer exchange, keyed by peer id.
    struct PeerRec {
        bool initiator = false;
        omnetpp::simtime_t start = 0;
        double computeMs = 0.0;
        bool success = false;
    };

    int uavId_ = -1;
    int numUavs_ = 0;
    bool fullMesh_ = true;
    omnetpp::simtime_t peerAuthStart_ = 30;
    std::string suiteName_;
    std::string feProfile_;
    int localPort_ = 9300;
    int gsPort_ = 9200;
    int peerBasePort_ = 9300;

    std::unique_ptr<crypto::CryptoSuite> suite_;
    std::unique_ptr<crypto::Drbg> rng_;
    std::unique_ptr<puf::PufModel> puf_;
    std::unique_ptr<protocol::UavProtocol> proto_;
    fe::FeParams feParams_;

    inet::UdpSocket socket_;
    inet::L3Address gsAddr_;
    omnetpp::cMessage* startTimer_ = nullptr;
    omnetpp::cMessage* peerTimer_ = nullptr;

    omnetpp::simtime_t phase2Start_ = 0;
    bool phase2Success_ = false;
    double wallLatencyMs_ = 0.0;
    double p2ComputeMs_ = 0.0;
    size_t bytesSent_ = 0, bytesReceived_ = 0;

    /// Peer id -> address, filled by buildPeerTable().
    std::map<int, inet::L3Address> peerAddr_;
    std::map<int, PeerRec> peers_;
    double p3ComputeMs_ = 0.0;
    int p3Successes_ = 0;
};

} // namespace inet_apps
} // namespace uavauth

#endif
