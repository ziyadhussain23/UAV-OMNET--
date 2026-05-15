#ifndef UAVAUTH_NODES_NETWORKCONTROLLER_H
#define UAVAUTH_NODES_NETWORKCONTROLLER_H

#include <omnetpp.h>

class NetworkController : public omnetpp::cSimpleModule {
  private:
    omnetpp::simtime_t reportInterval;
    int numUavs;

  protected:
    virtual void initialize() override;
    virtual void handleMessage(omnetpp::cMessage* msg) override;
};

#endif
