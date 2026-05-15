#include "NetworkController.h"

using namespace omnetpp;

Define_Module(NetworkController);

void NetworkController::initialize() {
    reportInterval = par("reportInterval");
    numUavs = par("numUAVs").intValue();

    if (reportInterval > SIMTIME_ZERO) {
        scheduleAt(simTime() + reportInterval, new cMessage("controllerReport"));
    }
}

void NetworkController::handleMessage(cMessage* msg) {
    EV_INFO << "[Controller] simTime=" << simTime() << " numUAVs=" << numUavs << "\n";
    scheduleAt(simTime() + reportInterval, msg);
}
