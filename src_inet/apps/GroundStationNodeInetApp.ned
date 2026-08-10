package apps;

import inet.applications.contract.IApp;

//
// Ground-station side of the Phase 2 handshake over a real INET UDP/802.11
// stack. Enrollment (Phase 1) happens over a direct C++ call into each UAV
// host's app module, exactly as GroundStationNode::enrollAll() does on the
// non-INET track -- it is specified as an offline, trusted-channel step in
// both the paper and the original implementation, so it is not something a
// network model should add contention to.
//
simple GroundStationNodeInetApp like IApp
{
    parameters:
        int numUAVs;

        string suite = default("sha3");
        string feProfile = default("bch255-131-18");
        double assumedMinEntropyRate = default(0.95);
        int timestampWindowMs = default(5000);

        int localPort = default(9200);

        @display("i=device/antennatower");
    gates:
        input socketIn;
        output socketOut;
}
