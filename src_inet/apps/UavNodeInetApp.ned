package apps;

import inet.applications.contract.IApp;

//
// Phases 2 and 3 driven over a real INET UDP/802.11 stack instead of the
// idealised WirelessMedium: same protocol::UavProtocol object, same crypto
// suites, same PUF models, different transport. Reuses core/crypto/protocol/
// puf/fe from ../../src unmodified -- only the transport is new.
//
// Scope: Phases 2 and 3. The attacker's interception hook is not ported to
// this track; INET's real gate/channel topology has no single relay point to
// intercept, unlike the sendDirect-based WirelessMedium, so no attack results
// are claimed here.
//
// Phase 3 runs over the same UDP socket as Phase 2, on peerPort, and the
// sending peer is identified by its network address (the peer table built at
// the first event) because P2 and P3 carry no identity field on the wire.
//
simple UavNodeInetApp like IApp
{
    parameters:
        // Superseded by the host's own index (getIndex()); kept only so a
        // config that still sets it does not fail. The code ignores it, because
        // `uavId = index` under a two-wildcard pattern silently gives every
        // device 0, which collides on the per-device port.
        int uavId = default(-1);
        int numUAVs = default(10);

        string suite = default("sha3");
        string feProfile = default("bch255-131-18");
        double assumedMinEntropyRate = default(0.95);

        string pufModel = default("ideal");
        double pufNoiseBer = default(0.03);

        double authStartTime @unit(s) = default(1s);
        double peerAuthStartTime @unit(s) = default(30s);
        bool fullMesh = default(true);
        int timestampWindowMs = default(5000);

        // Each UAV binds peerBasePort + uavId. The GS listens on gsPort, which
        // sits outside the peer range, so a source port alone names a sender.
        int peerBasePort = default(9300);
        int gsPort = default(9200);

        @display("i=misc/aircraft;is=s");
    gates:
        input socketIn;
        output socketOut;
}
