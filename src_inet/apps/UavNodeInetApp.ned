package apps;

import inet.applications.contract.IApp;

//
// Phase 2 (GS<->UAV) driven over a real INET UDP/802.11 stack instead of the
// idealised WirelessMedium: same protocol::UavProtocol object, same crypto
// suites, same PUF models, different transport. Reuses core/crypto/protocol/
// puf/fe from ../../src unmodified -- only the transport is new.
//
// Scope: Phase 2 only. Phase 3 (peer-to-peer) traffic and the attacker's
// interception hook are not ported to this track; see docs in ../../README.md
// for why (INET's real gate/channel topology has no single relay point to
// intercept, unlike the sendDirect-based WirelessMedium).
//
simple UavNodeInetApp like IApp
{
    parameters:
        int uavId;

        string suite = default("sha3");
        string feProfile = default("bch255-131-18");
        double assumedMinEntropyRate = default(0.95);

        string pufModel = default("ideal");
        double pufNoiseBer = default(0.03);

        double authStartTime @unit(s) = default(1s);
        int timestampWindowMs = default(5000);

        int localPort = default(9300);
        int gsPort = default(9200);

        @display("i=misc/aircraft;is=s");
    gates:
        input socketIn;
        output socketOut;
}
