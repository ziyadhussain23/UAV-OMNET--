import nodes.BaselineGroundStationNode;
import nodes.BaselineUavNode;
import nodes.WirelessMedium;

//
// Same Stadium perimeter layout and the same WirelessMedium delay model as
// UavAuthNetwork, running the RSA/ECDSA-signed baseline handshake
// (src/protocol/BaselineSigAuth.h) instead of the PUF-based protocol -- for a
// genuine same-platform, same-implementation, same-network-model latency
// comparison against Table~tab:latency's own numbers, not a bare primitive
// benchmark and not a literature figure.
//
network UavAuthNetworkBaseline
{
    parameters:
        int numUAVs = default(10);
        string sigSuite = default("rsa2048");
        @display("bgb=560,360");

    submodules:
        medium: WirelessMedium {
            @display("p=40,330");
        }
        groundStation: BaselineGroundStationNode {
            numUAVs = parent.numUAVs;
            sigSuite = parent.sigSuite;
            @display("p=275,175");
        }
        uav[numUAVs]: BaselineUavNode {
            uavId = index;
            sigSuite = parent.sigSuite;
            @display("p=$xpos,$ypos");
        }
    connections allowunconnected:
}
