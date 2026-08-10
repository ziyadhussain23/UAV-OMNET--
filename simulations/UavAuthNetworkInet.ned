import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211ScalarRadioMedium;

//
// Same Stadium perimeter layout as UavAuthNetwork (see omnetpp_inet.ini for
// the coordinates, mirrored from omnetpp.ini), but the transport is a real
// INET 802.11 ad-hoc stack (Ieee80211ScalarRadioMedium, real CSMA/CA) instead
// of WirelessMedium's idealised propagation+serialization+jitter model.
//
// All app-level parameters (uavId, suite, ...) are forwarded from the .ini
// file via the standard INET **.host.app[0].param pattern, not from NED --
// AdhocHost is an unmodified INET type, not a type this project owns, so
// there is no network-level parameter to forward through here.
//
network UavAuthNetworkInet
{
    parameters:
        int numUAVs = default(10);
        @display("bgb=560,360");
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=40,40;is=s");
        }
        radioMedium: Ieee80211ScalarRadioMedium {
            @display("p=40,90;is=s");
        }
        groundStation: AdhocHost {
            @display("p=275,175");
        }
        uav[numUAVs]: AdhocHost {
            @display("p=100,100");
        }
}
