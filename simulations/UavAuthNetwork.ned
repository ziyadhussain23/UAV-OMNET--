import nodes.AttackerNode;
import nodes.GroundStationNode;
import nodes.UavNode;
import nodes.WirelessMedium;

//
// Stadium-surveillance scenario: one ground station at the centre of a
// 500 x 300 m field with a ring of UAVs around the perimeter.
//
// Every submodule parameter is forwarded from a network-level parameter or left
// at its NED default. Nothing is hard-assigned, so the .ini file is authoritative
// for all of them -- the previous network fixed eight UAV parameters in the NED,
// which silently disabled the matching .ini lines and made one whole
// configuration measure something other than what it claimed.
//
network UavAuthNetwork
{
    parameters:
        int numUAVs = default(10);
        bool enableAttacker = default(false);
        string attackMode = default("eavesdrop");
        string suite = default("sha3");
        string feProfile = default("bch255-131-18");
        string pufModel = default("ideal");
        double pufNoiseBer = default(0.03);
        double assumedMinEntropyRate = default(0.95);
        @display("bgb=560,360");

    submodules:
        medium: WirelessMedium {
            @display("p=40,330");
        }
        groundStation: GroundStationNode {
            numUAVs = parent.numUAVs;
            suite = parent.suite;
            feProfile = parent.feProfile;
            pufModel = parent.pufModel;
            pufNoiseBer = parent.pufNoiseBer;
            assumedMinEntropyRate = parent.assumedMinEntropyRate;
            @display("p=275,175");
        }
        attacker[enableAttacker ? 1 : 0]: AttackerNode {
            attackMode = parent.attackMode;
            suite = parent.suite;
            @display("p=40,40");
        }
        uav[numUAVs]: UavNode {
            uavId = index;
            suite = parent.suite;
            feProfile = parent.feProfile;
            pufModel = parent.pufModel;
            pufNoiseBer = parent.pufNoiseBer;
            assumedMinEntropyRate = parent.assumedMinEntropyRate;
            @display("p=$xpos,$ypos");
        }
    connections allowunconnected:
        // No wired links: every message goes through the WirelessMedium module,
        // which owns the delay model and is the attacker's interception point.
}
