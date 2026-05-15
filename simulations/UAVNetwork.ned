import nodes.GroundStation;
import nodes.NetworkController;
import nodes.UAVNode;

// Stadium Air Protection Network
// Area: 500m x 300m (typical stadium coverage)
// 10 UAVs positioned around perimeter for full coverage
// Ground station at center (250m, 150m)
network UAVAuthNetwork
{
    parameters:
        int numUAVs = default(10);
        string hashMode = default("sha3");  // "sha3" or "spongent"
        @display("bgb=550,350");  // Scale: 1 pixel = ~1 meter
    submodules:
        controller: NetworkController {
            parameters:
                numUAVs = parent.numUAVs;
                reportInterval = 15s;
                @display("p=50,30");
        }

        groundStation: GroundStation {
            parameters:
                numUAVs = parent.numUAVs;
                hashMode = parent.hashMode;
                @display("p=275,175;i=device/antennatower;is=l");
        }

        // 10 UAVs positioned around stadium perimeter
        // UAVs 0-3: Long sides (100m from sides)
        // UAVs 4-7: End zones
        // UAVs 8-9: Center hovering above field
        uav[numUAVs]: UAVNode {
            parameters:
                uavId = index;
                pufSeed = 1000 + index;
                pufNoiseLevel = 0.03;
                tempId = "UAV_" + string(index);
                hashMode = parent.hashMode;
                authStartTime = 1s + index * 0.5s;
                peerAuthStartTime = 10s + index * 0.5s;
                peerTargetId = (index + 1) % parent.numUAVs;
                @display("p=$xpos,$ypos;i=misc/aircraft;is=s");
        }
    connections allowunconnected:
}
