package nodes;

//
// One UAV. Runs Phase 2 against the ground station, then Phase 3 with peers.
//
// Every parameter is declared with default(), so an .ini file can override it.
// The previous network hard-assigned eight of these, which silently voided the
// corresponding .ini lines -- that is why the old HighNoise configuration
// actually ran at 3% noise while claiming 5%.
//
simple UavNode
{
    parameters:
        int uavId;
        // @mutable: the mobility models below move a UAV by writing these at
        // runtime (WirelessMedium re-reads them fresh on every message, so no
        // other code needs to change for that to take effect).
        double xpos @unit(m) @mutable = default(0m);
        double ypos @unit(m) @mutable = default(0m);

        // "sha3" (software profile) | "spongent" (constrained-hardware profile)
        string suite = default("sha3");
        // bch255-131-18 | bch255-91-25 | rep3-bch255-131-18
        string feProfile = default("bch255-131-18");
        double assumedMinEntropyRate = default(0.95);

        // "ideal" (keyed PRF stand-in) | "arbiter" (additive-delay model)
        string pufModel = default("ideal");
        double pufNoiseBer = default(0.03);

        double authStartTime @unit(s) = default(1s);
        double peerAuthStartTime @unit(s) = default(10s);
        bool fullMesh = default(true);
        int timestampWindowMs = default(5000);

        // "static" (perimeter position, never moves) | "linear" (constant
        // velocity, reflects off the field boundary) | "randomwalk" (new
        // random heading each update tick, reflects off the field boundary)
        string mobilityModel = default("static");
        double mobilitySpeedMps = default(5.0);
        double mobilityHeadingDeg = default(45.0);
        double mobilityUpdateIntervalMs = default(100.0);
        double fieldWidthM @unit(m) = default(500m);
        double fieldHeightM @unit(m) = default(300m);

        // "hardened" (the specified protocol) | "legacy" (the audited protocol,
        // used only as the security control arm)
        string protocolVariant = default("hardened");

        @display("i=misc/aircraft;is=s");
        @signal[authLatency](type=double);
        @signal[peerAuthLatency](type=double);
        @signal[commOverhead](type=double);
        @statistic[authLatency](title="Phase 2 latency"; unit=ms; record=vector,mean,max,count);
        @statistic[peerAuthLatency](title="Phase 3 latency"; unit=ms; record=vector,mean,max,count);
        @statistic[commOverhead](title="bytes per message"; unit=B; record=vector,sum,mean,count);
    gates:
        input in @directIn;
}
