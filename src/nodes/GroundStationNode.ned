package nodes;

//
// Ground station: enrollment authority and Phase-2 peer.
//
// Enrollment happens in initialisation stage 1, after every UAV has constructed
// its PUF in stage 0, so the ground station interrogates each device's own PUF
// instance over the trusted channel rather than holding a copy of the silicon.
//
simple GroundStationNode
{
    parameters:
        int numUAVs;
        double xpos @unit(m) = default(275m);
        double ypos @unit(m) = default(175m);

        string suite = default("sha3");
        string feProfile = default("bch255-131-18");
        double assumedMinEntropyRate = default(0.95);

        string pufModel = default("ideal");
        double pufNoiseBer = default(0.03);

        int timestampWindowMs = default(5000);

        @display("i=device/receiverdish");
        @signal[authSuccess](type=double);
        @signal[commOverhead](type=double);
        @statistic[authSuccess](title="authentication outcome"; record=vector,mean,count);
        @statistic[commOverhead](title="bytes per message"; unit=B; record=vector,sum,mean,count);
    gates:
        input in @directIn;
}
