package nodes;

//
// Ground station for the RSA/ECDSA baseline (see BaselineUavNode.ned). Public
// keys are exchanged once, out of band, in initialize() -- analogous to
// UavAuthNetwork's enrollAll(), but registering a public key rather than
// interrogating a PUF, since this baseline has no physical root of trust.
//
simple BaselineGroundStationNode
{
    parameters:
        int numUAVs;
        double xpos @unit(m) = default(275m);
        double ypos @unit(m) = default(175m);

        string sigSuite = default("rsa2048");
        int timestampWindowMs = default(5000);

        @display("i=device/antennatower");
        @signal[authSuccess](type=double);
        @signal[commOverhead](type=double);
        @statistic[authSuccess](title="handshake success"; record=count,sum);
        @statistic[commOverhead](title="bytes per message"; unit=B; record=vector,sum,mean,count);
    gates:
        input in @directIn;
}
