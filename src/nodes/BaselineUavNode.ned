package nodes;

//
// One UAV, running the RSA/ECDSA-signed ephemeral-DH baseline handshake
// (src/protocol/BaselineSigAuth.h) instead of the PUF-based protocol --
// a real, fully implemented protocol run through the same WirelessMedium as
// UavNode, for a genuine same-platform latency comparison (see
// BaselineSigAuth.h's own header comment for the exact message shape).
//
// A separate node type from UavNode, not a runtime mode switch on it: this
// keeps the PUF-based protocol's own node code completely unmodified, at the
// cost of a small amount of duplication (the send/finish scaffolding), which
// this project's own style favours over a shared abstraction built for only
// two callers.
//
simple BaselineUavNode
{
    parameters:
        int uavId;
        double xpos @unit(m) @mutable = default(0m);
        double ypos @unit(m) @mutable = default(0m);

        // "rsa2048" | "ecdsa-p256"
        string sigSuite = default("rsa2048");
        double authStartTime @unit(s) = default(1s);
        int timestampWindowMs = default(5000);

        @display("i=misc/aircraft;is=s");
        @signal[authLatency](type=double);
        @signal[commOverhead](type=double);
        @statistic[authLatency](title="Baseline handshake latency"; unit=ms; record=vector,mean,max,count);
        @statistic[commOverhead](title="bytes per message"; unit=B; record=vector,sum,mean,count);
    gates:
        input in @directIn;
}
