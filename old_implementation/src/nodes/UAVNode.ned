package nodes;

simple UAVNode
{
    parameters:
        int uavId = default(0);
        int pufSeed = default(1000);
        double pufNoiseLevel = default(0.03);
        string tempId = default("UAV_0");
        string hashMode = default("sha3");  // "sha3" or "spongent"
        double authStartTime @unit(s) = default(1s);
        double peerAuthStartTime @unit(s) = default(10s);
        double linkBitrateBps @unit(bps) = default(6Mbps);
        double propagationSpeedMps @unit(mps) = default(299792458mps);
        double processingDelayMean @unit(s) = default(0.1ms);
        double queueJitterStddev @unit(s) = default(0.02ms);
        bool enableRandomJitter = default(true);
        int peerTargetId = default(-1);
        @display("i=misc/aircraft");
    gates:
        input in;
}
