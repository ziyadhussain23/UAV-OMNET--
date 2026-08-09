package nodes;

simple GroundStation
{
    parameters:
        int numUAVs = default(10);
        int numCRPsPerUAV = default(12);
        int pufSeedBase = default(1000);
        int responseDistanceThreshold = default(24);
        double defaultPUFNoise = default(0.03);
        int timestampWindowMs = default(5000);
        double linkBitrateBps @unit(bps) = default(6Mbps);
        double propagationSpeedMps @unit(mps) = default(299792458mps);
        double processingDelayMean @unit(s) = default(0.1ms);
        double queueJitterStddev @unit(s) = default(0.02ms);
        bool enableRandomJitter = default(true);
        string hashMode = default("sha3");  // "sha3" or "spongent"
        @display("i=device/antennatower");
    gates:
        input in;
}
