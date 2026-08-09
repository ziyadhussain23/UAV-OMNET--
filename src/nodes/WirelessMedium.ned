package nodes;

//
// The single transmission path for every protocol message.
//
// Centralising delivery gives one definition of the link-delay model (rather
// than the copy in each node type) and provides the relay an attacker needs:
// sendDirect has no channel object to intercept.
//
// With tapEnabled = false the medium forwards immediately, so baseline runs are
// behaviourally identical to a direct send.
//
simple WirelessMedium
{
    parameters:
        double linkBitrateBps = default(6e6);
        double propagationSpeedMps = default(299792458);
        double processingDelayMs = default(0.1);
        double jitterStddevMs = default(0.02);
        bool enableJitter = default(true);

        bool tapEnabled = default(false);
        // none | eavesdrop | credsniff | mitm | tamper
        string attackMode = default("none");

        @display("i=block/network2");
    gates:
        input in @directIn;
}
