package nodes;

//
// Adversary against the running protocol. Registers itself with the medium, so a
// run without an attacker keeps the medium's fast path and stays behaviourally
// identical to an unattacked run.
//
simple AttackerNode
{
    parameters:
        // none | eavesdrop | credsniff | tamper | mitm | gsimpersonate | replay
        string attackMode = default("eavesdrop");
        int targetUav = default(0);
        int maxAttempts = default(100);
        string suite = default("sha3");
        double xpos @unit(m) = default(20m);
        double ypos @unit(m) = default(20m);

        // True only for the legacy control arm, where the attack is SUPPOSED to
        // work. Lets each run assert its own expected outcome.
        bool expectSuccess = default(false);

        @display("i=misc/globe;i2=status/red");
    gates:
        input in @directIn;
}
