import nodes.SmokeNode;

//
// Minimal network used by the Stage-0 build gate.
//
network SmokeNetwork
{
    submodules:
        smoke: SmokeNode;
}
