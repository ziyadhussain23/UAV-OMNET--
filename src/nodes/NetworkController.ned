package nodes;

simple NetworkController
{
    parameters:
        int numUAVs = default(5);
        double reportInterval @unit(s) = default(10s);
        @display("i=block/control");
}
