pragma circom 2.1.6;

include "circomlib/circuits/poseidon.circom";

template MerkleMembership(depth) {
    signal input root;
    signal input nodeId;
    signal input leafType;
    signal input leafParent;
    signal input leafLabel;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    component leafH = Poseidon(4);
    leafH.inputs[0] <== nodeId;
    leafH.inputs[1] <== leafType;
    leafH.inputs[2] <== leafParent;
    leafH.inputs[3] <== leafLabel;

    component hashers[depth];
    signal cur[depth + 1];
    signal left[depth];
    signal right[depth];
    cur[0] <== leafH.out;

    for (var i = 0; i < depth; i++) {
        pathIndices[i] * (pathIndices[i] - 1) === 0;

        left[i]  <== cur[i] + pathIndices[i] * (pathElements[i] - cur[i]);
        right[i] <== pathElements[i] + pathIndices[i] * (cur[i] - pathElements[i]);

        hashers[i] = Poseidon(2);
        hashers[i].inputs[0] <== left[i];
        hashers[i].inputs[1] <== right[i];
        cur[i + 1] <== hashers[i].out;
    }

    root === cur[depth];
}

component main {public [root, nodeId]} = MerkleMembership(14);
