pragma circom 2.0.0;

include "comparators.circom";

/* Checks that the private input signal is larger than the public input signal and both signals are expected to be of 64 bits */

component main {public [b]} = GreaterThan(64);
