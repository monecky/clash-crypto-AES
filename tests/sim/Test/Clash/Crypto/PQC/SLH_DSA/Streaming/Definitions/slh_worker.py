#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f, shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa.lowlevel._utils import trunc
from hashlib import sha256
from generic import *
from math import ceil
from slhdsa.lowlevel.addresses import * # Import all address
from slhdsa.lowlevel.wots import WOTS
from slhdsa.lowlevel.xmss import XMSS
from slhdsa.lowlevel._utils import compact_address
import slhdsa.lowlevel.slhdsa as lowlevel
def main():
    if len(sys.argv) != 4:
        print("Usage: slh_worker.py <function> <slh-dsaVersion> <input>", file=sys.stderr)
        sys.exit(1)
    function = sys.argv[1]
    shaVersion = sys.argv[2]
    shaObject = findShaObject(shaVersion)
    input1 = binascii.unhexlify(sys.argv[3])
    result = calculateResult(function, input1, shaObject)
    print(binascii.hexlify(result).decode())
    


def calculateResult(strFunction, input1, version):
    sizeAdrs = 32
    intergerSize = 32
    mdLen = version.k * (version.a + 1) * version.n
    sig = version.h_m * m + WOTS(WOTSParameter(version)).len * version.n
    xmssObject = XMSS(WOTS(WOTSParameter(version), version), version)
    if version in [sha2_128f, sha2_128s, sha2_192f, sha2_192s, sha2_256f, sha2_256s]:
        sizeAdrs = 22
    match (strFunction):
        case "sign":
            msg       = input1[:-4*version.n]
            secret_key= [
                input1[-4*version.n:-3*version.n]
                , input1[-3*version.n:-2*version.n]
                , input1[-2*version.n:-version.n]
                , input1[-version.n:]
            ]
            randomize = False
            return lowlevel.sign(msg, secret_key, version, randomize)
        case "verify":
            msg       = input1[:-(sig + 2*version.n)]
            sig1       = input1[-(sig + 2*version.n):-2*version.n]
            public_key= [
                input1[-2*version.n:-version.n]
                , input1[-version.n:]
            ]
            return lowlevel.verify(msg, sig1, public_key, version)
        case _:
            raise Exception("Function not found") 
if __name__ == "__main__":
    main()
