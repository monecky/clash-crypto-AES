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
def main():
    if len(sys.argv) != 4:
        print("Usage: wots_worker.py <function> <slh-dsaVersion> <input>", file=sys.stderr)
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
        case "xmss_node":
            sk_seed = input1[:version.n]
            pk_seed = input1[version.n:2*version.n]
            address = obtainAddressObject(input1[2*version.n:2*version.n+sizeAdrs])
            cur     = int.from_bytes(input1[2*version.n+sizeAdrs:2*version.n+sizeAdrs + intergerSize])
            dep     = int.from_bytes(input1[2*version.n+sizeAdrs + intergerSize:2*version.n+sizeAdrs + 2*intergerSize])
            return xmssObject.node(sk_seed,cur,dep,pk_seed,address)
        case "xmss_sign":
            msg       = input1[:version.n]
            sk_seed   = input1[version.n:2*version.n]
            pk_seed   = input1[2*version.n:3*version.n]
            adrs      = obtainAddressObject(input1[3 * version.n:3 * version.n+sizeAdrs])
            idx       = int.from_bytes(input1[3 * version.n+sizeAdrs:3 * version.n+sizeAdrs+intergerSize])
            return xmssObject.sign()
        case "xmss_pkFromSig":
            sig1       = input1[:sig]
            msg       = input1[sig:sig + version.n]
            pk_seed   = input1[sig + version.n:sig + 2 * version.n]
            adrs      = obtainAddressObject(input1[sig + 2 * version.n:sig + 2 * version.n+sizeAdrs])
            idx       = int.from_bytes(input1[sig + 2 * version.n+sizeAdrs:sig + 2 * version.n+sizeAdrs+intergerSize])
            return xmssObject.public_key_from_sign(sig1, msg, pk_seed, adrs, idx)
        case _:
            raise Exception("Function not found") 
if __name__ == "__main__":
    main()
