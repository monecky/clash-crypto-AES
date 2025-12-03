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
    sigwotsLen = ceil((version.a * version.k) / 8)
    if version in [sha2_128f, sha2_128s, sha2_192f, sha2_192s, sha2_256f, sha2_256s]:
        sizeAdrs = 22
    match (strFunction):
        case "chain":
            key     = input1[:version.n]
            pk_seed = input1[version.n:version.n*2]
            address = obtainAddressObject(input1[version.n*2:version.n*2+sizeAdrs])
            beg     = int.from_bytes(input1[version.n*2+sizeAdrs:version.n*2+sizeAdrs + intergerSize], "big")
            step    = int.from_bytes(input1[version.n*2+sizeAdrs + intergerSize:version.n*2+sizeAdrs + 2*intergerSize], "big")
            return WOTS(WOTSParameter(version), version)._chain(key, beg, step, pk_seed, address)
        case "wots_pkGen":
            sk_seed = input1[:version.]
            pk_seed = input1[version.n:2*version.n]
            address = obtainAddressObject(input1[2*version.n:2*version.n+sizeAdrs])
            return  WOTS(WOTSParameter(version), version).generate_publickey(sk_seed, pk_seed, address)
        case "wots_sign":
            msg_    = input1[:version.n]
            sk_seed = input1[version.n:2*version.n]
            pk_seed = input1[2*version.n:3*version.n]
            address = int.from_bytes(input1[3*version.n+sizeAdrs:3*version.n+sizeAdrs], "big")
            return  WOTS(WOTSParameter(version), version).sign(msg_, sk_seed, pk_seed, address)
        case "wots_pkFromSig":
            sig     = input1[:version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n]
            msg_    = input1[version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n:version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n + version.n]
            pk_seed = input1[version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n + version.n:version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n + 2*version.n]
            address = obtainAddressObject(input1[version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n + version.n:version.d * (version.h_m + version.h_m *(WOTSParameter(version).len)) * version.n + 2*version.n + sizeAdrs])
            return WOTS(version).publickey_from_sign(sig, msg_, pk_seed, address)
        case _:
            raise Exception("Function not found") 
if __name__ == "__main__":
    main()
