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
    sigwotsLen = ceil((version.a * version.k) / 8)
    xmssObject = XMSS(WOTS(WOTSParameter(version), version), version)
    if version in [sha2_128f, sha2_128s, sha2_192f, sha2_192s, sha2_256f, sha2_256s]:
        sizeAdrs = 22
    match (strFunction):
        case "xmss_node":
            md      = input1[:md]
            sk_seed = input1[md:md + version.n]
            pk_seed = input1[md + version.n:md + 2*version.n]
            address = obtainAddressObject(input1[md + 2*version.n:md + 2*version.n+sizeAdrs])
            return xmssObject._chain(key, beg, step, address)
        case "xmss_sign":
            wots_sign = input1[:sigwotsLen]
            md        = input1[sigwotsLen:sigwotsLen+mdLen]
            pk_seed   = input1[sigwotsLen+mdLen:sigwotsLen+mdLen+version.n]
            adrs      = obtainAddressObject(input1[sigwotsLen+mdLen+version.n:sigwotsLen+mdLen+version.n+sizeAdrs])
            return WOTS(WOTSParameter(version), version)._chain(key, beg, step, adrs)
        case "xmss_pkFromSig":
            wots_sign = input1[:sigwotsLen]
            md        = input1[sigwotsLen:sigwotsLen+mdLen]
            pk_seed   = input1[sigwotsLen+mdLen:sigwotsLen+mdLen+version.n]
            adrs      = obtainAddressObject(input1[sigwotsLen+mdLen+version.n:sigwotsLen+mdLen+version.n+sizeAdrs])
            return xmssObject._chain(key, beg, step, adrs)
        case "ht_sign":
            wots_sign = input1[:sigwotsLen]
            md        = input1[sigwotsLen:sigwotsLen+mdLen]
            pk_seed   = input1[sigwotsLen+mdLen:sigwotsLen+mdLen+version.n]
            adrs      = obtainAddressObject(input1[sigwotsLen+mdLen+version.n:sigwotsLen+mdLen+version.n+sizeAdrs])
            return xmssObject._chain(key, beg, step, adrs)
        case "ht_verify":
            wots_sign = input1[:sigwotsLen]
            md        = input1[sigwotsLen:sigwotsLen+mdLen]
            pk_seed   = input1[sigwotsLen+mdLen:sigwotsLen+mdLen+version.n]
            adrs      = obtainAddressObject(input1[sigwotsLen+mdLen+version.n:sigwotsLen+mdLen+version.n+sizeAdrs])
            return xmssObject._chain(key, beg, step, adrs)
        case _:
            raise Exception("Function not found") 
if __name__ == "__main__":
    main()
