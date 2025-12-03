#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f, shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa.lowlevel._utils import trunc
from hashlib import sha256
from generic import *
from math import ceil
from slhdsa.lowlevel.addresses import * 
from slhdsa.lowlevel.wots import WOTS
from slhdsa.lowlevel.xmss import XMSS
from slhdsa.lowlevel._utils import compact_address
from slhdsa.lowlevel.hypertree import HyperTree
def main():
    if len(sys.argv) != 4:
        print("Usage: ht_worker.py <function> <slh-dsaVersion> <input>", file=sys.stderr)
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
    htObject = HyperTree(version)
    if version in [sha2_128f, sha2_128s, sha2_192f, sha2_192s, sha2_256f, sha2_256s]:
        sizeAdrs = 22
    match (strFunction):
        case "ht_sign":
            msg           = input1[:version.n]
            sk_seed       = input1[version.n:2*version.n]
            pk_seed       = input1[2*version.n:3*version.n]
            tree_idx      = int.from_bytes(input1[3*version.n:3*version.n+intergerSize], "big")
            leaf_idx      = int.from_bytes(input1[3*version.n+intergerSize:3*version.n+2*intergerSize], "big")
            return htObject.sign(msg, sk_seed, pk_seed, tree_idx, leaf_idx)
        case "ht_verify":
            msg           = input1[:version.n]
            ht_sign       = input1[version.n : 2*version.n * (version.h + version.d * WOTSParameter(version).len)] # TODO: wrong
            sk_seed       = input1[2*version.n * (version.h + version.d * WOTSParameter(version).len):3*version.n * (version.h + version.d * WOTSParameter(version).len)]
            pk_seed       = input1[3*version.n * (version.h + version.d * WOTSParameter(version).len):4*version.n * (version.h + version.d * WOTSParameter(version).len)]
            pk_root       = input1[4*version.n * (version.h + version.d * WOTSParameter(version).len):5*version.n * (version.h + version.d * WOTSParameter(version).len)]
            tree_idx      = int.from_bytes(input1[5*version.n * (version.h + version.d * WOTSParameter(version).len):5*version.n * (version.h + version.d * WOTSParameter(version).len) + intergerSize], "big")
            leaf_idx      = int.from_bytes(input1[5*version.n * (version.h + version.d * WOTSParameter(version).len)+ intergerSize:5*version.n * (version.h + version.d * WOTSParameter(version).len) + intergerSize*2], "big")
            return htObject.verify(msg, ht_sign, sk_seed, pk_seed, pk_root, tree_idx, leaf_idx)
        case _:
            raise Exception("Function not found") 
if __name__ == "__main__":
    main()
