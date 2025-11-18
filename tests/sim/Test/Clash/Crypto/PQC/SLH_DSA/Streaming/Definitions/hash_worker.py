#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f, shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa.lowlevel._utils import trunc
from hashlib import sha256
def main():
    if len(sys.argv) != 4:
        print("Usage: hash_worker.py <function> <shaVersion> <input>", file=sys.stderr)
        sys.exit(1)
    function = sys.argv[1]
    shaVersion = sys.argv[2]
    shaObject = findShaObject(shaVersion)
    input1 = binascii.unhexlify(sys.argv[3])
    result = calculateResult(function, input1, shaObject)
    print(binascii.hexlify(result).decode())
    
def findShaObject(strFunction):
    match (strFunction):
        case "SLH_DSA_SHA2_128s":
            return sha2_128s
        case "SLH_DSA_SHA2_128f":
            return sha2_128f
        case "SLH_DSA_SHA2_129s":
            return sha2_192s
        case "SLH_DSA_SHA2_":
            return sha2_192f
        case "SLH_DSA_SHA2_256s":
            return sha2_256s
        case "SLH_DSA_SHA2_256f":
            return sha2_256f
        case "SLH_DSA_SHAKE_128s":
            return shake_128s
        case "SLH_DSA_SHAKE_128f":
            return shake_128f
        case "SLH_DSA_SHAKE_192s":
            return shake_192s
        case "SLH_DSA_SHAKE_192f":
            return shake_192f
        case "SLH_DSA_SHAKE_256s":
            return shake_256s
        case "SLH_DSA_SHAKE_256f":
            return shake_256f
        case _:
            print("No match for the version", file=sys.stderr)
            return "Not found"

def calculateResult(strFunction, input1, version):
    match (strFunction):
        case "PRFmsg":
            sk_prf = input1[0]
            opt_rand = input1[1]
            msg = input1[2]
            return version.PRFmsg(sk_prf, opt_rand, msg)
        case "Hmsg":
            sk_prf = input1[0]
            opt_rand = input1[1]
            msg = input1[2]
            refResult = version.Hmsg(sk_prf, opt_rand, msg)
            return version.Hmsg
        case "PRF":
            pkSeed = input1[0]
            cmp_adrs = input1[2]
            sk_seed = input1[1]
            return trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + sk_seed).digest(), version.n)
        case "Tl":
            pkSeed = input1[0]
            cmp_adrs = input1[1]
            m = input1[2]
            return trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)
        case "H":
            pkSeed = input1[:version.n]
            cmp_adrs = input1[version.n:version.n + 22]
            m = input1[version.n + 22:]
            return trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)
        case "F":
            pkSeed = input1[:version.n]
            cmp_adrs = input1[version.n:version.n + 22]
            m = input1[version.n + 22:]
            return trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)
        case _:
            print("No match for the function", file=sys.stderr)
            return "Not found"
if __name__ == "__main__":
    main()
