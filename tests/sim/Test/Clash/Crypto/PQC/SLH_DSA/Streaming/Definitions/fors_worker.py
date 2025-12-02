#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f, shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa.lowlevel._utils import trunc
from hashlib import sha256
from generic import *
def main():
    if len(sys.argv) != 4:
        print("Usage: fors_worker.py <function> <slh-dsaVersion> <input>", file=sys.stderr)
        sys.exit(1)
    function = sys.argv[1]
    shaVersion = sys.argv[2]
    shaObject = findShaObject(shaVersion)
    input1 = binascii.unhexlify(sys.argv[3])
    result = calculateResult(function, input1, shaObject)
    print(binascii.hexlify(result).decode())
    
 

def calculateResult(strFunction, input1, version):
    match (strFunction):
        case "PRFmsg":
            sk_prf = input1[:version.n]
            opt_rand = input1[version.n:version.n + version.n]
            msg = input1[version.n + version.n:]
            return version.PRFmsg(sk_prf, opt_rand, msg)
        case "PRFmsgthr":
            sk_prf = input1[:version.n]
            opt_rand = input1[version.n:version.n + version.n]
            msg = input1[version.n + version.n:]
            return input1[:len(version.PRFmsg(sk_prf, opt_rand, msg))]
        case "PRFmsgFthr":
            sk_prf = input1[:version.n]
            sk_prf = sk_prf + b'\x00' * (64 - version.n )
            opt_rand = input1[version.n:version.n + version.n]
            msg = input1[version.n + version.n:]
            return sk_prf + opt_rand + msg
        case "Hmsg":
            r = input1[:version.n]
            pk_seed = input1[version.n:2*version.n]
            pk_root = input1[2*version.n:3* version.n]
            msg = input1[3*version.n:]
            if version == sha2_128f:
                return version.Hmsg(r, pk_seed, pk_root, msg)[:version.m] # As it should be according to the documentation of NIST FIPS 205.
            return version.Hmsg(r, pk_seed, pk_root, msg)
        case "PRF":
            pkSeed = input1[:version.n]
            sk_seed = input1[version.n:version.n + version.n]
            cmp_adrs = input1[version.n + version.n:]
            return trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + sk_seed).digest(), version.n)
        case "Tl":
            pkSeed = input1[:version.n]
            cmp_adrs = input1[version.n:version.n + 22]
            m = input1[version.n + 22:]
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
