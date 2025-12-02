#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f, shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa.lowlevel._utils import trunc
from hashlib import sha256
def findShaObject(strFunction):
    match (strFunction):
        case "SLH_DSA_SHA2_128s":
            return sha2_128s
        case "SLH_DSA_SHA2_128f":
            return sha2_128f
        case "SLH_DSA_SHA2_192s":
            return sha2_192s
        case "SLH_DSA_SHA2_192f":
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
