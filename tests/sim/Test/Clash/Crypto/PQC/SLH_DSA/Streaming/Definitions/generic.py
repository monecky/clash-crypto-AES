#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f, sha2_192s, sha2_192f, sha2_256s, sha2_256f, shake_128s, shake_128f, shake_192s, shake_192f, shake_256s, shake_256f
from slhdsa.lowlevel._utils import trunc
from hashlib import sha256
from slhdsa.lowlevel.addresses import * # Import all address
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
def obtainAddressObject(adresBytes: [bytes]):
    if len(adresBytes) == 32:
        adrslayer         =  int.from_bytes(adresBytes[0:4] , "big")
        adrstree          =  int.from_bytes(adresBytes[4:16] , "big")
        adrstype          =  int.from_bytes(adresBytes[16:20], "big")
        adrskeypair       =  int.from_bytes(adresBytes[20:24], "big")
        adrschainheight   =  int.from_bytes(adresBytes[24:28], "big")
        adrshashindex     =  int.from_bytes(adresBytes[28:31], "big")
    elif len(adresBytes) == 22:
        adrslayer         =  adresBytes[0]
        adrstree          =  int.from_bytes(adresBytes[1:9]  , "big")
        adrstype          =  adresBytes[9]
        adrskeypair       =  int.from_bytes(adresBytes[10:14] , "big")
        adrschainheight   =  int.from_bytes(adresBytes[14:18], "big")
        adrshashindex     =  int.from_bytes(adresBytes[18:22], "big")
    else:
        raise Exception("Wrong size of address") 
    adrs = Address(0,0)
    match(adrstype):
        case 0:
            adrs = WOTSHashAddress(adrslayer, adrstree)
            adrs.keypair = adrskeypair
            adrs.chain   = adrschainheight
            adrs.hash    = adrshashindex
        case 1:
            adrs = WOTSPKAddress(adrslayer, adrstree)
            adrs.keypair = adrskeypair
        case 2:
            adrs = TreeAddress(adrslayer, adrstree)
            adrs.height  = adrschainheight
            adrs.index   = adrshashindex
        case 3:
            adrs = FORSTreeAddress(adrslayer, adrstree)
            adrs.keypair  = adrskeypair
            adrs.height   = adrschainheight
            adrs.index    = adrshashindex
        case 4:
            adrs = FORSRootsAddress(adrslayer, adrstree)
            adrs.keypair = adrskeypair
        case 5:
            adrs = WOTSPrfAddress(adrslayer, adrstree)
            adrs.keypair = adrskeypair
            adrs.chain   = adrschainheight
            adrs.hash    = adrshashindex
        case 6:
            adrs = FORSPrfAddress(adrslayer, adrstree)
            adrs.keypair = adrskeypair
            adrs.height  = adrschainheight
            adrs.index    = adrshashindex
        case _:
            raise Exception("Invalid address" + str(adrstype))
    return adrs