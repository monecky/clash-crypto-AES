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
from slhdsa.lowlevel.fors import FORS
from slhdsa.lowlevel._utils import compact_address
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

def calculateResult(strFunction, input1, version):
    sizeAdrs = 32
    intergerSize = 32
    mdLen = version.k * (version.a + 1) * version.n
    sigForsLen = ceil((version.a * version.k) / 8)
    if version in [sha2_128f, sha2_128s, sha2_192f, sha2_192s, sha2_256f, sha2_256s]:
        sizeAdrs = 22
    match (strFunction):
        case "fors_skGen":
            sk_seed = input1[:version.n]
            pk_seed = input1[version.n:version.n + version.n]
            address = obtainAddressObject(input1[2*version.n:2*version.n+sizeAdrs])
            idx     = int.from_bytes(input1[2*version.n+sizeAdrs:intergerSize+2*version.n+sizeAdrs], "big")
            return FORS(version).generate_secretkey(sk_seed, pk_seed, address, idx)
        case "fors_skGen_adrs":
            sk_seed = input1[:version.n]
            pk_seed = input1[version.n:version.n + version.n]
            address = obtainAddressObject(input1[2*version.n:2*version.n+sizeAdrs])
            idx     = int.from_bytes(input1[2*version.n+sizeAdrs:intergerSize+2*version.n+sizeAdrs], "big")
            sk_address = address.with_type(FORSPrfAddress)
            sk_address.keypair = address.keypair
            sk_address.index = idx
            return  compact_address(sk_address.to_bytes())
        case "fors_node":
            sk_seed = input1[:version.n]
            pk_seed = input1[version.n:2*version.n]
            address = obtainAddressObject(input1[2*version.n:2*version.n+sizeAdrs])
            cur     = input1[2*version.n+sizeAdrs:intergerSize+2*version.n+sizeAdrs]
            dep     = input1[intergerSize+2*version.n+sizeAdrs:2*intergerSize+2*version.n+sizeAdrs]
            return FORS(version).node(sk_seed, pk_seed, address, idx)
        case "fors_sign":
            md      = input1[:md]
            sk_seed = input1[md:md + version.n]
            pk_seed = input1[md + version.n:md + 2*version.n]
            address = obtainAddressObject(input1[md + 2*version.n:md + 2*version.n+sizeAdrs])
            return FORS(version).sign(sk_seed, pk_seed, address, idx)
        case "fors_pkFromSig":
            fors_sign = input1[:sigForsLen]
            md        = input1[sigForsLen:sigForsLen+mdLen]
            pk_seed   = input1[sigForsLen+mdLen:sigForsLen+mdLen+version.n]
            adrs      = obtainAddressObject(input1[sigForsLen+mdLen+version.n:sigForsLen+mdLen+version.n+sizeAdrs])
            return FORS(version).publickey_from_sign(sk_seed, pk_seed, address, idx)
        case _:
            raise Exception("Function not found") 
if __name__ == "__main__":
    main()
