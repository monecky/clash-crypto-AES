#!/usr/bin/env python3
import sys
import binascii
import hashlib
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f , hmac_digest


def main():
    if len(sys.argv) != 5:
        print("Usage: hmac_worker.py <hexKey> <hexMsg> <digestName> <blocksize>", file=sys.stderr)
        sys.exit(1)

    hex_key, hex_msg, digest_name, blocksize = sys.argv[1:]

    key = binascii.unhexlify(hex_key)
    msg = binascii.unhexlify(hex_msg)

    result = hmac_digest(key, msg, digest_name)

    # print hex result for Haskell to parse
    print(binascii.hexlify(result).decode())

if __name__ == "__main__":
    main()
