#!/usr/bin/env python3
import sys
import binascii
from slhdsa.lowlevel.parameters import hmac_digest

def main():
    if len(sys.argv) != 4:
        print("Usage: hmac_worker.py <hexKey> <hexMsg> <digestName> [blocksize]", file=sys.stderr)
        sys.exit(1)

    hex_key, hex_msg, digest_name = sys.argv[1:4]

    key = binascii.unhexlify(hex_key)
    msg = binascii.unhexlify(hex_msg)

    # blocksize argument is optional, ignore if present
    result = hmac_digest(key, msg, digest_name)
    print(binascii.hexlify(result).decode())

if __name__ == "__main__":
    main()
