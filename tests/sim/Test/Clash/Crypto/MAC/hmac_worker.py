#!/usr/bin/env python3
import sys
import binascii
import hashlib

# These translation tables mimic CPython's internal approach
trans_36 = bytes((x ^ 0x36) for x in range(256))
trans_5C = bytes((x ^ 0x5C) for x in range(256))

try:
    import _hashopenssl
    _functype = type(lambda: None)
except ImportError:
    _hashopenssl = None
    _functype = type(lambda: None)

def digest(key, msg, digest):
    """Fast inline implementation of HMAC."""

    if _hashopenssl is not None and isinstance(digest, (str, _functype)):
        try:
            return _hashopenssl.hmac_digest(key, msg, digest)
        except _hashopenssl.UnsupportedDigestmodError:
            pass

    if callable(digest):
        digest_cons = digest
    elif isinstance(digest, str):
        digest_cons = lambda d=b'': hashlib.new(digest, d)
    else:
        digest_cons = lambda d=b'': digest.new(d)

    inner = digest_cons()
    outer = digest_cons()
    blocksize = getattr(inner, 'block_size', 64)

    if len(key) > blocksize:
        key = digest_cons(key).digest()

    key = key + b'\x00' * (blocksize - len(key))

    inner.update(key.translate(trans_36))
    outer.update(key.translate(trans_5C))
    inner.update(msg)
    outer.update(inner.digest())
    return outer.digest()

def main():
    if len(sys.argv) != 5:
        print("Usage: hmac_worker.py <hexKey> <hexMsg> <digestName> <blocksize>", file=sys.stderr)
        sys.exit(1)

    hex_key, hex_msg, digest_name, blocksize = sys.argv[1:]

    key = binascii.unhexlify(hex_key)
    msg = binascii.unhexlify(hex_msg)

    result = digest(key, msg, digest_name)

    # print hex result for Haskell to parse
    print(binascii.hexlify(result).decode())

if __name__ == "__main__":
    main()
