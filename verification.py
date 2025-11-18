# type: ignore
from hashlib import sha256
from typing import no_type_check

from _hashlib import compare_digest, hmac_digest
from slhdsa.lowlevel._utils import compact_address, trunc
from slhdsa.lowlevel.parameters import sha2_128s, sha2_128f #, hmac_digest  # type: ignore
from slhdsa import KeyPair, shake_256f, PublicKey
from slhdsa.lowlevel.addresses import Address, WOTSHashAddress

from slhdsa.lowlevel.addresses import Address

counter = 0
f = open("hash_test_results.csv")
# print(f.read())
f = f.read().split("\n")
f.remove('')
passedAll = True
for test in f:
    test = test.split(";")
    version = "Not matched yet"
    x, input, dutResult = test[2].split(",")
    input_bytes_len = (len(input.replace("_", ""))) // 8
    input = int(input.replace("_", ""), 2)
    b = input.to_bytes(input_bytes_len, "big")

    dutResult_bytes_len = (len(dutResult.replace("_", ""))) // 8
    dutResult = int(dutResult.replace("_", ""), 2)
    dutResult = dutResult.to_bytes(dutResult_bytes_len, "big")
    refResult = "Not working"
    match (test[1],test[0]):
        case("SLH_DSA_SHA2_128s", "H"):
            version = sha2_128s
            pkSeed = b[:version.n]
            cmp_adrs = b[version.n:version.n + 22]
            m = b[version.n + 22:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)

        case("SLH_DSA_SHA2_128f", "H"):
            version = sha2_128f
            pkSeed = b[:version.n]
            cmp_adrs = b[version.n:version.n + 22]
            m = b[version.n + 22:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)
        case ("SLH_DSA_SHA2_128s", "F"):
            version = sha2_128s
            pkSeed = b[:version.n]
            cmp_adrs = b[version.n:version.n + 22]
            m = b[version.n + 22:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)

        case ("SLH_DSA_SHA2_128f", "F"):
            version = sha2_128f
            pkSeed = b[:version.n]
            cmp_adrs = b[version.n:version.n + 22]
            m = b[version.n + 22:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)
        case ("SLH_DSA_SHA2_128s", "Tl"):
            version = sha2_128s
            pkSeed = b[:version.n]
            cmp_adrs = b[version.n:version.n + 22]
            m = b[version.n + 22:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)

        case ("SLH_DSA_SHA2_128f", "Tl"):
            version = sha2_128f
            pkSeed = b[:version.n]
            cmp_adrs = b[version.n:version.n + 22]
            m = b[version.n + 22:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + m).digest(), version.n)
        case("SLH_DSA_SHA2_128s", "PRF"):
            version = sha2_128s
            pkSeed = b[:version.n]
            skSeed = b[version.n:version.n + version.n]
            cmp_adrs = b[version.n + version.n:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + skSeed).digest(), version.n)

        case ("SLH_DSA_SHA2_128f", "PRF"):
            version = sha2_128f
            pkSeed = b[:version.n]
            skSeed = b[version.n:version.n + version.n]
            cmp_adrs = b[version.n + version.n:]
            # Since we have an address that is automatically generated and not apply the general convention of address.
            # An form of bypassing is needed. Therefor we use the definition of the function directly.
            refResult = trunc(sha256(pkSeed + b"\x00" * (64 - version.n) + cmp_adrs + skSeed).digest(), version.n)
        case("SLH_DSA_SHA2_128s", "PRFmsg"):
            version = sha2_128s
            sk_prf = b[:version.n]
            opt_rand = b[version.n:version.n + version.n]
            msg = b[version.n + version.n:]
            refResult = version.PRFmsg(sk_prf, opt_rand, msg)
            refResult = hmac_digest(sk_prf, opt_rand + msg, "sha256")
        case ("SLH_DSA_SHA2_128f", "PRFmsg"):
            version = sha2_128f
            sk_prf = b[:version.n]
            opt_rand = b[version.n:version.n + version.n]
            msg = b[version.n + version.n:]
            refResult = version.PRFmsg(sk_prf, opt_rand, msg)
            refResult = hmac_digest(sk_prf, opt_rand + msg, "sha256")
        case("SLH_DSA_SHA2_128s", "Hmsg"):
            version = sha2_128s
            sk_prf = b[:version.n]
            opt_rand = b[version.n:version.n + version.n]
            msg = b[version.n + version.n:]
            refResult = version.Hmsg(sk_prf, opt_rand, msg)

        case("SLH_DSA_SHA2_128f", "Hmsg"):
            version = sha2_128f
            sk_prf = b[:version.n]
            opt_rand = b[version.n:version.n + version.n]
            msg = b[version.n + version.n:]
            refResult = version.Hmsg(sk_prf, opt_rand, msg)
        case("SLH_DSA_SHA2_128s", "HMAC"):
            version = sha2_128s
            key = b[:64]
            # print(key)
            # print(len(key))
            msg = b[64:]
            # print(msg)
            # print(len(msg))
            # print(len(b))
            refResult = hmac_digest(key, msg, "sha256")
            refResult = hmac_digest(key, msg, "sha256")
            # if compare_digest(refResult, dutResult):
            #     print("Wow they are equal!")
        case("SLH_DSA_SHA2_128f", "HMAC"):
            version = sha2_128f
            key = b[:32]
            msg = b[32:]
            refResult = hmac_digest(key, msg, "sha256")
        case _:
            version = "Did not match"

    passs = refResult == dutResult
    passedAll = passedAll and passs
    if passs:
        counter += 1
    if not passs:
        print("This is the particular test case that failed: ❌")
        print("The reference result")
        print(list(refResult))
        print("The dut result")
        print(list(dutResult))
        print(len(list(refResult)) == len(list(dutResult)))
        print("Function")
        print((test[1], test[0]))
        x, input, dutResult = test[2].split(",")
        print(input.replace("0b","").replace("_"," "))
        print(hmac_digest((0).to_bytes(32, "big") ,b, "sha256"))
#          https://cryptii.com/pipes/xXbEWQ with key 0 and b is the hole message
if passedAll:
    print("All entries have been verified ✅")
else:
    print("Some tests have been failed.❌")
    print("Tests passed: " + str(counter))

