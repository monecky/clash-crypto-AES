{-|
Module      : Clash.Crypto.Hash.MGF1.Streaming
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX
Streaming implementation
MGF1 is a mask generation function based on a hash function.
In this specific case SHA hash.
[MGF1 from Appendix B.2.1 of RFC 8017: MGF1](https://doi.org/10.6028/NIST.FIPS.197-upd1).
-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
module Clash.Crypto.Hash.MGF1.Streaming (
    mgf1Streaming
) where
import Clash.Prelude

import Clash.Crypto.Hash.SHA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types (ByteSize, ByteType)
import Clash.Crypto.PQC.SLH_DSA.General.General (CeilXDivY)

mgf1Streaming ∷ ∀ (alg ∷ SHA) (maskLen ∷ Nat) (ℓ ∷ Nat)  (hLen ∷ Nat).
 (KnownSHA alg, KnownNat ℓ, KnownNat maskLen, KnownNat hLen, hLen ~ MessageDigestSize alg) 
 ⇒ DataStream () (Index ℓ) (BitVector ℓ) → Channel (BitVector (maskLen * ByteSize))
mgf1Streaming mgfSeed
    | SHAFacts {} ← knownSHA @alg 
    = resize (concatBitVector# (map  go (iterateI @(CeilXDivY maskLen hLen) (+1) (0 ∷ ByteType))))
    where 
        go ∷ ByteType → Digest alg
        go x = sha @alg (fmap  (\x → (x ++# c @4 x)) mgfSeed)
        c ∷ ∀ xLen . KnownNat xLen ⇒ ByteType → BitVector (ByteSize * xLen)
        c x = resize x ∷  BitVector (ByteSize * xLen)