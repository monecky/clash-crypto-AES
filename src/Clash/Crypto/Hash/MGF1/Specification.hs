{-|
Module      : Clash.Crypto.Hash.MGF1.Specification
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX
Functional implementation of MGF1
MGF1 is a mask generation function based on a hash function.
In this specific case SHA hash.
[MGF1 from Appendix B.2.1 of RFC 8017: MGF1](https://doi.org/10.6028/NIST.FIPS.197-upd1).
-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
module Clash.Crypto.Hash.MGF1.Specification (
    mgf1
) where
import Clash.Prelude
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.Hash.SHA.Specification
import Clash.Crypto.PQC.SLH_DSA.Specification.Types (ByteSize, ByteType)
import Clash.Crypto.PQC.SLH_DSA.General.General (CeilXDivY)

mgf1 ∷ ∀ (alg ∷ SHA) (maskLen ∷ Nat) (ℓ ∷ Nat)  (hLen ∷ Nat).
 (KnownSHA alg, KnownNat ℓ, KnownNat maskLen, KnownNat hLen, hLen ~ MessageDigestSize alg, maskLen * ByteSize ≤ (CeilXDivY (maskLen * ByteSize) hLen) * hLen ) 
 ⇒ BitVector ℓ → BitVector (maskLen * ByteSize)
mgf1 mgfSeed
    | SHAFacts {} ← knownSHA @alg 
    = if ((natToNum @maskLen) > 0x100000000 * (natToNum @hLen)) then ifthen else ifelse
    where
        ifthen = errorX "mask too long"
        ifelse ∷  (KnownSHA alg, KnownNat ℓ, KnownNat maskLen, KnownNat hLen, hLen ~ MessageDigestSize alg, 1≤ hLen) 
            ⇒ BitVector (maskLen * ByteSize)
        ifelse = v2bv takeMaskLenBit
            where 
                tv ∷ Vec (CeilXDivY (maskLen * ByteSize) hLen) (BitVector (MessageDigestSize alg))
                tv 
                    | SHAFacts {} ← knownSHA @alg 
                    = map  go indices
                    where 
                        go ∷ BitVector (ByteSize * 4) → Digest alg
                        go x = hash @alg (mgfSeed ++# x)
                        indices ∷ Vec (CeilXDivY (maskLen * ByteSize) hLen) (BitVector (ByteSize * 4))
                        indices = iterateI @(CeilXDivY (maskLen * ByteSize) hLen) (+1) (0 ∷ BitVector (ByteSize * 4)) 
                tbv ∷ Vec ((CeilXDivY (maskLen * ByteSize) hLen) * (MessageDigestSize alg)) Bit
                tbv 
                    | SHAFacts {} ← knownSHA @alg 
                    =  bv2v (concatBitVector# tv)  
                -- c ∷ ∀ xLen . KnownNat xLen ⇒ ByteType → BitVector (ByteSize * xLen)
                -- c x = resize   x ∷  BitVector (ByteSize * xLen)

                takeMaskLenBit ∷ Vec (maskLen * ByteSize) Bit
                takeMaskLenBit 
                    | SHAFacts {} ← knownSHA @alg 
                    = takeI @(maskLen * ByteSize) @((CeilXDivY (maskLen * ByteSize) hLen) * (MessageDigestSize alg) - (maskLen * ByteSize)) tbv

