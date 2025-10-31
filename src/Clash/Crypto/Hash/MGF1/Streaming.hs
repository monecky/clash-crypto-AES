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
    mgf1Stream
) where
import Clash.Prelude

import Clash.Crypto.Hash.SHA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types (ByteSize, ByteType)
import Clash.Crypto.PQC.SLH_DSA.General.General (CeilXDivY)
import Clash.Signal.DataStream
import Clash.Signal.Channel
import GHC.TypeNats.Proof (Rewrite(..), using)
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, ModTimes, DivTimes
  )
import Language.Haskell.Unicode (type (≤))
mgf1Stream ∷ ∀ (alg ∷ SHA) (maskLen ∷ Nat) (ℓ ∷ Nat) (hLen ∷ Nat) dom .
  (KnownSHA alg, KnownDomain dom, HiddenClockResetEnable dom, KnownNat ℓ) ⇒ -- General constrains
 (KnownNat ByteSize, 1 ≤ ByteSize, ByteSize ≤ BlockSize alg, Mod (BlockSize alg) ByteSize ~ 0, Mod (ℓ + (4 * 8)) 8 ~ 0) ⇒ -- constrains of use of sha
 (KnownNat maskLen, KnownNat hLen, hLen ~ MessageDigestSize alg, maskLen * ByteSize ≤ (CeilXDivY (maskLen * ByteSize) hLen) * hLen,
 -- Constain due definition of algorithm
   maskLen * ByteSize ≤ (0x100000000 * hLen) -1
  )   -- Constrains of mgf1
 ⇒ Channel dom (BitVector ℓ) → Channel dom (BitVector (maskLen * ByteSize))
mgf1Stream mgfSeed
    | SHAFacts {} ← knownSHA @alg 
    = fmap v2bv takeMaskLenBit
    where 
        tv ∷ Channel dom ( Vec (CeilXDivY (maskLen * ByteSize) hLen) (BitVector (MessageDigestSize alg)))
        tv 
          | SHAFacts {} ← knownSHA @alg 
          =  concatMapVC (map go indices⁰)
          where 
              go ∷ BitVector (ByteSize * 4) → Channel dom (Digest alg)
              go x = sha @alg (serializeHash @ByteSize (fmap  (++# x) mgfSeed))
              indices⁰ ∷ (1 ≤ hLen) ⇒ Vec (CeilXDivY (maskLen * ByteSize) hLen) (BitVector (ByteSize * 4))
              indices⁰ = iterateI @(CeilXDivY (maskLen * ByteSize) hLen) (+1) (0 ∷ BitVector (ByteSize * 4)) 
        tbv ∷ Channel dom (Vec ((CeilXDivY (maskLen * ByteSize) hLen) * (MessageDigestSize alg)) Bit)
        tbv 
            | SHAFacts {} ← knownSHA @alg 
            =  fmap (bv2v . concatBitVector#) tv  
        takeMaskLenBit ∷ Channel dom (Vec (maskLen * ByteSize) Bit)
        takeMaskLenBit 
            | SHAFacts {} ← knownSHA @alg 
            = fmap  (takeI @(maskLen * ByteSize) @((CeilXDivY (maskLen * ByteSize) hLen) * (MessageDigestSize alg) - (maskLen * ByteSize))) tbv

serializeHash ∷ ∀ (n ∷ Nat) (dom ∷ Domain) a . (KnownDomain dom, HiddenClockResetEnable dom) ⇒ 
    ( BitPack a, KnownNat (BitSize a), KnownNat n
  , 1 ≤ n, 1 ≤ BitSize a, BitSize a `Mod` n ~ 0) ⇒ 
    Channel  dom a → 
    -- ^ streamed input that needs to be split up.
    DataStream dom () (Index n) (BitVector n)
serializeHash input
  | Rewrite ← using @(KeepsPositiveIfMultiple (BitSize a) n)
  , Rewrite ← using @(CancelMultiple (BitSize a) n)
    = leToPlusKN @1 @(BitSize a `Div` n)
  $ mealy (~~>)
      ( repeat neval ∷ Vec (BitSize a `Div` n) (BitVector n)
      , 0 ∷ Index ((BitSize a `Div` n) + 1)
      ) (liftA2 (,) (content input) (hasUpdates input))
 where
  (buf, n) ~~> (Just _, False) | n > 0 = -- 
    ((buf <<+ neval, satPred SatBound n), frame $ head buf)
   where
    frame | n == maxBound = Start ()
          | n > 1         = Middle
          | otherwise     = End 0

  _ ~~> (Just x, True)  = -- (Just x, True) equivalent to 
    ((bitCoerce x, maxBound), Idle)

  (buf, n) ~~> _ =
    ((buf, n), if n > 0 then NoData else Idle)

  -- a value that should never be evaluated
  neval = error "Clash.Crypto.MAC.HMAC.serializeEn: Mealy"

concatMapBvC ∷ ∀ ℓ n dom . (KnownNat ℓ, KnownNat n) ⇒  Vec n (Channel dom (BitVector ℓ)) -> Channel dom (BitVector (ℓ * n))
concatMapBvC Nil = errorX "Invalid vector"
concatMapBvC ( x `Cons` Nil) = x 
concatMapBvC (x `Cons` xs) = liftA2 (++#) x (concatMapBvC xs)

concatMapVC ∷ ∀ ℓ a dom . (KnownNat ℓ) ⇒  Vec ℓ (Channel dom a) -> Channel dom (Vec ℓ a)
concatMapVC Nil = errorX "Invalid vector"
concatMapVC ( x `Cons` Nil) = fmap singleton  x 
concatMapVC (x `Cons` xs) = liftA2 (++) (fmap singleton x) (concatMapVC xs)