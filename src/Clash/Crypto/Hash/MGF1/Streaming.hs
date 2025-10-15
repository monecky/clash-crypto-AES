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
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple 
  )
import Language.Haskell.Unicode (type (≤))
mgf1Stream ∷ ∀ (alg ∷ SHA) (maskLen ∷ Nat) (ℓ ∷ Nat)
  (hLen ∷ Nat) dom.
 (ByteSize <= BlockSize alg, Mod (BlockSize alg) 8 ~ 0, Mod (ℓ + 32) 8 ~ 0, KnownDomain dom, HiddenClockResetEnable dom, KnownSHA alg, KnownNat ℓ, KnownNat maskLen, KnownNat hLen, hLen ~ MessageDigestSize alg) 
 ⇒ Channel dom (BitVector ℓ) → Channel dom (BitVector (maskLen * ByteSize))
mgf1Stream mgfSeed
    | SHAFacts {} ← knownSHA @alg 
    = fmap (\x → resize x) (concatMapC (map  go (iterateI @(CeilXDivY maskLen hLen) (+1) (0 ∷ ByteType))))
    where 
        go ∷ ByteType → Channel dom (Digest alg)
        go x = sha @alg (serializeHash @ByteSize (fmap  (\y → (y ++# c @4 x)) mgfSeed))
        c ∷ ∀ xLen . KnownNat xLen ⇒ ByteType → BitVector (ByteSize * xLen)
        c x = resize x ∷  BitVector (ByteSize * xLen)

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

concatMapC ∷ ∀ ℓ n dom . (KnownNat ℓ, KnownNat n) ⇒  Vec n (Channel dom (BitVector ℓ)) -> Channel dom (BitVector (ℓ * n))
concatMapC Nil = errorX "Invalid vector"
concatMapC ( x `Cons` Nil) = x 
concatMapC (x `Cons` xs) = liftA2 (++#) x (concatMapC xs)