{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics where
import Clash.Prelude
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Parameters
-- 2.3 Mathematical Symbols
(‖) ∷ Vec n a →  Vec m a → Vec (n + m) a 
(‖) = (++)

(∶) ∷ ∀ n m p q a. (
          Num a, 
          KnownNat p, 
          KnownNat q, 
          KnownNat n, 
          KnownNat m,
          (q ≤ n), 
          (p ≤ q),
          m ~ (q - p),
          (p + (q-p)) ≤ n
        ) 
    ⇒ Vec n a → SNat p → SNat q → Vec m a 
(∶) x s_p s_q = select @(n-p) @1 @(q-p) @p s_p (SNat :: SNat 1) (subSNat s_q s_p) x
--Test example  (∶) ((1:>2:>3:>7:>8:>Nil) :: Vec 5 Int) (∶) (SNat :: SNat 2) (SNat :: SNat 3)

truncˡ ∷ ∀ ℓ n m a . (KnownNat n, KnownNat m, KnownNat ℓ, ℓ+m ~ n) ⇒ Vec n a → Vec ℓ a
truncˡ x = takeI @ℓ x


(|·|) ∷ KnownNat n ⇒ Vec n a → SNat n 
(|·|) = lengthS

(⊕) ∷ KnownNat w ⇒ BitVector w → BitVector w → BitVector w
(⊕) = xor

-- Ceil rounder from 2.3 according to page 9
ceilXdivY ∷ ∀ w . KnownNat w ⇒ BitVector w → BitVector w → BitVector w
ceilXdivY x y = result + rounder
    where 
        division = divMod x y
        result = fst division
        remainder = snd division
        rounder = if remainder /= (0b0 ∷ BitVector w) then (0b1 ∷ BitVector w) else (0b0 ∷ BitVector w)
-- Ceil rounder from 2.3 according to page 9
floorXdivY ∷ ∀ w . KnownNat w ⇒ BitVector w → BitVector w → BitVector w
floorXdivY x y = div x y



-- mod function is already existing as it is.
-- (^) power function
(·) ∷ ∀ w . (KnownNat w) ⇒  BitVector w → BitVector w → BitVector w
(·) a b = v2bv (takeI @w (bv2v (mul a b)))
(^) ∷ ∀ w n . (KnownNat w, KnownNat n, n+1 ~ w) ⇒ BitVector w → BitVector w → BitVector w 
(^) a b = foldl (·) (0x00) (zipWith (\f g →  if f then g else (0x00)) (bv2vbool a) (scanl (·) b (repeat @n b)))
    where
        -- | function that transform from bitvector to vector of booleans.
        bv2vbool ∷  (KnownNat w) ⇒ BitVector w → Vec w Bool
        bv2vbool b1 = fmap (testBit b1) (iterateI (+1) 0)

(≫) ∷ ∀ w . (KnownNat w) ⇒ BitVector w → BitVector w → BitVector w  
(≫) a b = shiftR a (maxIndex# b)

(≪) ∷ ∀ w . (KnownNat w) ⇒ BitVector w → BitVector w → BitVector w 
(≪) a b = shiftL a (maxIndex# b)


-----------------------------------------------
-- The following functions are convergene methodes,   
-- which are define in Algorithm 2, 3 and 4 form FIPS205
-- The integer is a BitVector m since the Integer will
-- be represent on hardware as a serie of bits.
-- TODO: Verify no problems with big endian, otherwise a reverse will do the trick.
-----------------------------------------------
-- Algorithm 2 same name kept although the choicen instance is integer
toInt ∷ ∀ n w k . (KnownNat n, KnownNat w, KnownNat k ) ⇒ Vec (n + k) (BitVector w) → BitVector (n * w)
toInt = concatBitVector# . takeI
-- Algorithm 3
toByte ∷ ∀ n w s k . (KnownNat n, KnownNat w, KnownNat k, KnownNat s, (n + k) * w ~ s) ⇒ BitVector s → Vec n (BitVector w)
toByte = takeI . unconcatBitVector#
-- Algorithm 4
base_2ᵇ ∷ ∀ b out_len n m k s. (KnownNat b, KnownNat out_len, KnownNat n, KnownNat m, KnownNat s, KnownNat k, (out_len + k) * b ~ s * ByteSize) ⇒ Vec s ByteType → Vec (out_len) (BitVector b)
base_2ᵇ =  unconcatBitVector# . resize. concatBitVector#
