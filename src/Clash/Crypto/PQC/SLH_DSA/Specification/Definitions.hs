{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UndecidableInstances #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Definitions where
import Clash.Prelude
import Language.Haskell.Unicode (type (≤))
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

truncₗ ∷ ∀ n m a ℓ. (KnownNat n, KnownNat m, KnownNat ℓ, ℓ+m ~ n) ⇒ Vec n a → SNat ℓ →  Vec ℓ a
truncₗ x s_ℓ = take (s_ℓ) x


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
floorXdivY x y = result + rounder
    where 
        division = divMod x y
        result = fst division
        remainder = snd division
        rounder = if remainder /= (0b0 ∷ BitVector w) then (0b0 ∷ BitVector w) else (0b1 ∷ BitVector w)
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
zzz = ceilXdivY  (0b1 :: BitVector 8) (0b1 :: BitVector 8)