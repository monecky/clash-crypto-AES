{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.WOTSplus
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic WOTS definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.WOTSplus where
-- import Clash.Prelude
-- import Language.Haskell.Unicode (type (≤))
-- import Clash.Crypto.PQC.SLH_DSA.General.General
-- import Clash.Crypto.PQC.SLH_DSA.Specification.Types

-- import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
-- Algorithm 5
-- chain ∷ ∀ i s ℓ (alg ∷ SLH_DSA). (KnownNat ℓ, KnownNat i, KnownNat s, 1 ≤ i, s + 1 ≤ (ℓ - i) + 1, SLH_DSA_hash alg) ⇒ BitVector ℓ → PKSeedType alg → ADRSType alg → BitVector ℓ
-- chain x pkSeed adrs = v2bv $ foldl (function) tmp (iterateI @s (+1) (natToNum @i @(Index ℓ)))
--     where
--         function ∷ Vec ℓ Bit → Index n → Vec ℓ Bit
--         function x1 j = x1 -- TODO _F pkSeed (setHashAddress adrs j) x
--         tmp ∷ Vec ℓ Bit
--         tmp = bv2v x
-- Algorithm 6