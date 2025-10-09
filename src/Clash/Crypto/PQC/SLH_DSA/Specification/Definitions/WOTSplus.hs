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
import Clash.Prelude
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions

chain ∷ ∀ i s (alg ∷ SLH_DSA). (KnownNat i, KnownNat s, SLH_DSA_hash alg) ⇒ BitVector ℓ → PKSeed alg → ADRS alg
chain x pkSeed adrs = ifoldl (function) tmp (iterateI @s (+1) (natToNum @i)) selection
    where
        selection = select 
        function j x = _F pkSeed (setHashAddress adrs j) x
        tmp = x