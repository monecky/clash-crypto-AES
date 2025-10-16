{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus
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
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus where
import Clash.Prelude
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Signal.Channel
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Data.Proxy (Proxy(..))
-- Algorithm 5
chain ∷ ∀ i s ℓ (alg ∷ SLH_DSA) dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, KnownNat ℓ, KnownNat i, KnownNat s, 1 ≤ i, s + 1 ≤ (ℓ - i) + 1, SLH_DSA_hashStream alg) 
    ⇒ Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) → Channel dom (NBlockType alg)
chain tmp 
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = fmap (\(x, pk, ad) → x) (foldl (function alg) tmp (iterateI @s (+1) (natToNum @i)))
            where
                function ∷ Proxy alg 
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg) 
                    → BitVector (ChainAddressTreeHeightSize alg * ByteSize)
                    → Channel dom (NBlockType alg, PKSeedType alg, ADRSType alg)
                function alg x1 j = liftA3 (,,) (_FStream alg (fmap (go j) x1)) pkSeed adrs
                    where 
                        pkSeed ∷ Channel dom (PKSeedType alg)
                        pkSeed = fmap (\(x, pk, ad) → pk) x1
                        adrs ∷ Channel dom (ADRSType alg)
                        adrs = fmap (\(x, pk, ad) → ad) x1
                go ∷  BitVector (ChainAddressTreeHeightSize alg * ByteSize) 
                    → (NBlockType alg, PKSeedType alg, ADRSType alg)
                    → (PKSeedType alg, ADRSType alg, NBlockType alg)
                go j (x, pkSeed, adrs) = (pkSeed, setHashAddress adrs j, x)
-- Algorithm 6

fstOf3   :: (a,b,c) -> a
sndOf3   :: (a,b,c) -> b
thdOf3   :: (a,b,c) -> c
fstOf3      (a,_,_) =  a
sndOf3      (_,b,_) =  b
thdOf3      (_,_,c) =  c
