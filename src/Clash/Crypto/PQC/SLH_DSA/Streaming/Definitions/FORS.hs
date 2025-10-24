{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic FORS definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS where

import Clash.Prelude
import Clash.Sized.Internal.BitVector
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics (base_2ᵇ)
import Data.Proxy (Proxy(..))
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Address 
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address 
import Clash.Signal.Extra(apWhen)
-- Algorithm 14
fors_skGen ∷  ∀ (alg ∷ SLH_DSA)  dom . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStream alg) 
    ⇒ Channel dom (SKSeedType alg, PKSeedType alg, ADRSType alg) 
     → Channel dom (IdxType alg) -- idx
     → Channel dom (PRFOutType alg)
fors_skGen input idx
        | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
        = _PRFStream alg (liftA2 go input idx)
        where 
            go (s,p,a) i = (s,p, skADRS²)
                where 
                    skADRS  = setTypeAndClear a FORS_PRF
                    skADRS¹ = setKeyPairAddress skADRS (getKeyPairAddress a)
                    skADRS² = setTreeIndex skADRS¹ i