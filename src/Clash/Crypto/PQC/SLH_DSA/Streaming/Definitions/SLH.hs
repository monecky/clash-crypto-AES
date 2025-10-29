{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Implemenetation of algorithm in Chapter 19 and 10.
Algorithm 18-23
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
{-# OPTIONS_GHC -fno-max-relevant-binds #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH where
import Clash.Prelude
import Clash.Sized.Internal.BitVector
import Language.Haskell.Unicode (type (≤))
import Clash.Crypto.PQC.SLH_DSA.General.General
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics (base_2ᵇ)
import Data.Proxy (Proxy(..))
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Address 
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus 
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address 
import Clash.Signal.Extra(apWhen)

-- Algorithm 18
-- slh_keygen_internal ∷ ∀ (alg ∷ SLH_DSA)  dom ℓ . (KnownDomain dom, HiddenClockResetEnable dom,  KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownNat ℓ) 
--     ⇒ Channel dom (SKSeedType alg, SKPrfType alg, PKSeedType alg)  
--      → Channel dom ((, ,), (, ))




     ----------------------------------------
-- The following might be too specific.
-- Maybe moved to somewhere else
----------------------------------------
concatMapC ∷ ∀ ℓ a dom . (KnownNat ℓ) ⇒  Vec ℓ (Channel dom a) -> Channel dom (Vec ℓ a)
concatMapC Nil = errorX "Invalid vector"
concatMapC ( x `Cons` Nil) = fmap singleton  x 
concatMapC (x `Cons` xs) = liftA2 (++) (fmap singleton x) (concatMapC xs)



transferAddressC ∷ ∀ alg dom . (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg) → ADRSTypeType → Channel dom (ADRSType alg) 
transferAddressC adrs t 
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    = liftA2 (\ad ad¹  → setKeyPairAddress ad¹ (getKeyPairAddress ad)) (setTypeAndClearC adrs t) adrs

record2bv ∷ SIGˣᵐˢˢType alg → Vec ((H' alg + Len alg)* N alg) ByteType
record2bv XMSSType {
  sig_ots,
  auth
  } = concat (sig_ots ‖ auth)