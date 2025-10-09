{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Properties
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Some properties that can be proven to be valid from the FIPS 205
specification.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Properties where
import Data.Proxy (Proxy(..))

import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types

data SLH_DSAFacts (alg ∷ SLH_DSA) where
    SLH_DSAFacts ∷
        ( KnownNat (N alg)
        , KnownNat (H alg)
        , KnownNat (D alg)
        , KnownNat (H' alg)
        , KnownNat (A alg)
        , KnownNat (K alg)
        , KnownNat (Lgʷ alg)
        , KnownNat (M alg)
        , KnownNat (W alg)
        , KnownNat (Len¹ alg)
        , KnownNat (Len² alg)
        , KnownNat (Len alg)
        , KnownNat (LayerAddressSize alg)
        , KnownNat (TreeAddressSize alg)
        , KnownNat (TypeSize alg)
        -- Expected to be neded at some point.
        -- , PrivateKey alg
        -- , PublicKey alg
        -- , SK alg
        -- , PK alg
        -- Properties according p.17, TODO it can be delete since it holds for many more cases.
        -- This works as verification methode that the calculation is done right on Type level.
        , Lgʷ alg ~ 4
        , W alg ~ 16
        , Len¹ alg ~ 2 * N alg
        , Len² alg ~ 3
        , Len alg ~ 2 * N alg + 3
        ) ⇒
        Proxy alg →
        SLH_DSAFacts alg

-- | We utilize the type checker to provide evidence for all of the
-- required properties, which are proven automatically for each
-- instance of the class.
class    KnownSLH_DSA alg                    where knownSLH_DSA ∷ SLH_DSAFacts alg
instance KnownSLH_DSA SLH_DSA_SHA2_128s      where knownSLH_DSA = SLH_DSAFacts Proxy
instance KnownSLH_DSA SLH_DSA_SHA2_128f      where knownSLH_DSA = SLH_DSAFacts Proxy
instance KnownSLH_DSA SLH_DSA_SHA2_192s      where knownSLH_DSA = SLH_DSAFacts Proxy
instance KnownSLH_DSA SLH_DSA_SHA2_192f      where knownSLH_DSA = SLH_DSAFacts Proxy
instance KnownSLH_DSA SLH_DSA_SHA2_256s      where knownSLH_DSA = SLH_DSAFacts Proxy
instance KnownSLH_DSA SLH_DSA_SHA2_256f      where knownSLH_DSA = SLH_DSAFacts Proxy
  {-TODO:When the right implementation exist of SHA other algorithms can be added-}

