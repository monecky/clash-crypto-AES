{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Implemenetation of function regards ADRS of Table 1 and 3 of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address where
import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Sized.BitVector (BitVector)
import Clash.Sized.Vector (Vec)
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties
import Data.Proxy (Proxy(..))
setLayerAddress ∷ ADRSType alg → LayerAddressType alg → ADRSType alg
setLayerAddress adrs l = adrs {layerAddress = l }
setTypeAndClear ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSA alg) ⇒ ADRSType alg → ADRSTypeType → ADRSType alg
setTypeAndClear adrs WOTS_HASH 
      | SLH_DSAFacts{} <- knownSLH_DSA @alg     
      = adrs {typeAddress = toByte @(TypeSize alg) 0b0 ∷ TypeType alg}
-- setTypeAndClear adrs WOTS_PK   = adrs {typeAddress = toByte @(TypeSize alg) 1}
-- setTypeAndClear adrs TREE      = adrs {typeAddress = toByte @(TypeSize alg) 2}
-- setTypeAndClear adrs FORS_TREE = adrs {typeAddress = toByte @(TypeSize alg) 3}
-- setTypeAndClear adrs FORS_ROOTS= adrs {typeAddress = toByte @(TypeSize alg) 4}
-- setTypeAndClear adrs WOTS_PRF  = adrs {typeAddress = toByte @(TypeSize alg) 5}
-- setTypeAndClear adrs FORS_PRF  = adrs {typeAddress = toByte @(TypeSize alg) 6}
-- setTypeAndClear adrs _         = adrs {typeAddress = toByte @(TypeSize alg) 7}