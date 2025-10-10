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
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Data.Proxy (Proxy(..))
setLayerAddress ∷ ADRSType alg → LayerAddressType alg → ADRSType alg
setLayerAddress adrs l = adrs {layerAddress = l }

setTreeAddress ∷ ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSA alg, KnownNat ℓ)⇒ ADRSType alg → BitVector ℓ →  ADRSType alg
setTreeAddress adrs t 
      | SLH_DSAFacts{} <- knownSLH_DSA @alg     
      = adrs {treeAddress = toByte @(TreeAddressSize alg) @ByteSize @(TreeAddressSize alg * ByteSize) @0  (resize t)  ∷ TreeAddressType alg}

setTypeAndClear ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSA alg) ⇒ ADRSType alg → ADRSTypeType → ADRSType alg
setTypeAndClear adrs WOTS_HASH       
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x0 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs WOTS_PK   
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x1 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs TREE      
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x2 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs FORS_TREE 
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x3 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs FORS_ROOTS
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x4 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs WOTS_PRF  
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x5 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs FORS_PRF  
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x6 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs _         
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = _setTypeAndClear adrs (0x7 ∷ BitVector (TypeSize alg * ByteSize))
_setTypeAndClear ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSA alg) ⇒ ADRSType alg → BitVector (TypeSize alg * ByteSize) → ADRSType alg
_setTypeAndClear adrs l 
      | SLH_DSAFacts{} <- knownSLH_DSA @alg 
      = adrs {   typeAddress = toByte @(TypeSize alg) @ByteSize @(TypeSize alg * ByteSize) @0  l ∷ TypeType alg
              , keyPairAddress           = toByte @(KeyPairAddressSize alg) @ByteSize @(KeyPairAddressSize alg * ByteSize) @0  0b0  ∷ KeyPairAddressType alg
              , chainAddressTreeHeight   = toByte @(ChainAddressTreeHeightSize alg) @ByteSize @(ChainAddressTreeHeightSize alg * ByteSize) @0  0b0  ∷ ChainAddressTreeHeightType alg
              , hashAddressTreeIndexType = toByte @(HashAddressTreeIndexSize alg) @ByteSize @(HashAddressTreeIndexSize alg * ByteSize) @0  0b0  ∷ HashAddressTreeIndexType alg
              }
setKeyPairAddress ∷ ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSA alg, KnownNat ℓ)⇒ ADRSType alg → BitVector ℓ →  ADRSType alg
setKeyPairAddress adrs t 
      | SLH_DSAFacts{} <- knownSLH_DSA @alg     
      = adrs {treeAddress = toByte @(TreeAddressSize alg) @ByteSize @(TreeAddressSize alg * ByteSize) @0  (resize t)  ∷ TreeAddressType alg}

