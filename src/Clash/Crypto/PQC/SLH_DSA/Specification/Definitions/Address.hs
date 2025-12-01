{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Implemenetation of function regards ADRS of Table 1 and 3 of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# OPTIONS_GHC -fconstraint-solver-iterations=20 #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address where
import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Sized.BitVector (BitVector)
import Clash.Sized.Vector (Vec)
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Data.Proxy (Proxy(..))
import Data.Constraint.Nat.Extra
import GHC.TypeNats.Proof (Rewrite(..), using)
import GHC.TypeNats.Proof (Rewrite(..), using)
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
------------------------------
-- Setters
------------------------------
setLayerAddress ∷ ADRSType alg → LayerAddressType alg → ADRSType alg
setLayerAddress adrs l = adrs {layerAddress = l }

setTreeAddress ∷ ∀ (alg ∷ SLH_DSA) ℓ . (KnownSLH_DSAParameters alg, KnownNat ℓ)⇒ ADRSType alg → BitVector ℓ →  ADRSType alg
setTreeAddress adrs t 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = adrs {treeAddress = toByte @(TreeAddressSize alg) @ByteSize @(TreeAddressSize alg * ByteSize) @0  (resize t)  ∷ TreeAddressType alg}

setTypeAndClear ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg) ⇒ ADRSType alg → ADRSTypeType → ADRSType alg
setTypeAndClear adrs WOTS_HASH       
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x0 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs WOTS_PK   
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x1 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs TREE      
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x2 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs FORS_TREE 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x3 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs FORS_ROOTS
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x4 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs WOTS_PRF  
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x5 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs FORS_PRF  
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x6 ∷ BitVector (TypeSize alg * ByteSize))
setTypeAndClear adrs _         
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear adrs (0x0 ∷ BitVector (TypeSize alg * ByteSize))
_setTypeAndClear ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg) ⇒ ADRSType alg → BitVector (TypeSize alg * ByteSize) → ADRSType alg
_setTypeAndClear adrs l 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = adrs {   typeAddress             = toByte @(TypeSize alg) @ByteSize @(TypeSize alg * ByteSize) @0  l ∷ TypeType alg
              , keyPairAddress           = toByte @(KeyPairAddressSize alg) @ByteSize @(KeyPairAddressSize alg * ByteSize) @0  0b0  ∷ KeyPairAddressType alg
              , chainAddressTreeHeight   = toByte @(ChainAddressTreeHeightSize alg) @ByteSize @(ChainAddressTreeHeightSize alg * ByteSize) @0  0b0  ∷ ChainAddressTreeHeightType alg
              , hashAddressTreeIndexType = toByte @(HashAddressTreeIndexSize alg) @ByteSize @(HashAddressTreeIndexSize alg * ByteSize) @0  0b0  ∷ HashAddressTreeIndexType alg
              }
setKeyPairAddress ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (ChainAddressTreeHeightSize alg * ByteSize) →  ADRSType alg
setKeyPairAddress adrs i 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = adrs {keyPairAddress           = toByte @(KeyPairAddressSize alg) @ByteSize @(KeyPairAddressSize alg * ByteSize) @0  i  ∷ KeyPairAddressType alg}
setChainAddress ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (ChainAddressTreeHeightSize alg * ByteSize) →  ADRSType alg
setChainAddress adrs i 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = adrs {chainAddressTreeHeight   = toByte @(ChainAddressTreeHeightSize alg) @ByteSize @(ChainAddressTreeHeightSize alg * ByteSize) @0  i  ∷ ChainAddressTreeHeightType alg}
setTreeHeight ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (ChainAddressTreeHeightSize alg * ByteSize) →  ADRSType alg
setTreeHeight = setChainAddress

setHashAddress ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (ChainAddressTreeHeightSize alg * ByteSize) →  ADRSType alg
setHashAddress adrs i 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = adrs {hashAddressTreeIndexType = toByte @(HashAddressTreeIndexSize alg) @ByteSize @(HashAddressTreeIndexSize alg * ByteSize) @0  i  ∷ HashAddressTreeIndexType alg}
setTreeIndex ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (ChainAddressTreeHeightSize alg * ByteSize) →  ADRSType alg
setTreeIndex = setHashAddress
------------------------------
-- Getters
------------------------------
getKeyPairAddress ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (KeyPairAddressSize alg * ByteSize) 
getKeyPairAddress ADRSType{keyPairAddress = keyPairAddress} = pack keyPairAddress

getTreeIndex ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector (HashAddressTreeIndexSize alg * ByteSize) 
getTreeIndex ADRSType{hashAddressTreeIndexType = hashAddressTreeIndexType} = pack hashAddressTreeIndexType

getADRSVector ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg) ⇒ ADRSType alg → Vec (ADRSTypeVectorSize alg) ByteType
getADRSVector ADRSType{
              layerAddress             = layerAddress             
            , treeAddress              = treeAddress              
            , typeAddress              = typeAddress              
            , keyPairAddress           = keyPairAddress           
            , chainAddressTreeHeight   = chainAddressTreeHeight   
            , hashAddressTreeIndexType = hashAddressTreeIndexType } 
            | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
            -- , Rewrite ← using @(DivTimes (((LayerAddressSize alg * ByteSize) + ((TreeAddressSize alg * ByteSize) + (TypeSize alg * ByteSize))) + 96) ByteSize)
              = layerAddress ++ treeAddress ++ typeAddress ++ keyPairAddress ++ chainAddressTreeHeight ++ hashAddressTreeIndexType
getADRSBitVector ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg) ⇒ ADRSType alg → BitVector (BitSize (ADRSType alg)) 
getADRSBitVector 
            | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
              = pack 


getInitADRS ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg) ⇒ ADRSType alg 
getInitADRS             
            | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
            = ADRSType{
              layerAddress             = unconcatBitVector# ( 0x0)            
            , treeAddress              = unconcatBitVector# ( 0x0)            
            , typeAddress              = unconcatBitVector# ( 0x0)            
            , keyPairAddress           = unconcatBitVector# ( 0x0)            
            , chainAddressTreeHeight   = unconcatBitVector# ( 0x0)            
            , hashAddressTreeIndexType = unconcatBitVector# ( 0x0)            } 
