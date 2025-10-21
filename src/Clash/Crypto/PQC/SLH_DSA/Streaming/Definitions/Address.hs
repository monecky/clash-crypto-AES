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
module Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Address where
import Clash.Prelude
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Sized.BitVector (BitVector)
import Clash.Sized.Vector (Vec)
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Data.Proxy (Proxy(..))
import Data.Constraint.Nat.Extra
import GHC.TypeNats.Proof (Rewrite(..), using)
import Clash.Signal.Channel

------------------------------
-- Setters
------------------------------
setLayerAddressC ∷  ∀ (alg ∷ SLH_DSA) dom . KnownSLH_DSAParameters alg ⇒ Channel dom (ADRSType alg) → LayerAddressType alg → Channel dom (ADRSType alg)
setLayerAddressC adrs l 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = fmap (`setLayerAddress` l) adrs
setTreeAddressC ∷ ∀ (alg ∷ SLH_DSA) ℓ dom . (KnownSLH_DSAParameters alg, KnownNat ℓ)⇒ Channel dom (ADRSType alg) → Channel dom (BitVector ℓ) →  Channel dom (ADRSType alg)
setTreeAddressC adrs t 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = liftA2 setTreeAddress adrs t

setTypeAndClearC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg) → ADRSTypeType → Channel dom (ADRSType alg)
setTypeAndClearC adrs adrstype       
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = fmap (`setTypeAndClear` adrstype) adrs 

_setTypeAndClearC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg) → Channel dom (BitVector (TypeSize alg * ByteSize)) → Channel dom (ADRSType alg)
_setTypeAndClearC adrs l 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
      = _setTypeAndClear <$> adrs <*> l

setKeyPairAddressC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) →  Channel dom (BitVector (ChainAddressTreeHeightSize alg * ByteSize)) →  Channel dom (ADRSType alg)
setKeyPairAddressC adrs i 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = liftA2 setKeyPairAddress adrs i
setChainAddressC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) →  Channel dom (BitVector (ChainAddressTreeHeightSize alg * ByteSize)) →  Channel dom (ADRSType alg)
setChainAddressC adrs i 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = liftA2 setChainAddress adrs i
setTreeHeightC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) →  Channel dom (BitVector (ChainAddressTreeHeightSize alg * ByteSize)) →  Channel dom (ADRSType alg)
setTreeHeightC adrs i
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = liftA2 setTreeHeight adrs i

setHashAddressC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) →  Channel dom (BitVector (ChainAddressTreeHeightSize alg * ByteSize)) →  Channel dom (ADRSType alg)
setHashAddressC adrs i 
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = liftA2 setHashAddress adrs i
setTreeIndexC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) → Channel dom (BitVector (ChainAddressTreeHeightSize alg * ByteSize)) →  Channel dom (ADRSType alg)
setTreeIndexC adrs i
      | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
      = liftA2 setTreeIndex adrs i
------------------------------
-- Getters
------------------------------
getKeyPairAddressC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) → Channel dom (BitVector (KeyPairAddressSize alg * ByteSize))
getKeyPairAddressC input
            | SLH_DSAParametersFacts{} ← knownSLH_DSAParameters @alg     
            = fmap getKeyPairAddress input 
getTreeIndexC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg)⇒ Channel dom (ADRSType alg) → Channel dom (BitVector (HashAddressTreeIndexSize alg * ByteSize))
getTreeIndexC input
            | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
            = fmap getTreeIndex input
getADRSVectorC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg) → Channel dom (Vec (ADRSTypeVectorSize alg) ByteType)
getADRSVectorC input
            | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
            = fmap getADRSVector input
getADRSBitVectorC ∷ ∀ (alg ∷ SLH_DSA) dom . (KnownSLH_DSAParameters alg) ⇒ Channel dom (ADRSType alg) → Channel dom (BitVector (BitSize (ADRSType alg)))
getADRSBitVectorC input
            | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg     
            = fmap getADRSBitVector input
