{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Types.Address
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

This file covers the data structures and setters and getters regards ADRS.
This section 4.2, 4.3 and 11.2 of FIPS 205
Algorithmic reference implementation of FIPS 205 using a purely
functional description.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Types.Address where
import Clash.Sized.BitVector (BitVector)
import Clash.Sized.Vector (Vec)
import Clash.Class.BitPack (BitPack)
import Clash.XException (NFDataX)
import Data.Eq (Eq)
import Data.Enum (Enum, Bounded)
import Data.Kind (Type)
import Data.Ord (Ord)
import Data.Typeable (Typeable)
import GHC.Show (Show)

import GHC.Generics (Generic)
import GHC.TypeLits
import Data.Proxy (Proxy(..))
import Data.Type.Bool (If)
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Parameters
---------------------------------------------------------------------------
-- ADRS that is define in SLH_DSA 
-- according Table 2/ Figure 18 in FIPS205
--
---------------------------------------------------------------------------
type LayerAddressSize ∷ SLH_DSA → Nat
type family LayerAddressSize (alg ∷ SLH_DSA) where
  LayerAddressSize SLH_DSA_SHA2_128s  = 1
  LayerAddressSize SLH_DSA_SHAKE_128s = 4
  LayerAddressSize SLH_DSA_SHA2_128f  = 1
  LayerAddressSize SLH_DSA_SHAKE_128f = 4
  LayerAddressSize SLH_DSA_SHA2_192s  = 1
  LayerAddressSize SLH_DSA_SHAKE_192s = 4
  LayerAddressSize SLH_DSA_SHA2_192f  = 1
  LayerAddressSize SLH_DSA_SHAKE_192f = 4
  LayerAddressSize SLH_DSA_SHA2_256s  = 1
  LayerAddressSize SLH_DSA_SHAKE_256s = 4
  LayerAddressSize SLH_DSA_SHA2_256f  = 1
  LayerAddressSize SLH_DSA_SHAKE_256f = 4
  LayerAddressSize _                  = 1
type LayerAddressType (alg ∷ SLH_DSA) = Vec (LayerAddressSize alg) ByteType
type TreeAddressSize ∷ SLH_DSA → Nat
type family TreeAddressSize (alg ∷ SLH_DSA) where
  TreeAddressSize SLH_DSA_SHA2_128s  = 8
  TreeAddressSize SLH_DSA_SHAKE_128s = 12
  TreeAddressSize SLH_DSA_SHA2_128f  = 8
  TreeAddressSize SLH_DSA_SHAKE_128f = 12
  TreeAddressSize SLH_DSA_SHA2_192s  = 8
  TreeAddressSize SLH_DSA_SHAKE_192s = 12
  TreeAddressSize SLH_DSA_SHA2_192f  = 8
  TreeAddressSize SLH_DSA_SHAKE_192f = 12
  TreeAddressSize SLH_DSA_SHA2_256s  = 8
  TreeAddressSize SLH_DSA_SHAKE_256s = 12
  TreeAddressSize SLH_DSA_SHA2_256f  = 8
  TreeAddressSize SLH_DSA_SHAKE_256f = 12
  TreeAddressSize _                  = 8
type TreeAddressType (alg ∷ SLH_DSA) = Vec (TreeAddressSize alg) ByteType
type TypeSize ∷ SLH_DSA → Nat
type family TypeSize (alg ∷ SLH_DSA) where
  TypeSize SLH_DSA_SHA2_128s  = 1
  TypeSize SLH_DSA_SHAKE_128s = 4
  TypeSize SLH_DSA_SHA2_128f  = 1
  TypeSize SLH_DSA_SHAKE_128f = 4
  TypeSize SLH_DSA_SHA2_192s  = 1
  TypeSize SLH_DSA_SHAKE_192s = 4
  TypeSize SLH_DSA_SHA2_192f  = 1
  TypeSize SLH_DSA_SHAKE_192f = 4
  TypeSize SLH_DSA_SHA2_256s  = 1
  TypeSize SLH_DSA_SHAKE_256s = 4
  TypeSize SLH_DSA_SHA2_256f  = 1
  TypeSize SLH_DSA_SHAKE_256f = 4
  TypeSize _                  = 1
type DataSize ∷ SLH_DSA → Nat
type family DataSize (alg ∷ SLH_DSA) where
  DataSize _  = 12

type KeyPairAddressSize ∷ SLH_DSA → Nat
type family KeyPairAddressSize (alg ∷ SLH_DSA) where
  KeyPairAddressSize _  = 4
type ChainAddressTreeHeightSize ∷ SLH_DSA → Nat
type family ChainAddressTreeHeightSize (alg ∷ SLH_DSA) where
  ChainAddressTreeHeightSize _  = 4
type HashAddressTreeIndexSize ∷ SLH_DSA → Nat
type family HashAddressTreeIndexSize (alg ∷ SLH_DSA) where
  HashAddressTreeIndexSize _  = 4
type TypeType (alg ∷ SLH_DSA) = Vec (TypeSize alg) ByteType
type DataType (alg ∷ SLH_DSA) = Vec (DataSize alg) ByteType
type KeyPairAddressType (alg ∷ SLH_DSA) = Vec (KeyPairAddressSize alg) ByteType
type ChainAddressTreeHeightType (alg ∷ SLH_DSA) = Vec (ChainAddressTreeHeightSize alg) ByteType
type HashAddressTreeIndexType (alg ∷ SLH_DSA) = Vec (HashAddressTreeIndexSize alg) ByteType
data ADRSType (alg ∷ SLH_DSA) = ADRSType {
  layerAddress ∷ LayerAddressType alg,
  treeAddress ∷ TreeAddressType alg,
  typeAddress ∷ TypeType alg,
  keyPairAddress ∷ KeyPairAddressType alg,
  chainAddressTreeHeight ∷ ChainAddressTreeHeightType alg,
  hashAddressTreeIndexType ∷ HashAddressTreeIndexType alg
} deriving     ( Generic
              , Show
              , Typeable   
              )
deriving anyclass instance (KnownNat (TreeAddressSize alg), KnownNat (H' alg), KnownNat (LayerAddressSize alg), KnownNat (TypeSize alg), KnownNat (N alg)) ⇒ BitPack (ADRSType alg)
deriving anyclass instance (KnownNat (TreeAddressSize alg), KnownNat (H' alg), KnownNat (LayerAddressSize alg), KnownNat (TypeSize alg), KnownNat (N alg)) ⇒ NFDataX (ADRSType alg)
deriving anyclass instance (KnownNat (TreeAddressSize alg), KnownNat (H' alg), KnownNat (LayerAddressSize alg), KnownNat (TypeSize alg), KnownNat (N alg)) ⇒ Eq      (ADRSType alg)
deriving anyclass instance (KnownNat (TreeAddressSize alg), KnownNat (H' alg), KnownNat (LayerAddressSize alg), KnownNat (TypeSize alg), KnownNat (N alg)) ⇒ Ord     (ADRSType alg)
type ADRSTypeType ∷ Type
data ADRSTypeType =
    WOTS_HASH -- 0
  | WOTS_PK -- 1
  | TREE -- 2
  | FORS_TREE -- 3
  | FORS_ROOTS -- 4
  | WOTS_PRF -- 5
  | FORS_PRF -- 6
  deriving
    ( Generic
    , NFDataX
    , BitPack
    , Eq
    , Ord
    , Show
    , Enum
    , Bounded
    , Typeable
    )