{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Types
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic types covering the fundamentals of FIPS 205.
All subscript are superscripts, since not all subscripts are 
defined in unicode. But for superscript there are.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}

module Clash.Crypto.PQC.SLH_DSA.Specification.Types (
  -- Parameters
  N 
  , H 
  , D 
  , H' 
  , A 
  , K 
  , Lgʷ 
  , M 
  , W 
  , Len¹ 
  , Len² 
  , Len 
  , ByteType
  , SLH_DSA(..)
  , PKSeedType
  , SKSeedType
  , PKRootType
  , SKPrfType
  , ByteSize
  , NBlockType
  , MType
  , M¹Type
  , M²Type
  , MˡType
  , RType
  , Opt_randType
  , FOutType
  , HOutType
  , TˡOutType
  , PRFOutType
  , HᵐˢᵍOutType
  , PRFᵐˢᵍOutType
  , SIGʷᵒᵗˢPlusType
  , PKˢⁱᵍType
  , NodeType
  , AUTHType
  , SIGˣᵐˢˢType(..)
  , SIGᴴᵀType
  -- Address
  , ADRSType(..)
  , ADRSTypeType(..)
  , ADRSTypeVectorSize
  , LayerAddressSize
  , TreeAddressSize
  , TypeSize
  , KeyPairAddressSize
  , ChainAddressTreeHeightSize
  , HashAddressTreeIndexSize
  , KeyPairAddressType
  , ChainAddressTreeHeightType
  , HashAddressTreeIndexType
  , LayerAddressType
  , TreeAddressType
  , TypeType
  , IdxType
  -- Hash
  , SecurityLevelSLH_DSA
  , SHAVersionSLH_DSA
  , SHAVersion (..)
  , SecurityLevel (..)
  , SHAVersionPRFᵐˢᵍSLH_DSA
  , SHAVersionPRFᵐˢᵍ
  -- Deterministic
  , deterministicSLHDSA
  -- FORS
  , MD
  , MDType
  , SIGᶠᵒʳˢType
  , PrivateKeyValueTreeType
  , AUTHTreeType
  , ElemForsType (..)
  -- Keys
  , PrivateKey (..)
  , PublicKey (..)
  , PK (..)
  , SK (..)
)where
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
import Clash.Crypto.Hash.SHA as SHA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Types.Address