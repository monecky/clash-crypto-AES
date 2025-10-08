{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Types
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic types covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# OPTIONS_GHC -Wno-unrecognised-pragmas #-}
{-# HLINT ignore "[]" #-}
{-# HLINT ignore "Use camelCase" #-}
module Clash.Crypto.PQC.SLH_DSA.Specification.Types where
import Clash.Class.BitPack (BitPack)
import Clash.XException (NFDataX)
import Data.Eq (Eq)
import Data.Enum (Enum, Bounded)
import Data.Kind (Type)
import Data.Ord (Ord)
import Data.Typeable (Typeable)
import GHC.Show (Show)
import GHC.Generics (Generic)
import Clash.Crypto.Hash.SHA
type SLH_DSA ∷ Type
data SLH_DSA =
    SLH_DSA_SHA2_128s
  | SLH_DSA_SHAKE_128s
  | SLH_DSA_SHA2_128f
  | SLH_DSA_SHAKE_128f
  | SLH_DSA_SHA2_192s
  | SLH_DSA_SHAKE_192s
  | SLH_DSA_SHA2_192f
  | SLH_DSA_SHAKE_192f
  | SLH_DSA_SHA2_256s
  | SLH_DSA_SHAKE_256s
  | SLH_DSA_SHA2_256f
  | SLH_DSA_SHAKE_256f
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
type TypeOfSHA ∷ Type
data TypeOfSHA =
      SHA
    | SHAKE
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
type SizeOfSHA ∷ Type
data SizeOfSHA =
      Size128
    | Size192
    | Size256
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
type ModeOfSLH_DSA ∷ Type
data ModeOfSLH_DSA =
      S
    | F
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
class SpecificSLH_DSA (alg ∷ SLH_DSA) where
  type TypeSHA alg ∷ TypeOfSHA
  type SizeSHA alg ∷ SizeOfSHA
  type ModeSLH_DSA alg ∷ ModeOfSLH_DSA

type SLH_DSA_SHA ∷ SLH_DSA → SHA
class  SpecificSLH_DSA alg ⇒ SLH_DSA_SHA alg where
  -- SLH_DSA_SHA SLH_DSA_SHA2_256s = SHA.SHA256
  -- SLH_DSA_SHA SLH_DSA_SHA2_256f = SHA.SHA256
  -- SLH_DSA_SHA _                 = SHA.SHA256
