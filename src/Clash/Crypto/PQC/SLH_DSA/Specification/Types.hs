{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Types
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic types covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
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
type SLH_DSA_SHA ∷ SLH_DSA → SHA
type family SLH_DSA_SHA alg where
  SLH_DSA_SHA SLH_DSA_SHA2_256s = SHA256
  SLH_DSA_SHA SLH_DSA_SHA2_256f = SHA256
  SLH_DSA_SHA _                 = SHA256
 