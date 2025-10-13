{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Generic
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Some helper functions that may be looked different
Fits the definition of symbols of FIPS205
-}
{-# LANGUAGE UndecidableInstances #-}
module Clash.Crypto.PQC.SLH_DSA.General.General(
    CeilXDivY
    , FloorXDivY
) where

import GHC.TypeLits
import Data.Type.Bool (If)

type CeilXDivY ∷ Nat → Nat → Nat
type family CeilXDivY a b where
    CeilXDivY a b = If (a `Mod`b <=? (0 ∷ Nat)) (a `Div` b + 0) (a `Div` b + 1)


type FloorXDivY ∷ Nat → Nat → Nat
type family FloorXDivY a b where
    FloorXDivY a b = (a `Div` b)