{-|
Module      : Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Basic definitions covering the fundamentals of FIPS 205.
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE UndecidableInstances #-}

module Clash.Crypto.PQC.SLH_DSA.Specification.Definitions (
    ceilXdivY
    , floorXdivY
)where
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Hash