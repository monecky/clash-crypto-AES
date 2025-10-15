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

module Clash.Crypto.PQC.SLH_DSA.Streaming.Types (
    SLH_DSA_hashStream(..)
) where
import Clash.Crypto.PQC.SLH_DSA.Streaming.Types.Hash