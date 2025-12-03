{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Algorithm
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.ALgorithm'
-}


module Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions (tastyTests) where



import Clash.Prelude

import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog

import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)
import qualified Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash     as Hash
import qualified Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS     as FORS
import qualified Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus as WOTS
tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.PQC.SLH_DSA.Streaming.Algorithm"
  [
    Hash.tastyTests,
    FORS.tastyTests,
    WOTS.tastyTests
   ] 

