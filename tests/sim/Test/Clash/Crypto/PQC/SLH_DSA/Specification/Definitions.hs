{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Specification.Definitions'
-}


module Test.Clash.Crypto.PQC.SLH_DSA.Specification.Definitions (tastyTests) where

import Clash.Prelude

import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog

import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)


tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.PQC.SLH_DSA.Specification.Definitions"
  [testProperty "Dummy" $ property $ do
        a ← forAll $ genDefinedBitVector @2
        a === a] 

