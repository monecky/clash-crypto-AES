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

import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions

tastyTests ∷ TestTree
tastyTests = localOption (HedgehogTestLimit (Just 100)) $  testGroup "Clash.Crypto.PQC.SLH_DSA.Specification.Definitions"
  [
   testProperty "Test division with ceiling operator" $ property $ do
        a ← forAll $ genDefinedBitVector
        b ← forAll $ genDefinedBitVector
        testPropertyCeilXdivY a b,
    testProperty "Test division with floor operator" $ property $ do
          a ← forAll $ genDefinedBitVector
          b ← forAll $ genDefinedBitVector
          testPropertyFloorXdivY a b] 

type TestLen = 8
testPropertyCeilXdivY ∷ (Monad m) => BitVector TestLen -> BitVector TestLen -> PropertyT m ()
testPropertyCeilXdivY x y = if y /= (0b0 ∷ BitVector TestLen) then ceilXdivY x y === fromInteger (result + rounder) else x === x
    where 
        division = divMod (toInteger x) (toInteger y)
        result = fst division
        remainder = snd division
        rounder = if remainder /= 0 then 1 else 0

testPropertyFloorXdivY ∷ (Monad m) => BitVector TestLen -> BitVector TestLen -> PropertyT m ()
testPropertyFloorXdivY x y = if y /= (0b0 ∷ BitVector TestLen) then floorXdivY x y === fromInteger result else x === x
    where 
        result = div (toInteger x) (toInteger y)
 