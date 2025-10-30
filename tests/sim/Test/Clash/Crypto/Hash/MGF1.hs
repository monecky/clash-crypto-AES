{-|
Module      : Test.Clash.Crypto.Hash.MGF1
Copyright   : Copyright © 2024 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.Hash.MGF1'.
-}
module Test.Clash.Crypto.Hash.MGF1 (
    tastyTests
) where
import Clash.Prelude
-- import Data.Maybe (catMaybes, listToMaybe, fromMaybe)

-- https://hackage.haskell.org/package/clash-prelude-hedgehog
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog


-- Generate BitVecor and Vector
import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)
import Clash.Hedgehog.Sized.Vector
import qualified Crypto.PubKey.MaskGenFunction as RefMGF1
tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.Hash.MGF1"
  [localOption (HedgehogTestLimit (Just 10)) $ -- Purpose is mainly to get familiar with testing.
      testProperty "Functional equality of XOR" $ property $ do
        a ← forAll $ genDefinedBitVector
        b ← forAll $ genDefinedBitVector
        testOplus a b] 
type TestLen = 8
testOplus ∷ (Monad m) => BitVector TestLen -> BitVector TestLen -> PropertyT m ()
testOplus a b = xor b a === xor a b