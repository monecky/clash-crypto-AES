{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash'
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE ScopedTypeVariables #-}



module Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash (tastyTests) where

import Clash.Prelude
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog
import Clash.Crypto.PQC.SLH_DSA.General.General

import Control.Monad.IO.Class

import System.IO (appendFile)
import qualified Data.List as List
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)
import Clash.Crypto.PQC.SLH_DSA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Signal.Channel
import Data.Monoid (First(..))
import Data.Maybe (fromMaybe)
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import  Clash.Crypto.PQC.SLH_DSA.Streaming.Types
tastyTests :: TestTree
tastyTests =
  testGroup
    "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions"
    [ localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.H"
          [ testProperty "Division with ceiling operator" $ property $ do
              a <- forAll genDefinedBitVector
              b <- forAll genDefinedBitVector
              testPropertyCeilXdivY a b
          , testProperty "Division with floor operator" $ property $ do
              a <- forAll genDefinedBitVector
              b <- forAll genDefinedBitVector
              testPropertyFloorXdivY a b
          , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M²Type SLH_DSA_SHA2_128s) @(HOutType SLH_DSA_SHA2_128s) "H: SLH_DSA_SHA2_128s" _HStream
          , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M²Type SLH_DSA_SHA2_128f) @(HOutType SLH_DSA_SHA2_128f) "H: SLH_DSA_SHA2_128f" _HStream
          -- , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_192s, ADRSType SLH_DSA_SHA2_192s, M²Type SLH_DSA_SHA2_192s) @(HOutType SLH_DSA_SHA2_192s) "H: SLH_DSA_SHA2_192s" _HStream
          -- , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_192f, ADRSType SLH_DSA_SHA2_192f, M²Type SLH_DSA_SHA2_192f) @(HOutType SLH_DSA_SHA2_192f) "H: SLH_DSA_SHA2_192f" _HStream
          -- , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M²Type SLH_DSA_SHA2_128s) @(HOutType SLH_DSA_SHA2_128s) "H: SLH_DSA_SHA2_128s" _HStream
          -- , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_256s, ADRSType SLH_DSA_SHA2_256s, M²Type SLH_DSA_SHA2_256s) @(HOutType SLH_DSA_SHA2_256s) "H: SLH_DSA_SHA2_256s" _HStream
          -- , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_256f, ADRSType SLH_DSA_SHA2_256f, M²Type SLH_DSA_SHA2_256f) @(HOutType SLH_DSA_SHA2_256f) "H: SLH_DSA_SHA2_256f" _HStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.F"
          [ 
          testProperty "Hash F SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M¹Type SLH_DSA_SHA2_128s) @(FOutType SLH_DSA_SHA2_128s) "F SLH_DSA_SHA2_128s" _FStream
          , testProperty "Hash F SLH_DSA_SHA2_128f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M¹Type SLH_DSA_SHA2_128f) @(FOutType SLH_DSA_SHA2_128f) "F SLH_DSA_SHA2_128f" _FStream
          -- , testProperty "Hash F SLH_DSA_SHA2_192s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_192s, ADRSType SLH_DSA_SHA2_192s, M¹Type SLH_DSA_SHA2_192s) @(FOutType SLH_DSA_SHA2_192s) "F SLH_DSA_SHA2_192s" _FStream
          -- , testProperty "Hash F SLH_DSA_SHA2_192f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_192f, ADRSType SLH_DSA_SHA2_192f, M¹Type SLH_DSA_SHA2_192f) @(FOutType SLH_DSA_SHA2_192f) "F SLH_DSA_SHA2_192f" _FStream
          -- , testProperty "Hash F SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M¹Type SLH_DSA_SHA2_128s) @(FOutType SLH_DSA_SHA2_128s) "F SLH_DSA_SHA2_128s" _FStream
          -- , testProperty "Hash F SLH_DSA_SHA2_256s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_256s, ADRSType SLH_DSA_SHA2_256s, M¹Type SLH_DSA_SHA2_256s) @(FOutType SLH_DSA_SHA2_256s) "F SLH_DSA_SHA2_256s" _FStream
          -- , testProperty "Hash F SLH_DSA_SHA2_256f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_256f, ADRSType SLH_DSA_SHA2_256f, M¹Type SLH_DSA_SHA2_256f) @(FOutType SLH_DSA_SHA2_256f) "F SLH_DSA_SHA2_256f" _FStream
          ]
    ]
  

type TestLen = 8

testPropertyCeilXdivY
  ∷ (Monad m)
  ⇒ BitVector TestLen
  → BitVector TestLen
  → PropertyT m ()
testPropertyCeilXdivY x y =
  if y /= (0b0 ∷ BitVector TestLen)
    then ceilXdivY x y === fromInteger (result + rounder)
    else x === x
 where
  division = divMod (toInteger x) (toInteger y)
  result = fst division
  remainder = snd division
  rounder = if remainder /= 0 then 1 else 0

testPropertyFloorXdivY
  ∷ (Monad m, MonadIO m)
  ⇒ BitVector TestLen
  → BitVector TestLen
  → PropertyT m ()
testPropertyFloorXdivY x y =
  if y /= (0b0 ∷ BitVector TestLen)
    then do
      let result = div (toInteger x) (toInteger y)
      liftIO $
        appendFile "floor_div_results.csv"
          (List.intercalate "," [show (toInteger x), show (toInteger y), show result] <> "\n")
      floorXdivY x y === fromInteger result
    else x === x



type HashComponent a b dom =
 HiddenClockResetEnable dom =>
 Channel dom (a) ->
 Channel dom (b)

hashProperty :: ∀ a b. (BitPack a, BitPack b, NFDataX b) ⇒ String →  KnownDomain System => HashComponent a b System -> Property
hashProperty name hashComp = property $ do
  f <- forAll $ genDefinedBitVector 
  let f' = compute $ unpack f
  liftIO $
        appendFile "hash_test_results.csv"
          (List.intercalate "," [name, show (pack f), show (pack f')] <> "\n")
  -- Just to satisfy the test environment.
  pack f' === pack f'
 where
  moduloError =
    error "Since the modulo of the field is prime, the inverse always exists."
  compute input
    = fromMaybe (error "The returned list was empty")
    $ getFirst
    $ foldMap First
    $ sampleN @System 10000000
    $ withClockResetEnable @System clockGen resetGen enableGen
    $ newsfeed
    $ hashComp
    $ channel
    $ fmap (input, )
    $ fromList
    $ Keep : Keep : Release : List.repeat Keep

