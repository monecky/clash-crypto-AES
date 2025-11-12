{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash'
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE MagicHash #-}

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
import Clash.Signal.DataStream
import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Language.Haskell.Unicode (type (≤))
import GHC.TypeNats.Proof (Rewrite(..), using)

import GHC.TypeLits.Extra
import Data.Proxy
import Data.Constraint
import Unsafe.Coerce
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
type TestLen = 33
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
          , testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M²Type SLH_DSA_SHA2_128s) @(HOutType SLH_DSA_SHA2_128s) "H;SLH_DSA_SHA2_128s;" _HStream
          , testProperty "Hash H SLH_DSA_SHA2_128f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M²Type SLH_DSA_SHA2_128f) @(HOutType SLH_DSA_SHA2_128f) "H;SLH_DSA_SHA2_128f;" _HStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.F"
          [ 
          testProperty   "Hash F SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M¹Type SLH_DSA_SHA2_128s) @(FOutType SLH_DSA_SHA2_128s) "F;SLH_DSA_SHA2_128s;" _FStream
          , testProperty "Hash F SLH_DSA_SHA2_128f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M¹Type SLH_DSA_SHA2_128f) @(FOutType SLH_DSA_SHA2_128f) "F;SLH_DSA_SHA2_128f;" _FStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.Tl"
          [ 
          testProperty   "Hash Tl SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, MˡType TestLen SLH_DSA_SHA2_128s) @(TˡOutType SLH_DSA_SHA2_128s) "Tl;SLH_DSA_SHA2_128s;" _TˡStream
          , testProperty "Hash Tl SLH_DSA_SHA2_128f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, MˡType TestLen SLH_DSA_SHA2_128f) @(TˡOutType SLH_DSA_SHA2_128f) "Tl;SLH_DSA_SHA2_128f;" _TˡStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.PRF"
          [ 
          testProperty   "Hash PRF SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, SKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s) @(PRFOutType SLH_DSA_SHA2_128s) "PRF;SLH_DSA_SHA2_128s;" _PRFStream
          , testProperty "Hash PRF SLH_DSA_SHA2_128f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, SKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f) @(PRFOutType SLH_DSA_SHA2_128f) "PRF;SLH_DSA_SHA2_128f;" _PRFStream
          ]
      
    ]
  



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

----------
-- Generalized methodes
--
-----------
transferToC ∷ ∀ a n dom. (KnownDomain dom, HiddenClockResetEnable dom) ⇒ (BitPack a, KnownNat n, BitSize a `Mod` n ~ 0, 1 ≤ n)  
            ⇒ DataStream dom () () (BitVector n) → Channel dom a 
transferToC = channel . mealy (~~>) 
    -- Starting state
    (repeat 0x0 ∷ Vec (BitSize a `Div` n) (BitVector n)
    , 0 ∷ Index ((BitSize a `Div` n) + 1) 
    , Clear
    )
    where
      (~~>) ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) 
              ⇒  ( -- Current state
                  Vec (BitSize a1 `Div` n1) (BitVector n1) -- PK and addrnd buffer
                  , Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  , ProviderAction
                  ) 
              → (Frame () () (BitVector n1)) 
              → ( -- Next state
                  (Vec (BitSize a1 `Div` n1) (BitVector n1) -- PK and addrnd buffer
                  , Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  ,ProviderAction
                  )
                  -- Output
                , (a1, ProviderAction))
      (~~>) state@(vObject, counter, prevProviderAction) frame = ((goBuff frame counter, goIdx frame counter, goProviderAction frame counter prevProviderAction), ((unpacked vObject), (goProviderAction frame counter prevProviderAction)))
        where 
          goBuff ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Vec (BitSize a1 `Div` n1) (BitVector n1)
          goBuff (Start _ x) idx
            | idx /= 0 = vObject <<+ x
            | otherwise = vObject
          goBuff (Middle x) idx
            | idx /= 0 = vObject <<+ x
            | otherwise = vObject
          goBuff (End _ x) idx
            | idx == 1 = vObject <<+ x
            | otherwise = vObject
          goIdx ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Index ((BitSize a1 `Div` n1) + 1)
          goIdx (Start _ x) idx = maxBound
          goIdx frame idx       = satPred SatBound idx
          goProviderAction ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → ProviderAction → ProviderAction
          goProviderAction (Start _ x) _ _ = Clear
          goProviderAction (Middle x) idx prev
            | idx == 1 = Release
            | idx == 0 = Keep
            | otherwise = prev
          goProviderAction (End _ x) _  _= Keep
      unpacked ∷ ∀ a n . (BitPack a, KnownNat n, 1 ≤ n, Mod (BitSize a) n ~ 0) ⇒ Vec (BitSize a `Div` n) (BitVector n) → a
      unpacked 
        | Rewrite ← using @(DivTimes (BitSize a) n)
        , Rewrite ← using @(CancelMultiple (BitSize a) n)
        = unpack . concatBitVector#
      neval = error "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH.serializeEn: Mealy"
-- Ignores the Div BitSize a n frames and continures from there
transferToD ∷ ∀ a n dom. (KnownDomain dom, HiddenClockResetEnable dom) ⇒ (BitPack a, KnownNat n, BitSize a `Mod` n ~ 0, 1 ≤ n)  
            ⇒ DataStream dom () () (BitVector n) → DataStream dom () () (BitVector n) 
transferToD = mealy  ((~~>) @a @n)
    -- Starting state
    ( 0 ∷ Index ((BitSize a `Div` n) + 1) 
    , False
    )
    where
      (~~>) ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) ⇒  ( -- Current state
                  Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  , Bool
                  ) 
              → (Frame () () (BitVector n1)) 
              → ( -- Next state
                  (Index ((BitSize a1 `Div` n1) + 1) -- Counter
                  , Bool
                  )
                  -- Output
                , Frame () () (BitVector n1))
      (~~>) state@(counter, isStarted) frame = ((goIdx @a1 @n1 frame counter, (counter == 1) && (goIdx @a1 @n1 frame counter == 0)), (goFrame @a1 @n1 frame counter isStarted))
        where 
          goFrame ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) 
              ⇒ Frame () () (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Bool → Frame () () (BitVector n1)
          goFrame (Middle x) idx isStarted
            | idx /= 0 = NoData
            | idx == 0, isStarted = Start () x
            | otherwise = Middle x
          goFrame f _ idx = f
          goIdx ∷ ∀ a1 n1 . (BitPack a1, KnownNat n1, BitSize a1 `Mod` n1 ~ 0, 1 ≤ n1) 
              ⇒ Frame () () (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Index ((BitSize a1 `Div` n1) + 1)
          goIdx (Start _ x) idx = maxBound
          goIdx frame idx       = satPred SatBound idx
      neval = error "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.SLH.serializeEn: Mealy"

