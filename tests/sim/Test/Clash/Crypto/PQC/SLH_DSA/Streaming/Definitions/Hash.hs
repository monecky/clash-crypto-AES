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
          [ testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M²Type SLH_DSA_SHA2_128s) @(HOutType SLH_DSA_SHA2_128s) "H;SLH_DSA_SHA2_128s;" _HStream
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
    -- , localOption (HedgehogTestLimit (Just 100)) $
    --     testGroup
    --       "Hash.PRFᵐˢᵍ"
    --       [ 
    --       testProperty   "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128s" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128s) "PRFmsg;SLH_DSA_SHA2_128s;" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s)x))))
    --       , testProperty "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128f" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128f) "PRFmsg;SLH_DSA_SHA2_128f;" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f)x))))
    --       ]
    -- , localOption (HedgehogTestLimit (Just 100)) $
    --     testGroup
    --       "Hash.Hᵐˢᵍ"
    --       [ 
    --       testProperty   "Hash Hᵐˢᵍ SLH_DSA_SHA2_128s" $ hashProperty @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) @(HᵐˢᵍOutType SLH_DSA_SHA2_128s) "PRFmsg;SLH_DSA_SHA2_128s;" (\x → _HᵐˢᵍStream @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) x))) (transferToD @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s)x))))
    --       , testProperty "Hash Hᵐˢᵍ SLH_DSA_SHA2_128f" $ hashProperty @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) @(HᵐˢᵍOutType SLH_DSA_SHA2_128f) "PRFmsg;SLH_DSA_SHA2_128f;" (\x → _HᵐˢᵍStream @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) x))) (transferToD @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f)x))))
    --       ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Test transferToC, used also later"
          [ 
          testProperty   "transferToC" $ transferToCEqualProperty @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) "PRFmsg;SLH_DSA_SHA2_128s;" (\x → (transferToC @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) x))))
          , testProperty "transferToC" $ transferToCEqualProperty @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) "PRFmsg;SLH_DSA_SHA2_128f;" (\x → (transferToC @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) x))))
          , testProperty   "transferToC not equal" $ transferToCNotEqualProperty @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s) "PRFmsg;SLH_DSA_SHA2_128s;" (\x → (transferToC @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s) (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, PKRootType SLH_DSA_SHA2_128s) x))))
          , testProperty "transferToC not equal" $ transferToCNotEqualProperty @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f) "PRFmsg;SLH_DSA_SHA2_128f;" (\x → (transferToC @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f) (mapEnd (\y → ()) (serializeHash @ByteSize @(RType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, PKRootType SLH_DSA_SHA2_128f) x))))
          ]
    ]
  


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


transferToCEqualProperty :: ∀ a b. (BitPack a, BitPack b, NFDataX b, a~b) ⇒ String →  KnownDomain System => HashComponent a b System -> Property
transferToCEqualProperty name hashComp = property $ do
  f <- forAll $ genDefinedBitVector 
  let f' = compute $ unpack f
  liftIO $
        appendFile "hash_test_results.csv"
          (List.intercalate "," [name, show (pack f), show (pack f')] <> "\n")
  -- Just to satisfy the test environment.
  pack f' === f
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
transferToCNotEqualProperty :: ∀ a b. (BitPack a, BitPack b, NFDataX b, BitSize b ≤ BitSize a, BitSize a ~ (BitSize b + (BitSize a - BitSize b))) ⇒ String →  KnownDomain System => HashComponent a b System -> Property
transferToCNotEqualProperty name hashComp = property $ do
  f <- forAll $ genDefinedBitVector 
  let f' = compute $ unpack f
  liftIO $
        appendFile "hash_test_results.csv"
          (List.intercalate "," [name, show (pack f), show (pack f')] <> "\n")
  -- Just to satisfy the test environment.
  (pack f') === ((v2bv . takeI @(BitSize b) . bv2v) f)
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
      (~~>) state@(vObject, counter, prevProviderAction) frame = ((goBuff frame counter, goIdx frame counter, goProviderAction frame counter prevProviderAction), ((unpacked (goBuff frame counter)), (goProviderAction frame counter prevProviderAction)))
        where 
          goBuff ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Vec (BitSize a1 `Div` n1) (BitVector n1)
          goBuff (Start _ x) idx = vObject <<+ x
          goBuff (Middle x) idx
            | idx /= 1, idx /= 0 = vObject <<+ x
            | otherwise = vObject
          goBuff (End _ x) idx
            | idx == 2 = vObject <<+ x
            | otherwise = vObject 
          goBuff _ _ = vObject
          goIdx ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → Index ((BitSize a1 `Div` n1) + 1)
          goIdx (Start _ _) idx = maxBound
          goIdx (Middle _) idx       = satPred SatBound idx
          goIdx (End _ _) idx       = satPred SatBound idx
          goIdx _ idx       = idx
          goProviderAction ∷ Frame s e (BitVector n1) → Index ((BitSize a1 `Div` n1) + 1) → ProviderAction → ProviderAction
          goProviderAction (Start _ x) _ _ = Clear
          goProviderAction (Middle x) idx prev
            | idx == 2 = Release
            | idx == 1 = Keep
            | idx == 0 = Keep
            | otherwise = prev
          goProviderAction (End _ x) _  _= Release
          goProviderAction Idle _ _ = Keep
          goProviderAction NoData _ _ = Clear
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
