{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus'
Tests regards to algorithms section 5 from NIST FIPS 205
-}

{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE MagicHash #-}

module Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTSplus (tastyTests) where

import Clash.Prelude
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog
import Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.RandomAddress
import Clash.Crypto.PQC.SLH_DSA.General.General

import Control.Monad.IO.Class

import System.IO (appendFile)
import qualified Data.List as List
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions
import Clash.Hedgehog.Sized.BitVector (genDefinedBitVector)
import Clash.Crypto.PQC.SLH_DSA
import Clash.Crypto.PQC.SLH_DSA.Specification.Types
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
import Clash.Signal.Channel
import Data.Monoid (First(..))
import Data.Maybe (fromMaybe)
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Hash
import  Clash.Crypto.PQC.SLH_DSA.Streaming.Types
import Clash.Signal.DataStream
import Clash.Signal.Channel
import Clash.Signal.Channel.Extra 
import Language.Haskell.Unicode (type (≤))
-- import GHC.TypeNats.Proof (Rewrite(..), using)

-- import GHC.TypeLits.Extra
import Data.Proxy
import Data.Constraint
import Unsafe.Coerce
import Data.Constraint.Nat.Extra
  ( ModBound, TimesMonotoneRight, LeTrans, CancelMultiple, CancelFactor
  , CondMonotoneGE, ModZero, KeepsPositiveIfMultiple, DivTimes, ModTimes
  )
-- Testing HMAC
import Clash.Crypto.Hash.SHA.Specification
import Clash.Crypto.Hash.SHA as SHA
import Clash.Crypto.MAC.HMAC as HMAC
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import System.Process (readProcess)
import GHC.Utils.Misc (fstOf3, sndOf3,thdOf3)
type TestLen = 16 -- Should be bigger or equal to 2
tastyTests :: TestTree
tastyTests =
  testGroup
    "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.WOTS"
    [ 
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.fors_skGen"
          [ testProperty "Fors fors_skGen SLH_DSA_SHA2_128s" $ forsProperty  @SLH_DSA_SHA2_128s @(SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, IdxType SLH_DSA_SHA2_128s) @(NBlockType SLH_DSA_SHA2_128s) "fors_skGen" "SLH_DSA_SHA2_128s" (natToNum @(BitSize (SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s))) FORS_TREE fors_skGen
          , testProperty "Fors fors_skGen SLH_DSA_SHA2_128f" $ forsProperty  @SLH_DSA_SHA2_128f @(SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, IdxType SLH_DSA_SHA2_128f) @(NBlockType SLH_DSA_SHA2_128f) "fors_skGen" "SLH_DSA_SHA2_128f" (natToNum @(BitSize (SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f))) FORS_TREE fors_skGen
          ]
      ,
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.fors_node"
          [ testProperty "Fors fors_node SLH_DSA_SHA2_128s" $ forsProperty  @SLH_DSA_SHA2_128s @(SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, IdxType SLH_DSA_SHA2_128s, IdxType SLH_DSA_SHA2_128s) @(NBlockType SLH_DSA_SHA2_128s) "fors_node" "SLH_DSA_SHA2_128s" (natToNum @(BitSize (SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s))) FORS_TREE fors_node
          , testProperty "Fors fors_node SLH_DSA_SHA2_128f" $ forsProperty  @SLH_DSA_SHA2_128f @(SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, IdxType SLH_DSA_SHA2_128f, IdxType SLH_DSA_SHA2_128f) @(NBlockType SLH_DSA_SHA2_128f) "fors_node" "SLH_DSA_SHA2_128f" (natToNum @(BitSize (SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f))) FORS_TREE fors_node
          ]
      ,
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.fors_sign"
          [ testProperty "Fors fors_sign SLH_DSA_SHA2_128s" $ forsProperty  @SLH_DSA_SHA2_128s @(MDByteType SLH_DSA_SHA2_128s, SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s) @(SIGᶠᵒʳˢType SLH_DSA_SHA2_128s) "fors_sign" "SLH_DSA_SHA2_128s" (natToNum @(BitSize (MDByteType SLH_DSA_SHA2_128s, SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s))) FORS_TREE fors_sign
          , testProperty "Fors fors_sign SLH_DSA_SHA2_128f" $ forsProperty  @SLH_DSA_SHA2_128f @(MDByteType SLH_DSA_SHA2_128f, SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f) @(SIGᶠᵒʳˢType SLH_DSA_SHA2_128f) "fors_sign" "SLH_DSA_SHA2_128f" (natToNum @(BitSize (MDByteType SLH_DSA_SHA2_128f, SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f))) FORS_TREE fors_sign
          ]
      ,
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.fors_pkFromSig"
          [ testProperty "Fors fors_pkFromSig SLH_DSA_SHA2_128s" $ forsProperty  @SLH_DSA_SHA2_128s @(SIGᶠᵒʳˢType SLH_DSA_SHA2_128s, MDByteType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s) @(NBlockType SLH_DSA_SHA2_128s) "fors_pkFromSig" "SLH_DSA_SHA2_128s" (natToNum @(BitSize (SIGᶠᵒʳˢType SLH_DSA_SHA2_128s, MDByteType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s))) FORS_TREE fors_pkFromSig
          , testProperty "Fors fors_pkFromSig SLH_DSA_SHA2_128f" $ forsProperty  @SLH_DSA_SHA2_128f @(SIGᶠᵒʳˢType SLH_DSA_SHA2_128f, MDByteType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f) @(NBlockType SLH_DSA_SHA2_128f) "fors_pkFromSig" "SLH_DSA_SHA2_128f" (natToNum @(BitSize (SIGᶠᵒʳˢType SLH_DSA_SHA2_128f, MDByteType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f))) FORS_TREE fors_pkFromSig
          ]


    ]
  
type ForsComponent a b dom =
 (HiddenClockResetEnable dom
  , Mod (BitSize a) ByteSize ~ 0
  , Mod (BitSize b) ByteSize ~ 0
  , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
  , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)) =>
 Channel dom (a) ->
 Channel dom (b)


forsProperty ∷  ∀ (alg ∷ SLH_DSA) a b. (
  BitPack a, BitPack b, NFDataX b
 , Mod (BitSize a) ByteSize ~ 0
  , Mod (BitSize b) ByteSize ~ 0
  , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
  , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)
  ,  KnownSLH_DSAParameters alg
  ) ⇒ String → String → KnownDomain System => Integer → ADRSTypeType → ForsComponent a b System -> Property
forsProperty name version placeAdrs typeType forsComp 
   | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
   = property $ do

  f <- forAll $ genDefinedBitVector -- General input
  fAdrs ← forAll $ genDefinedBitVector-- Only an address
  let fAdrs' = genAdrsType @alg fAdrs typeType
  let f' = v2bv (scatter @Integer @(BitSize a) @(BitSize (ADRSType alg)) @Bit @0 (bv2v f) (iterateI (+1) placeAdrs) (bv2v fAdrs'))
  let f'' = compute $ unpack f'
  let input1 = bv2ByteString @a (unpack f')
  liftIO $
        appendFile "test_speed.csv"
          (List.intercalate "," [name, show (pack f'')] <> "\n")
  python <- liftIO $ forsRefImplPython name version input1
  bv2ByteString (pack f'') === python
 where
  moduloError =
    error "Since the modulo of the field is prime, the inverse always exists."
  compute input
    = fromMaybe (error "The returned list was empty")
    $ getFirst
    $ foldMap First
    $ sampleN @System 1000000
    $ withClockResetEnable @System clockGen resetGen enableGen
    $ newsfeed
    $ forsComp
    $ channel
    $ fmap (input, )
    $ fromList
    $ Keep : Keep : Release : List.repeat Keep


-----------------------------------------
-- Python reference
--
-----------------------------------------
bv2ByteString ∷ ∀ a . (BitPack a, BitSize a ~ (Div (BitSize a) ByteSize) * ByteSize)
  ⇒ a → ByteString
bv2ByteString a = BS.pack $ toList $ unpack <$> (unconcatBitVector# (pack a))
-- Convert ByteString to hex for safe CLI passing
bsToHex :: ByteString -> String
bsToHex = BC.unpack . B16.encode

hexToBs :: String -> ByteString
hexToBs s =
  case B16.decode (BC.pack s) of
    Right bs -> bs
    Left err -> error ("hexToBs: invalid hex input: " <> err)
forsRefImplPython ::
  String → String -> ByteString -> IO ByteString
forsRefImplPython name version input1 =
      let digestName = name
      in do
          outputHex <- readProcess
              "python3"
              [ "tests/sim/Test/Clash/Crypto/PQC/SLH_DSA/Streaming/Definitions/fors_worker.py"
              , name
              , version
              , bsToHex input1
              ]
              ""
          pure (hexToBs (List.init outputHex))
