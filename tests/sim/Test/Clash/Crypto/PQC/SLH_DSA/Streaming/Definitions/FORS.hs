{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS'
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE MagicHash #-}

module Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS (tastyTests) where

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
import Data.Typeable (Typeable)
type TestLenA = 20 -- Should be bigger or equal to 2
type TestLenB = 16 -- Should be bigger or equal to 2
tastyTests :: TestTree
tastyTests =
  testGroup
    "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions"
    [ 
      -- localOption (HedgehogTestLimit (Just 100)) $
      --   testGroup
      --     "Fors.fors_skGen"
      --     [ testProperty "Fors fors_skGen SLH_DSA_SHA2_128s" $ forsProperty  @SLH_DSA_SHA2_128s @(SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, IdxType SLH_DSA_SHA2_128s) @(NBlockType SLH_DSA_SHA2_128s) "fors_skGen" "SLH_DSA_SHA2_128s" (natToNum @(BitSize (SKSeedType SLH_DSA_SHA2_128s, PKSeedType SLH_DSA_SHA2_128s))) fors_skGen
      --     , testProperty "Fors fors_skGen SLH_DSA_SHA2_128f" $ forsProperty  @SLH_DSA_SHA2_128f @(SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, IdxType SLH_DSA_SHA2_128f) @(NBlockType SLH_DSA_SHA2_128f) "fors_skGen" "SLH_DSA_SHA2_128f" (natToNum @(BitSize (SKSeedType SLH_DSA_SHA2_128f, PKSeedType SLH_DSA_SHA2_128f))) fors_skGen
      --     ]

      -- , 
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.fors_skGen"
          [ testProperty "Fors fors_skGen SLH_DSA_SHA2_128s" $ reproducer  @AA @(BitVector (Dum1 AA)) @(BitVector (Dum2 AA)) (natToNum @(BitSize (BitVector (Dum AA))))
          , testProperty "Fors fors_skGen SLH_DSA_SHA2_128f" $ reproducer  @BB @(BitVector (Dum1 BB)) @(BitVector (Dum2 BB)) (natToNum @(BitSize (BitVector (Dum BB))))
          ]
    -- , localOption (HedgehogTestLimit (Just 100)) $
    --     testGroup
    --       "Fors.F"
    --       [ 
    --       testProperty   "Fors F SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M¹Type SLH_DSA_SHA2_128s) @(FOutType SLH_DSA_SHA2_128s) "F" "SLH_DSA_SHA2_128s" _FStream
    --       , testProperty "Fors F SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M¹Type SLH_DSA_SHA2_128f) @(FOutType SLH_DSA_SHA2_128f) "F" "SLH_DSA_SHA2_128f" _FStream
    --       ]
    -- , localOption (HedgehogTestLimit (Just 100)) $
    --     testGroup
    --       "Fors.Tl"
    --       [ 
    --       testProperty   "Fors Tl SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, MˡType TestLen SLH_DSA_SHA2_128s) @(TˡOutType SLH_DSA_SHA2_128s) "Tl" "SLH_DSA_SHA2_128s" _TˡStream
    --       , testProperty "Fors Tl SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, MˡType TestLen SLH_DSA_SHA2_128f) @(TˡOutType SLH_DSA_SHA2_128f) "Tl" "SLH_DSA_SHA2_128f" _TˡStream
    --       ]
    -- , localOption (HedgehogTestLimit (Just 100)) $
    --     testGroup
    --       "Fors.PRF"
    --       [ 
    --       testProperty   "Fors PRF SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, SKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s) @(PRFOutType SLH_DSA_SHA2_128s) "PRF" "SLH_DSA_SHA2_128s" _PRFStream
    --       , testProperty "Fors PRF SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, SKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f) @(PRFOutType SLH_DSA_SHA2_128f) "PRF" "SLH_DSA_SHA2_128f" _PRFStream
    --       ]
    -- , localOption (HedgehogTestLimit (Just 100)) $
    --     testGroup
    --       "Fors.PRFᵐˢᵍ"
    --       [ 
    --       testProperty   "Fors PRFᵐˢᵍ SLH_DSA_SHA2_128s" $ forsProperty @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128s) "PRFmsg" "SLH_DSA_SHA2_128s" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen)x))))
    --       , testProperty "Fors PRFᵐˢᵍ SLH_DSA_SHA2_128f" $ forsProperty @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128f) "PRFmsg" "SLH_DSA_SHA2_128f" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen)x))))
    --       ]

    ]
  
type ForsComponent a b dom =
 (HiddenClockResetEnable dom
  , Mod (BitSize a) ByteSize ~ 0
  , Mod (BitSize b) ByteSize ~ 0
  , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
  , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)) =>
 Channel dom (a) ->
 Channel dom (b)

type DUMMY ∷ Type
data DUMMY = 
    AA
  | BB 
  deriving 
    ( Generic
    , NFDataX
    , BitPack
    , Eq
    , Ord
    , Show
    , Enum
    , Bounded
    , Typeable
    )
type Dum ∷ DUMMY → Nat
type family Dum (alg ∷ DUMMY) where
  Dum AA = 16
  Dum BB = 124143
type Dum1 ∷ DUMMY → Nat
type family Dum1 (alg ∷ DUMMY) where
  Dum1 AA = 12
  Dum1 BB = 12
type Dum2 ∷ DUMMY → Nat
type family Dum2 (alg ∷ DUMMY) where
  Dum2 AA = 16 
  Dum2 BB = 124
data DUMMYFacts (alg ∷ DUMMY) where
    DUMMYFacts ∷
        ( KnownNat (Dum alg)
        , KnownNat (Dum1 alg)
        , KnownNat (Dum2 alg)
 
        ) ⇒
        Proxy alg →
        DUMMYFacts alg
class    KnownDUMMY alg    where knownDUMMY ∷ DUMMYFacts alg
instance KnownDUMMY AA      where knownDUMMY = DUMMYFacts Proxy
instance KnownDUMMY BB      where knownDUMMY = DUMMYFacts Proxy
reproducer ∷  ∀ (alg ∷ DUMMY) a b. (
  BitPack a, BitPack b, NFDataX b
  ,  KnownDUMMY alg
  ) ⇒ Integer → Property
reproducer placeAdrs
   | DUMMYFacts alg ← knownDUMMY @alg
   = property $ do
  f <- forAll $ genDefinedBitVector -- General input
  fAdrs ← forAll $ genDefinedBitVector -- Only an address
  let f' = v2bv (scatter @Integer @(BitSize a) @(BitSize (b)) @Bit @(0 ∷ Nat) (bv2v f) (iterateI (+1) placeAdrs) (bv2v fAdrs))
  f === f
-- forsProperty ∷  ∀ (alg ∷ SLH_DSA) a b. (
--   BitPack a, BitPack b, NFDataX b
--  , Mod (BitSize a) ByteSize ~ 0
--   , Mod (BitSize b) ByteSize ~ 0
--   , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
--   , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)
--   ,  KnownSLH_DSAParameters alg
--   ) ⇒ String → String → KnownDomain System => Integer → ForsComponent a b System -> Property
-- forsProperty name version placeAdrs forsComp 
--    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
--    = property $ do

--   f <- forAll $ genDefinedBitVector -- General input
--   fAdrs ← forAll $ genDefinedBitVector-- Only an address
--   let fAdrs' = genAdrs @alg fAdrs
--   let f' = v2bv (scatter @Integer @(BitSize a) @(BitSize (ADRSType alg)) @0 (bv2v f) (iterateI (+1) placeAdrs) (bv2v fAdrs'))
--   let f' = compute $ unpack f
--   liftIO $
--         appendFile "Fors_test_results.csv"
--           (List.intercalate "," [name, version, show (pack f), show (pack f')] <> "\n")
--   let input1 = bv2ByteString @a (unpack f)

--   python <- liftIO $ forsRefImplPython name version input1
--   -- Just to satisfy the test environment.
--   bv2ByteString (pack f') === python
--  where
--   moduloError =
--     error "Since the modulo of the field is prime, the inverse always exists."
--   compute input
--     = fromMaybe (error "The returned list was empty")
--     $ getFirst
--     $ foldMap First
--     $ sampleN @System 10000000
--     $ withClockResetEnable @System clockGen resetGen enableGen
--     $ newsfeed
--     $ forsComp
--     $ channel
--     $ fmap (input, )
--     $ fromList
--     $ Keep : Keep : Release : List.repeat Keep


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
