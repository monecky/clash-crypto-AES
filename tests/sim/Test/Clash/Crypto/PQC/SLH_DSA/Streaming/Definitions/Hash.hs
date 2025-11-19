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
import Clash.Crypto.PQC.SLH_DSA.Specification.Properties.Parameters
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Address
import Clash.Crypto.PQC.SLH_DSA.Specification.Definitions.Basics
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
type TestLen = 82 -- Should be bigger or equal to 2
tastyTests :: TestTree
tastyTests =
  testGroup
    "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions"
    [ 
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.H"
          [ testProperty "Hash H SLH_DSA_SHA2_128s" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M²Type SLH_DSA_SHA2_128s) @(HOutType SLH_DSA_SHA2_128s) "H" "SLH_DSA_SHA2_128s" _HStream
          , testProperty "Hash H SLH_DSA_SHA2_128f" $ hashProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M²Type SLH_DSA_SHA2_128f) @(HOutType SLH_DSA_SHA2_128f) "H" "SLH_DSA_SHA2_128f" _HStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.PRFᵐˢᵍ"
          [ 
          testProperty   "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128s" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128s) "PRFmsg" "SLH_DSA_SHA2_128s" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen)x))))
          , testProperty "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128f" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128f) "PRFmsg" "SLH_DSA_SHA2_128f" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen)x))))
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.PRFᵐˢᵍ.through"
          [ 
          testProperty   "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128s through" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128s) "PRFmsgthr" "SLH_DSA_SHA2_128s" (\x → _PRFᵐˢᵍthr @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen)x))))
          , testProperty "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128f through" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128f) "PRFmsgthr" "SLH_DSA_SHA2_128f" (\x → _PRFᵐˢᵍthr @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen)x))))
          ]
   , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Hash.PRFᵐˢᵍ.Fthrough"
          [ 
          testProperty   "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128s Fthrough" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) @(BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA SLH_DSA_SHA2_128s)) ByteSize + N SLH_DSA_SHA2_128s + TestLen) * ByteSize)) "PRFmsgFthr" "SLH_DSA_SHA2_128s" (\x → _PRFᵐˢᵍFthr @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen)x))))
          , testProperty "Hash PRFᵐˢᵍ SLH_DSA_SHA2_128f Fthrough" $ hashProperty @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) @(BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA SLH_DSA_SHA2_128f)) ByteSize + N SLH_DSA_SHA2_128f + TestLen) * ByteSize)) "PRFmsgFthr" "SLH_DSA_SHA2_128f" (\x → _PRFᵐˢᵍFthr @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen)x))))
          ]
    ]
  
type HashComponent a b dom =
 (HiddenClockResetEnable dom
  , Mod (BitSize a) ByteSize ~ 0
  , Mod (BitSize b) ByteSize ~ 0
  , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
  , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)) =>
 Channel dom (a) ->
 Channel dom (b)

hashProperty :: ∀ a b. (BitPack a, BitPack b, NFDataX b
 , Mod (BitSize a) ByteSize ~ 0
  , Mod (BitSize b) ByteSize ~ 0
  , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
  , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)
  ) ⇒ String → String → KnownDomain System => HashComponent a b System -> Property
hashProperty name version hashComp = property $ do
  f <- forAll $ genDefinedBitVector 
  let f' = compute $ unpack f
  liftIO $
        appendFile "hash_test_results.csv"
          (List.intercalate "," [name, version, show (pack f), show (pack f')] <> "\n")
  let input1 = bv2ByteString @a (unpack f)

  python <- liftIO $ hashRefImplPython name version input1
  -- Just to satisfy the test environment.
  bv2ByteString (pack f') === python
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
hashRefImplPython ::
  String → String -> ByteString -> IO ByteString
hashRefImplPython name version input1 =
      let digestName = name
      in do
          outputHex <- readProcess
              "python3"
              [ "tests/sim/Test/Clash/Crypto/PQC/SLH_DSA/Streaming/Definitions/hash_worker.py"
              , name
              , version
              , bsToHex input1
              ]
              ""
          pure (hexToBs (List.init outputHex))


-- Equivalent prfmsg without hmac
_PRFᵐˢᵍThrough ∷ ∀ sha security alg dom . 
                (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg)
              ⇒ Proxy alg 
              →  Channel dom (SKPrfType alg, Opt_randType alg) 
              →  DataStream dom () () (ByteType)
              →  Channel dom (PRFᵐˢᵍOutType alg)
_PRFᵐˢᵍThrough alg inputC inputD  
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    -- , SHAFacts {} ← knownSHA @(SHAVersionPRFᵐˢᵍSLH_DSA alg)
    , Rewrite ← using @(ModTimes (Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg) ByteSize)
    , Rewrite ← using @(ModTimes (N alg + N alg) ByteSize)
        -- = fmap makeOutput (HMAC.hmac @(SHAVersionPRFᵐˢᵍSLH_DSA alg) ( mapStart (\y → natToNum @(N alg) ∷ Index ((BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg) `Div` ByteSize) + 1)) ( mapEnd (const ()) (serializePrepend transfer inputD))))
        = fmap makeOutput ((transferToC) ( mapStart (const ()) ( mapEnd (const ()) (serializePrepend transfer inputD))))
        
        where
            transfer = fmap go inputC
            makeOutput ∷ Digest (SHAVersionPRFᵐˢᵍSLH_DSA alg) → PRFᵐˢᵍOutType alg -- N alg * ByteSize == 16*8 = 128 while SHA 256 == 256
            makeOutput output 
              | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
              , Rewrite ← using @(DivTimes (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
              , Rewrite ← using @(ModTimes (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
              , Rewrite ← using @(CancelMultiple (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
              = takeI @(N alg) @(Div (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize - N alg) (unconcatBitVector# @(Div (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize) @(ByteSize) output)       
            go ∷ (KnownSLH_DSAParameters alg) 
              ⇒ (SKPrfType alg, Opt_randType alg) 
              → BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg) * ByteSize)
            go (skPrf, opt_rand)
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = concatBitVector# (skPrf ‖ unconcatBitVector# @((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize) - N alg) @ByteSize 0x0 ‖ opt_rand)

_PRFᵐˢᵍthr ∷ ∀ alg dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom) 
                  ⇒ Channel dom (SKPrfType alg, Opt_randType alg) 
                  → DataStream dom () () (ByteType)
                  →  Channel dom (PRFᵐˢᵍOutType alg)
_PRFᵐˢᵍthr 
  | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
  = _PRFᵐˢᵍThrough  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg  alg

-- Testing if the full message comes through.
_PRFᵐˢᵍFThrough ∷ ∀ sha security alg dom . 
                (KnownDomain dom, HiddenClockResetEnable dom, KnownSLH_DSAParameters alg)
              ⇒ Proxy alg 
              →  Channel dom (SKPrfType alg, Opt_randType alg) 
              →  DataStream dom () () (ByteType)
              →  Channel dom (BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg + TestLen) * ByteSize) )
_PRFᵐˢᵍFThrough alg inputC inputD  
    | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
    -- , SHAFacts {} ← knownSHA @(SHAVersionPRFᵐˢᵍSLH_DSA alg)
    , Rewrite ← using @(ModTimes (Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg) ByteSize)
    , Rewrite ← using @(ModTimes (Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg + TestLen) ByteSize)
    , Rewrite ← using @(ModTimes (N alg + N alg) ByteSize)
        -- = fmap makeOutput (HMAC.hmac @(SHAVersionPRFᵐˢᵍSLH_DSA alg) ( mapStart (\y → natToNum @(N alg) ∷ Index ((BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg) `Div` ByteSize) + 1)) ( mapEnd (const ()) (serializePrepend transfer inputD))))
        = ((transferToC) ( mapStart (const ()) ( mapEnd (const ()) (serializePrepend transfer inputD))))
        
        where
            transfer = fmap go inputC
            makeOutput ∷ Digest (SHAVersionPRFᵐˢᵍSLH_DSA alg) → PRFᵐˢᵍOutType alg -- N alg * ByteSize == 16*8 = 128 while SHA 256 == 256
            makeOutput output 
              | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
              , Rewrite ← using @(DivTimes (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
              , Rewrite ← using @(ModTimes (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
              , Rewrite ← using @(CancelMultiple (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize)
              = takeI @(N alg) @(Div (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize - N alg) (unconcatBitVector# @(Div (MessageDigestSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize) @(ByteSize) output)       
            go ∷ (KnownSLH_DSAParameters alg) 
              ⇒ (SKPrfType alg, Opt_randType alg) 
              → BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg) * ByteSize)
            go (skPrf, opt_rand)
                | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
                = concatBitVector# (skPrf ‖ unconcatBitVector# @((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize) - N alg) @ByteSize 0x0 ‖ opt_rand)

_PRFᵐˢᵍFthr ∷ ∀ alg dom . (KnownSLH_DSAParameters alg, SLH_DSA_hashStreamFact alg, KnownDomain dom, HiddenClockResetEnable dom) 
                  ⇒ Channel dom (SKPrfType alg, Opt_randType alg) 
                  → DataStream dom () () (ByteType)
                  →  Channel dom (BitVector ((Div (BlockSize (SHAVersionPRFᵐˢᵍSLH_DSA alg)) ByteSize + N alg + TestLen) * ByteSize) )
_PRFᵐˢᵍFthr 
  | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
  = _PRFᵐˢᵍFThrough  @(SHAVersionSLH_DSA alg) @(SecurityLevelSLH_DSA alg) @alg  alg