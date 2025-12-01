{-|
Module      : Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Fors
Copyright   : Copyright © 2025 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Fors'
-}
{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-# LANGUAGE MagicHash #-}

module Test.Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.Fors (tastyTests) where

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
import Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions.FORS
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
type TestLen = 16 -- Should be bigger or equal to 2
tastyTests :: TestTree
tastyTests =
  testGroup
    "Clash.Crypto.PQC.SLH_DSA.Streaming.Definitions"
    [ 
      localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.H"
          [ testProperty "Fors H SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M²Type SLH_DSA_SHA2_128s) @(HOutType SLH_DSA_SHA2_128s) "H" "SLH_DSA_SHA2_128s" _HStream
          , testProperty "Fors H SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M²Type SLH_DSA_SHA2_128f) @(HOutType SLH_DSA_SHA2_128f) "H" "SLH_DSA_SHA2_128f" _HStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.F"
          [ 
          testProperty   "Fors F SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, M¹Type SLH_DSA_SHA2_128s) @(FOutType SLH_DSA_SHA2_128s) "F" "SLH_DSA_SHA2_128s" _FStream
          , testProperty "Fors F SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, M¹Type SLH_DSA_SHA2_128f) @(FOutType SLH_DSA_SHA2_128f) "F" "SLH_DSA_SHA2_128f" _FStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.Tl"
          [ 
          testProperty   "Fors Tl SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s, MˡType TestLen SLH_DSA_SHA2_128s) @(TˡOutType SLH_DSA_SHA2_128s) "Tl" "SLH_DSA_SHA2_128s" _TˡStream
          , testProperty "Fors Tl SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f, MˡType TestLen SLH_DSA_SHA2_128f) @(TˡOutType SLH_DSA_SHA2_128f) "Tl" "SLH_DSA_SHA2_128f" _TˡStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.PRF"
          [ 
          testProperty   "Fors PRF SLH_DSA_SHA2_128s" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128s, SKSeedType SLH_DSA_SHA2_128s, ADRSType SLH_DSA_SHA2_128s) @(PRFOutType SLH_DSA_SHA2_128s) "PRF" "SLH_DSA_SHA2_128s" _PRFStream
          , testProperty "Fors PRF SLH_DSA_SHA2_128f" $ forsProperty @(PKSeedType SLH_DSA_SHA2_128f, SKSeedType SLH_DSA_SHA2_128f, ADRSType SLH_DSA_SHA2_128f) @(PRFOutType SLH_DSA_SHA2_128f) "PRF" "SLH_DSA_SHA2_128f" _PRFStream
          ]
    , localOption (HedgehogTestLimit (Just 100)) $
        testGroup
          "Fors.PRFᵐˢᵍ"
          [ 
          testProperty   "Fors PRFᵐˢᵍ SLH_DSA_SHA2_128s" $ forsProperty @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128s) "PRFmsg" "SLH_DSA_SHA2_128s" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128s (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128s, Opt_randType SLH_DSA_SHA2_128s, MType TestLen)x))))
          , testProperty "Fors PRFᵐˢᵍ SLH_DSA_SHA2_128f" $ forsProperty @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) @(PRFᵐˢᵍOutType SLH_DSA_SHA2_128f) "PRFmsg" "SLH_DSA_SHA2_128f" (\x → _PRFᵐˢᵍStream @SLH_DSA_SHA2_128f (transferToC (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen) x))) (transferToD @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f) @ByteSize (mapEnd (\y → ()) (serializeHash @ByteSize @(SKPrfType SLH_DSA_SHA2_128f, Opt_randType SLH_DSA_SHA2_128f, MType TestLen)x))))
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

forsProperty :: ∀ a b. (BitPack a, BitPack b, NFDataX b
 , Mod (BitSize a) ByteSize ~ 0
  , Mod (BitSize b) ByteSize ~ 0
  , (Div (BitSize a) ByteSize) * ByteSize ~ (BitSize a)
  , (Div (BitSize b) ByteSize) * ByteSize ~ (BitSize b)
  ) ⇒ String → String → KnownDomain System => ForsComponent a b System -> Property
forsProperty name version forsComp = property $ do
  f <- forAll $ genDefinedBitVector 
  let f' = compute $ unpack f
  liftIO $
        appendFile "Fors_test_results.csv"
          (List.intercalate "," [name, version, show (pack f), show (pack f')] <> "\n")
  let input1 = bv2ByteString @a (unpack f)

  python <- liftIO $ forsRefImplPython name version input1
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
    $ forsComp
    $ channel
    $ fmap (input, )
    $ fromList
    $ Keep : Keep : Release : List.repeat Keep


-----------------------------------------
-- Generate a valid random address
--
-----------------------------------------
genAdrs ∷ ∀ (alg ∷ SLH_DSA) . KnownSLH_DSAParameters alg ⇒ BitVector (BitSize (ADRSType alg)) → BitVector (BitSize (ADRSType alg))
genAdrs genadrs
    | SLH_DSAParametersFacts alg ← knownSLH_DSAParameters @alg
    = getADRSBitVector genadrs²
      where
        genadrs⁰ ∷ ADRSType alg
        genadrs⁰ 
          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
          = unpack genadrs
        -- Get the correct type
        gentype ∷ ADRSTypeType
        gentype = getTypeAsType genadrs⁰
        -- Clear all unnessary fields and set type.
        genadrs¹ ∷ ADRSType alg
        genadrs¹ 
          | SLH_DSAParametersFacts {} ← knownSLH_DSAParameters @alg
          = setTypeAndClear genadrs⁰ gentype
        -- Set back nessary fields and set type.
        genadrs² ∷ ADRSType alg 
        genadrs²
              | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
              = genadrs³ genadrs¹ genadrs⁰ gentype
          where
            genadrs³ ∷ ADRSType alg → ADRSType alg → ADRSTypeType → ADRSType alg 
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ }  WOTS_HASH       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
             }  WOTS_PK       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                  }

            genadrs³ adrs¹ ADRSType{                  
              chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } TREE       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {          
                      chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } FORS_TREE       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
             }  FORS_ROOTS       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ }  WOTS_PRF       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } FORS_PRF       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }
            genadrs³ adrs¹ ADRSType{                  
            keyPairAddress           = keyPairAddress⁰           
            , chainAddressTreeHeight   = chainAddressTreeHeight⁰   
            , hashAddressTreeIndexType = hashAddressTreeIndexType⁰ } _       
                  | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg 
                  = adrs¹ {
                      keyPairAddress           = keyPairAddress⁰           
                    , chainAddressTreeHeight   = chainAddressTreeHeight⁰  
                    , hashAddressTreeIndexType = hashAddressTreeIndexType⁰
                  }

-- genInputBlock ∷ ∀ (alg ∷ Spec.AES). Spec.KnownAES alg => Gen ByteString
-- genInputBlock 
--     | AESFacts _ ← knownAES @alg =
--     BS.pack <$> Gen.list (Range.singleton (snatToNum (SNat @(Spec.Nb alg * Spec.WordSize alg)))) Gen.enumBounded
-- genKeyFor :: ∀ (alg ∷ Spec.AES). Spec.KnownAES alg => Gen ByteString
-- genKeyFor   
--   | AESFacts _ ← knownAES @alg = do
--   BS.pack <$> Gen.list (Range.singleton (natToNum @( Spec.WordSize alg  * Spec.Nk alg ))) Gen.enumBounded




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
------
-- Address methode for testing purposes
--
-----
getTypeAsBv ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → BitVector 4
getTypeAsBv ADRSType{typeAddress = typeAddress} 
       | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
       =  v2bv (dropI (bv2v (pack typeAddress)))
getTypeAsType ∷ ∀ (alg ∷ SLH_DSA) . (KnownSLH_DSAParameters alg)⇒ ADRSType alg → ADRSTypeType
getTypeAsType adrs 
       | SLH_DSAParametersFacts{} <- knownSLH_DSAParameters @alg  
       =  match (getTypeAsBv adrs)
        where
          match ∷ BitVector 4 → ADRSTypeType
          match $(bitPattern "0000") = WOTS_HASH
          match $(bitPattern "0001") = WOTS_PK
          match $(bitPattern "0010") = TREE
          match $(bitPattern "0011") = FORS_TREE
          match $(bitPattern "0100") = FORS_ROOTS
          match $(bitPattern "0101") = WOTS_PRF
          match $(bitPattern "0110") = FORS_PRF
          match $(bitPattern "....") = WOTS_HASH
