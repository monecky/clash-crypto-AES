{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
module Test.Clash.Crypto.MAC.HMAC where

import Clash.Prelude hiding (init, length, (!!), foldr, map)
import Clash.Signal.Channel
import Clash.Signal.DataStream

import Data.Constraint.Nat.Extra (CancelMultiple)
import Data.Maybe
import GHC.TypeNats.Proof (Rewrite(..), using)
import qualified Data.List as List

import Test.Tasty
import Test.Tasty.Hedgehog

import Clash.Crypto.MAC.HMAC
import Clash.Crypto.Hash.SHA

import Test.Clash.Crypto.Hash.SHA

import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

-- Reference implementation
import qualified "cryptohash" Crypto.MAC.HMAC as Spec
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)


import Test.Tasty

import Control.Monad.IO.Class (liftIO)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import System.Process (readProcess)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Base16 as B16
import Data.ByteString.Base16
import Data.Proxy
-- import Data.Char
import GHC.TypeLits
-- import Crypto.Hash (CryptoHash)
-- import SHA (SHA, KnownSHA(..), SHAFacts(..), BlockSize)
-- import Utils (natToNum)
tastyTests :: TestTree
tastyTests =
  testGroup "Test.Clash.Crypto.MAC.HMAC"
    [ testProperty "Contiguous Input"     $ testHmacHedgehog @SHA256 True
    , testProperty "Non-contiguous Input" $ testHmacHedgehog @SHA256 False
    , testProperty "SHA256 matches contiguous" $ testPropertyPythonMatchesRef @SHA256 "sha256" True
    , testProperty "SHA512 matches contiguous" $ testPropertyPythonMatchesRef @SHA512 "sha512" True
    , testProperty "SHA256 matches non-contiguous" $ testPropertyPythonMatchesRef @SHA256 "sha256" False
    , testProperty "SHA512 matches non-contiguous" $ testPropertyPythonMatchesRef @SHA512 "sha512" False 
    ]

testHmacHedgehog ::
  forall (alg :: SHA).
  ( KnownSHA alg, CryptoHash alg
  , 8 <= BlockSize alg, Mod (BlockSize alg) 8 ~ 0
  ) =>
  Bool -> Property
testHmacHedgehog contiguous
  | SHAFacts _ <- knownSHA @alg
  = property $ do
    let n = natToNum @(BlockSize alg `Div` 8)
        m = 499 -- max message size
        genSpacings (BS.length -> j)
          | contiguous = pure $ List.replicate j 0
          | otherwise  = Gen.list (Range.singleton j)
                       $ Gen.integral @_ @Int $ Range.linear 1 100
    testKey <- forAll $ Gen.bytes $ Range.linear 1 n
    testMsg <- forAll $ Gen.bytes $ Range.linear 1 m
    keySpacings <- forAll $ genSpacings testKey
    msgSpacings <- forAll $ genSpacings testMsg
    let testInput = (testKey, testMsg)
    (===) (hmacRefImpl @alg testInput)
          (hmacImpl @alg (keySpacings, msgSpacings) testInput)

showLn :: ShowX a => [a] -> String
showLn = List.concatMap ((<> "\n") . showX)

hmacImpl ::
  forall (alg :: SHA).
  (KnownSHA alg, 8 <= BlockSize alg, Mod (BlockSize alg) 8 ~ 0) =>
  ([Int], [Int]) ->
  (ByteString, ByteString) ->
  ByteString
hmacImpl (keySpacings, msgSpacings) (keyData, msgData)
  | SHAFacts _ <- knownSHA @alg
  , Rewrite ← using @(CancelMultiple (MessageDigestSize alg) 8)
  = let
      addSpacings xs
        = List.concatMap (\(j, x) -> x : List.replicate j NoData)
        . List.zip xs

      restructure = (Middle . bitCoerce <$>) . BS.unpack

      keyInput = addSpacings keySpacings $
        case restructure keyData of
          Middle x : xr -> Start (toEnum $ BS.length keyData) x : xr
          y -> y

      msgSpacings' = List.reverse $ case List.reverse msgSpacings of
        []     -> []
        _ : xr -> 0 : xr

      msgInput = addSpacings msgSpacings' $ List.reverse $
        case List.reverse $ restructure msgData of
          Middle x : xr -> End () x : xr
          y -> y

      n = natToNum @(BlockSize alg `Div` 8)
      m = BS.length keyData + BS.length msgData
      i = List.length keyInput + List.length msgInput + n - BS.length keyData
      sc = max n $ natToNum @(ScheduleCount alg)

      -- over-approximation (for keeping the calculation simple)
      requiredSamples           -- cycles for
        = i                     --   > passing all input
        + sc * (m `div` sc + 3) --   > computing the inner hash
        + 2 * n                 --   > passing key and digest of the outer hash
        + 5 * sc                --   > computing the outer hash

      hmacTestInput ::
        [Frame (Index ((BlockSize alg `Div` 8) + 1)) () (BitVector 8)]
      hmacTestInput =
        -- Skip over reset
        List.replicate 3 Idle
        -- Test data
        <> keyInput
        -- we need to send exactly `BlockSize alg` many bits before
        -- sending the msg
        <> List.replicate (n - BS.length keyData) (Middle 0xFF)
        <> msgInput
        <> List.repeat Idle

      output :: Vec (MessageDigestSize alg `Div` 8) (BitVector 8)
      output
        = unconcatBitVector#
        $ maybe (error "No response received.") fst
        $ List.uncons
        $ catMaybes
        $ sampleN @System requiredSamples
        $ newsfeed
        $ withClockResetEnable clockGen resetGen enableGen
        $ hmac @alg
        $ fromList hmacTestInput
    in
      BS.pack $ toList $ unpack <$> output
testPropertyPythonMatchesRef ::
  forall alg. (KnownSHA alg, CryptoHash alg, 8 <= BlockSize alg, Mod (BlockSize alg) 8 ~ 0) =>
  String → Bool → Property
testPropertyPythonMatchesRef name contiguous
  | SHAFacts alg <- knownSHA @alg
  = property $ do
      let n = natToNum @(BlockSize alg `Div` 8)
          m = 499
          genSpacings contiguous bs
            | contiguous = pure $ List.replicate (BS.length bs) 0
            | otherwise  = Gen.list (Range.singleton $ BS.length bs)
                         $ Gen.integral @_ @Int $ Range.linear 1 100
      testKey <- forAll $ Gen.bytes $ Range.linear 1 n
      testMsg <- forAll $ Gen.bytes $ Range.linear 1 m
      keySpacings <- forAll $ genSpacings contiguous testKey
      msgSpacings <- forAll $ genSpacings contiguous testMsg
      let testInput = (testKey, testMsg)
      ref    <- liftIO $ pure $ hmacRefImpl @alg testInput
      python <- liftIO $ hmacRefImplPython @alg name testInput
      let clash = hmacImpl @alg (keySpacings, msgSpacings) testInput
      ref    === python
      python === clash


hmacRefImpl ::
  forall (alg :: SHA).
  (KnownSHA alg, CryptoHash alg) =>
  (ByteString, ByteString) ->
  ByteString
hmacRefImpl (key, msg)
  | SHAFacts alg <- knownSHA @alg
  = Spec.hmac (cryptoHash alg) (natToNum @(BlockSize alg `Div` 8)) key msg


-- Convert ByteString to hex for safe CLI passing
bsToHex :: ByteString -> String
bsToHex = BC.unpack . B16.encode

hexToBs :: String -> ByteString
hexToBs s =
  case B16.decode (BC.pack s) of
    Right bs -> bs
    Left err -> error ("hexToBs: invalid hex input: " <> err)

hmacRefImplPython ::
  forall alg. (KnownSHA alg, CryptoHash alg) => String → 
  (ByteString, ByteString) -> IO ByteString
hmacRefImplPython sha (key, msg)
  | SHAFacts alg <- knownSHA @alg =
      let digestName = sha
          blockSize  = show (natToNum @(BlockSize alg `Div` 8))
      in do
          outputHex ∷ String <- readProcess
              "python3"
              [ "hmac_worker.py"
              , bsToHex key
              , bsToHex msg
              , digestName
              , blockSize
              ]
              ""
          pure (hexToBs (List.init outputHex))   -- init: remove newline

