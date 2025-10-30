{-|
Module      : Test.Clash.Crypto.Hash.MGF1
Copyright   : Copyright © 2024 QBayLogic B.V.
Maintainer  : QBayLogic B.V.
Stability   : experimental
Portability : POSIX

Test suite for 'Clash.Crypto.Hash.MGF1'.
MGF1 is implemenent to work for security level 1 and 3 of the SLH-DSA algorithm.
Therefore only the combination of SHA256 and SHA512 is properly tested.
-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedLists #-}
{-# OPTIONS_GHC -Wno-deprecations #-}
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
import Data.ByteString (ByteString)

import Clash.Prelude
import Clash.Signal.Channel
import Clash.Signal.DataStream
import Clash.Sized.Vector (unsafeFromList)

import Data.ByteString (ByteString, dropEnd )
import Data.Constraint.Nat.Extra
import Data.Maybe
import Data.Proxy
import GHC.TypeNats.Proof (Rewrite(..), using)
import Hedgehog
import Language.Haskell.Unicode (type (≤))
import Test.Tasty
import Test.Tasty.Hedgehog

import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range

import qualified Data.ByteString as BS
import qualified Data.List as List


import qualified Clash.Crypto.Hash.SHA.Specification as Spec
import Crypto.PubKey.MaskGenFunction as Ref
import Crypto.Hash.Algorithms as RefAlg
import Data.ByteArray (ByteArrayAccess, ByteArray)
import Crypto.Hash.IO
import Clash.Crypto.Hash.SHA as CryptoSHA
import Clash.Crypto.Hash.MGF1.Specification as DUT
import Clash.Crypto.PQC.SLH_DSA.Specification.Types 
import qualified Crypto.Hash.SHA1    as SHA1
import qualified Crypto.Hash.SHA224  as SHA224
import qualified Crypto.Hash.SHA256  as SHA256
import qualified Crypto.Hash.SHA384  as SHA384
import qualified Crypto.Hash.SHA512  as SHA512
import qualified Crypto.Hash.SHA512t as SHA512t
import Data.Word (Word8)
tastyTests ∷ TestTree
tastyTests = testGroup "Clash.Crypto.Hash.MGF1"
  [localOption (HedgehogTestLimit (Just 10)) $ -- Purpose is mainly to get familiar with testing.
      testProperty "Functional equality of XOR" $ property $ do
        a ← forAll $ genDefinedBitVector
        b ← forAll $ genDefinedBitVector
        testOplus a b
        , localOption (HedgehogTestLimit $ Just 4)
      $ testGroup "Specification Sanity Checks (unit tests)"
          [ testProperty ("SHA-" <> algName)
              $ property
              $ forAll (Gen.element inputs)
                  >>= hashPure
          | let inputs = [input1, input2, input3, input4] ∷ [ByteString]
          , (hashPure, algName) ← [
              -- (testMGF1Pure @CryptoSHA.SHA1,      "1")
              -- , (testMGF1Pure @CryptoSHA.SHA224,    "224")
              -- ,
              
               (testMGF1Pure @CryptoSHA.SHA256,    "256")
              -- , (testMGF1Pure @CryptoSHA.SHA512,    "512")
            --   , (testMGF1Pure @SHA512224, "512/224")
            --   , (testMGF1Pure @SHA512256, "512/246")
              ]
          ]
        ] 
type TestLen = 8
testOplus ∷ (Monad m) => BitVector TestLen -> BitVector TestLen -> PropertyT m ()
testOplus a b = xor b a === xor a b
type TestMaskLen = 3

testMGF1Pure ∷ ∀ (sha ∷ SHA) m n0. (KnownSHA sha, Monad m, KnownNat n0, CryptoMGF1 sha,CryptoHash sha, ((TestMaskLen + n0)
                        ~ Div (MessageDigestSize sha) 8)) ⇒ ByteString → PropertyT m ()
testMGF1Pure bs
  | SHAFacts sha ← knownSHA @sha
  , Rewrite ← using @(CancelMultiple (MessageDigestSize sha) 8)
  = do

  Just (SomeNat (_ ∷ Proxy n)) ←
    return $ someNatVal $ toInteger $ BS.length bs

  let
    inputAsBv8 ∷ [BitVector 8]
    inputAsBv8 = pack <$> BS.unpack bs

    inputAsVBv8 ∷ Vec n (BitVector 8)
    inputAsVBv8 = unsafeFromList @n inputAsBv8

    inputAsBv ∷ Message (n * 8)
    inputAsBv = concatBitVector# inputAsVBv8

    -- resultDigestAsBv ∷ BitVector (TestMaskLen * ByteSize)
    resultDigestAsBv ∷ BitVector (MessageDigestSize sha)
    resultDigestAsBv = Spec.hash @sha ((++#) inputAsBv (0 ∷ BitVector (ByteSize * 4)))
    -- resultDigestAsBv = DUT.mgf1 @sha @(TestMaskLen)  inputAsBv


    resultDigestAsVBv8 ∷ ((TestMaskLen + n0)
                        ~ Div (MessageDigestSize sha) 8) ⇒  Vec (TestMaskLen) (BitVector 8)
    -- resultDigestAsVBv8 ∷ Vec (TestMaskLen) (ByteType)
    -- resultDigestAsVBv8 = unconcatBitVector# resultDigestAsBv
    resultDigestAsVBv8 = takeI @TestMaskLen (unconcatBitVector# resultDigestAsBv)
    dut ∷ ((TestMaskLen + n0)
                        ~ Div (MessageDigestSize sha) 8) ⇒ [Word8] 
    dut = toList $ unpack <$> resultDigestAsVBv8
    ref = BS.unpack $ cryptoMGF1 sha bs (natToNum @(TestMaskLen))
    -- ref = BS.unpack $ cryptoHash sha bs

  ref === dut


class CryptoMGF1 (alg ∷ CryptoSHA.SHA) where
  cryptoMGF1 ∷ Proxy alg → ByteString → Int → ByteString

instance CryptoMGF1 CryptoSHA.SHA1      where cryptoMGF1 _ = Ref.mgf1  RefAlg.SHA1
instance CryptoMGF1 CryptoSHA.SHA224    where cryptoMGF1 _ = Ref.mgf1  RefAlg.SHA224
instance CryptoMGF1 CryptoSHA.SHA256    where cryptoMGF1 _ = Ref.mgf1  RefAlg.SHA256
instance CryptoMGF1 CryptoSHA.SHA384    where cryptoMGF1 _ = Ref.mgf1  RefAlg.SHA384
instance CryptoMGF1 CryptoSHA.SHA512    where cryptoMGF1 _ = Ref.mgf1  RefAlg.SHA512
class CryptoHash (alg ∷ CryptoSHA.SHA) where
  cryptoHash ∷ Proxy alg → ByteString → ByteString

instance CryptoHash CryptoSHA.SHA1      where cryptoHash _ = SHA1.hash
instance CryptoHash CryptoSHA.SHA224    where cryptoHash _ = SHA224.hash
instance CryptoHash CryptoSHA.SHA256    where cryptoHash _ = SHA256.hash
instance CryptoHash CryptoSHA.SHA384    where cryptoHash _ = SHA384.hash
instance CryptoHash CryptoSHA.SHA512    where cryptoHash _ = SHA512.hash
instance CryptoHash CryptoSHA.SHA512224 where cryptoHash _ = SHA512t.hash 224
instance CryptoHash CryptoSHA.SHA512256 where cryptoHash _ = SHA512t.hash 256

-- | Some example input for unit testing.
input1 ∷ ByteString
input1 =
  [102, 111, 111, 111, 111, 111, 111, 111, 111, 111, 102, 111, 111, 111, 111, 111, 111, 111, 111, 111, 102, 111, 111, 111, 111, 111, 111, 111, 111, 111
  ,102, 111, 111, 111, 111, 111, 111, 111, 111, 111, 102, 111, 111, 111, 111, 111, 111, 111, 111, 111, 102, 111, 111, 111, 111, 111, 111, 111, 111, 111, 0 ,0 ,0 ,0]
-- input1 ∷ ByteString
-- input1 =
--   [ 255, 23, 42, 38, 29, 48, 244, 65, 2, 99 ]

-- | Some example input for unit testing.
input2 ∷ ByteString
input2 =
  [ 255, 23, 42, 38, 29, 48, 244, 65, 2, 99, 41, 31, 231, 199, 25, 32
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  , 255, 23, 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 231
  ]

-- | Some example input for unit testing.
input3 ∷ ByteString
input3 =
  [ 255, 23, 42, 38, 29, 48, 244, 65, 2, 99, 41, 31, 231, 199, 25, 32
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  , 255, 23, 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 231
  , 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 255, 23, 231
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  ]

-- | Some example input for unit testing.
input4 ∷ ByteString
input4 =
  [ 255, 23, 42, 38, 29, 48, 244, 65, 2, 99, 41, 31, 231, 199, 25, 32
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  , 255, 23, 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 231
  , 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 255, 23, 231
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  , 255, 23, 42, 38, 29, 48, 244, 65, 2, 99, 41, 31, 231, 199, 25, 32
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  , 255, 23, 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 231
  , 42, 38, 199, 25, 32, 29, 48, 244, 65, 2, 99, 41, 31, 255, 23, 231
  , 65, 2, 99, 41, 31, 231, 199, 25, 32, 255, 23, 42, 38, 29, 48, 244
  ]
